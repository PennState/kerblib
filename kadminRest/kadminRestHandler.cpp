#include "base64.h"
#include "kerberosAdminSession.h"
#include "kerberosAdminFlags.h"
#include "userMetrics.h"
#include "pistache/router.h"
#include "pistache/endpoint.h"
#include "pistache/optional.h"
#include "pistache/http.h"
#include "pistache/http_headers.h"
#include "pistache/mime.h"
#include "json.hpp"
#include "base64.h"
#include "unableToChangePasswordException.h"
#include "userAlreadyExistsException.h"
#include "invalidPasswordException.h"
#include "securityRequestFailedException.h"
#include "loggers/consoleLogger.h"
#include <arpa/inet.h>
#include <signal.h>
#include <chrono>
#include <memory>

using namespace Pistache;

class KadminRestHandler {

  public:
    const std::string PASSWORD_REQUIREMENTS_MESSAGE = "It must be at least eight characters in length (Longer is generally better.)\nIt must contain at least one alphabetic and one numeric character.\nIt must be significantly different from previous passwords.\nIt cannot be the same as the userid.\nIt cannot contain the following special characters - spaces, \', \", &, (, ), |, <, >.\nIt should not be information easily obtainable about you. This includes license plate, social security, telephone numbers, or street address";

    KadminRestHandler(Pistache::Address addr, const std::string princ, std::string realm, std::string keytab, std::chrono::seconds timeout) : httpEndpoint_(std::make_shared<Pistache::Http::Endpoint>(addr)),
                                                                                                           adminUser_(princ),
                                                                                                           realm_(realm),
                                                                                                           keytab_(keytab),
                                                                                                           timeout_(timeout) {}

    void init(int threads) {
      auto opts = Pistache::Http::Endpoint::options()
        .threads(threads)
        .flags(Tcp::Options::ReuseAddr);

      httpEndpoint_->init(opts);
      setupRoutes();
    }

    void start() {
       httpEndpoint_->setHandler(router_.handler());
       httpEndpoint_->serveThreaded();
    }
   
    void shutdown() {
      httpEndpoint_->shutdown();
    }

  private : 
    void setupRoutes() {
      using namespace Pistache::Rest;

      Routes::Post(router_, "/resources/users/", Routes::bind(&KadminRestHandler::createUser, this));
      Routes::Get(router_, "/resources/users/:uid", Routes::bind(&KadminRestHandler::getUserMetrics, this));
      Routes::Get(router_, "/resources/healthcheck/", Routes::bind(&KadminRestHandler::doHealthCheck, this));
      Routes::Get(router_, "/resources/version/", Routes::bind(&KadminRestHandler::version, this));
      Routes::Put(router_, "/resources/users/:uid", Routes::bind(&KadminRestHandler::alterUser, this));
      Routes::Put(router_, "/resources/users/:uid/.passwordExpiration", Routes::bind(&KadminRestHandler::setPasswordExpiration, this));
      Routes::Put(router_, "/resources/users/:uid/.passwordPolicy", Routes::bind(&KadminRestHandler::setPasswordPolicy, this));
      Routes::Delete(router_, "/resources/users/:uid", Routes::bind(&KadminRestHandler::deleteUser, this));
      Routes::Get(router_, "/*", Routes::bind(&KadminRestHandler::catchAll, this));
      Routes::Get(router_, "/", Routes::bind(&KadminRestHandler::catchAll, this));
    }

    void version(const Rest::Request& request, Http::ResponseWriter response) {
      auto starttime = std::chrono::steady_clock::now();
      std::string s = "version=\"" + std::string(BUILD_VERSION) + "\" builddate=\"" + std::string(BUILD_DATE) + "\"";
      response.send(Http::Code::Ok, s.c_str());
      logRequest(request, response.code(), starttime);
    }

    void catchAll(const Rest::Request& request, Http::ResponseWriter response) {
      auto starttime = std::chrono::steady_clock::now();
      response.send(Http::Code::Not_Found, "not found");
      logRequest(request, response.code(), starttime);
    }

    void createUser(const Rest::Request& request, Http::ResponseWriter response) {
      auto starttime = std::chrono::steady_clock::now();

      std::string msg = "";
      std::string entity = request.body();

      try {
        nlohmann::json j = nlohmann::json::parse(entity);
        auto userid = j["userid"].get<std::string>();
        auto password = j["password"].get<std::string>();
        std::string policy = "";

        try {
          policy = j["policy"].get<std::string>();
        } catch(...) {
          //Do nothing, use default policy
        }

        try {
          ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser_, realm_, keytab_);
          if (policy != "") {
            kerbSession.createUser(userid, password, policy, ait::kerberos::REQUIRE_PREAUTH);
          } else {
            kerbSession.createUser(userid, password, ait::kerberos::REQUIRE_PREAUTH);
          }
          response.send(Http::Code::Created);
          msg = "User '" + userid + "' with policy '" + policy + "' created";
        } catch (ait::kerberos::UserAlreadyExistsException &ex) {
          response.send(Http::Code::Conflict);
          msg = "User '" + userid + "' already exists";
        } catch (ait::kerberos::InvalidPasswordException &ex) {
          response.send(Http::Code::Bad_Request, PASSWORD_REQUIREMENTS_MESSAGE);
          msg = "Invalid password for '" + userid + "': " + ex.what();
        } catch (ait::kerberos::SecurityRequestFailedException &ex) {
          msg = "Create user '" + userid + "' failed because: " + ex.what(); 
          response.send(Http::Code::Internal_Server_Error, msg);
        } catch(ait::kerberos::InvalidRequestException &e) {
          msg = "Create user '" + userid + "' failed because: " + e.what();
          response.send(Http::Code::Bad_Request, e.what());
        }catch (ait::kerberos::NotAuthorizedException &e) {
          msg = "Not authorized to create user '" + userid + "': " + e.what();
          response.send(Http::Code::Forbidden);
        }catch (...) {
          msg = "Unknown error";
          response.send(Http::Code::Internal_Server_Error, "Unknown error received, contact the service desk");
        }

      } catch(nlohmann::json::exception &e) {
        msg = "Could not parse JSON data: " + std::string(e.what());
        response.send(Http::Code::Bad_Request, msg);
        logRequest(request, response.code(), starttime, msg);
        return;
      }
      
      logRequest(request, response.code(), starttime, msg);
    }

    void doHealthCheck(const Rest::Request& request, Http::ResponseWriter response) {
      auto starttime = std::chrono::steady_clock::now();
      std::string error;
      try {
        ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser_, realm_, keytab_);
	      kerbSession.healthCheck();
        response.send(Http::Code::Ok);
      } catch(ait::kerberos::NotAuthorizedException &e) {
        error = e.what();
        response.send(Http::Code::Forbidden, error);
      } catch(ait::kerberos::CommunicationException &e) {
        error = e.what();
        response.send(Http::Code::Internal_Server_Error, error);
      } catch(ait::kerberos::UnableToFindUserException &e) {
        error = e.what();
        response.send(Http::Code::Not_Found, error);
      } catch(ait::kerberos::UnableToCreateSessionException &utcse) {
        error = utcse.what();
        response.send(Http::Code::Internal_Server_Error, error + "\n");
      } catch(...) {
        error = "Unknown error";
        response.send(Http::Code::Internal_Server_Error, error);
      }

      logRequest(request, response.code(), starttime, error);
    }

    void getUserMetrics(const Rest::Request& request, Http::ResponseWriter response) {
      auto starttime = std::chrono::steady_clock::now();
      std::string error;
      try {
        ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser_, realm_, keytab_);

        std::string uid = request.param(":uid").as<std::string>();
        ait::kerberos::UserMetrics metrics = kerbSession.getUserMetrics(uid);

        nlohmann::json j = {
          {"passwordCreation", metrics.passwordCreationAsString()},
          {"passwordExpiration", metrics.passwordExpirationAsString()},
          {"principalExpiration", metrics.principalExpirationAsString()},
          {"lastSuccessfulLogin", metrics.lastSuccessfulLoginAsString()},
          {"lastFailedLogin", metrics.lastFailedLoginAsString()},
          {"kvno", metrics.passwordChangeCount()}};

        response.setMime(Pistache::Http::Mime::MediaType::fromString("application/json"));
        response.send(Http::Code::Ok, j.dump(2));
      } catch(ait::kerberos::UnableToFindUserException &srfe) {
        error = "Unable to find user" + srfe.what();
	      response.send(Http::Code::Not_Found, error + "\n");
      } catch(ait::kerberos::UserAlreadyExistsException &uaee) {
        error = "User already Exists Exception " + uaee.what();
        response.send(Http::Code::Internal_Server_Error, error + "\n");
      } catch(ait::kerberos::InvalidPasswordException &ipe) {
        error = "Invalid password exception " + ipe.what();
        response.send(Http::Code::Internal_Server_Error, error + "\n");
      } catch(ait::kerberos::UnableToCreateSessionException &utcse) {
        error = utcse.what();
        response.send(Http::Code::Internal_Server_Error, error + "\n");
      } catch(...) {
        response.send(Http::Code::Internal_Server_Error, "\n");
      }

      logRequest(request, response.code(), starttime, error);
    }

    void deleteUser(const Rest::Request& request, Http::ResponseWriter response) {
      auto starttime = std::chrono::steady_clock::now();

      ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser_, realm_, keytab_);

      std::string uid = request.param(":uid").as<std::string>();
      
      try {
        kerbSession.deleteUser(uid);
        response.send(Http::Code::No_Content);
      } catch(ait::kerberos::NotAuthorizedException &e) {
         response.send(Http::Code::Forbidden);
      } catch(ait::kerberos::UnableToDeletePrincipalException &e) {
         response.send(Http::Code::Bad_Request, e.what());
      } catch(ait::kerberos::CommunicationException &e) {
         response.send(Http::Code::Internal_Server_Error);
      } catch(ait::kerberos::UnableToFindUserException &e) {
         response.send(Http::Code::Not_Found, e.what());
      } catch(...) {
        response.send(Http::Code::Internal_Server_Error);
      }

      logRequest(request, response.code(), starttime);
    }

    void setPasswordExpiration(const Rest::Request& request, Http::ResponseWriter response) {
      auto starttime = std::chrono::steady_clock::now();
      try {
        ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser_, realm_, keytab_);

        std::string uid = request.param(":uid").as<std::string>();

        const Http::Uri::Query& query = request.query();
        Optional<std::string> optionalWhen  = query.get("when");
        if (optionalWhen.isEmpty()) {
          std::string msg = "Password Expiration changes must have the date desired";
          response.send(Http::Code::Bad_Request, msg);
          logRequest(request, response.code(), starttime);
          return;
	      }
        std::string when = optionalWhen.get();

        try {
          kerbSession.setPasswordExpiration(uid, when);
        } catch(ait::kerberos::UnableToFindUserException &ex) {
          response.send(Http::Code::Not_Found, "User not found");
        } catch(ait::kerberos::UnauthorizedException &ex) {
          response.send(Http::Code::Unauthorized, "Unauthorized");
        } catch(ait::kerberos::SecurityRequestFailedException &ex) {
          response.send(Http::Code::Bad_Request, ex.what());
        }
        response.send(Http::Code::Ok, "User " + uid + " password expiration changed to " + when);
      } catch(...) {
        //TODO - Fix this, this doesn't help
        response.send(Http::Code::Internal_Server_Error, "Failed to set the password Expiration");
      }

      logRequest(request, response.code(), starttime);
    }

    void setPasswordPolicy(const Rest::Request& request, Http::ResponseWriter response)
    {
      auto starttime = std::chrono::steady_clock::now();
      Http::Code code = Http::Code::Ok;
      std::string message = "";
      std::string uid;

      try {
        ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser_, realm_, keytab_);
        uid = request.param(":uid").as<std::string>();
        const Http::Uri::Query& query = request.query();
        Optional<std::string> optionalPolicy = query.get("policy");

        if (!optionalPolicy.isEmpty()) {
          std::string policy = optionalPolicy.get();
          std::string when = query.get("when").getOrElse("");

          kerbSession.updateUserPasswordPolicy(uid, policy, when);

          message = "Policy for user '" + uid + "' was successfuly set to '" + policy + "'";

          if (when != "") {
            message += " with expiration of " + when;
          }
        } else {
          code = Http::Code::Bad_Request;
          message = "Password Policy changes must provide a policy";
        }
      } catch(ait::kerberos::UnableToFindUserException &ex) {
        code = Http::Code::Not_Found;
        message = "User not found: " + uid;
      } catch(ait::kerberos::UnauthorizedException &ex) {
        code = Http::Code::Unauthorized;
        message = "Unauthorized";
      } catch(ait::kerberos::SecurityRequestFailedException &ex) {
        code = Http::Code::Bad_Request;
        message = ex.what();
      } catch (...) {
        code = Http::Code::Internal_Server_Error;
        message = "Failed to set the password Policy";
      }
      if (message == "") {
        response.send(code);
      } else {
        response.send(code, message);
      }
      logRequest(request, response.code(), starttime, message);
    }

    void alterUser(const Rest::Request& request, Http::ResponseWriter response) {
      auto starttime = std::chrono::steady_clock::now();
      try {
        ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser_, realm_, keytab_);

        std::string uid = request.param(":uid").as<std::string>();

        const Http::Uri::Query& query = request.query();

        Optional<std::string> queryParam = query.get("userAction");

        if (queryParam.isEmpty()) {
          auto msg = "Missing query parameter \"userAction\"";
          response.send(Http::Code::Bad_Request, msg);
          logRequest(request, response.code(), starttime, msg);
          return;
        }

        auto action = queryParam.get();        

        if (action == "lock") {
          kerbSession.lockUser(uid); 
          response.send(Http::Code::Ok, "User " + uid + " locked");
	      } else if (action == "lockPassword") {
          kerbSession.lockPassword(uid); 
          response.send(Http::Code::Ok, "User " + uid + " locked");
        } else if (action == "unlock") {
          kerbSession.unlockUser(uid);
          response.send(Http::Code::Ok, "User " + uid + " unlocked");
        } else if (action == "pwchange") {
          auto auth = request.headers().tryGet<Http::Header::Authorization>();
          if (auth != NULL) {
            std::string val = auth->value();
            std::string basic("Basic ");
            val = base64_decode(val.substr(basic.length()));

            std::size_t pos = val.find(":");
            if (pos == std::string::npos) {
              auto msg = "pwchange: Authorization header malformed";
              response.send(Http::Code::Bad_Request, msg);
              logRequest(request, response.code(), starttime, msg);
              return;
            }

            std::string userid = val.substr(0, pos);
            if (userid != uid) {
              response.send(Http::Code::Forbidden);
            } else {
              std::string password = val.substr(pos + 1);

              try {
                kerbSession.updateUserPassword(userid, password);
                response.send(Http::Code::Ok, "User " + uid + " password changed");
              } catch (ait::kerberos::UnableToChangePasswordException &ex) {
                response.send(Http::Code::Bad_Request, ex.what());
              } catch (ait::kerberos::UnableToFindUserException& ex) {
                response.send(Http::Code::Not_Found, ex.what());
              } catch (ait::kerberos::SecurityRequestFailedException& ex) {
                response.send(Http::Code::Not_Found, ex.what());
              }
            }
          } else {
            response.send(Http::Code::Bad_Request, "pwchange: Missing Authorization header");
          }
        } else {
            response.send(Http::Code::Bad_Request, ("Invalid User Action requested: " + action));
        }

        logRequest(request, response.code(), starttime, action);
        return;

      } catch (ait::kerberos::UnableToFindUserException& ex) {
        response.send(Http::Code::Not_Found, ex.what()); 
        logRequest(request, response.code(), starttime, ex.what());
        return;
      } catch(...) {
        response.send(Http::Code::Internal_Server_Error, "unknown error");
      }

      logRequest(request, response.code(), starttime);
    }

    std::shared_ptr<Pistache::Http::Endpoint> httpEndpoint_;
    Rest::Router router_;
   
    std::string adminUser_;
    std::string realm_;
    std::string keytab_;
    std::chrono::seconds timeout_;

    void logRequest(const Rest::Request& r, Http::Code c, std::chrono::steady_clock::time_point starttime, std::string msg = "") {
      auto et = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - starttime).count();

      auto ua = r.headers().tryGet<Http::Header::UserAgent>();
      std::string ua_str = "";
      if (ua != NULL) {
        ua_str = ua->agent();
      }

      auto xff = r.headers().tryGetRaw("X-Forwarded-For");
      std::string xff_str = "";
      if (!xff.isEmpty()) {
        xff_str = xff.get().value();
      }

      auto host = r.headers().tryGetRaw("Host");
      std::string host_str = "";
      if (!host.isEmpty()) {
        host_str = host.get().value();
      }

      std::string message = "";
      if (msg != "") {
          message = " msg=\"" + msg + "\"";
      }

      // opentracing headers
      std::string spanid_str = "";
      auto spanid = r.headers().tryGetRaw("x-b3-spanid");
      if (!spanid.isEmpty()) {
        spanid_str = spanid.get().value();
      }
      std::string traceid_str = "";
      auto traceid = r.headers().tryGetRaw("x-b3-traceid");
      if (!traceid.isEmpty()) {
        traceid_str = traceid.get().value();
      }
      
      std::cout << "time=\"" << iso8601() << "\""
        << " version=\"" << BUILD_VERSION << "\""
        << " tid=" << std::this_thread::get_id()
        << " addr=" << r.address().host()
        << " xff=\"" << xff_str << "\""
        << " host=\"" << host_str << "\""
        << " method=" << r.method()
        << " status_code=" << static_cast<int>(c)
        << " et=\"" << et << "ms\""
        << " resource=" << r.resource()
        << " ua=\"" <<ua_str << "\""
        << message
        << " x-b3-spanid=\"" << spanid_str << "\""
        << " x-b3-traceid=\"" << traceid_str << "\""
        << std::endl;
    }
};

void usage()
{
  std::cout << "Usage:\nkadminRest -a <adminPrincipal> -k <keytab> -r <kerbRealm> [-p <port>] [-i <interface>] [-t <threads>] [-w <timeout>]" << std::endl;
}

int main(int argc, char** argv) {
  // signal handling
  sigset_t signals;
    if (sigemptyset(&signals) != 0
            || sigaddset(&signals, SIGTERM) != 0
            || sigaddset(&signals, SIGINT) != 0
            || sigaddset(&signals, SIGHUP) != 0
            || pthread_sigmask(SIG_BLOCK, &signals, nullptr) != 0) {
        perror("install signal handler failed");
        return 1;
    }

  std::cout << "time=\"" << iso8601() 
    << "\" msg=\"Starting kadminrest\" version=\"" << BUILD_VERSION << "\" builddate=\"" << BUILD_DATE << "\"" << std::endl;
  if (argc < 7) {
    std::cerr<<"Not enough arguments"<<std::endl;
    usage();
    return -1;
  }

  std::string adminPrincipal("");
  std::string keytab("");
  std::string realm("");
  struct sockaddr_in ipaddr;
  bool ipaddrSet = false;
  int port = 9080;
  int threads = 1;
  int timeout = 10;

  int option;
  while ((option = getopt(argc, argv, "a:k:i:p:r:t:w:")) != -1)
  {
    switch(option)
    {
      case 'a' :
        adminPrincipal = optarg;
        break;
      case 'k' :
        keytab = optarg;
        break;
      case 'r' :
        realm = optarg;
        break;
      case 'p' :
        port = std::stoi(optarg);
        break;
      case 'i' :
        inet_pton(AF_INET, optarg, &(ipaddr.sin_addr)); 
        ipaddrSet = true;
        break;
      case 't' :
        threads = std::stoi(optarg);
        break;
      case 'w' :
        timeout = std::stoi(optarg);
        break;
    }
  }

  if (adminPrincipal.empty() || keytab.empty() || realm.empty()) {
     std::cerr << "Admin Principal, Keytab, and Realm are required fields" << std::endl;
     usage();
     return -1;
  }

  Pistache::Address addr;

  if (ipaddrSet) {
    ipaddr.sin_port = port;
    ipaddr.sin_family = AF_INET;
    addr = std::move(Pistache::Address::fromUnix((sockaddr *)&ipaddr));
  } else {
    std::cout<<"msg=\"-i not specified, setting interface to listen on any address"<<std::endl;
    addr = std::move(Pistache::Address(Pistache::Ipv4::any(), Pistache::Port(port)));
  }

  std::cout<<"msg=\"Built configuration\" principal=\""<<adminPrincipal<<"\""
    <<" keytab=\""<<keytab<<"\""
    <<" realm=\""<<realm<<"\""
    <<" interface=\""<<addr.host()<<"\""
    <<" port="<<port
    <<" threads="<<threads
    <<" timeout="<<timeout
    <<std::endl;

  KadminRestHandler hrh(addr, adminPrincipal, realm, keytab, std::chrono::seconds(timeout));
  hrh.init(threads);
  std::cout << "time=\"" << iso8601() << "\" msg=\"Starting kadminrest server...\""<<std::endl;
  hrh.start();

  int signal = 0;
  int status = sigwait(&signals, &signal);
  if (status == 0) {
    std::cout << "time=\"" << iso8601() << "\" msg=\"[1/3] Received signal " << signal << "\"" << std::endl;
  } else {
    std::cout << "time=\"" << iso8601() << "\" msg=\"[1/3] sigwait returns " << signal << "\"" << std::endl;
  }
  std::cout << "time=\"" << iso8601() << "\" msg=\"[2/3] shutting down...\"" << std::endl;
  hrh.shutdown();
  std::cout << "time=\"" << iso8601() << "\" msg=\"[3/3] ...done\"" << std::endl;

  return 0;
}

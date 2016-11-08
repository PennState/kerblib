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
#include "authorizationHeader.h"
#include "json.hpp"
#include "base64.h"
#include "unable_to_initialize_exception.h"
#include "unableToChangePasswordException.h"
#include "userAlreadyExistsException.h"
#include "invalidPasswordException.h"
#include "securityRequestFailedException.h"
#include "loggers/consoleLogger.h"
#include <arpa/inet.h>

using namespace Net;

class KadminRestHandler {

  public:
    const std::string PASSWORD_REQUIREMENTS_MESSAGE = "It must be at least eight characters in length (Longer is generally better.)\nIt must contain at least one alphabetic and one numeric character.\nIt must be significantly different from previous passwords.\nIt cannot be the same as the userid.\nIt cannot contain the following special characters - spaces, \', \", &, (, ), |, <, >.\nIt should not be information easily obtainable about you. This includes license plate, social security, telephone numbers, or street address";

    KadminRestHandler(Net::Address addr, const std::string princ, std::string realm, std::string keytab) : httpEndpoint_(std::make_shared<Net::Http::Endpoint>(addr)),
                                                                                                           adminUser_(princ),
                                                                                                           realm_(realm),
                                                                                                           keytab_(keytab) {
       //Net::Http::Header::Registry::registerHeader<AuthorizationHeader>();      
    }

    void init(int threads) {
      auto opts = Net::Http::Endpoint::options().threads(threads)
                                                .flags(Net::Tcp::Options::InstallSignalHandler);
      httpEndpoint_->init(opts);
      setupRoutes();
    }

    void start() {
       httpEndpoint_->setHandler(router_.handler());
       httpEndpoint_->serve();
    }
   
    void shutdown() {
      httpEndpoint_->shutdown();
    }

  private : 
    void setupRoutes() {
      using namespace Net::Rest;

      Routes::Post(router_, "/resources/users/", Routes::bind(&KadminRestHandler::createUser, this));
      Routes::Get(router_, "/resources/users/:uid", Routes::bind(&KadminRestHandler::getUserMetrics, this));
      Routes::Put(router_, "/resources/users/:uid", Routes::bind(&KadminRestHandler::alterUser, this));
      Routes::Delete(router_, "/resources/users/:uid", Routes::bind(&KadminRestHandler::deleteUser, this));
    }

    void createUser(const Rest::Request& request, Http::ResponseWriter response) {
      std::string entity = request.body();

      nlohmann::json j = nlohmann::json::parse(entity);

      auto userid = j["userid"].get<std::string>();
      auto password = j["password"].get<std::string>();
      std::string policy = "none";

      try {
        policy = j["policy"].get<std::string>();
      } catch(std::domain_error &de) {
        //Do nothing, use default policy
      }

      std::cout << "Recieved a request to create user: " << userid << " with policy: " << policy << std::endl;

      try {
        ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser_, realm_, keytab_);
        if (policy != "none") {
          kerbSession.createUser(userid, password, policy);
        } else {
          kerbSession.createUser(userid, password);
        }
      } catch (ait::kerberos::UserAlreadyExistsException &ex) {
        response.send(Http::Code::Conflict);
        return;
      } catch (ait::kerberos::InvalidPasswordException &ex) {
        response.send(Http::Code::Bad_Request, PASSWORD_REQUIREMENTS_MESSAGE);
        return;
      } catch (ait::kerberos::SecurityRequestFailedException &ex) {
        response.send(Http::Code::Internal_Server_Error, "Contact the service desk");
        return;
       } catch(ait::kerberos::InvalidRequestException &e) {
        response.send(Http::Code::Bad_Request, e.what());
        return;
       }catch (ait::kerberos::NotAuthorizedException &e) {
        response.send(Http::Code::Forbidden);
        return;
       }catch (...) {
        std::cout << "Unknown error received while attempting to create a user" << std::endl;
        response.send(Http::Code::Internal_Server_Error, "Unknown error received, contact the service desk");
      }

      response.send(Http::Code::Created);
    }

    void getUserMetrics(const Rest::Request& request, Http::ResponseWriter response) {
      
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

        response.setMime(Net::Http::Mime::MediaType::fromString("application/json"));
        response.send(Http::Code::Ok, j.dump(2));
      } catch(ait::kerberos::UnableToFindUserException &srfe) {
	      response.send(Http::Code::Not_Found, srfe.what() + "\n");
      } catch(ait::kerberos::UserAlreadyExistsException &uaee) {
         std::string error = "User already Exists Exception " + uaee.what();
         std::cerr << error << std::endl;
         response.send(Http::Code::Internal_Server_Error, error + "\n");
      } catch(ait::kerberos::InvalidPasswordException &ipe) {
         std::string error = "Invalid password exception " + ipe.what();
         std::cerr << error << std::endl;
         response.send(Http::Code::Internal_Server_Error, error + "\n");
      } catch(ait::kerberos::UnableToCreateSessionException &utcse) {
         std::string error = "Unable to create session exception " + utcse.what();
         std::cerr << error << std::endl;
         response.send(Http::Code::Internal_Server_Error, error + "\n");
      } catch(UnableToInitializeException &utie) {
         std::string what = utie.what();
         std::string error = "Failed initialization: " + what;
         std::cout << error << std::endl; 
         response.send(Http::Code::Internal_Server_Error, error + "\n");
      } catch(...) {
         std::cerr << "Unknown exception thrown" << std::endl;
      }
    }

    void deleteUser(const Rest::Request& request, Http::ResponseWriter response) {
      ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser_, realm_, keytab_);

      std::string uid = request.param(":uid").as<std::string>();

      std::cout << "Recieved a request to delete user: " << uid << std::endl;
      
      try {
        kerbSession.deleteUser(uid);
      } catch(ait::kerberos::NotAuthorizedException &e) {
         response.send(Http::Code::Forbidden);
      } catch(ait::kerberos::UnableToDeletePrincipalException &e) {
         response.send(Http::Code::Bad_Request, e.what());
      } catch(ait::kerberos::CommunicationException &e) {
         response.send(Http::Code::Internal_Server_Error);
      } catch(ait::kerberos::UnableToFindUserException &e) {
         response.send(Http::Code::Not_Found, e.what());
      }
      response.send(Http::Code::No_Content);
    }

    void alterUser(const Rest::Request& request, Http::ResponseWriter response) {

      try {
        ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser_, realm_, keytab_);

        std::string uid = request.param(":uid").as<std::string>();

        const Http::Uri::Query& query = request.query();

        Optional<std::string> queryParam = query.get("userAction");

        if (queryParam.isEmpty()) {
           response.send(Http::Code::Bad_Request, "Missing query parameter \"userAction\"");
        }

        auto action = queryParam.get();        

        std::cout << "Recieved a request to alter user: " << uid << " action: " << action << std::endl;

        if (action == "lock") {
          kerbSession.lockUser(uid); 
          response.send(Http::Code::Ok, "User " + uid + " locked");
        } else if (action == "unlock") {
          kerbSession.unlockUser(uid);
          response.send(Http::Code::Ok, "User " + uid + " unlocked");
        } else if (action == "pwchange") {
          std::cout << "Change password request received, trying to get the Authorization header" << std::endl;
          auto auth = request.headers().tryGetRaw("Authorization");

          std::cout << "Check to see if auth is empty: " << auth.isEmpty() << std::endl;
          if (!auth.isEmpty()) {
            auto raw = auth.get();
            std::string val = raw.value();
            std::string basic("Basic ");
            val = base64_decode(val.substr(basic.length()));

            std::size_t pos = val.find(":");
            if (pos == std::string::npos) {
              response.send(Http::Code::Bad_Request, "Header parameters malformed");
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
            response.send(Http::Code::Bad_Request, "Missing Auth Header Data");
            std::cout << "Missing Auth Header Data" << std::endl;
          }
        } else {
            response.send(Http::Code::Bad_Request, ("Invalid User Action requested: " + action));
            std::cout << "Invalid User Action requested: " << action << std::endl;
        }

        //response.send(Http::Code::Ok, "Executing action: " + action);
      } catch(...) {
      }
    }

    std::shared_ptr<Net::Http::Endpoint> httpEndpoint_;
    Rest::Router router_;
   
    std::string adminUser_;
    std::string realm_;
    std::string keytab_;
};

void usage()
{
  std::cout << "Usage:\nkadminRest -a adminPrincipal -k keytab -r kerbRealm [-p port] [-t threadCount]" << std::endl;
}

int main(int argc, char** argv) {

  std::cout << "argc = " << argc << std::endl;
  if (argc < 7) {
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

  int option;
  while ((option = getopt(argc, argv, "a:k:i:p:r:m:")) != -1)
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
    }
  }

  if (adminPrincipal.empty() || keytab.empty() || realm.empty()) {
     std::cerr << "Admin Principal, Keytab and Realm are required fields" << std::endl;
     usage();
     return -1;
  }

  Net::Address addr;

  if (ipaddrSet) {
    ipaddr.sin_port = port;
    addr = std::move(Net::Address::fromUnix((sockaddr *)&ipaddr));
  } else {
    addr = std::move(Net::Address(Net::Ipv4::any(), Net::Port(port)));
  }

  //Net::Address addr(ipv4, Net::Port(port));

  KadminRestHandler hrh(addr, adminPrincipal, realm, keytab);
  hrh.init(threads);
  hrh.start();

  hrh.shutdown();
}

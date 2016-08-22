#include "http.h"
#include "router.h"
#include "endpoint.h"
#include "optional.h"
#include "base64.h"
#include "kerberosAdminSession.h"
#include "kerberosAdminFlags.h"
#include "userMetrics.h"
#include "http_headers.h"
#include "authorizationHeader.h"
#include "json.hpp"
#include "base64.h"
#include "unable_to_initialize_exception.h"
#include "unableToChangePasswordException.h"
#include "securityRequestFailedException.h"
#include "loggers/consoleLogger.h"

using namespace Net;

class KadminRestHandler {

  public:
    KadminRestHandler(Net::Address addr) : httpEndpoint_(std::make_shared<Net::Http::Endpoint>(addr)) {
       //Net::Http::Header::Registry::registerHeader<AuthorizationHeader>();      
    }

    void init() {
      auto opts = Net::Http::Endpoint::options().threads(1)
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

      Routes::Get(router_, "/resources/users/:uid", Routes::bind(&KadminRestHandler::getUserMetrics, this));
      Routes::Put(router_, "/resources/users/:uid", Routes::bind(&KadminRestHandler::alterUser, this));
      Routes::Delete(router_, "/resources/users/:uid", Routes::bind(&KadminRestHandler::deleteUser, this));
    }

    void getUserMetrics(const Rest::Request& request, Http::ResponseWriter response) {
      std::string adminUser = "admin";
      std::string realm = "dce.psu.edu";
      std::string keytab = "/home/shawn/src/c++/pistache/admin.keytab";
      try {
        ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser, realm, keytab);

        std::string uid = request.param(":uid").as<std::string>();
        ait::kerberos::UserMetrics metrics = kerbSession.getUserMetrics(uid);

        nlohmann::json j = {
           {"passwordExpiration", metrics.passwordExpirationAsString()},
           {"principalExpiration", metrics.principalExpirationAsString()},
           {"passwordCreation", metrics.passwordCreationAsString()},
           {"lastSuccessfulLogin", metrics.lastSuccessfulLoginAsString()},
           {"lastFailedLogin", metrics.lastFailedLoginAsString()}};

       
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
      std::string adminUser = "admin";
      std::string realm = "dce.psu.edu";
      std::string keytab = "/home/shawn/src/c++/pistache/admin.keytab";

      ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser, realm, keytab);

      std::string uid = request.param(":uid").as<std::string>();
      kerbSession.deleteUser(uid);
    }

    void alterUser(const Rest::Request& request, Http::ResponseWriter response) {
      std::string adminUser = "admin";
      std::string realm = "dce.psu.edu";
      std::string keytab = "/home/shawn/src/c++/pistache/admin.keytab";

      try {
        ait::kerberos::AdminSession<ConsoleLogger> kerbSession(adminUser, realm, keytab);

        std::string uid = request.param(":uid").as<std::string>();

        const Http::Uri::Query& query = request.query();

        Optional<std::string> queryParam = query.get("userAction");

        if (queryParam.isEmpty()) {
           response.send(Http::Code::Bad_Request, "Missing query parameter \"userAction\"");
        }

        auto action = queryParam.get();        

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
            std::cout << val << std::endl;

            std::size_t pos = val.find(":");
            if (pos == std::string::npos) {
              response.send(Http::Code::Bad_Request, "Header paramaters malformed");
              return;
            }

            std::string userid = val.substr(0, pos);
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
          } else {
            response.send(Http::Code::Bad_Request, "Missing password change headers");
            std::cout << "no auth header" << std::endl;
          }
        }


        response.send(Http::Code::Ok, "Executing action: " + action);
      } catch(...) {
      }
    }

    std::shared_ptr<Net::Http::Endpoint> httpEndpoint_;
    Rest::Router router_;
};

void usage()
{
  std::cout << "Usage:\nkadminRest -a adminPrincipal -k keytab -r kerbRealm [-p logMessage] [-t threadCount]" << std::endl;
}

int main(int argc, char** argv) {

  std::string adminPrincipal;
  std::string keytab;
  std::string real;
  int port = 9080;
  int threads = 1;

  int option;
  while ((option = getopt(argc, argv, "a:k:p:r:m:")) != -1)
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
      case 't' :
        threads = std::stoi(optarg);
        break;
    }
  }

  Net::Address addr(Net::Ipv4::any(), Net::Port(port));
  auto opts = Net::Http::Endpoint::options().threads(threads);

  KadminRestHandler hrh(addr);
  hrh.init();
  hrh.start();

  hrh.shutdown();
}

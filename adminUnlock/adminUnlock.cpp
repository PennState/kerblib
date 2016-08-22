#include <iostream>
#include <unistd.h>

#include "kerberosAdminSession.h"
#include "kerberosAdminFlags.h"
#include "invalidPasswordException.h"
#include "securityRequestFailedException.h"
#include "unableToCreateSessionException.h"
#include "userAlreadyExistsException.h"
#include "userMetrics.h"
//#include "loggers/syslogLogger.h"
#include "loggers/consoleLogger.h"

void usage()
{
  std::cout << "Usage:\nadminUnlock -a adminPrincipal -k keytab -p principal -r kerbRealm [-m logMessage]" << std::endl;
}

int main(int argc, char **argv)
{
  if (argc < 9)
  {
    usage();
    return -1;
  }

  std::string adminPrincipal;
  std::string keytab;
  std::string principal;
  std::string logMessage;
  std::string realm;

  std::cout << "Parsing out options" << std::endl;
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
      case 'p' :
        principal = optarg;
        break;
      case 'r' :
        realm = optarg;
        break;
      case 'm' :
        logMessage = optarg;
        break;
    } 
  }

  if (adminPrincipal.empty() || keytab.empty() || principal.empty() || realm.empty())
  {
    std::cout << "Missing a required parameter" << std::endl;;
    usage();
    return -1;
  }

  try
  {
    //ait::kerberos::AdminSession<SyslogLogger> session(adminPrincipal, realm, keytab);
    ait::kerberos::AdminSession<ConsoleLogger> session(adminPrincipal, realm, keytab);

    if (!logMessage.empty())
      session.unlockUser(principal, logMessage);
    else
      session.unlockUser(principal);
  }
  catch(ait::kerberos::SecurityRequestFailedException &srfe)
  {
    std::cerr << srfe.what() << std::endl;
  }
  catch(ait::kerberos::UserAlreadyExistsException &uaee)
  {
    std::cerr << uaee.what() << std::endl;
  }
  catch(ait::kerberos::InvalidPasswordException &ipe)
  {
    std::cerr << ipe.what() << std::endl;
  }
  catch(ait::kerberos::UnableToCreateSessionException &utcse)
  {
    std::cerr << utcse.what() << std::endl;
  }
  catch(...)
  {
    std::cerr << "Unknown exception thrown" << std::endl;
  }
}

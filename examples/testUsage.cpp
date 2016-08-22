#include <iostream>

#include "kerberosAdminSession.h"
#include "kerberosAdminFlags.h"
#include "invalidPasswordException.h"
#include "securityRequestFailedException.h"
#include "unableToCreateSessionException.h"
#include "userAlreadyExistsException.h"
#include "userMetrics.h"
#include "loggers/consoleLogger.h"

int main()
{

  //OR
  //ait::kerberos::AdminSession session("admin/kadmin"); //Defaults to ACCESS and the default expected keytab file
  //
  //OR
  //ait::kerberos::AdminSession session("admin/kadmin", ait::kerberos::Session::FPS); //Defaults keytab file location
  
  try
  {
    ait::kerberos::AdminSession<ConsoleLogger> session("testk5prinmod@testk5.css.psu.edu", "testk5.css.psu.edu", "/etc/krb5/testk5prinmod.keytab");
    //ait::kerberos::AdminSession session("k5playground/admin@K5PLAYGROUND.AIT.PSU.EDU", "K5PLAYGROUND.AIT.PSU.EDU", "/etc/krb5/k5pg.keytab");
    //ait::kerberos::AdminSession session("ses44/admin", "K5PLAYGROUND.AIT.PSU.EDU", "/etc/krb5/k5playground.keytab");
    //                   uid          password
    //std::cout << "Calling Create User" << std::endl;
    //session.createUser("ses44_Bruce_123", "CrazyBruce'sLiquor");
    //session.updateUserPassword("ses44test@testk5.css.psu.edu", "CrazyBruce'sLiquor");
    //session.lockUser("ses44test@testk5.css.psu.edu");
    session.unlockUser("ses44test@testk5.css.psu.edu");
    //std::cout << "	Called Create User" << std::endl;

    //ait::kerberos::UserMetrics metrics = session.getUserMetrics("ses44test@testk5.css.psu.edu");
    //ait::kerberos::UserMetrics metrics = session.getUserMetrics("ses44@testk5.css.psu.edu");
    //std::cout << "Password Expires: " << metrics.passwordExpiration() << "\n";
    //std::cout << "Password Created: " << metrics.passwordCreation() << "\n";
    //std::cout << "Last Good Login: " << metrics.lastSuccessfulLogin() << "\n";
    //std::cout << "Last Failed Login: " << metrics.lastFailedLogin() << "\n";

    //std::cout << "Password Expires: " << metrics.passwordExpirationAsString() << "\n";
    //std::cout << "Password Created: " << metrics.passwordCreationAsString() << "\n";
    //std::cout << "Last Good Login: " << metrics.lastSuccessfulLoginAsString() << "\n";
    //std::cout << "Last Failed Login: " << metrics.lastFailedLoginAsString() << "\n";

    //session.lockUser("Bruce");
    //session.createUser("Lee", "Tigers'sBlood", ait::kerberos::REQUIRE_PREAUTH | ait::kerberos::FORCE_CHANGE | ait::kerberos::REQUIRE_HWAUTH);

    //session.createUser("Brandon", "LittleTigers'sBlood", ait::kerberos::StandardStudentPolicy);

    //session.updateUserPassword("Bruce", "BruceShortForBrutus");

    //session.deleteUser("Bruce");
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

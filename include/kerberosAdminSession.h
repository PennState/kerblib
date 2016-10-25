#ifndef KERBEROS_ADMIN_SESSION_H__
#define KERBEROS_ADMIN_SESSION_H__

#include <kadm5/admin.h>
#include <inttypes.h>
#include "networking.h"
#include "kerberosSession.h"
#include "kerberosAdminFlags.h"
#include "realmDefs.h"
#include "userMetrics.h"
#include "userAlreadyExistsException.h"
#include "unableToChangePasswordException.h"
#include "invalidPasswordException.h"
#include "invalidUserException.h"
#include "unableToFindUserException.h"
#include "notAuthorizedException.h"
#include "communicationException.h"
#include "unableToDeletePrincipalException.h"
#include "invalidRequestException.h"

#include "securityRequestFailedException.h"

#include <kadm5/kadm_err.h>
#include <cstring>
#include <iostream>
#include <sstream>

namespace ait
{
  namespace kerberos
  {
    class UserMetrics;
    template <typename LOGGER>
    class AdminSession : public Session<LOGGER>
    {
      public:
        AdminSession(const std::string &clientString, ait::kerberos::Realm realm = ACCESS, const std::string &keytab = "") : ait::kerberos::Session<LOGGER>(clientString, realm, keytab)
        {}

        AdminSession(const std::string &clientString, const std::string &realm, const std::string &keytab) : ait::kerberos::Session<LOGGER>(clientString, realm, keytab)
        {}

        void createUser(const std::string &userID, const std::string &password, uint32_t flags = 0x00000000)
        {
          kadm5_principal_ent_rec principal;
          //krb5_error_code ret;

          long mask = 0;

          std::cout << "Clearing out the principal" << std::endl;
          memset((void *) &principal, '\0', sizeof(principal));

//          char userID_Array[userID.size() + 1];
//          memset((void *)userID_Array, '\0', userID.size() + 1);
//          //char *userID_Array = nullptr;
//
//          std::cout << "strncpy" << std::endl;
//          strncpy(userID_Array, userID.c_str(), userID.size());
//          std::cout << "parse name" << std::endl;
//          ret = krb5_parse_name(this->context_, userID_Array, &(principal.principal));
          //ret = krb5_unparse_name(this->context_, principal.principal, &userID_Array);

//          if (ret) {
//            std::cerr << "Oops on parse " << ret << std::endl;
//          }

//          char pw[password.length() + 1];
//          memset((void *)pw, '\0', password.size() + 1);
//          strncpy(pw, password.c_str(), password.length());

          std::cout << "Checking if we have flags set" << std::endl;
          bool flagSet = false;
          if (flags & ait::kerberos::DISALLOW_POSTDATED_TICKETS)
          {
            principal.attributes |= KRB5_KDB_DISALLOW_POSTDATED;
            flagSet = true;
          }

          if (flags & ait::kerberos::DISALLOW_FORWARDABLE_TICKETS)
          {
            principal.attributes |= KRB5_KDB_DISALLOW_FORWARDABLE;
            flagSet = true;
          }
          if (flags & ait::kerberos::DISALLOW_RENEWABLE_TICKETS)
          {
            principal.attributes |= KRB5_KDB_DISALLOW_RENEWABLE;
            flagSet = true;
          }

          if (flags & ait::kerberos::DISALLOW_PROXIABLE_TICKETS)
          {
            principal.attributes |= KRB5_KDB_DISALLOW_PROXIABLE;
            flagSet = true;
          }

          if (flags & ait::kerberos::DISALLOW_DUP_SKEY)
          {
            principal.attributes |= KRB5_KDB_DISALLOW_DUP_SKEY;
            flagSet = true;
          }

          if (flags & ait::kerberos::REQUIRE_PREAUTH)
          {
            principal.attributes |= KRB5_KDB_REQUIRES_PRE_AUTH;
            flagSet = true;
          }

          if (flags & ait::kerberos::REQUIRE_PREAUTH)
          {
            principal.attributes |= KRB5_KDB_REQUIRES_PRE_AUTH;
            flagSet = true;
          }

          if (flags & ait::kerberos::REQUIRE_HWAUTH)
          {
            principal.attributes |= KRB5_KDB_REQUIRES_HW_AUTH;
            flagSet = true;
          }

          if (flags & ait::kerberos::FORCE_CHANGE)
          {
            principal.attributes |= KRB5_KDB_REQUIRES_PWCHANGE;
            flagSet = true;
          }

          if (flags & ait::kerberos::DISALLOW_SERVER_TICKETS)
          {
            principal.attributes |= KRB5_KDB_DISALLOW_SVR;
            flagSet = true;
          }

          if (flags & ait::kerberos::REQUIRE_OK_AS_DELEGATE)
          {
            principal.attributes |= KRB5_KDB_OK_AS_DELEGATE;
            flagSet = true;
          }

          if(flagSet)
          {
            std::cout << "There are flags, setting the ATTRIBUTES mask" << std::endl;
            mask |= KADM5_ATTRIBUTES;
          }
          else {
            std::cout << "No flags this time" << std::endl;
          }

          mask |= KADM5_PRINCIPAL;
          createUser(principal, mask, userID, password);
        }

        void createUser(const std::string &userID, const std::string &password, const std::string &policy)
        {
           kadm5_principal_ent_rec principal;
         
           std::cout << "Creating a principal with policy " << policy << std::endl;

           std::cout << "Clearing the principal" << std::endl;
           memset((void *) &principal, '\0', sizeof(principal));
         
           char policyString[policy.length() + 1];
           memset((void *) &policyString, '\0', sizeof(policyString));
           strncpy(policyString, policy.c_str(), policy.length());
         
           std::cout << "Policy string is " << policyString << std::endl;

           principal.policy = policyString;
         
           kadm5_policy_ent_rec pol;

           if (kadm5_get_policy(this->serverHandle_, policyString, &pol) != 0) {
              std::cout << "Policy " << policyString << " does not exist" << std::endl;
           } else {
              std::cout << "Policy " << policyString << " does exist" << std::endl;
              kadm5_free_policy_ent(this->serverHandle_, &pol);
           } 

           long mask  = 0l | KADM5_POLICY;
           mask |= KADM5_PRINCIPAL;

           createUser(principal, mask, userID, password);
        }
    
        UserMetrics getUserMetrics(const std::string &userID) const
        {
          kadm5_principal_ent_rec principal = getPrincipal(userID);
          std::cout << "princ exp: " << principal.princ_expire_time << std::endl;
          return UserMetrics(principal.pw_expiration, principal.princ_expire_time, principal.last_pwd_change, principal.last_success, principal.last_failed);
        }

        void deleteUser(const std::string &userID)
        {
          kadm5_principal_ent_rec principalData = getPrincipal(userID);
          kadm5_ret_t ret = kadm5_delete_principal(this->serverHandle_, principalData.principal);

          switch (ret) {
            case KADM5_AUTH_DELETE :
              throw kerberos::NotAuthorizedException();
              break;
            case KADM5_BAD_CLIENT_PARAMS :
              throw kerberos::UnableToDeletePrincipalException("Incorrect parameter specified");
              break;
            case KADM5_BAD_SERVER_HANDLE:
            case KADM5_GSS_ERROR:
            case KADM5_RPC_ERROR:
              throw kerberos::CommunicationException();
              break;
            case KADM5_UNK_PRINC:
              throw kerberos::UnableToFindUserException("Principal " + userID + " was not found");
              break;
            default:
              //Assume Success
              std::cout << "Delete return = " << ret << std::endl;
          }
        }

        void updateUserPassword(const std::string &userID, const std::string &password)
        {
          std::cout << "In updateUserPassword with userid " << userID << std::endl;
          kadm5_principal_ent_rec principalData = getPrincipal(userID);

          std::cout << "Received the principal" << std::endl;
          char pass[password.length() + 1];
          strncpy(pass, password.c_str(), password.length());
          std::cout << "Calling kadm5_chpass_principal" << std::endl;
          kadm5_ret_t ret = kadm5_chpass_principal(this->serverHandle_, principalData.principal, pass);
          std::cout << "Called kadm5_chpass_principal, checking the return value: " << ret << std::endl;

          switch(ret) {
            case KADM5_UNK_PRINC :
              throw kerberos::UnableToFindUserException("Principal " + userID + " was not found");
              break;
            case KADM5_PASS_REUSE : 
              throw kerberos::UnableToChangePasswordException("The password selected was used within three password change cycles");
              break;
            case KADM5_PASS_TOOSOON :                 
              throw kerberos::UnableToChangePasswordException("The current password is not sufficiently old to allow for change");
              break;
            case KADM5_PROTECT_PRINCIPAL :                 
              throw kerberos::UnableToChangePasswordException("This is a protected principal and the password cannot be changed");
              break;
            case KADM5_PASS_Q_TOOSHORT:
            case KADM5_PASS_Q_CLASS:
            case KADM5_PASS_Q_DICT:
            case KADM5_PASS_Q_GENERIC:
              throw kerberos::UnableToChangePasswordException("The password is inadequately formed");
              break;
            default:
              //This should mean success
              break;
          }
        }

        void lockUser(const std::string &userID, const std::string why = "")
        {
          kadm5_principal_ent_rec principal;
         
          memset((void *) &principal, '\0', sizeof(principal));
         
          krb5_parse_name(this->context_, userID.c_str(), &(principal.principal));
         
          krb5_timestamp now;
          krb5_timeofday(this->context_, &now);
          principal.princ_expire_time = now;
         
          std::stringstream str;
          str << "Locking user " << userID << ", reason: " << why << ", Lock originated from IP Address " << ait::util::get_local_ip();
          this->logMessage(str.str());

          kadm5_modify_principal(this->serverHandle_, &principal, KADM5_PRINC_EXPIRE_TIME);
        }

        void unlockUser(const std::string &userID, const std::string & why = "")
        {
          kadm5_principal_ent_rec principal;
        
          memset((void *) &principal, '\0', sizeof(principal));
        
          krb5_parse_name(this->context_, userID.c_str(), &(principal.principal));
        
          principal.princ_expire_time = 0;
        
          //std::stringstream str;
          //str << "Unlocking user " << userID << ", reason: " << why << ", unlock originated from IP Address " << ait::util::get_local_ip();
          std::string message = "Unlocking user " + userID + ", reason: " + why + ", unlock originated from IP Address " + ait::util::get_local_ip();
          this->logMessage(message);
          std::cout << "---------> After the log send <-------------" << std::endl;
          kadm5_modify_principal(this->serverHandle_, &principal, KADM5_PRINC_EXPIRE_TIME);
        }
    
      private:
        kadm5_principal_ent_rec getPrincipal(const std::string &userID) const
        {
          kadm5_principal_ent_rec principal;
        
          memset((void *) &principal, '\0', sizeof(principal));
        
          krb5_parse_name(this->context_, userID.c_str(), &(principal.principal));
        
          kadm5_principal_ent_rec principalData;
        
          kadm5_ret_t ret = kadm5_get_principal(this->serverHandle_, principal.principal, &principalData, KADM5_PRINCIPAL_NORMAL_MASK);
        
          switch(ret)
          {
            case KADM5_UNK_PRINC:
            {
              throw kerberos::UnableToFindUserException("Principal " + userID + " was not found");
              break;
            }
            default:
              break;
          }
        
          return principalData;
        }

        void createUser(kadm5_principal_ent_rec &principal, long mask, const std::string &userID, const std::string &password)
        {
           if (userID.empty()) {
             throw InvalidUserException("Cannot create a principal with an empty userID");
           }
         
           std::cout << "Parsing the name" << std::endl;
           krb5_parse_name(this->context_, userID.c_str(), &(principal.principal));
           std::cout << "        Parsed the name" << std::endl;
         
           if (password.empty()) {
             throw InvalidPasswordException("Cannot create a principal with an empty password");
           }
         
           char pw[password.length() + 1];
           memset((void *)pw, '\0', password.length() + 1);
           strncpy(pw, password.c_str(), password.length());
         
           std::cout << "Calling create principal" << std::endl;
           //kadm5_ret_t ret = kadm5_create_principal(&(this->serverHandle_), &principal, mask, pw);
           kadm5_ret_t ret = kadm5_create_principal(this->serverHandle_, &principal, mask, pw);
           std::cout << "        Called create principal, ret = " << ret << std::endl;
         
           switch(ret)
           {
             case KADM5_AUTH_ADD:
                throw NotAuthorizedException();
             case KADM5_DUP:
               throw UserAlreadyExistsException(userID);
               break;
             case KADM5_PASS_Q_TOOSHORT:
               throw InvalidPasswordException("The password you requested is too short");
               break;
             case KADM5_PASS_Q_DICT:
               throw InvalidPasswordException("The password you requested is succeptible to a dictionary attack");
               break;
             case KADM5_PASS_Q_CLASS:
               throw InvalidPasswordException("The password you requested is wrong because...");
               break;
             case KADM5_PASS_Q_GENERIC:
               throw InvalidPasswordException("The password you requested is wrong because...");
               break;
             case KADM5_BAD_MASK:
               throw SecurityRequestFailedException("Bad Mask on the create request");
               break;
             case KADM5_UNK_POLICY:
               throw  InvalidRequestException("The requested Policy is unknown to the KDC");
             case KADM5_BAD_SERVER_HANDLE:
             case KADM5_GSS_ERROR:
             case KADM5_RPC_ERROR:
               throw CommunicationException();
               break;
             default:
               std::cout << "Error on the create " << ret << std::endl;
               break;
           }
        }
    };
  }
}
    
//#include "kerberosAdminSession.cpp"

#endif

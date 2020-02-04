#ifndef KERBEROS_SESSION_H__
#define KERBEROS_SESSION_H__

#include <string>
#include <krb5/krb5.h>
#include "kerberosDefaults.h"
#include "unableToCreateSessionException.h"
#include "kadm5/admin.h"
//#include "adm_proto.h"
#include "kadm5/kadm_err.h"
#include <cstring>
#include <boost/lexical_cast.hpp>
#include <iostream>

namespace ait
{
  namespace kerberos
  {
    template <typename LOGGER>
    class Session : public LOGGER
    {
      public:
        Session(const std::string &clientString, const std::string &realm, const std::string &keytab) {
          realm_ = realm;
          try {
            init(clientString, realm, keytab);
          } catch (UnableToCreateSessionException &ex) {
            krb5_free_context(context_);
            if (serverHandle_) {
              kadm5_destroy(serverHandle_);
            }
            throw;
          }
        }

        ~Session() throw()
        {
          krb5_free_context(context_);
          if (serverHandle_)
            kadm5_destroy(serverHandle_);
        }
    
      protected:
        krb5_context context_;
        void *serverHandle_;
        std::string realm_;
 
        void init(const std::string &clientString, const std::string &realm, const std::string &keytab) {

          krb5_error_code error;
          if ((error = krb5_init_context(&context_)) != 0) {
            throw UnableToCreateSessionException("Unable to initialize the kerberos context");
          }

          char client[clientString.length() + 1];
          memset((void *)client, '\0', clientString.length() + 1);
          strncpy(client, clientString.c_str(), clientString.length());

          kadm5_ret_t ret;

          char **dbargs = NULL;
          kadm5_config_params params;
          memset(&params, 0, sizeof(params));

          char realmString[realm.length() + 1];
          memset(realmString, 0, realm.length() + 1);
          strcpy(realmString, realm.c_str());
          params.mask |= KADM5_CONFIG_REALM;
          params.realm = realmString;

          char kt[keytab.length() + 1];
          memset((void *)kt, '\0', keytab.length() + 1);
          strncpy(kt, keytab.c_str(), keytab.length());

          krb5_ccache cc;
          ret = krb5_cc_default(context_, &cc);
          if (ret) {
            throw UnableToCreateSessionException("Unable to initialize credentials cache");
          }

          ret = kadm5_init_with_skey(context_,
                                     client,
                                     kt,
                                     NULL,
                                     &params,
                                     KADM5_STRUCT_VERSION,
                                     KADM5_API_VERSION_2,
                                     dbargs,
                                     &serverHandle_);

          if (ret != KADM5_OK)
          {
            std::string message;
            switch(ret)
            {
              case KADM5_NO_SRV:
                message = "No server currently available";
                break;
              case KADM5_RPC_ERROR:
                message = "An RPC Error occured";
                break;
              case KADM5_BAD_PASSWORD:
                message = "Invalid Password";
                break;
              case KADM5_SECURE_PRINC_MISSING:
                message = "The principal Admin Service or Change PW service does not exist";
                break;
              case KADM5_BAD_CLIENT_PARAMS:
                message = "There is an invalid field in the client parameters mask";
                break;
              case KADM5_BAD_SERVER_PARAMS:
                message = "There is an invalid field in the server paramters mask";
                break;
              case KADM5_GSS_ERROR :
                message = "A GSS Error occured initializing";
                break;
              default:
                auto krb5_err = krb5_get_error_message(context_, ret);
                std::string krb5_err_str(krb5_err);
                krb5_free_error_message(krb5_err);
                message = krb5_err_str + " (" + boost::lexical_cast<std::string>(ret) + ")";
                break;
            }
            throw UnableToCreateSessionException(message);
          }
        
          ret = krb5_cc_close(context_, cc);
          if (ret) {
            throw UnableToCreateSessionException("Failed while closing cache");
          }
        
          ret = kadm5_init_iprop(serverHandle_, 0);
          if (ret) {
            throw UnableToCreateSessionException("kadm5_init_iprop");
          }
        }
    };  
  }
}

//#include "kerberosSession.cpp"
    
#endif

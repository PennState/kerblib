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
#include "pthread.h"

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
          init(clientString, realm, keytab);
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
 
        void init(const std::string &clientString, const std::string &realmString, const std::string &keytabString) {

          krb5_error_code error;
          if ((error = krb5_init_context(&context_)) != 0) {
            throw UnableToCreateSessionException("Unable to initialize the kerberos context");
          }

          char client[clientString.length() + 1] = {0};
          strncpy(client, clientString.c_str(), clientString.length());

          char realm[realmString.length() + 1] = {0};
          strncpy(realm, realmString.c_str(), realmString.length());

          char kt[keytabString.length() + 1] = {0};
          strncpy(kt, keytabString.c_str(), keytabString.length());

          char **dbargs = NULL;
          kadm5_config_params params;
          memset(&params, 0, sizeof(params));

          params.mask |= KADM5_CONFIG_REALM;
          params.realm = realm;

          kadm5_ret_t ret;

          // use a named MEMORY cred cache unique per thread        
          krb5_ccache cc;
          std::stringstream ss;
          ss << pthread_self();
          std::string ccacheNameStr = "MEMORY:kadminrest_"+ss.str();
          char ccacheName[ccacheNameStr.length() + 1] = {0};
          strncpy(ccacheName, ccacheNameStr.c_str(), ccacheNameStr.length());
          ret = krb5_cc_resolve(context_, ccacheName, &cc);
          
          //ret = krb5_cc_default(context_, &cc);
          if (ret) {
            throw UnableToCreateSessionException("Unable to initialize credentials cache");
          }

          ret = kadm5_init_with_skey(context_,
                                     client,
                                     kt,
                                     DEFAULT_SERVICE_NAME,
                                     &params,
                                     KADM5_STRUCT_VERSION,
                                     KADM5_API_VERSION_2,
                                     dbargs,
                                     &serverHandle_);

          if (ret != KADM5_OK)
          {
            std::string message;
            auto krb5_err = krb5_get_error_message(context_, ret);
            std::string krb5_err_str(krb5_err);
            krb5_free_error_message(context_, krb5_err);
            message = "error occured during kadm5_init_with_skey(): " + krb5_err_str + " (" + boost::lexical_cast<std::string>(ret) + ")";
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

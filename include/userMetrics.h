#ifndef AIT_KERBEROS_USER_METRICS_H__
#define AIT_KERBEROS_USER_METRICS_H__

#include <string>
#include <inttypes.h>

namespace ait
{
  namespace kerberos
  {
    class UserMetrics
    {
      public:
        UserMetrics(uint32_t pwExpiration, uint32_t princExpiration, uint32_t creation, uint32_t lastSuccess, uint32_t lastFailure, uint32_t kvno);

        std::string passwordExpirationAsString() const;
        uint32_t passwordExpiration() const;

        std::string principalExpirationAsString() const;
        uint32_t principalExpiration() const;

        std::string passwordCreationAsString() const;
        uint32_t passwordCreation() const;

        std::string lastSuccessfulLoginAsString() const;
        uint32_t lastSuccessfulLogin() const;

        std::string lastFailedLoginAsString() const;
        uint32_t lastFailedLogin() const;

        std::string passwordChangeCountAsString() const;
        uint32_t passwordChangeCount() const;

      private:
        uint32_t passwordExpirationDate_;
        uint32_t principalExpirationDate_;
        uint32_t passwordCreationDate_;
        uint32_t lastSuccessfulLoginDate_;
        uint32_t lastFailedLoginDate_;
        uint32_t passwordChangeCount_;

        mutable std::string passwordExpirationString_;
        mutable std::string principalExpirationString_;
        mutable std::string passwordCreationString_;
        mutable std::string lastSuccessfulLoginString_;
        mutable std::string lastFailedLoginString_;
        mutable std::string passwordChangeCountString_;

        std::string toString(uint32_t timeVal) const;        
    };
  }
}

#endif

#include <cstring>
#include <ctime>
#include "userMetrics.h"

ait::kerberos::UserMetrics::UserMetrics(uint32_t passwordExpiration, uint32_t principalExpiration, uint32_t creation, 
                                        uint32_t lastSuccess, uint32_t lastFailure,
                                        uint32_t kvno) : passwordExpirationDate_(passwordExpiration),
                                                         principalExpirationDate_(principalExpiration),
                                                         passwordCreationDate_(creation),
                                                         lastSuccessfulLoginDate_(lastSuccess),
                                                         lastFailedLoginDate_(lastFailure),
                                                         passwordChangeCount_(kvno),
                                                         passwordExpirationString_(""),
                                                         passwordCreationString_(""),
                                                         lastSuccessfulLoginString_(""),
                                                         lastFailedLoginString_(""),
                                                         passwordChangeCountString_("")

{}

std::string ait::kerberos::UserMetrics::passwordExpirationAsString() const {
  if (passwordExpirationString_.empty())
    passwordExpirationString_ = toString(passwordExpirationDate_);

  return passwordExpirationString_; 
}

uint32_t ait::kerberos::UserMetrics::passwordExpiration() const {
  return passwordExpirationDate_;
}

std::string ait::kerberos::UserMetrics::principalExpirationAsString() const {
  if (principalExpirationString_.empty())
    principalExpirationString_ = toString(principalExpirationDate_);

  return principalExpirationString_; 
}

uint32_t ait::kerberos::UserMetrics::principalExpiration() const {
  return principalExpirationDate_;
}

std::string ait::kerberos::UserMetrics::passwordCreationAsString() const {
  if (passwordCreationString_.empty())
    passwordCreationString_ = toString(passwordCreationDate_);

  return passwordCreationString_; 
}

uint32_t ait::kerberos::UserMetrics::passwordCreation() const {
  return passwordCreationDate_;
}

std::string ait::kerberos::UserMetrics::lastSuccessfulLoginAsString() const {
  if (lastSuccessfulLoginString_.empty())
    lastSuccessfulLoginString_ = toString(lastSuccessfulLoginDate_);

  return lastSuccessfulLoginString_;
}

uint32_t ait::kerberos::UserMetrics::lastSuccessfulLogin() const {
  return lastSuccessfulLoginDate_;
}

std::string ait::kerberos::UserMetrics::lastFailedLoginAsString() const {
  if (lastFailedLoginString_.empty())
    lastFailedLoginString_ = toString(lastFailedLoginDate_);

  return lastFailedLoginString_;
}

uint32_t ait::kerberos::UserMetrics::lastFailedLogin() const {
  return lastFailedLoginDate_;
}

std::string ait::kerberos::UserMetrics::passwordChangeCountAsString() const {
  if (passwordChangeCountString_.empty())
    passwordChangeCountString_ = toString(lastFailedLoginDate_);

  return passwordChangeCountString_;
}

uint32_t ait::kerberos::UserMetrics::passwordChangeCount() const {
  return passwordChangeCount_;
}

std::string ait::kerberos::UserMetrics::toString(uint32_t timeVal) const
{
  if (timeVal == 0)
    return "Never";

  time_t tt = timeVal;
  std::string timeString = ctime(&tt);
  timeString = timeString.substr(0, timeString.find("\n"));
  return timeString;
}

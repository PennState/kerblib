#ifndef SYSLOG_LOGGER_H__
#define SYSLOG_LOGGER_H__

#include <string>
#include <syslog.h>

class SyslogLogger
{
  public:
    SyslogLogger(int facility = LOG_DAEMON)
    {
      openlog("", LOG_PID | LOG_NDELAY, facility);
    }

    ~SyslogLogger() throw()
    {
      closelog();
    }

    void logMessage(const std::string &message)
    {
      syslog(LOG_NOTICE, message.c_str());
    }
};

#endif

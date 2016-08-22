#ifndef CONSOLE_LOGGER_H__
#define CONSOLE_LOGGER_H__

#include <string>

class ConsoleLogger
{
  public:
    void logMessage(const std::string &message)
    {
      time_t t = time(NULL);
      std::string logDate(ctime(&t));

      size_t pos = logDate.find("\n");
      if (pos != std::string::npos)
        logDate.replace(pos, 1, " ");

      std::cout << logDate << ": " << message << std::endl;
    }
};

#endif

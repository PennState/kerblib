#ifndef CONSOLE_LOGGER_H__
#define CONSOLE_LOGGER_H__

#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>

std::string iso8601() {
  using namespace std::chrono;

  // get current time
  auto now = system_clock::now();

  // get number of milliseconds for the current second
  // (remainder after division into seconds)
  auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

  // convert to std::time_t in order to convert to std::tm (broken time)
  auto timer = system_clock::to_time_t(now);

  // convert to broken time
  std::tm bt = *std::localtime(&timer);

  std::stringstream oss;
  oss << std::put_time(&bt, "%FT%T") << '.' << std::setfill('0') << std::setw(3) << ms.count() << std::put_time(&bt, "%z");

  return oss.str();
}

class ConsoleLogger
{
  public:
    void logMessage(const std::string &message)
    {
      std::cout << "time=\"" << iso8601() << "\" " << message << std::endl;
    }
};

#endif

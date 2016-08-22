#ifndef JMS_LOGGER_H__
#define JMS_LOGGER_H__

#include <string>
#include <memory>

#include "JMS_Writer.h"

class JMS_Logger
{
  public:
    JMS_Logger();

    void logMessage(const std::string &message);

  private:
    //std::shared_ptr<cms::Session> session_;
    //std::shared_ptr<cms::Queue> queue_;
    //std::shared_ptr<cms::Connection> connection_;
    //std::shared_ptr<cms::MessageProducer> producer_;
    std::shared_ptr<ait::communication::JMS_Writer> writer_;

    void init();
};

#endif

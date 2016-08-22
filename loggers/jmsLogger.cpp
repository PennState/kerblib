#include <string>
#include "jmsLogger.h"
#include "unable_to_initialize_exception.h"
#include "properties.h"
#include "JMS_ConnectionFactory.h"

JMS_Logger::JMS_Logger()
{
  init();
}

void JMS_Logger::logMessage(const std::string &message)
{
  std::string timeString;
  time_t rawTime;
  time(&rawTime);
  timeString = ctime(&rawTime);

  size_t newlinePos = timeString.find("\n");
  if (newlinePos != std::string::npos)
    timeString.replace(newlinePos, timeString.length() - newlinePos, "\0");

  std::cout << "Raw Time: " << timeString << std::endl;

  std::string buffer = timeString + " : " + message;
  std::cout << "Sending " << buffer << std::endl;
  writer_->writeMessage(buffer);
  std::cout << "      Sent: " << buffer << "\n";
}

void JMS_Logger::init()
{
/*
  std::cout << "Intialize the JMQ Library" << std::endl;
  activemq::library::ActiveMQCPP::initializeLibrary();
  std::cout << "	Intialized the JMQ Library" << std::endl;

*/
  std::cout << "Getting the rootDir" << std::endl;
  char * rootDir = getenv("KERBEROS_LIB_ROOT");
  
  std::cout << "	Got the rootDir" << std::endl;

  if (rootDir == NULL)
  {
    std::cout << "KERBEROS_LIB_HOME not set" << std::endl;
    throw UnableToInitializeException("JMS Logging requires the KERBEROS_LIB_HOME environment variable to be set and a jms.properties file in $KERBEROS_LIB_HOME/config");
  }

  std::string propFile(rootDir);
  propFile +=  "/config/jms.properties";

  std::cout << "Initializing properties with " << propFile << std::endl;
  ait::util::Properties props(propFile);
  std::cout << "	Initialized properties with " << propFile << std::endl;

  std::cout << "Getting the factory" << std::endl;
  ait::communication::JMS_ConnectionFactory & factory = ait::communication::JMS_ConnectionFactory::instance();
  std::cout << "	Got the factory" << std::endl;

  std::cout << "Getting the Writer" << std::endl;
  ait::communication::JMS_Writer * writer = factory.getWriter(props);
  std::cout << "	Got the Writer" << std::endl;

  if (writer == NULL)
  {
    std::cout << "NULL Writer returned" << std::endl;
    throw UnableToInitializeException("Failed to initialize the JMS Writer");
  }
   
  writer_.reset(writer);
  std::cout << "Resetting the writer, should be valid now" << std::endl;
/*  
  if (!props.containsProperty("jms.connection.uri"))
    throw UnableToInitializeException("The properties file does not contain the uri (property name = jms.connection.uri)");

  std::shared_ptr<cms::ConnectionFactory> factory(cms::ConnectionFactory::createCMSConnectionFactory(props.getProperty("jms.connection.uri")));

  if (!props.containsProperty("jms.connection.user"))
    throw UnableToInitializeException("The properties file does not contain the user id (property name = jms.connection.user)");

  if (!props.containsProperty("jms.connection.password"))
    throw UnableToInitializeException("The properties file does not contain the password (property name = jms.connection.password)");

  try
  {
    connection_.reset(factory->createConnection(props.getProperty("jms.connection.user"), props.getProperty("jms.connection.password")));
    std::cout << "Connection to JMS succesfully Made" << std::endl;
  }
  catch(cms::CMSException &e)
  {
    std::cout << "Connection to JMS succesfully FAILED" << std::endl;
    throw UnableToInitializeException(e.what());
  }

  try
  {
    session_.reset(connection_->createSession());
  }
  catch(cms::CMSException &e)
  {
    throw UnableToInitializeException(e.what());
  }

  if (!props.containsProperty("jms.connection.queue"))
    throw UnableToInitializeException("The properties file does not contain the queue name (property name = jms.connection.queue)");

  std::auto_ptr<cms::Queue> queue(session_->createQueue(props.getProperty("jms.connection.queue")));
  producer_.reset(session_->createProducer(queue.get()));
*/
}

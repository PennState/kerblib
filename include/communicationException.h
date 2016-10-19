#ifndef COMMUNICATION_EXCEPTION_H__
#define COMMUNICATION_EXCEPTION_H__

#include <stdexcept>

namespace ait
{
  namespace kerberos
  {
    class CommunicationException : public std::exception
    {
      public:
       CommunicationException()
       {}
    
       ~CommunicationException() throw()
       {}
    };
  }
}    

#endif

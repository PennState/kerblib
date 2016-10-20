#ifndef INVALID_REQUEST_EXCEPTION_H__
#define INVALID_REQUEST_EXCEPTION_H__

#include <stdexcept>

namespace ait
{
  namespace kerberos
  {
    class InvalidRequestException : public std::exception
    {
      public:
       explicit InvalidRequestException(const std::string &what) : what_(what)
       {}
    
       ~InvalidRequestException() throw()
       {}
    
       std::string what()
       {
         return what_;
       }
    
      private:
        std::string what_;
    };
  }
}
    
#endif

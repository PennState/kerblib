#ifndef SECURITY_REQUEST_FAILED_EXCEPTION_H__
#define SECURITY_REQUEST_FAILED_EXCEPTION_H__

#include <stdexcept>

namespace ait
{
  namespace kerberos
  {
    class SecurityRequestFailedException : public std::exception
    {
      public:
       explicit SecurityRequestFailedException(const std::string &what) : what_(what)
       {}
    
       ~SecurityRequestFailedException() throw()
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

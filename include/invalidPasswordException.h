#ifndef INVALID_PASSWORD_EXCEPTION_H__
#define INVALID_PASSWORD_EXCEPTION_H__

#include <stdexcept>

namespace ait
{
  namespace kerberos
  {
    class InvalidPasswordException : public std::exception
    {
      public:
       explicit InvalidPasswordException(const std::string &what) : what_(what)
       {}
    
       ~InvalidPasswordException() throw()
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

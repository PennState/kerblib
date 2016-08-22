#ifndef INVALID_USER_EXCEPTION_H__
#define INVALID_USER_EXCEPTION_H__

#include <stdexcept>

namespace ait
{
  namespace kerberos
  {
    class InvalidUserException : public std::exception
    {
      public:
       explicit InvalidUserException(const std::string &what) : what_(what)
       {}
    
       ~InvalidUserException() throw()
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

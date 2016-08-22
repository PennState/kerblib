#ifndef USER_ALREADY_EXISTS_EXCEPTION_H__
#define USER_ALREADY_EXISTS_EXCEPTION_H__

#include <stdexcept>

namespace ait
{
  namespace kerberos
  {
    class UserAlreadyExistsException : public std::exception
    {
      public:
       explicit UserAlreadyExistsException(const std::string &what) : what_(what)
       {}
    
       ~UserAlreadyExistsException() throw()
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

#ifndef UNABLE_TO_FIND_USER_EXCEPTION_H__
#define UNABLE_TO_FIND_USER_EXCEPTION_H__

#include <stdexcept>

namespace ait
{
  namespace kerberos
  {
    class UnableToFindUserException : public std::exception
    {
      public:
       explicit UnableToFindUserException(const std::string &what) : what_(what)
       {}
    
       ~UnableToFindUserException() throw()
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

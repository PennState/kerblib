#ifndef UNABLE_TO_CHANGE_PASSWORD_EXCEPTION_H__
#define UNABLE_TO_CHANGE_PASSWORD_EXCEPTION_H__

#include <stdexcept>

namespace ait {
namespace kerberos
{
  class UnableToChangePasswordException : public std::exception
  {
    public:
     explicit UnableToChangePasswordException(const std::string &what) : what_(what)
     {}
  
     ~UnableToChangePasswordException() throw()
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

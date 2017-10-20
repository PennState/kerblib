#ifndef UNAUTHORIZED_EXCEPTION_H__
#define UNAUTHORIZED_EXCEPTION_H__

#include <stdexcept>

namespace ait {
namespace kerberos
{
  class UnauthorizedException : public std::exception
  {
    public:
     explicit UnauthorizedException(const std::string &what) : what_(what)
     {}
  
     ~UnauthorizedException() throw()
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

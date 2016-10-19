#ifndef NOT_AUTHORIZED_EXCEPTION_H__
#define NOT_AUTHORIZED_EXCEPTION_H__

#include <stdexcept>

namespace ait
{
  namespace kerberos
  {
    class NotAuthorizedException : public std::exception
    {
      public:
       NotAuthorizedException()
       {}
    
       ~NotAuthorizedException() throw()
       {}
    };
  }
}    

#endif

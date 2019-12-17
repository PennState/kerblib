#ifndef UNABLE_TO_CREATE_SESSION_EXCEPTION_H__	
#define UNABLE_TO_CREATE_SESSION_EXCEPTION_H__	

#include <stdexcept>

namespace ait
{
  namespace kerberos
  {
    class UnableToCreateSessionException : public std::exception
    {
      public:
       explicit UnableToCreateSessionException(const std::string &what) : what_(what)
       {}
    
       ~UnableToCreateSessionException() throw()
       {}
    
       std::string what()
       {
         return "Unable to create session: " + what_;
       }
    
      private:
        std::string what_;
    };
  }
}    

#endif

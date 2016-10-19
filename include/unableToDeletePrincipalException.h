#ifndef UNABLE_TO_DELETE_PRINCIPAL_EXCEPTION_H__
#define UNABLE_TO_DELETE_PRINCIPAL_EXCEPTION_H__

#include <stdexcept>

namespace ait
{
  namespace kerberos
  {
    class UnableToDeletePrincipalException : public std::exception
    {
      public:
       explicit UnableToDeletePrincipalException(const std::string &what) : what_(what)
       {}
    
       ~UnableToDeletePrincipalException() throw()
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

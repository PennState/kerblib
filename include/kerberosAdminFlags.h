#ifndef KERBEROS_ADMIN_FLAGS_H__
#define KERBEROS_ADMIN_FLAGS_H__

#include <inttypes.h>
#include <string>

namespace ait
{
  namespace kerberos
  {
    const std::string StandardStudentPolicy = "student";
    const std::string StandardFacultyStaffPolicy = "facstaff";

    const uint32_t ALLOW_POSTDATED_TICKETS = 0X00000001;
    const uint32_t DISALLOW_POSTDATED_TICKETS = 0X00000002;
    
    const uint32_t ALLOW_FORWARDABLE_TICKETS = 0X00000004;
    const uint32_t DISALLOW_FORWARDABLE_TICKETS = 0X00000008;
    
    const uint32_t ALLOW_RENEWABLE_TICKETS = 0X00000010;
    const uint32_t DISALLOW_RENEWABLE_TICKETS = 0X00000020;
    
    const uint32_t ALLOW_PROXIABLE_TICKETS = 0X00000040;
    const uint32_t DISALLOW_PROXIABLE_TICKETS = 0X00000080;
    
    const uint32_t ALLOW_DUP_SKEY = 0X00000100;
    const uint32_t DISALLOW_DUP_SKEY = 0X00000200;
    
    const uint32_t REQUIRE_PREAUTH = 0X00000400;
    const uint32_t DO_NOT_REQUIRE_PREAUTH = 0X00000800;
    
    const uint32_t REQUIRE_HWAUTH = 0X00001000;
    const uint32_t DO_NOT_REQUIRE_HWAUTH = 0X00002000;
    
    const uint32_t REQUIRE_OK_AS_DELEGATE = 0X00004000;
    const uint32_t DO_NOT_REQUIRE_OK_AS_DELEGATE = 0X00008000;
    
    const uint32_t ALLOW_SERVER_TICKETS = 0X00010000;
    const uint32_t DISALLOW_SERVER_TICKETS = 0X00020000;
    
    const uint32_t ALLOW_TGS_REQUEST = 0X00040000;
    const uint32_t DISALLOW_TGS_REQUEST = 0X00080000;
    
    const uint32_t ALLOW_TICKET_ISSUANCE = 0X00100000;
    const uint32_t DISALLOW_TICKET_ISSUANCE = 0X00200000;
    
    const uint32_t FORCE_CHANGE = 0X00400000;
    const uint32_t DO_NOT_FORCE_CHANGE = 0X00800000;
  }
}

#endif

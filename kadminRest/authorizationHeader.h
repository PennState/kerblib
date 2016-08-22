#ifndef AUTHORIZATION_HEADER_HH
#define AUTHORIZATION_HEADER_HH

#include "base64.h"
#include "http_header.h"
#include <iostream>

using namespace Net;

class AuthorizationHeader : public Http::Header::Header {
  NAME("Authorization")

  public:
    void parse(const std::string &data) {
      std::cout << base64_decode(data) << std::endl;
    }

    void parseRaw(const char* str, size_t len) {
      std::string data(str);
      std::cout << base64_decode(data) << std::endl;
    }

  private:
   std::string userid;
   std::string password;
};

#endif

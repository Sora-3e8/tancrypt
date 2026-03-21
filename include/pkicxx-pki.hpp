#ifndef PKICXX_PKI_HPP
#define PKICXX_PKI_HPP

#include "pkicxx-hashtypes.hpp"
#include <vector>

extern "C" struct evp_pkey_st;

namespace pkicxx
{
  class pkic;
  class pki
  {
    public:
      static std::vector<unsigned char> encrypt(pkic& key,std::vector<unsigned char>& payload);
      static std::vector<unsigned char> decrypt(pkic& key,std::vector<unsigned char>& payload);
      static std::vector<unsigned char> sign(pkic& key, std::vector<unsigned char> &buffer, hashAlg alg);

    private:
      pki(){}
  };
}
#endif

#ifndef TANCRYPT_AES
#define TANCRYPT_AES

#include "tancrypt-aes-keyc.hpp"

namespace tancrypt
{
  namespace AES
  {
    std::vector<unsigned char> encrypt(AES::keyc &key_container,std::vector<unsigned char> buffer);
    class keyc; 
  }
}

#endif

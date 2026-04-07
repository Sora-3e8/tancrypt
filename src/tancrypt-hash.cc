#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdexcept>
#include "tancrypt-hash.hpp"

namespace tancrypt
{
  std::vector<unsigned char> hash(const std::vector<unsigned char> &buffer, hashAlg alg)
  {
    if(_hashTypeMap().count((int)alg)==0) throw std::invalid_argument("[tancrypt::hash] Invalid hashing algorithm.");
    EVP_MD *md = EVP_MD_fetch(NULL, _hashTypeMap().at((int)alg), NULL);

    if(!md)
    {
      unsigned long _err = ERR_get_error();
      throw std::invalid_argument("[pkicxx::hash] Could not load hasing algorithm.\n Error "+std::to_string(_err)+", "+ERR_reason_error_string(_err));  
    }
    size_t dlen = EVP_MD_get_size(md);
    EVP_MD_free(md);
    
    std::vector<unsigned char>buffer_hashed(dlen);
    size_t dwritten;
    
    if(EVP_Q_digest(NULL,_hashTypeMap().at((int)alg),NULL,buffer.data(),buffer.size(),buffer_hashed.data(),&dwritten)!=1)
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[tancrypt::hash] Hashing failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    if(dwritten!=dlen)
    {
      throw std::runtime_error("[tancrypt::hash] Critical error, buffer corrupted or incomplete.\nExpected size: "+std::to_string(dlen)+"\nBytes written:"+std::to_string(dwritten));
    }

    return buffer_hashed;
  }

}

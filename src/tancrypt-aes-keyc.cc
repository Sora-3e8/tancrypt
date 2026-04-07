#include "tancrypt-aes-keyc.hpp"
#include "tancrypt-hashtypes.hpp"
#include <openssl/evp.h>

namespace tancrypt
{
  namespace AES
  {
    keyc::keyc(){}
    
    keyc::~keyc()
    {
      EVP_CIPHER_free(cipher);
    }

    
    void keyc::setKey(const std::vector<unsigned char> &key)
    {
       _key = key;
    }
    
    const std::vector<unsigned char>& keyc::getKey()
    {
      return _key;
    }
    
    keyc::keyc(const std::vector<unsigned char>& key,AES::Type type)
    {
      setType(type);
      setKey(key);
    }
    
    keyc::keyc(const std::vector<unsigned char>& key,AES::Type type,hashAlg alg)
    {
      setType(type);
      setKey(key);
      setHashAlg(alg);
      setHashEnabled(true);
    }
    
    void keyc::setType(AES::Type type)
    { 
      if(cipher!=nullptr) EVP_CIPHER_free(cipher);
      cipher = EVP_CIPHER_fetch(NULL, _aesTypeMap().at(type), NULL);
    }
    
    void keyc::setHashEnabled(bool val) { do_hash = val; }
    
    void keyc::setHashAlg(hashAlg alg) { _alg = alg; }
    
    const bool keyc::getHashEnabled() { return do_hash; }
    
    const hashAlg keyc::getHashAlg() { return _alg; }
  }
}

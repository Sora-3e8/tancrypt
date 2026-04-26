#include "tancrypt-aes-keyc.hpp"
#include "tancrypt-hashtypes.hpp"
#include <openssl/evp.h>
#include <stdexcept>

namespace tancrypt
{
  namespace AES
  {
    keyc::keyc(){}
    
    keyc::~keyc()
    {
      EVP_CIPHER_free(cipher);
    }

    int keyc::getCiphKLen()
    {
      if (cipher==nullptr) throw std::logic_error("[tancrypt::AES::keyc::getCiphKLen] Key is not initialized");
      return EVP_CIPHER_key_length(cipher);
    }
    
    void keyc::setKey(const dutils::dbuffer &key)
    {
       _key = key;
    }
    
    const dutils::dbuffer& keyc::getKey()
    {
      return _key;
    }
    
    keyc::keyc(const dutils::dbuffer& key,AES::Type type)
    {
      setType(type);
      setKey(key);
    }
    
    keyc::keyc(const dutils::dbuffer& key,AES::Type type,hashAlg alg)
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

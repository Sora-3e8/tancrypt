#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include "pkicxx-pki.hpp"
#include "pkicxx-pkic.hpp"
#include <openssl/err.h>
#include <stdexcept>

namespace pkicxx{
  
  std::vector<unsigned char> pki::encrypt(pkic& key,std::vector<unsigned char>& payload)
  {
    if(key.key_container==nullptr)
    {
      throw std::logic_error("[pkicxx::pki::encrypt] The key container was not initialized.");
    }
   
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key.key_container,NULL);
    if(!ctx) return std::vector<unsigned char>();
      
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      return {};
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      return {};
    }
    
    size_t len;
    if (EVP_PKEY_encrypt(ctx,NULL,&len,payload.data(),payload.size())<=0)
    {
      EVP_PKEY_CTX_free(ctx);
      return {};
    }
    std::vector<unsigned char> encrypted(len);
    if(EVP_PKEY_encrypt(ctx,encrypted.data(),&len,payload.data(),payload.size())<=0)
    {
      EVP_PKEY_CTX_free(ctx);
      return {};
    }

    EVP_PKEY_CTX_free(ctx);
    return encrypted;
  }

  std::vector<unsigned char> pki::decrypt(pkic& key,std::vector<unsigned char>& payload)
  {
    if(key.key_container==nullptr)
    {
      throw std::logic_error("[pkicxx::pki::decrypt] The key container was not initialized.");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key.key_container,NULL);
    if(!ctx) return std::vector<unsigned char>();
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      return {};
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0){ return{};}

    size_t len;
    if (EVP_PKEY_decrypt(ctx,NULL,&len,payload.data(),payload.size())<=0)
    {
      EVP_PKEY_CTX_free(ctx);
      return {};
    }
    
    std::vector<unsigned char> decrypted(len);
    if(EVP_PKEY_decrypt(ctx,decrypted.data(),&len,payload.data(),payload.size())<=0)
    {
      EVP_PKEY_CTX_free(ctx);
      return {};
    }
    decrypted.resize(len);
    
    EVP_PKEY_CTX_free(ctx);
    return decrypted;
  }

  void pki::sign()
  {
    
  }
}

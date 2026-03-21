#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include "pkicxx-pki.hpp"
#include "pkicxx-pkic.hpp"
#include <openssl/err.h>
#include <stdexcept>

namespace pkicxx
{
    
  std::vector<unsigned char> pki::encrypt(pkic& key,std::vector<unsigned char>& payload)
  {
    if(!key.isInitialized())
    {
      throw std::logic_error("[pkicxx::pki::encrypt] The key container was not initialized.");
    }
   
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key,NULL);
    if(!ctx) return std::vector<unsigned char>();
      
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[pkicxx::pki::ecrypt] Encryption context init failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[pkicxx::pki::encrypt] Encryption context init failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    size_t len;
    if (EVP_PKEY_encrypt(ctx,NULL,&len,payload.data(),payload.size())<=0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[pkicxx::pki::encrypt] Encryption failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    std::vector<unsigned char> encrypted(len);
    if(EVP_PKEY_encrypt(ctx,encrypted.data(),&len,payload.data(),payload.size())<=0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[pkicxx::pki::encrypt] Encryption failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    EVP_PKEY_CTX_free(ctx);
    return encrypted;
  }

  std::vector<unsigned char> pki::decrypt(pkic& key,std::vector<unsigned char>& payload)
  {
    if(!key.isInitialized())
    {
      throw std::logic_error("[pkicxx::pki::decrypt] The key container was not initialized.");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key,NULL);
    if(!ctx) return std::vector<unsigned char>();
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[pkicxx::pki::decrypt] Decryption context init failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0){ return{};}

    size_t len;
    if (EVP_PKEY_decrypt(ctx,NULL,&len,payload.data(),payload.size())<=0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[pkicxx::pki::decrypt] Decryption failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    std::vector<unsigned char> decrypted(len);
    if(EVP_PKEY_decrypt(ctx,decrypted.data(),&len,payload.data(),payload.size())<=0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[pkicxx::pki::decrypt] Decryption failed.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    
    decrypted.resize(len);
    EVP_PKEY_CTX_free(ctx);
    
    return decrypted;
  }

  std::vector<unsigned char> pki::sign(pkic& key,std::vector<unsigned char> &buffer)
  {
    if(!key.isInitialized())
    {
      throw std::logic_error("[pkicxx::pki::sign] The key container was not initialized.");
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key,NULL);
    if(!ctx) return {};
    if (EVP_PKEY_sign_init(ctx) <= 0)
    {
      int _err = ERR_get_error();
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("[pkicxx::pki::sign] Could not initialize signature.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
    EVP_PKEY_CTX_free(ctx);
    return {};
  }
}

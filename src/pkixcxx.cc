#include <memory>
#include <openssl/cryptoerr_legacy.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cstring>
#include "pkixcxx.hpp"

namespace pkixcxx
{
  pkix::pkix(){}
  void pkix::generate_keypair(int length)
  {
    if(pki != nullptr) EVP_PKEY_free(pki);
    pki = EVP_RSA_gen(length);
  }

  std::string pkix::getPrivkeyPEM()
  {
    if (pki == nullptr) return "";
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    if(PEM_write_bio_PrivateKey(bio,pki,NULL,NULL,0,NULL,NULL)!=1)
    {
      BIO_free(bio);
      return "";       
    }
    
    char* data = nullptr;
    int len = BIO_get_mem_data(bio, &data);
    char* data2 = new char[len+1];
    memcpy(data2,data,len);
    data2[len] = '\0';
    BIO_free(bio);
    std::string data_string = std::string(data2);
    delete[] data2;
    return data_string;
  }

  std::string pkix::getPubkeyPEM()
  {
    if (pki == nullptr) return "";
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    if(PEM_write_bio_PUBKEY(bio,pki)!=1)
    {
      BIO_free(bio);
      return "";    
    }

    char* data = nullptr;
    int len = BIO_get_mem_data(bio, &data);
    char* data2 = new char[len+1];
    memcpy(data2,data,len);
    data2[len] = '\0';
    
    BIO_free(bio);
    std::string data_string = std::string(data2);
    delete[] data2;
    return data_string;
  }
  
  std::unique_ptr<unsigned char[]> pkix::getPubkeyDER()
  {
    if(pki == nullptr) return std::unique_ptr<unsigned char[]>();

    int key_len = i2d_PublicKey(pki, NULL);
    unsigned char* key_der = new unsigned char[key_len]; 
    i2d_PublicKey(pki, &key_der);

    return std::unique_ptr<unsigned char[]>(key_der);
  }
  
  pkix::~pkix()
  {
    if(pki != nullptr) EVP_PKEY_free(pki);
  } 
}

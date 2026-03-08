#include <iomanip>
#include <sstream>
#include <openssl/cryptoerr_legacy.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include "pkicxx.hpp"

namespace pkicxx
{
  pkix::pkix(){}
  void pkix::generate_keypair(int length)
  {
    if(pki != nullptr) EVP_PKEY_free(pki);
    pki = EVP_RSA_gen(length);
  }

  std::string pkix::getPrivPEM()
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

  std::string pkix::getPubPEM()
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

  std::string DERhexStr(const std::vector<unsigned char> &DER)
  {
    int counter = 0;
    std::stringstream hex_str;
    for(unsigned char val : DER)
    {
     hex_str << std::hex << std::setw(2) << std::setfill('0') << (int) val << (((counter+1)%16==0) ? '\n' : ' ' );
     counter++;
    }

    return hex_str.str();
  }

  std::string pkix::getBundlePEM()
  {
    return getPubPEM() + getPrivPEM();
  }
  
  std::vector<unsigned char> pkix::getPubDER()
  {
    if(pki == nullptr) return std::vector<unsigned char>();

    int key_len = i2d_PublicKey(pki, NULL);
    std::vector<unsigned char> key_der(key_len);
    unsigned char* pkey = key_der.data();
    i2d_PublicKey(pki,&pkey);
    return key_der;
  }

  std::vector<unsigned char> pkix::getPrivDER()
  {
    if(pki == nullptr) return std::vector<unsigned char>();

    int key_len = i2d_PrivateKey(pki, NULL);
    std::vector<unsigned char> key_der(key_len);
    unsigned char* pkey = key_der.data();
    i2d_PrivateKey(pki,&pkey);
    return key_der;
  }

  
  pkix::~pkix()
  {
    if(pki != nullptr) EVP_PKEY_free(pki);
  } 
}

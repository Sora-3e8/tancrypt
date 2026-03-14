#include <cstddef>
#include <ios>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "pkicxx-pkic.hpp"
#include <sstream>
#include <fstream>

namespace pkicxx
{
  pkic::pkic(){}
  pkic::~pkic(){ if(key_container != nullptr) EVP_PKEY_free(key_container); }

  void pkic::generate_keypair(int length)
  {
    if(key_container != nullptr) EVP_PKEY_free(key_container);
    key_container = EVP_RSA_gen(length);
  }

  void pkic::loadPrivDER(std::vector<unsigned char>& DER)
  {
    const unsigned char* content = DER.data();
    d2i_PrivateKey(EVP_PKEY_RSA,&key_container,&content,DER.size());
  }
  
  void pkic::loadPubDER(std::vector<unsigned char>& DER)
  {
    const unsigned char* content = DER.data();
    d2i_PublicKey(EVP_PKEY_RSA,&key_container,&content,DER.size());
  }
  
  std::vector<unsigned char> pkic::getPrivDER()
  {
    if(key_container == nullptr) return std::vector<unsigned char>();

    int key_len = i2d_PrivateKey(key_container, NULL);
    std::vector<unsigned char> key_der(key_len);
    unsigned char* pkey = key_der.data();
    i2d_PrivateKey(key_container, &pkey);
    
    return key_der;
  }
  
  std::vector<unsigned char> pkic::getPubDER()
  {
    if(key_container == nullptr) return std::vector<unsigned char>();

    int key_len = i2d_PublicKey(key_container, NULL);
    std::vector<unsigned char> key_der(key_len);
    unsigned char* pkey = key_der.data();
    i2d_PublicKey(key_container, &pkey);
    
    return key_der;
  }
  void pkic::importPEM(const char* file)
  {
    std::stringstream pem_str;
    std::fstream pem_file(file,std::ios_base::in); 
    pem_str << pem_file.rdbuf();
    pem_file.close();
    const std::string str_tmp = pem_str.str();
    const char* pem_str2 = str_tmp.c_str();
    BIO* bio = BIO_new_mem_buf(pem_str2, pem_str.str().size());
    ::evp_pkey_st* tmp_key = nullptr;
    tmp_key = PEM_read_bio_PrivateKey(bio, NULL, NULL,NULL);
    BIO_reset(bio);

    if(tmp_key != nullptr) key_container=tmp_key;
    if(tmp_key == nullptr) tmp_key = PEM_read_bio_PUBKEY(bio, NULL,NULL,NULL);
    if(tmp_key != nullptr) key_container = tmp_key;

    BIO_free(bio);
  }

  void pkic::loadPEMStr(const char* PEM)
  {
    BIO* bio = BIO_new_mem_buf(PEM, strlen(PEM));
    ::evp_pkey_st* tmp_key = nullptr;
    tmp_key = PEM_read_bio_PrivateKey(bio, NULL, NULL,NULL);
    BIO_reset(bio);

    if(tmp_key != nullptr) key_container=tmp_key;
    if(tmp_key == nullptr) tmp_key = PEM_read_bio_PUBKEY(bio, NULL,NULL,NULL);
    if(tmp_key != nullptr) key_container = tmp_key;

    BIO_free(bio);
  }


  std::string pkic::getPrivPEM()
  {
    if (key_container == nullptr) return "";
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    if(PEM_write_bio_PrivateKey(bio,key_container,NULL,NULL,0,NULL,NULL)!=1)
    {
      BIO_free(bio);
      return "";       
    }
    
    int len = BIO_pending(bio);
    std::string pem_str(len,'\0');
    BIO_read(bio,&pem_str[0],len);
    BIO_free(bio);
    
    return pem_str;
  }

  std::string pkic::getPubPEM()
  {
    if (key_container == nullptr) return "";
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    if(PEM_write_bio_PUBKEY(bio,key_container)!=1)
    {
      BIO_free(bio);
      return "";       
    }
    
    int len = BIO_pending(bio);
    std::string pem_str(len,'\0');
    BIO_read(bio,&pem_str[0],len);
    BIO_free(bio);

    return pem_str;
  }

  std::string pkic::getBundlePEM()
  {
    return getPubPEM() + getPrivPEM();
  }
      
  void pkic::exportPrivPEM(const char* file)
  {
    std::fstream pem_out(file,std::ios_base::out);
    pem_out << getPrivPEM();
    pem_out.close();
  }

  
  void pkic::exportPubPEM(const char* file)
  {
    std::fstream pem_out(file,std::ios_base::out);
    pem_out << getPubPEM();
    pem_out.close();
  }

  void pkic::exportBundlePEM(const char* file)
  {
    std::fstream pem_out(file,std::ios_base::out);
    pem_out << getBundlePEM();
    pem_out.close();
  }
}

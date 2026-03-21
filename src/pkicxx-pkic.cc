#include <cstddef>
#include <ios>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "pkicxx-pkic.hpp"
#include <sstream>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace pkicxx
{
  pkic::pkic(){}
  pkic::~pkic(){ if(key_container != nullptr) EVP_PKEY_free(key_container); }

  bool pkic::isInitialized()
  {
    return (key_container!=nullptr);
  }

  pkic::operator evp_pkey_st*()
  {
    return key_container;
  }

  void pkic::generate_keypair(int length)
  {
    if(key_container != nullptr) EVP_PKEY_free(key_container);
    key_container = EVP_RSA_gen(length);
  }

  void pkic::loadPrivDER(std::vector<unsigned char>& DER)
  {
    const unsigned char* content = DER.data();
    d2i_PrivateKey(EVP_PKEY_RSA,&key_container,&content,DER.size());
    if(key_container==NULL)
    {
      unsigned long _err = ERR_get_error();    
      throw std::runtime_error( "[pkicxx::pkic::loadPrivDER] Failed to load privkey from DER.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }  
  }
  
  void pkic::loadPubDER(std::vector<unsigned char>& DER)
  {
    const unsigned char* content = DER.data();
    d2i_PublicKey(EVP_PKEY_RSA,&key_container,&content,DER.size());
    if(key_container==NULL)
    {
      unsigned long _err = ERR_get_error();    
      throw std::runtime_error( "[pkicxx::pkic::loadPubDER] Failed to load privkey from DER.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));
    }
  }
  
  std::vector<unsigned char> pkic::getPrivDER()
  {
    if(key_container==nullptr)
    {
      throw std::logic_error("[pkicxx::pkic::getPrivDER] The key container was not initialized.");
    }
    
    int key_len = i2d_PrivateKey(key_container, NULL);

    if (key_len < 0)
    {
      unsigned long _err = ERR_get_error();
      std::cerr<<"[pkicxx::pkic::getPrivDER] Could not get DER of the privkey.\n"<<"Error "<<_err<<", "<<ERR_reason_error_string(_err)<< std::endl;
      return {};     
    }

    std::vector<unsigned char> key_der(key_len);
    unsigned char* pkey = key_der.data();
    int _bytes_written = i2d_PrivateKey(key_container, &pkey);
    if(_bytes_written!=key_len) throw std::runtime_error("\033[31m[pkicxx::pkic::getPrivDER] Critical error, buffer corrupted.\nBuffer size expected: "+std::to_string(key_len)+"\nBuffer written: "+std::to_string(_bytes_written)+"\033[0m");

    return key_der;
  }
  
  std::vector<unsigned char> pkic::getPubDER()
  {
    if(key_container==nullptr)
    {
      throw std::logic_error("[pkicxx::pkic::getPubDER] The key container was not initialized.");
    }

    int key_len = i2d_PublicKey(key_container, NULL);

    if (key_len <= 0)
    {
      unsigned long _err = ERR_get_error();
      std::cerr<<"[pkicxx::pkic::getPubDER] Could not get DER of the pubkey.\n"<<"Error "<<_err<<", "<<ERR_reason_error_string(_err)<< std::endl;
      return {};     
    }

    std::vector<unsigned char> key_der(key_len);
    unsigned char* pkey = key_der.data();
    int _bytes_written = i2d_PublicKey(key_container, &pkey);

    if(_bytes_written!=key_len) throw std::runtime_error("\033[31m[pkicxx::pkic::getPubDER] Critical error, buffer corrupted.\nBuffer size expected: "+std::to_string(key_len)+"\nBuffer written: "+std::to_string(_bytes_written)+"\033[0m");
    
    return key_der;
  }

  void pkic::loadPEMStr(const char* PEM)
  {
    BIO* bio = BIO_new_mem_buf(PEM, strlen(PEM));
    
    if (!bio)
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[pkicxx::pkic::loadPEMStr] Could not allocate buffer.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));     
    }

    ::evp_pkey_st* tmp_key = nullptr;
    tmp_key = PEM_read_bio_PrivateKey(bio, NULL, NULL,NULL);
    BIO_reset(bio);

    if(tmp_key != nullptr) key_container=tmp_key;
    if(tmp_key == nullptr) tmp_key = PEM_read_bio_PUBKEY(bio, NULL,NULL,NULL);
    if(tmp_key != nullptr) key_container = tmp_key;    
    if(tmp_key == nullptr) std::cerr << "[pkicxx::pkic::loadPEMStr] Failed to read PEM, \ncheck if the provided PEM string is valid." << std::endl;
    
    BIO_free(bio);
  }
  
  void pkic::importPEM(const char* file)
  {
    std::fstream pem_file(file,std::ios_base::in);
    
    if(!pem_file)
    {
      std::cerr << "[pkicxx::pkic::importPEM] Could not open file: "<<file<<"\nError "<<errno<<", "<<strerror(errno) << std::endl;
      return;
    }
    
    std::stringstream pem_str;
    pem_str << pem_file.rdbuf();
    pem_file.close();
    const std::string str_tmp = pem_str.str();
    const char* pem_str2 = str_tmp.c_str();
    loadPEMStr(pem_str2);
    
  }

  std::string pkic::getPrivPEM()
  {
    if(key_container == nullptr)
    {
      throw std::logic_error("[pkicxx::pkic::getPrivPEM] The key container was not initialized.");
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[pkicxx::pkic::getPrivPEM] Could not allocate buffer.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));     
    }


    if(PEM_write_bio_PrivateKey(bio,key_container,NULL,NULL,0,NULL,NULL)!=1)
    {
      unsigned long _err = ERR_get_error();
      BIO_free(bio);
      std::cerr<<"[pkicxx::pkic::getPrivPEM] Could not retrieve PEM.\n"<<"Error "<<_err<<", "<<ERR_reason_error_string(_err)<<std::endl;
      
      return "";       
    }
    
    int len = BIO_pending(bio);
    if(len<=0)
    {
      unsigned long _err = ERR_get_error();
      BIO_free(bio);
      std::cerr<<"[pkicxx::pkic::getPrivPEM] Could not retrieve PEM.\n"<<"Error "<<_err<<", "<<ERR_reason_error_string(_err)<<std::endl;
      
      return "";       
    }
    
    std::string pem_str(len,'\0');
    BIO_read(bio,&pem_str[0],len);
    BIO_free(bio);
    
    return pem_str;
  }

  std::string pkic::getPubPEM()
  {
    if(key_container == nullptr)
    {
      throw std::logic_error("[pkicxx::pkic::getPubPEM] The key container was not initialized.");
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    
    if (!bio)
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[pkicxx::pkic::getPubPEM] Could not allocate buffer.\nError "+std::to_string(_err)+", "+ERR_reason_error_string(_err));     
    }


    if(PEM_write_bio_PUBKEY(bio,key_container)!=1)
    {
      unsigned long _err = ERR_get_error();
      BIO_free(bio);
      std::cerr<<"[pkicxx::pkic::getPubPEM] Could not retrieve PEM.\n"<<"Error "<<_err<<", "<<ERR_reason_error_string(_err)<<std::endl;
      
      return "";       
    }
    
    int len = BIO_pending(bio);
    if(len<=0)
    {
      unsigned long _err = ERR_get_error();
      BIO_free(bio);
      std::cerr<<"[pkicxx::pkic::getPubPEM] Could not retrieve PEM.\n"<<"Error "<<_err<<", "<<ERR_reason_error_string(_err)<<std::endl;
      
      return "";       
    }
    
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

    if(!pem_out)
    {
      std::cerr << "[pkicxx::pkic::exportPrivPEM] Could not open file: "<<file<<"\nError "<<errno<<", "<<strerror(errno) << std::endl;
      return;
    }
    
    pem_out << getPrivPEM();
    pem_out.close();
  }

  
  void pkic::exportPubPEM(const char* file)
  {
    std::fstream pem_out(file,std::ios_base::out);

    if(!pem_out)
    {
      std::cerr << "[pkicxx::pkic::exportPubPEM] Could not open file: "<<file<<"\nError "<<errno<<", "<<strerror(errno) << std::endl;
      return;
    }
    
    pem_out << getPubPEM();
    pem_out.close();
  }

  void pkic::exportBundlePEM(const char* file)
  {
    std::fstream pem_out(file,std::ios_base::out);
    
    if(!pem_out)
    {
      std::cerr << "[pkicxx::pkic::exportBundlePEM] Could not open file: "<<file<<"\nError "<<errno<<", "<<strerror(errno) << std::endl;
      return;
    }
    
    pem_out << getBundlePEM();
    pem_out.close();
  }
}

#ifndef TANCRYPT_AES_KEYC
#define TANCRYPT_AES_KEYC

#include <vector>
#include <map>
#include "tancrypt-hashtypes.hpp"
#include "dutils.hpp"

struct evp_cipher_st;

namespace tancrypt
{
  namespace AES
  {    
    enum class Type : int
    {
      CBC128 = 0,
      GCM128 = 1,
      CBC192 = 2,
      GCM192 = 3,
      CBC256 = 4,
      GCM256 = 5
    };

    static const std::map<AES::Type,const char*>& _aesTypeMap()
    {
      static const std::map<AES::Type,const char*> m =
      {
        {Type::CBC128,"AES-128-CBC"},
        {Type::GCM128,"AES-128-GCM"},
        {Type::CBC192,"AES-192-CBC"},
        {Type::GCM192,"AES-192-GCM"},
        {Type::CBC256,"AES-256-CBC"},
        {Type::GCM256,"AES-256-GCM"}
      };

      return m;
    }
    
    class keyc
    {
      public:
        keyc();
        ~keyc();
        keyc(const dutils::dbuffer& key,AES::Type type);
        keyc(const dutils::dbuffer& key,AES::Type type,hashAlg alg);
        
        void setType(AES::Type type);
        void setHashAlg(hashAlg alg);
        void setHashEnabled(bool val);
        const hashAlg getHashAlg();
        const bool getHashEnabled();
        void setKey(const dutils::dbuffer &key);
        int getCiphKLen();
        const dutils::dbuffer &getKey();
        evp_cipher_st* cipher = nullptr;
        
        
      private:
        hashAlg _alg=hashAlg::SHA256;
        bool do_hash=false;
        dutils::dbuffer _key;
    };
  }
}
#endif

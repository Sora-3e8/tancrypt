#ifndef PKICXX_PKIC_HPP
#define PKICXX_PKIC_HPP

#include <string>
#include <vector>

extern "C" struct evp_pkey_st;

namespace pkicxx
{
  class pkic
  {
    public:
      pkic();
      ~pkic();
      
      // PKIC pair generators
      void generate_keypair(int length);

      operator evp_pkey_st*();

      bool isInitialized();
            
      // DER loaders
      void loadPrivDER(std::vector<unsigned char>& DER);
      void loadPubDER(std::vector<unsigned char>& DER);

      // DER getters
      std::vector<unsigned char> getPrivDER();
      std::vector<unsigned char> getPubDER();
      
      // PEM loaders
      void importPEM(const char* file);
      void loadPEMStr(const char* PEM);

      // PEM string getters
      std::string getPubPEM();
      std::string getPrivPEM();
      std::string getBundlePEM();

      // PEM exporters
      void exportPrivPEM(const char* file);
      void exportPubPEM(const char* file);
      void exportBundlePEM(const char* file);
    private:
      ::evp_pkey_st *key_container = nullptr;
  };
}
#endif 

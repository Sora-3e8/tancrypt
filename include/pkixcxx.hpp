#ifndef PKIXCXX_HPP
#define PKIXCXX_HPP

#include <vector>
#include <string>

extern "C"
{
  struct evp_pkey_st;
  
  namespace pkixcxx
  {
    class pkix
    {
      public:
        pkix();
        ~pkix();
        int length=2048;
        void generate_keypair(int length);
        std::string getPubPEM();
        std::string getPrivPEM();
        std::string getBundlePEM();
        std::vector<unsigned char> getPubDER();
        void exportPEM();
        char* encrypt();
        char* decrypt();
        char* sign();

      private:
        ::evp_pkey_st *pki=nullptr;
    };
  }
}
#endif

#ifndef PKIXCXX_HPP
#define PKIXCXX_HPP

#include <memory>
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
        std::string getPubkeyPEM();
        std::string getPrivkeyPEM();
        std::unique_ptr<unsigned char[]> getPubkeyDER();
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

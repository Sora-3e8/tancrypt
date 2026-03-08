#ifndef PKICXX_HPP
#define PKICXX_HPP

#include <vector>
#include <string>

extern "C" struct evp_pkey_st;

namespace pkicxx
{

  std::string DERhexStr(const std::vector<unsigned char> &DER);

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
      std::vector<unsigned char> getPrivDER();
      void exportPEM();
      char* encrypt();
      char* decrypt();
      char* sign();

    private:
      ::evp_pkey_st *pki=nullptr;
  };
}
#endif

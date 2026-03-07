#include <iostream>
#include "pkixcxx.hpp"

int main(int argc, char* argv[])
{
  pkixcxx::pkix key_factory;
  key_factory.generate_keypair(2048);

  std::cout << key_factory.getPrivkeyPEM() << std::endl;
  std::cout << key_factory.getPubkeyPEM() << std::endl;
  return 0;  
}

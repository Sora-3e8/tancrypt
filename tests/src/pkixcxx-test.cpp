#include <iostream>
#include <map>
#include <functional>
#include <iostream>
#include "pkixcxx.hpp"

int keyfactoryInit_test()
{
  pkixcxx::pkix key_factory;
  
  return 0;
}

int keypairGen_test()
{
  pkixcxx::pkix key_factory;
  key_factory.generate_keypair(2048);
  
  return 0;
}

int keypairRegen_test()
{
  pkixcxx::pkix key_factory;
  key_factory.generate_keypair(2048);
  key_factory.generate_keypair(2048);
  
  return 0;
  
}

int keypairMultigen_test()
{
  pkixcxx::pkix key_factory;
  
  for(int i=0; i<10; i++)
  {
    key_factory.generate_keypair(2048);
  }
  
  return 0;
}

int privPEM_test()
{
  pkixcxx::pkix key_factory;
  key_factory.generate_keypair(2048);
  std::string priv = key_factory.getPrivPEM();
  std::cout << priv << std::endl;
  return 0;
}

int pubPEM_test()
{
  pkixcxx::pkix key_factory;
  key_factory.generate_keypair(2048);
  std::string pub = key_factory.getPubPEM();
  std::cout << pub << std::endl;
  return 0;
}

int bundlePEM_test()
{
  pkixcxx::pkix key_factory;
  key_factory.generate_keypair(2048);
  std::string bundle = key_factory.getBundlePEM();
  std::cout << bundle << std::endl;
  return 0;
}
  
  

std::map<std::string,std::function<int()>> handler =
{

  {"--factoryInit", &keyfactoryInit_test},
  {"--pairGen", &keypairGen_test},
  {"--pairRegen", &keypairRegen_test},
  {"--pairMultigen", &keypairMultigen_test},
  {"--privPEM", &privPEM_test},
  {"--pubPEM", &pubPEM_test},
  {"--bundlePEM", &bundlePEM_test},
};

void printUsage(std::string bin_name)
{
  std::cout << " " << std::endl;
  std::cout << "usage: "<< bin_name << " [option]" << std::endl;
  std::cout << "Available options: [";
  for(auto v_pair : handler)
  {
    std::cout << "  " << v_pair.first;
  }
  std::cout << "]" << std::endl;
}

int main(int argc, char* argv[])
{
  if ((argc-1) !=1)
  {
    std::cout << "Invalid usage." << std::endl;
    printUsage("pkixcxx-test");
    return 1;
  }
  
  if(handler.count(argv[1])!=1)
  {
    std::cout << "Invalid option: " << argv[1] << std::endl;
    printUsage("pkixcxx-test");
    return 1;
  }
  
  return handler[argv[1]]();
}

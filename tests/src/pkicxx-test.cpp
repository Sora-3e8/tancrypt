#include <iostream>
#include <map>
#include <functional>
#include <iostream>
#include <vector>
#include "pkicxx.hpp"

int pkicInit(char* argv[], int argc)
{
  pkicxx::pkic key_factory;
  
  return 0;
}

int keypairGen(char* argv[], int argc)
{
  pkicxx::pkic key_factory;
  key_factory.generate_keypair(2048);
  
  return 0;
}

int keypairRegen(char* argv[], int argc)
{
  pkicxx::pkic key_factory;
  key_factory.generate_keypair(2048);
  key_factory.generate_keypair(2048);
  
  return 0;
  
}

int keypairMultigen(char* argv[], int argc)
{
  pkicxx::pkic key_factory;
  
  for(int i=0; i<10; i++)
  {
    key_factory.generate_keypair(2048);
  }
  
  return 0;
}

int getPrivDER(char* argv[], int argc)
{
  pkicxx::pkic key_factory;
  key_factory.generate_keypair(2048);
  std::vector<unsigned char> priv_der= key_factory.getPrivDER();
  std::cout << pkicxx::hexStr(priv_der) << std::endl;
  return 0;
}

int getPubDER(char* argv[], int argc)
{
  pkicxx::pkic key_factory;
  key_factory.generate_keypair(2048);
  std::vector<unsigned char> pub_der= key_factory.getPubDER();
  std::cout << pkicxx::hexStr(pub_der) << std::endl;
  
  return 0;
}


int loadPrivDER(char* argv[], int argc)
{
  pkicxx::pkic key_synth;
  pkicxx::pkic key_loaded;
  key_synth.generate_keypair(2048);
  std::vector<unsigned char> der_synth = key_synth.getPrivDER();
  key_loaded.loadPrivDER(der_synth);
  std::vector<unsigned char> der_loaded = key_loaded.getPrivDER();
  std::cout << "Generated priv hex:" << std::endl;
  std::cout << pkicxx::hexStr(der_synth) << std::endl;
  std::cout << "Loaded priv hex:" << std::endl;
  std::cout << pkicxx::hexStr(der_loaded) << std::endl;
  
  if(pkicxx::hexStr(der_synth)!=pkicxx::hexStr(der_loaded)) return 1;
  return 0;
}

int loadPubDER(char* argv[], int argc)
{
  pkicxx::pkic key_synth;
  pkicxx::pkic key_loaded;
  key_synth.generate_keypair(2048);
  std::vector<unsigned char> der_synth = key_synth.getPubDER();
  key_loaded.loadPubDER(der_synth);
  std::vector<unsigned char> der_loaded = key_loaded.getPubDER();
  std::cout << "Generated pub hex:" << std::endl;
  std::cout << pkicxx::hexStr(der_synth) << std::endl;
  std::cout << "Loaded pub hex:" << std::endl;
  std::cout << pkicxx::hexStr(der_loaded) << std::endl;
  
  if(pkicxx::hexStr(der_synth)!=pkicxx::hexStr(der_loaded)) return 1;
  return 0;
}

int importPrivPEM(char* argv[], int argc)
{
  pkicxx::pkic keyc;
  std::cout << "Priv pem: " << argv[2] << std::endl;
  keyc.importPEM(argv[2]);
  std::string content = pkicxx::hexStr(keyc.getPrivDER());
  std::cout << "Priv hex:" << std::endl;
  std::cout << content << std::endl;
  if(content=="") return 1;

  return 0;
}

int importPubPEM(char* argv[], int argc)
{
  pkicxx::pkic keyc;
  keyc.importPEM(argv[2]);
  std::string content = pkicxx::hexStr(keyc.getPubDER());
  std::cout << "Pub hex:" << std::endl;
  std::cout << content << std::endl;
  if(content == "") return 1;
  
  return 0;
}

int importBundlePEM(char* argv[], int argc)
{
  if(importPrivPEM(argv, argc)||importPubPEM(argv, argc)) return 1;
  return 0;
}

int getPrivPEM(char* argv[], int argc)
{
  pkicxx::pkic key_synth;
  key_synth.generate_keypair(2048);
  std::string synth_pem = key_synth.getPrivPEM();
  std::cout << "Synthesized Priv PEM:" << std::endl;
  std::cout << synth_pem << std::endl;

  pkicxx::pkic key_imported;
  key_imported.importPEM(argv[2]);
  std::string imported_pem = key_imported.getPrivPEM();
  std::cout << "Synthesized Priv PEM:" << std::endl;
  std::cout << imported_pem << std::endl;

  return 0;
}

int getPubPEM(char* argv[], int argc)
{
  pkicxx::pkic key_synth;
  key_synth.generate_keypair(2048);
  std::string synth_pem = key_synth.getPubPEM();
  std::cout << "Synthesized Pub PEM:" << std::endl;
  std::cout << synth_pem << std::endl;

  pkicxx::pkic key_imported;
  key_imported.importPEM(argv[2]);
  std::string imported_pem = key_imported.getPubPEM();
  std::cout << "Synthesized Pub PEM:" << std::endl;
  std::cout << imported_pem << std::endl;

  return 0;
}

int getBundlePEM(char* argv[], int argc)
{
  pkicxx::pkic key_synth;
  key_synth.generate_keypair(2048);
  std::string synth_pem = key_synth.getPrivPEM();
  std::cout << "Synthesized Bundle PEM:" << std::endl;
  std::cout << synth_pem << std::endl;

  pkicxx::pkic key_imported;
  key_imported.generate_keypair(2048);
  std::string imported_pem = key_imported.getPrivPEM();
  std::cout << "Synthesized Priv PEM:" << std::endl;
  std::cout << imported_pem << std::endl;

  return 0;
}

int loadPrivPEM(char* argv[], int argc)
{
  pkicxx::pkic keyc_synth;
  pkicxx::pkic keyc_loaded;
  
  keyc_synth.generate_keypair(2048);
  keyc_loaded.loadPEMStr(keyc_synth.getPrivPEM().c_str());
  std::cout << "Priv synth: " << std::endl;
  std::cout << pkicxx::hexStr(keyc_synth.getPrivDER()) << std::endl;
  std::cout << "Priv loaded: " << std::endl;
  std::cout << pkicxx::hexStr(keyc_loaded.getPrivDER()) << std::endl;
  if(pkicxx::hexStr(keyc_synth.getPrivDER()) != pkicxx::hexStr(keyc_loaded.getPrivDER())) return 1;
  return 0; 
}

int loadPubPEM(char* argv[], int argc)
{
  pkicxx::pkic keyc_synth;
  pkicxx::pkic keyc_loaded;
  
  keyc_synth.generate_keypair(2048);
  keyc_loaded.loadPEMStr(keyc_synth.getPubPEM().c_str());
  std::cout << "Pub synth: " << std::endl;
  std::cout << pkicxx::hexStr(keyc_synth.getPubDER()) << std::endl;
  std::cout << "Pub loaded: " << std::endl;
  std::cout << pkicxx::hexStr(keyc_loaded.getPubDER()) << std::endl;

  if(pkicxx::hexStr(keyc_synth.getPubDER()) != pkicxx::hexStr(keyc_loaded.getPubDER())) return 1;

  return 0; 
}

int loadBundlePEM(char* argv[], int argc)
{
  pkicxx::pkic keyc_synth;
  pkicxx::pkic keyc_loaded;
  
  keyc_synth.generate_keypair(2048);
  keyc_loaded.loadPEMStr(keyc_synth.getBundlePEM().c_str());
  std::cout << "Pub loaded: " << std::endl;
  std::cout << pkicxx::hexStr(keyc_loaded.getPubDER()) << std::endl;

  if(pkicxx::hexStr(keyc_synth.getPrivDER()) != pkicxx::hexStr(keyc_loaded.getPrivDER())) return 1;
  if(pkicxx::hexStr(keyc_synth.getPubDER()) != pkicxx::hexStr(keyc_loaded.getPubDER())) return 1;

  return 0; 
}
int exportPrivPEM(char* argv[], int argc)
{
  pkicxx::pkic keyc;
  keyc.generate_keypair(2048);
  keyc.exportPrivPEM("priv_out.pem");
  
  return 0;
}

int exportPubPEM(char* argv[], int argc)
{
  pkicxx::pkic keyc;
  keyc.generate_keypair(2048);
  keyc.exportPubPEM("pub_out.pem");
  
  return 0;
}

int exportBundlePEM(char* argv[], int argc)
{
  pkicxx::pkic keyc;
  keyc.generate_keypair(2048);
  keyc.exportBundlePEM("bundle_out.pem");
  
  return 0;
}

int Encrypt_test(char* argv[], int argc)
{
  pkicxx::pkic key_factory;
  key_factory.generate_keypair(2048);
  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data());
  std::vector<unsigned char> res = pkicxx::pki::encrypt(key_factory,payload);
  std::cout << "Original:" << std::endl;
  std::cout << my_message << std::endl;
  std::cout << "Hex::" << std::endl;
  std::cout << pkicxx::hexStr(payload) << std::endl;
  std::cout << "Encrypted:" << std::endl;
  std::cout << pkicxx::hexStr(res) << std::endl;
  if (pkicxx::hexStr(payload)==pkicxx::hexStr(res)||res.size()==0) return 1;
  
  return 0;
}

int Decrypt_test(char* argv[], int argc)
{
  pkicxx:: pkic key;
  key.generate_keypair(2048);
  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data());
  std::vector<unsigned char> res = pkicxx::pki::encrypt(key,payload);
  std::cout << "Original:" << std::endl;
  std::cout << my_message << std::endl;
  std::cout << "Hex:" << std::endl;
  std::cout << pkicxx::hexStr(payload) << std::endl;
  std::cout << "Encrypted:" << std::endl;
  std::cout << pkicxx::hexStr(res) << std::endl;
  std::vector<unsigned char> res_decrypted = pkicxx::pki::decrypt(key,res);
  std::cout << "Res decrypted hex:"<< std::endl;
  std::cout << pkicxx::hexStr(res_decrypted) << std::endl;
  std::cout << "Res decrypted:" << std::endl;
  std::cout << res_decrypted.data() << std::endl;
  if(pkicxx::hexStr(payload)==pkicxx::hexStr(res_decrypted)) return 0;
  
  return 1;
}

int debugPass(char* argv[], int argc)
{
  std::cout << "Arg pass: ";
  for(int i=0;i<argc;i++)
  {
    std::cout << argv[i];
  }
  std::cout << std::endl;

  return 0;
}

std::map<std::string,std::function<int(char* argv[],int argc)>> handler =
{
  {"--pkicInit", &pkicInit},
  {"--pairGen", &keypairGen},
  {"--pairRegen", &keypairRegen},
  {"--pairMultigen", &keypairMultigen},
  {"--getPrivDER", &getPrivDER},
  {"--getPubDER", &getPubDER},
  {"--loadPrivDER", &loadPrivDER},
  {"--loadPubDER", &loadPubDER},
  {"--getPrivPEM", &getPrivPEM},
  {"--getPubPEM", &getPubPEM},
  {"--loadPrivPEM", &loadPrivPEM},
  {"--loadPubPEM", &loadPubPEM},
  {"--loadBundlePEM", &loadBundlePEM},
  {"--getBundlePEM", &getBundlePEM},
  {"--importPrivPEM", &importPrivPEM},
  {"--importPubPEM", &importPubPEM},
  {"--importBundlePEM", &importBundlePEM},
  {"--exportPrivPEM", &exportPrivPEM},
  {"--exportPubPEM", &exportPubPEM},
  {"--exportBundlePEM", &exportBundlePEM},
  {"--encrypt", &Encrypt_test},
  {"--decrypt", &Decrypt_test},
  {"--debugTest", &debugPass}
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
  if ((argc-1) < 1)
  {
    std::cout << "Invalid usage." << std::endl;
    printUsage("pkicxx-test");
    return 1;
  }
  
  if(handler.count(argv[1])!=1)
  {
    std::cout << "Invalid option: " << argv[1] << std::endl;
    printUsage("pkicxx-test");
    return 1;
  }
  
  return handler[argv[1]](argv,argc);
}

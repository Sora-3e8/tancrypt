#include <iostream>
#include <map>
#include <functional>
#include <iostream>
#include <vector>
#include "tancrypt-aes-keyc.hpp"
#include "tancrypt-hash.hpp"
#include "tancrypt-hashtypes.hpp"
#include "tancrypt.hpp"

int pkicInit(char* argv[], int argc)
{
  tancrypt::RSA::pkic key_factory;
  
  return 0;
}

int keypairGen(char* argv[], int argc)
{
  tancrypt::RSA::pkic key_factory;
  key_factory.generate_keypair(2048);
  
  return 0;
}

int keypairRegen(char* argv[], int argc)
{
  tancrypt::RSA::pkic key_factory;
  key_factory.generate_keypair(2048);
  key_factory.generate_keypair(2048);
  
  return 0;
  
}

int keypairMultigen(char* argv[], int argc)
{
  tancrypt::RSA::pkic key_factory;
  
  for(int i=0; i<10; i++)
  {
    key_factory.generate_keypair(2048);
  }
  
  return 0;
}

int getPrivDER(char* argv[], int argc)
{
  tancrypt::RSA::pkic key_factory;
  key_factory.generate_keypair(2048);
  std::vector<unsigned char> priv_der= key_factory.getPrivDER();
  std::cout << tancrypt::hexStr(priv_der) << std::endl;
  
  return 0;
}

int getPubDER(char* argv[], int argc)
{
  tancrypt::RSA::pkic key_factory;
  key_factory.generate_keypair(2048);
  std::vector<unsigned char> pub_der= key_factory.getPubDER();
  std::cout << tancrypt::hexStr(pub_der) << std::endl;
  
  return 0;
}


int loadPrivDER(char* argv[], int argc)
{
  tancrypt::RSA::pkic key_synth;
  tancrypt::RSA::pkic key_loaded;
  key_synth.generate_keypair(2048);
  std::vector<unsigned char> der_synth = key_synth.getPrivDER();
  key_loaded.loadPrivDER(der_synth);
  std::vector<unsigned char> der_loaded = key_loaded.getPrivDER();
  std::cout << "Generated priv hex:" << std::endl;
  std::cout << tancrypt::hexStr(der_synth) << std::endl;
  std::cout << "Loaded priv hex:" << std::endl;
  std::cout << tancrypt::hexStr(der_loaded) << std::endl;
  
  if(tancrypt::hexStr(der_synth)!=tancrypt::hexStr(der_loaded)) return 1;
  return 0;
}

int loadPubDER(char* argv[], int argc)
{
  tancrypt::RSA::pkic key_synth;
  tancrypt::RSA::pkic key_loaded;
  key_synth.generate_keypair(2048);
  std::vector<unsigned char> der_synth = key_synth.getPubDER();
  key_loaded.loadPubDER(der_synth);
  std::vector<unsigned char> der_loaded = key_loaded.getPubDER();
  std::cout << "Generated pub hex:" << std::endl;
  std::cout << tancrypt::hexStr(der_synth) << std::endl;
  std::cout << "Loaded pub hex:" << std::endl;
  std::cout << tancrypt::hexStr(der_loaded) << std::endl;
  
  if(tancrypt::hexStr(der_synth)!=tancrypt::hexStr(der_loaded)) return 1;
  return 0;
}

int importPrivPEM(char* argv[], int argc)
{
  tancrypt::RSA::pkic keyc;
  std::cout << "Priv pem: " << argv[2] << std::endl;
  keyc.importPEM(argv[2]);
  std::string content = tancrypt::hexStr(keyc.getPrivDER());
  std::cout << "Priv hex:" << std::endl;
  std::cout << content << std::endl;
  if(content=="") return 1;

  return 0;
}

int importPubPEM(char* argv[], int argc)
{
  tancrypt::RSA::pkic keyc;
  keyc.importPEM(argv[2]);
  std::string content = tancrypt::hexStr(keyc.getPubDER());
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
  tancrypt::RSA::pkic key_synth;
  key_synth.generate_keypair(2048);
  std::string synth_pem = key_synth.getPrivPEM();
  std::cout << "Synthesized Priv PEM:" << std::endl;
  std::cout << synth_pem << std::endl;

  tancrypt::RSA::pkic key_imported;
  key_imported.importPEM(argv[2]);
  std::string imported_pem = key_imported.getPrivPEM();
  std::cout << "Synthesized Priv PEM:" << std::endl;
  std::cout << imported_pem << std::endl;

  return 0;
}

int getPubPEM(char* argv[], int argc)
{
  tancrypt::RSA::pkic key_synth;
  key_synth.generate_keypair(2048);
  std::string synth_pem = key_synth.getPubPEM();
  std::cout << "Synthesized Pub PEM:" << std::endl;
  std::cout << synth_pem << std::endl;

  tancrypt::RSA::pkic key_imported;
  key_imported.importPEM(argv[2]);
  std::string imported_pem = key_imported.getPubPEM();
  std::cout << "Synthesized Pub PEM:" << std::endl;
  std::cout << imported_pem << std::endl;

  return 0;
}

int getBundlePEM(char* argv[], int argc)
{
  tancrypt::RSA::pkic key;
  key.generate_keypair(2048);
  std::string bundle_pem = key.getBundlePEM();
  std::cout << "Bundle PEM:" << std::endl;
  std::cout << bundle_pem << std::endl;

  return 0;
}

int loadPrivPEM(char* argv[], int argc)
{
  tancrypt::RSA::pkic keyc_synth;
  tancrypt::RSA::pkic keyc_loaded;
  
  keyc_synth.generate_keypair(2048);
  keyc_loaded.loadPEMStr(keyc_synth.getPrivPEM().c_str());
  std::cout << "Priv synth: " << std::endl;
  std::cout << tancrypt::hexStr(keyc_synth.getPrivDER()) << std::endl;
  std::cout << "Priv loaded: " << std::endl;
  std::cout << tancrypt::hexStr(keyc_loaded.getPrivDER()) << std::endl;
  if(tancrypt::hexStr(keyc_synth.getPrivDER()) != tancrypt::hexStr(keyc_loaded.getPrivDER())) return 1;
  return 0; 
}

int loadPubPEM(char* argv[], int argc)
{
  tancrypt::RSA::pkic keyc_synth;
  tancrypt::RSA::pkic keyc_loaded;
  
  keyc_synth.generate_keypair(2048);
  keyc_loaded.loadPEMStr(keyc_synth.getPubPEM().c_str());
  std::cout << "Pub synth: " << std::endl;
  std::cout << tancrypt::hexStr(keyc_synth.getPubDER()) << std::endl;
  std::cout << "Pub loaded: " << std::endl;
  std::cout << tancrypt::hexStr(keyc_loaded.getPubDER()) << std::endl;

  if(tancrypt::hexStr(keyc_synth.getPubDER()) != tancrypt::hexStr(keyc_loaded.getPubDER())) return 1;

  return 0; 
}

int loadBundlePEM(char* argv[], int argc)
{
  tancrypt::RSA::pkic keyc_synth;
  tancrypt::RSA::pkic keyc_loaded;
  
  keyc_synth.generate_keypair(2048);
  keyc_loaded.loadPEMStr(keyc_synth.getBundlePEM().c_str());
  std::cout << "Pub loaded: " << std::endl;
  std::cout << tancrypt::hexStr(keyc_loaded.getPubDER()) << std::endl;

  if(tancrypt::hexStr(keyc_synth.getPrivDER()) != tancrypt::hexStr(keyc_loaded.getPrivDER())) return 1;
  if(tancrypt::hexStr(keyc_synth.getPubDER()) != tancrypt::hexStr(keyc_loaded.getPubDER())) return 1;

  return 0; 
}
int exportPrivPEM(char* argv[], int argc)
{
  tancrypt::RSA::pkic keyc;
  keyc.generate_keypair(2048);
  keyc.exportPrivPEM("priv_out.pem");
  
  return 0;
}

int exportPubPEM(char* argv[], int argc)
{
  tancrypt::RSA::pkic keyc;
  keyc.generate_keypair(2048);
  keyc.exportPubPEM("pub_out.pem");
  
  return 0;
}

int exportBundlePEM(char* argv[], int argc)
{
  tancrypt::RSA::pkic keyc;
  keyc.generate_keypair(2048);
  keyc.exportBundlePEM("bundle_out.pem");
  
  return 0;
}

int Encrypt_test(char* argv[], int argc)
{
  tancrypt::RSA::pkic key_factory;
  key_factory.generate_keypair(2048);
  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data());
  std::vector<unsigned char> res = tancrypt::RSA::encrypt(key_factory,payload);
  std::cout << "Original:" << std::endl;
  std::cout << my_message << std::endl;
  std::cout << "Hex::" << std::endl;
  std::cout << tancrypt::hexStr(payload) << std::endl;
  std::cout << "Encrypted:" << std::endl;
  std::cout << tancrypt::hexStr(res) << std::endl;
  if (tancrypt::hexStr(payload)==tancrypt::hexStr(res)||res.size()==0) return 1;
  
  return 0;
}

int Decrypt_test(char* argv[], int argc)
{
  tancrypt::RSA::pkic key;
  key.generate_keypair(2048);
  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data()); 
  std::vector<unsigned char> res = tancrypt::RSA::encrypt(key,payload);
  std::cout << "Original:" << std::endl;
  std::cout << my_message << std::endl;
  std::cout << "Hex:" << std::endl;
  std::cout << tancrypt::hexStr(payload) << std::endl;
  std::cout << "Encrypted:" << std::endl;
  std::cout << tancrypt::hexStr(res) << std::endl;
  std::vector<unsigned char> res_decrypted = tancrypt::RSA::decrypt(key,res);
  std::cout << "Res decrypted hex:"<< std::endl;
  std::cout << tancrypt::hexStr(res_decrypted) << std::endl;
  std::cout << "Res decrypted:" << std::endl;
  std::cout << res_decrypted.data() << std::endl;
  if(tancrypt::hexStr(payload)==tancrypt::hexStr(res_decrypted)) return 0;
  
  return 1;
}

int hashTest(char* argv[], int argc)
{

  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data()); 
  std::vector<unsigned char> hashed_payload = tancrypt::hash(payload,tancrypt::hashAlg::SHA256);
  std::cout<<tancrypt::hexStr(hashed_payload)<<std::endl;
  return 0;
}


int signTest(char* argv[], int argc)
{
  tancrypt::RSA::pkic key;
  key.generate_keypair(2048);
  std::string my_message = "Hewwo I am signed ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data()); 
  std::vector<unsigned char> signature = tancrypt::RSA::sign(key,payload,tancrypt::hashAlg::SHA256);
  std::cout << "Signature hex:" << std::endl;
  std::cout<<tancrypt::hexStr(signature)<<std::endl;
  return 0;
}

int verifyTest(char* argv[], int argc)
{
  tancrypt::RSA::pkic key;
  key.generate_keypair(2048);
  std::string my_message = "Hewwo I am signed ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data());
  std::vector<unsigned char> signature = tancrypt::RSA::sign(key,payload,tancrypt::hashAlg::SHA256);
  std::cout << "Signature hex:" << std::endl;
  std::cout<<tancrypt::hexStr(signature)<<std::endl;
  bool res = tancrypt::RSA::verify(key, signature, payload,tancrypt::hashAlg::SHA256);

  return res;
}

int AESKEY_init1Test(char* argv[], int argc)
{
  using namespace tancrypt;  
  std::string my_key = "Hewwo I am key ^.^";
  std::vector<unsigned char> my_keydata(my_key.size());
  std::copy(my_key.data(),my_key.data()+my_key.size(),my_keydata.data());
  tancrypt::AES::keyc key_variant1(my_keydata,AES::Type::CBC256);

  return 0;
}

int AESKEY_init2Test(char* argv[], int argc)
{
  using namespace tancrypt;  
  std::string my_key = "Hewwo I am key ^.^";
  std::vector<unsigned char> my_keydata(my_key.size());
  std::copy(my_key.data(),my_key.data()+my_key.size(),my_keydata.data());
  tancrypt::AES::keyc key_variant2(my_keydata,AES::Type::CBC256,hashAlg::SHA256);
  
  return 0;
}

int AesEncryptV1(char* argv[], int argc)
{

  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data()); 
  
  using namespace tancrypt;  
  std::string my_key = "Hewwo I am key ^.^";
  std::vector<unsigned char> my_keydata(my_key.size());
  std::copy(my_key.data(),my_key.data()+my_key.size(),my_keydata.data());
  std::vector<unsigned char> hashed_key = tancrypt::hash(my_keydata , hashAlg::SHA256);
  tancrypt::AES::keyc key_variant1(hashed_key,AES::Type::CBC256);
  std::vector<unsigned char>enc_buffer = AES::encrypt(key_variant1, payload);

  std::cout << "Original: " << my_message << std::endl; 
  std::cout << "Original(hex): " << tancrypt::hexStr(payload) << std::endl; 
  std::cout << "Encrypted(hex): " << tancrypt::hexStr(enc_buffer) << std::endl;
  
  return 0;
}


int AesEncryptV2(char* argv[], int argc)
{
  using namespace tancrypt;

  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data()); 
  
  std::string my_key = "Hewwo I am key ^.^";
  std::vector<unsigned char> my_keydata(my_key.size());
  std::copy(my_key.data(),my_key.data()+my_key.size(),my_keydata.data());
  tancrypt::AES::keyc key_variant2(my_keydata,AES::Type::CBC256,hashAlg::SHA256);
  std::vector<unsigned char>enc_buffer = AES::encrypt(key_variant2, payload);

  std::cout << "Original: " << my_message << std::endl; 
  std::cout << "Original(hex): " << tancrypt::hexStr(payload) << std::endl; 
  std::cout << "Encrypted(hex): " << tancrypt::hexStr(enc_buffer) << std::endl;
  
  return 0;
}

int AesDecryptV1(char* argv[], int argc)
{

  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data()); 
  
  using namespace tancrypt;  
  std::string my_key = "Hewwo I am key ^.^";
  std::vector<unsigned char> my_keydata(my_key.size());
  std::copy(my_key.data(),my_key.data()+my_key.size(),my_keydata.data());
  std::vector<unsigned char> hashed_key = tancrypt::hash(my_keydata , hashAlg::SHA256);
  tancrypt::AES::keyc key_variant1(hashed_key,AES::Type::CBC256);
  std::vector<unsigned char>enc_buffer = AES::encrypt(key_variant1, payload);

  std::cout << "Original: " << my_message << std::endl; 
  std::cout << "Original(hex): " << tancrypt::hexStr(payload) << std::endl; 
  std::cout << "Encrypted(hex): " << tancrypt::hexStr(enc_buffer) << std::endl;

  std::vector<unsigned char>dec_buffer = AES::decrypt(key_variant1, enc_buffer);

  std::cout << "Decrypted(hex): " << tancrypt::hexStr(dec_buffer) << std::endl;
  std::cout << "Decrypted: " << dec_buffer.data() << std::endl;

  
  return 0;
}


int AesDecryptV2(char* argv[], int argc)
{

  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data()); 
  
  using namespace tancrypt;  
  std::string my_key = "Hewwo I am key ^.^";
  std::vector<unsigned char> my_keydata(my_key.size());
  std::copy(my_key.data(),my_key.data()+my_key.size(),my_keydata.data());
  std::vector<unsigned char> hashed_key = tancrypt::hash(my_keydata , hashAlg::SHA256);
  tancrypt::AES::keyc key_variant1(hashed_key,AES::Type::CBC256);
  std::vector<unsigned char>enc_buffer = AES::encrypt(key_variant1, payload);

  std::cout << "Original: " << my_message << std::endl; 
  std::cout << "Original(hex): " << tancrypt::hexStr(payload) << std::endl; 
  std::cout << "Encrypted(hex): " << tancrypt::hexStr(enc_buffer) << std::endl;

  std::vector<unsigned char>dec_buffer = AES::decrypt(key_variant1, enc_buffer);

  std::cout << "Decrypted(hex): " << tancrypt::hexStr(dec_buffer) << std::endl;
  std::cout << "Decrypted: " << dec_buffer.data() << std::endl;
  if(tancrypt::hexStr(dec_buffer)!=tancrypt::hexStr(payload)) return 1;
  
  return 0;
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
  {"--hash", &hashTest},
  {"--sign", &signTest},
  {"--verify", &verifyTest},
  {"--aesKeyInit1", &AESKEY_init1Test},
  {"--aesKeyInit2", &AESKEY_init2Test},
  {"--aesEncryptV1", &AesEncryptV1},
  {"--aesEncryptV2", &AesEncryptV2},
  {"--aesDecryptV1", &AesDecryptV1},
  {"--aesDecryptV2", &AesDecryptV2},
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
    printUsage("tancrypt-test");
    return 1;
  }
  
  if(handler.count(argv[1])!=1)
  {
    std::cout << "Invalid option: " << argv[1] << std::endl;
    printUsage("tancrypt-test");
    return 1;
  }
  
  return handler[argv[1]](argv,argc);
}

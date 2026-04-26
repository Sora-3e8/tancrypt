# Tancrypt

## Introduction

This C++ library provides simple cryptographic API with focus on RSA and AES.</br>
Built on OpenSSL, but isn't a direct wrapper to make the usage as simple as possible.

This library is MIT licensed, so you can use it however you want in your projects!

## Requirements
- C++ Standard : C++11 or later
- Dependencies : OpenSSL3.0+

## Example usage
Example encryption:
```cpp {.no-copy linenums="1"}
#include "tancrypt.hpp"

int main()
{
  // Databuffer from string
  dutils::dbuffer payload("Hewwo, I am secret ^.^");

  // Keypair with key size of 2048 gets generated and our buffer gets encrypted
  tancrypt::RSA::pkic key;
  key_factory.generate_keypair(2048);
  dutils::dbuffer res = tancrypt::RSA::encrypt(key,payload);

  // Check results compared original, hex x  encrypted
  std::cout << "Original:" << std::endl;
  std::cout << my_message.toStr() << std::endl;
  std::cout << "Hex:" << std::endl;
  std::cout << dutils::hexStr(payload) << std::endl;
  std::cout << "Encrypted:" << std::endl;
  std::cout << dutils::hexStr(res) << std::endl;

  return 0;
}
```

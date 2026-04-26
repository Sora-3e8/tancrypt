# Tancrypt
- Simple cryptographic C++ library based on OpenSSL for C++11
- Wraps around the EVP C api to allow easy keypair generation with simplfied API


Features
--------------------------------------------------------------------------
- RSA keyc container and management
- RSA encrypt, decrypt, sign and verify
- AES key container
- AES encrypt, decrypt
- Custom data buffer


Documentation
--------------------------------------------------------------------------
https://sora-3e8.github.io/tancrypt

Dependencies
--------------------------------------------------------------------------
- OpenSSL3.0+

# Build
```bash
git clone https://github.com/Sora-3e8/tancrypt && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build .
```

Example usage
--------------------------------------------------------------------------
```cpp
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

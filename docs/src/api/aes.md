# AES

## Overview
This namespace provides basic AES cryptographic operations, depends AES::keyc.
For proper use, also check documentation of AES::keyc.

Example usage:
```cpp

int main()
{
  dutils::dbuffer payload("Hewwo, I am secret >.<");

  // Makes life easier as it shortens tancrypt::AES --> AES:: 
  using namespace tancrypt;

  // Setting up symmetric key - key is not padded/prehashed/derived, so keyc's hashing will need to be used
  dutils::dbuffer my_keydata("Hewwo, I am key ^.^");

  // We enabled hashing here by adding hashAlg::SHA256
  tancrypt::AES::keyc key_variant2(my_keydata,AES::Type::CBC256,hashAlg::SHA256);
  dutils::dbuffer enc_buffer = AES::encrypt(key_variant2, payload);

  std::cout << "Original: " << payload.toStr() << std::endl; 
  std::cout << "Original(hex): " << dutils::hexStr(payload) << std::endl; 
  std::cout << "Encrypted(hex): " << dutils::hexStr(enc_buffer) << std::endl;

  dutils::dbuffer dec_buffer = AES::decrypt(key_variant2, enc_buffer);

  std::cout << "Decrypted(hex): " << dutils::hexStr(dec_buffer) << std::endl;
  std::cout << "Decrypted: " << dec_buffer.data() << std::endl;

  return 0;  
}
```
</br>
</br>
</br>
</br>

## `#!cpp AES::encrypt`
### `#!cpp AES::encrypt(AES::keyc &key_container, dutils::dbuffer &buffer)`
* **Parameters:**
    * `#!cpp tancrypt::AES::keyc &key_container - AES key with preloaded credentials`
    * `#!cpp dutils::dbuffer &buffer - Data to encrypt`
* **Returns:**
    * `#!cpp dutils::dbuffer AES_DATA` - Encrypted buffer
</br>
</br>
</br>
</br>

## `#!cpp AES::decrypt`
### `#!cpp AES::decrypt(AES::keyc &key_container, dutils::dbuffer &buffer)`
* **Parameters:**
    * `#!cpp tancrypt::AES::keyc &key_container - AES key with preloaded credentials`
    * `#!cpp dutils::dbuffer &buffer - Data to decrypt`
* **Returns:**
    * `#!cpp dutils::dbuffer AES_DATA` - Decrypted buffer
</br>
</br>
</br>
</br>

## `#!cpp AES::getNonce`
!!! Warning
    Please note that this should be only used for ciphers where it's applicable, otherwise logic error exception  
    "Not applicable" is thrown.
### `#!cpp AES::getNonce(dutils::dbuffer buffer,AES::Type type)`
* **Parameters:**
  * `#!cpp tancrypt::AES::keyc &key_container` - AES key with preloaded credentials
  * `#!cpp AES::Type type` - Type of the AES cipher, needed to determine nonce/IV length
* **Returns:**
    * `#!cpp dutils::dbuffer nonce_buffer` - Nonce/IV buffer

</br>
</br>
</br>
</br>

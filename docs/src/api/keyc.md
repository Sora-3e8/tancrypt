# KEYC

## Overview

!!! Warning
    Please note that when constructing without a Hashing enabled on the keyc,
    you're expected to provide a properly padded key of correct length.
    If you do not want to handle your key enable hashing by constructing with `hashAlg`.

AES::keyc fulfills function of key container, similar to how `RSA::pkic` does, the `AES::keyc` stores a key and AES type.

## Constructors


## `#!cpp AES::keyc()`
* **Parameters:**

Constructs blank keyc, you then need to manually setup the key container.  
When using hashing via the keyc, you also need to enable the hashing not just set the hashAlg.

Example of blank construction:
```cpp
// Blank key created
tancrypt::AES::keyc key;

// Setting AES type 
key.setType(tancrypt::AES::CBC256);

// Setting key assuming buffer is a key of proper size
// Proper size can be acquired after setting the AES type via getCiphKLen().
int key_len = key.getCiphKLen();
key.setKey(buffer);

// In case we do not have proper key in advance we can use built in hashing

// Blank key created
tancrypt::AES::keyc key;

// Setting AES type 
key.setType(type);

// Setting the key assuming arbitrary key data
key.setKey(buffer);

// Setting hashing algorithm, though hashAlg::SHA256 is default
key.setHashAlg(hashAlg::SHA256);

// We must also enable hashing, otherwise it won't be used
key.setHashEnabled(true);
```

### `#!cpp AES::keyc(const dutils::dbuffer& key,AES::Type type)`
When constructing without hashAlg, you must ensure your key data are prepadded


* **Parameters:**
    * `#!cpp const dutils::dbuffer& key` - Prepadded key data
    * `#!cpp tancrypt::AES::Type type` - Type of AES algorithm to use
* **Returns:**
    * `#!cpp tancrypt::AES::keyc key`

### `#!cpp AES::keyc(const dutils::dbuffer& key,AES::Type type,hashAlg alg)`
!!! Note
    Bear in mind that to avoid possible race conditions and unnecessary state holding,
    the hashing occurs on encryption runtime this may cause this key variant to be less efficient.

* **Parameters:**
    * `#!cpp dutils::dbuffer key` - Key data
    * `#!cpp tancrypt::AES::Type type` - AES algorithm type
    * `#!cpp hashAlg alg` - Hashing algorithm to use on key during encryption
* **Returns:**
    * `#!cpp tancrypt::AES::keyc key`

## AES supported types
* `#!cpp AES::Type::CBC128` - AES-128-CBC
* `#!cpp AES::Type::CBC192` - AES-192-CBC
* `#!cpp AES::Type::CBC256` - AES-256-CBC
* `#!cpp AES::Type::GCM128` - AES-128-GCM
* `#!cpp AES::Type::GCM192` - AES-192-GCM
* `#!cpp AES::Type::GCM256` - AES-256-GCM
</br>
</br>

## Setter methods

### `#!cpp AES::key::setType(AES::Type type)`
Sets type of AES algorithm, does not corrupt key and can be used even past first initialization


* **Parameters:**
    * `#!cpp tancrypt::AES::Type type` - AES algorithm type
* **Returns:**

### `#!cpp AES::keyc::setHashAlg(hashAlg alg)`
Sets hashing algorithm to be used for key, does not corrupt key and can be used even past first initialization


* **Parameters:**
    * `#!cpp tancrypt::hashAlg alg` - Hashing algorithm of your choice
* **Returns:**

### `#!cpp AES::keyc::setKey(dutils::dbuffer key)`
Sets the key data


* **Parameters:**
    * `#!cpp dutils::dbuffer key` - Key data buffer
* **Returns:**

## Getter methods

### `#!cpp AES::keyc::getCiphKLen()`
Retrieves required key size for given AES::Type, the key is required to have set type before using


* **Parameters:**
* **Returns:**
    * `int key_len` - Key size

### `#!cpp AES::keyc::getHashAlg()`
Retrieves currently set hasing algorithm


* **Parameters:**
* **Returns:**
    * `hashAlg alg` - Current hashing algorithm

### `#!cpp AES::keyc::getHashEnabled()`
Retrieves current bool state - is hasing enabled ? true/false


* **Parameters:**
* **Returns:**
    * `bool hashingEnabled`

### `#!cpp AES::keyc::getKey()`
Retrieves current key data buffer [readonly!]


* **Parameters:**
* **Returns:**
    * `dutils::dbuffer key`







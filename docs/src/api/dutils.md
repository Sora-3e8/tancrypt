# Dutils

Helpful utilities, provides custom data buffer and data utility functions.  

## `dutils::dbuffer`
Useful class for storing data it's based on `#!cpp std::vector<unsigned char>`, main advantage is that dutils::dbuffer provides easy conversion from string and back.


## `dutils::dbuffer constructors`
Dbuffer supports various construction methods.

### `#!cpp dutils::dbuffer(std::initializer_list<unsinged int> list)`
Equivalent to `#!cpp std::vector<unsigned char> buffer = {1,2,3...};`

* **Parameters:**
    * `#!cpp std::initializer_list<unsigned int> list` - Input data
* **Returns:**
    * `#!cpp dutils::dbuffer buffer`

### `#!cpp dutils::dbuffer(std::vector<unsigned char> dbuffer)`
Copies data from `#!cpp std::vector<unsigned char>` to newly created blank dbuffer,
this is primarily for compatibility purposes, but direct construction of `#!cpp dutils::dbuffer` is more efficient.

* **Parameters:**
    * `#!cpp std::vector<unsinged char> buffer` - Buffer to copy
* **Returns:**
    * `#!cpp dutils::dbuffer buffer`
    
## `#!cpp dutils::dbuffer` Member methods

### `#!cpp dutils::dbuffer::toStr()`
!!! Warning
    Please note that the dbuffer contents are not checked for string safety,
    thus when converting you must handle possible nullterminators yourself.
Converts dbuffer contents to string

* **Parametrs:**
* **Returns:**
    * `#!cpp std::string buffer_stringified`

## `#!cpp dutils::hexStr`
This function provides an easy way to convert data into string interpretation of hex values.  
Useful when you want to print out or compare buffers with non-string data.  

### `#!cpp dutils::hexStr(const dutils::dbuffer &data)`

* **Parameters:**
    * `#!cpp const dutils::dbuffer &data` - The input data buffer.
* **Returns:**
    * `#!cpp std::string` - A formatted hex string (16 blocks per row).


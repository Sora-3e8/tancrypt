#ifndef TANCRYPT_HASH_HPP
#define TANCRYPT_HASH_HPP

#include "tancrypt-hashtypes.hpp"
#include <vector>

namespace tancrypt
{
  std::vector<unsigned char> hash(const std::vector<unsigned char> &buffer, hashAlg alg);
}

#endif

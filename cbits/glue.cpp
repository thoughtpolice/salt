#include <string>
#include <cassert>

// NaCl headers
#include "crypto_hash_sha256.h"
#include "crypto_hash_sha512.h"

// Glue definitions exposed via FFI
#include "glue.h"


/*
 * Hashing
 */

// Returns the amount of bytes in the resulting hash
int glue_crypto_hash(const unsigned char* m, unsigned long long mlen, unsigned char* out) {
  int r = crypto_hash_sha512(out,m,mlen);
  assert(r == 0);
  return crypto_hash_sha512_BYTES;
}

// Returns the amount of bytes in the resulting hash
int glue_crypto_hash_sha256(const unsigned char* m, unsigned long long mlen, unsigned char* out) {
  int r = crypto_hash_sha256(out,m,mlen);
  assert(r == 0);
  return crypto_hash_sha256_BYTES;
}

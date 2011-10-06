/* Haskell <-> NaCl FFI glue

   Copyright (C) 2011 Austin Seipp. See LICENSE for details.

   These bindings are currently written in C++ and exposed with a C
   interface for simplicity when dealing with NaCl. In the future,
   this may need to be rewritten in C for efficiency (i.e. to not
   construct/deconstruct std::strings) if it's deemed necessary.
 */
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

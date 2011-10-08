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

#include "crypto_box.h"

/*
 * Hashing
 */

extern "C" int 
glue_crypto_hash_sha512(unsigned char *out, const unsigned char* m, unsigned long long mlen)
{
  int r = crypto_hash_sha512(out,m,mlen);
  assert(r == 0);
  return 0;
}

extern "C" int
glue_crypto_hash_sha256(unsigned char *out, const unsigned char* m, unsigned long long mlen)
{
  int r = crypto_hash_sha256(out,m,mlen);
  assert(r == 0);
  return 0;
}

extern "C" int
glue_crypto_box_keypair(unsigned char *pk, unsigned char *sk)
{
  int r = crypto_box_keypair(pk,sk);
  assert(r == 0);
  return 0;
}

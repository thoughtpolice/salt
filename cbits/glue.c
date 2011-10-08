/* Haskell <-> NaCl FFI glue.

   Copyright (C) 2011 Austin Seipp. See LICENSE for details.
 */
#include <string.h>
#include <assert.h>

// NaCl headers
#include "crypto_hash_sha256.h"
#include "crypto_hash_sha512.h"
#include "crypto_box.h"
#include "crypto_sign.h"


/*
 * Hashing
 */

int 
glue_crypto_hash_sha512(unsigned char *out, const unsigned char* m, unsigned long long mlen)
{
  int r = crypto_hash_sha512(out, m, mlen);
  assert(r == 0);
  return 0;
}

int
glue_crypto_hash_sha256(unsigned char *out, const unsigned char* m, unsigned long long mlen)
{
  int r = crypto_hash_sha256(out, m, mlen);
  assert(r == 0);
  return 0;
}

/*
 * Public-key cryptography
 */

int
glue_crypto_box_keypair(unsigned char *pk, unsigned char *sk)
{
  int r = crypto_box_keypair(pk, sk);
  assert(r == 0);
  return 0;
}

int
glue_crypto_box(unsigned char *c, const unsigned char *m,
		unsigned long long mlen, const unsigned char *n,
		const unsigned char *pk, const unsigned char *sk)
{
  int r = crypto_box(c, m, mlen, n, pk, sk);
  assert(r == 0);
  return 0;
}

// NOTE: return value must be checked for ciphertext verification!
int
glue_crypto_box_open(unsigned char *m, const unsigned char *c,
		     unsigned long long clen, const unsigned char *n,
		     const unsigned char *pk, const unsigned char *sk)
{
  return crypto_box_open(m, c, clen, n, pk, sk);
}


/*
 * Public key signatures
 */

int
glue_crypto_sign_keypair(unsigned char* pk, unsigned char* sk)
{
  int r = crypto_sign_keypair(pk, sk);
  assert(r == 0);
  return 0;
}

int
glue_crypto_sign(unsigned char* sm, const unsigned char* m, 
		 unsigned long long mlen, const unsigned char* sk)
{
  unsigned long long smlen;
  int r = crypto_sign(sm, &smlen, m, mlen, sk);
  assert(r == 0);
  return smlen;
}

// NOTE: must check return value to verify signature!
int glue_crypto_sign_open(unsigned char *m, unsigned long long* mlen,
			  const unsigned char* sm, unsigned long long smlen,
			  const unsigned char* pk)
{
  return crypto_sign_open(m, mlen, sm, smlen, pk);
}

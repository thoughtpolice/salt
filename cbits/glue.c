/* Haskell <-> NaCl FFI glue.

   Copyright (C) 2011 Austin Seipp. See LICENSE for details.
 */
#include <string.h>
#include <assert.h>

// NaCl headers
#include "crypto_hash_sha256.h"
#include "crypto_hash_sha512.h"
#include "crypto_box.h"
#include "crypto_secretbox.h"
#include "crypto_sign.h"
#include "crypto_auth.h"
#include "crypto_onetimeauth.h"
#include "crypto_stream.h"

/*
 * Hashing
 */

int 
glue_crypto_hash_sha512(unsigned char *out, const unsigned char* m, unsigned long long mlen)
{
  int r = crypto_hash_sha512(out, m, mlen);
  assert(r == 0);
  return r;
}

int
glue_crypto_hash_sha256(unsigned char *out, const unsigned char* m, unsigned long long mlen)
{
  int r = crypto_hash_sha256(out, m, mlen);
  assert(r == 0);
  return r;
}

/*
 * Public-key cryptography
 */

int
glue_crypto_box_keypair(unsigned char *pk, unsigned char *sk)
{
  int r = crypto_box_keypair(pk, sk);
  assert(r == 0);
  return r;
}

int
glue_crypto_box(unsigned char *c, const unsigned char *m,
		unsigned long long mlen, const unsigned char *n,
		const unsigned char *pk, const unsigned char *sk)
{
  int r = crypto_box(c, m, mlen, n, pk, sk);
  assert(r == 0);
  return r;
}

// NOTE: return value must be checked for ciphertext verification!
int
glue_crypto_box_open(unsigned char *m, const unsigned char *c,
		     unsigned long long clen, const unsigned char *n,
		     const unsigned char *pk, const unsigned char *sk)
{
  return crypto_box_open(m, c, clen, n, pk, sk);
}

int
glue_crypto_box_beforenm(unsigned char *k,
			 const unsigned char *pk,
			 const unsigned char *sk)
{
  int r = crypto_box_beforenm(k, pk, sk);
  assert(r == 0);
  return r;
}

int
glue_crypto_box_afternm(unsigned char *c,
			const unsigned char *m, unsigned long long mlen,
			const unsigned char *n,
			const unsigned char *k)
{
  int r = crypto_box_afternm(c, m, mlen, n, k);
  assert(r == 0);
  return r;
}

// NOTE: return value must be checked for ciphertext verification!
int
glue_crypto_box_open_afternm(unsigned char *m,
			     const unsigned char *c, unsigned long long clen,
			     const unsigned char *n,
			     const unsigned char *k)
{
  return crypto_box_open_afternm(m, c, clen, n, k);
}

/*
 * Public key signatures
 */

int
glue_crypto_sign_keypair(unsigned char* pk, unsigned char* sk)
{
  int r = crypto_sign_keypair(pk, sk);
  assert(r == 0);
  return r;
}

// NOTE: this returns smlen!
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

/*
 * Authenticated, secret-key cryptography
 */

int glue_crypto_secretbox(unsigned char* c, const unsigned char* m,
			  unsigned long long mlen, const unsigned char* n,
			  const unsigned char* k)
{
  int r = crypto_secretbox(c, m, mlen, n, k);
  assert(r == 0);
  return r;
}

// Note: must check return value!
int glue_crypto_secretbox_open(unsigned char* m, const unsigned char* c,
			       unsigned long long clen, const unsigned char* n,
			       const unsigned char* k)
{
  return crypto_secretbox_open(m, c, clen, n, k);
}

/*
 * Authentication
 */
int glue_crypto_auth(unsigned char* a, const unsigned char* m,
		     unsigned long long mlen, const unsigned char* k)
{
  int r = crypto_auth(a, m, mlen, k);
  assert(r == 0);
  return r;
}

// Note: must check return value!
int glue_crypto_auth_verify(const unsigned char* a, const unsigned char* m,
			    unsigned long long mlen, const unsigned char* k)
{
  return crypto_auth_verify(a, m, mlen, k);
}


int glue_crypto_onetimeauth(unsigned char* a, const unsigned char* m,
			    unsigned long long mlen, const unsigned char* k)
{
  int r = crypto_onetimeauth(a, m, mlen, k);
  assert(r == 0);
  return r;
}

// Note: must check return value!
int glue_crypto_onetimeauth_verify(const unsigned char* a, const unsigned char* m,
				   unsigned long long mlen, const unsigned char* k)
{
  return crypto_onetimeauth_verify(a, m, mlen, k);
}

/*
 * Nonces
 */

void
glue_incnonce(unsigned char* p, size_t len)
{
  int i=len;
  for(; --i >= 0;) {
    if(++p[i] != 0) break;
  }
}

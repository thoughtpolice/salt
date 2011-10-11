/* Haskell <-> NaCl FFI glue.

   Copyright (C) 2011 Austin Seipp. See LICENSE for details.
 */
#include <string.h>
#include <assert.h>

// NaCl headers
#include "crypto_stream_xsalsa20.h"
#include "crypto_stream_salsa20.h"
#include "crypto_stream_salsa2012.h"
#include "crypto_stream_salsa208.h"
#include "crypto_stream_aes128ctr.h"

/*
 * Secret-key encryption
 */

/*
 * XSalsa20/20
 */

int
glue_crypto_stream_xsalsa20(unsigned char* c, unsigned long long clen,
			    const unsigned char* n, const unsigned char *k)
{
  int r = crypto_stream_xsalsa20(c, clen, n, k);
  assert(r == 0);
  return r;
}

int
glue_crypto_stream_xsalsa20_xor(unsigned char* c, unsigned char* m, 
				unsigned long long mlen,
				const unsigned char* n, const unsigned char* k)
{
  int r = crypto_stream_xsalsa20_xor(c, m, mlen, n, k);
  assert(r == 0);
  return r;
}

/*
 * Salsa20/20
 */

int
glue_crypto_stream_salsa20(unsigned char* c, unsigned long long clen,
			   const unsigned char* n, const unsigned char *k)
{
  int r = crypto_stream_salsa20(c, clen, n, k);
  assert(r == 0);
  return r;
}

int
glue_crypto_stream_salsa20_xor(unsigned char* c, unsigned char* m, 
			       unsigned long long mlen,
			       const unsigned char* n, const unsigned char* k)
{
  int r = crypto_stream_salsa20_xor(c, m, mlen, n, k);
  assert(r == 0);
  return r;
}

/*
 * Salsa20/12
 */


int
glue_crypto_stream_salsa2012(unsigned char* c, unsigned long long clen,
			     const unsigned char* n, const unsigned char *k)
{
  int r = crypto_stream_salsa2012(c, clen, n, k);
  assert(r == 0);
  return r;
}

int
glue_crypto_stream_salsa2012_xor(unsigned char* c, unsigned char* m, 
				 unsigned long long mlen,
				 const unsigned char* n, const unsigned char* k)
{
  int r = crypto_stream_salsa2012_xor(c, m, mlen, n, k);
  assert(r == 0);
  return r;
}

/*
 * Salsa20/8
 */

int
glue_crypto_stream_salsa208(unsigned char* c, unsigned long long clen,
			    const unsigned char* n, const unsigned char *k)
{
  int r = crypto_stream_salsa208(c, clen, n, k);
  assert(r == 0);
  return r;
}

int
glue_crypto_stream_salsa208_xor(unsigned char* c, unsigned char* m, 
				unsigned long long mlen,
				const unsigned char* n, const unsigned char* k)
{
  int r = crypto_stream_salsa208_xor(c, m, mlen, n, k);
  assert(r == 0);
  return r;
}

/*
 * AES-128-CTR
 */

int
glue_crypto_stream_aes128ctr(unsigned char* c, unsigned long long clen,
			     const unsigned char* n, const unsigned char *k)
{
  int r = crypto_stream_aes128ctr(c, clen, n, k);
  assert(r == 0);
  return r;
}

int
glue_crypto_stream_aes128ctr_xor(unsigned char* c, unsigned char* m, 
				 unsigned long long mlen,
				 const unsigned char* n, const unsigned char* k)
{
  int r = crypto_stream_aes128ctr_xor(c, m, mlen, n, k);
  assert(r == 0);
  return r;
}

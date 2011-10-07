#ifndef __HS_NACL_GLUE_H__
#define __HS_NACL_GLUE_H__

extern "C" {

  // Hashing functions
  int glue_crypto_hash(const unsigned char*, unsigned long long, unsigned char*);
  int glue_crypto_hash_sha256(const unsigned char*, unsigned long long, unsigned char*);

  // Random byte generation
  int glue_randombytes(unsigned char*, unsigned long long);
}

#endif /* __HS_NACL_GLUE_H__ */

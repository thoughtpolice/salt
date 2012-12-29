{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.NaCl.FFI
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
--
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable (FFI)
--
-- This is a low-level module providing some internal
-- FFI bindings to various nacl functionality.
--
-- Do not use or import this directly. All relevant
-- functionality is re-exported elsewhere.
--
module Crypto.NaCl.FFI
       (
         -- NB: Don't bother providing signatures for
         -- this module.

         -- * Low-level C functions

         -- ** Randomness
         c_randombytes

         -- ** Hashing
       , c_crypto_hash_sha512
       , c_crypto_hash_sha256

         -- ** Public-key encryption
       , pkNonceLength
       , pkPublicKeyLength
       , pkSecretKeyLength
       , pkNmLength
       , pk_msg_ZEROBYTES, pk_msg_BOXZEROBYTES
       , c_crypto_box_keypair
       , c_crypto_box
       , c_crypto_box_open
       , c_crypto_box_beforenm
       , c_crypto_box_afternm
       , c_crypto_box_open_afternm

         -- ** Private-key encryption
       , skNonceLength
       , skKeyLength
       , sk_msg_ZEROBYTES, sk_msg_BOXZEROBYTES
       , c_crypto_secretbox
       , c_crypto_secretbox_open

         -- ** Streaming encryption
       , streamKeyLength
       , streamNonceLength
       , c_crypto_stream_xsalsa20
       , c_crypto_stream_xsalsa20_xor

         -- ** Authentication
       , authKeyLength
       , auth_BYTES
       , c_crypto_auth
       , c_crypto_auth_verify

         -- ** One-Time Authentication
       , oneTimeAuthKeyLength
       , onetimeauth_BYTES
       , c_crypto_onetimeauth
       , c_crypto_onetimeauth_verify

         -- ** Signatures
       , signPublicKeyLength
       , signSecretKeyLength
       , sign_BYTES
       , c_crypto_sign_keypair
       , c_crypto_sign
       , c_crypto_sign_open
       ) where
import Foreign.Ptr
import Foreign.C.Types
import Data.Word


#include <crypto_box.h>
#include <crypto_secretbox.h>
#include <crypto_stream_xsalsa20.h>

#include <crypto_auth.h>
#include <crypto_onetimeauth.h>
#include <crypto_sign.h>

--
-- Randomness from @/dev/urandom@
--

foreign import ccall unsafe "randombytes"
  c_randombytes :: Ptr Word8 -> CULLong -> IO Int

--
-- Hashing functions
--

type HashFunc = Ptr Word8 -> Ptr CChar -> CULLong -> IO CInt

foreign import ccall unsafe "glue_crypto_hash_sha512"
  c_crypto_hash_sha512 :: HashFunc

foreign import ccall unsafe "glue_crypto_hash_sha256"
  c_crypto_hash_sha256 :: HashFunc

--
-- Public-key encryption
--

-- | Length of a Nonce
pkNonceLength :: Int
pkNonceLength = #{const crypto_box_NONCEBYTES}

-- | Length of a 'Crypto.NaCl.Key.Public' signing 'Crypto.NaCl.Key.Key' in
-- bytes.
pkPublicKeyLength :: Int
pkPublicKeyLength  = #{const crypto_box_PUBLICKEYBYTES}

-- | Length of a 'Crypto.NaCl.Key.Secret' signing 'Crypto.NaCl.Key.Key' in
-- bytes.
pkSecretKeyLength :: Int
pkSecretKeyLength  = #{const crypto_box_SECRETKEYBYTES}

-- | Length of the intermediate 'NM' data used by the precomputation
-- interface.
pkNmLength :: Int
pkNmLength         = #{const crypto_box_BEFORENMBYTES}

pk_msg_ZEROBYTES,pk_msg_BOXZEROBYTES :: Int
pk_msg_ZEROBYTES    = #{const crypto_box_ZEROBYTES}
pk_msg_BOXZEROBYTES = #{const crypto_box_BOXZEROBYTES}

foreign import ccall unsafe "glue_crypto_box_keypair"
  c_crypto_box_keypair :: Ptr Word8 -> Ptr Word8 -> IO Int

foreign import ccall unsafe "glue_crypto_box"
  c_crypto_box :: Ptr Word8 -> Ptr CChar -> CULLong ->
                  Ptr CChar -> Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_box_open"
  c_crypto_box_open :: Ptr Word8 -> Ptr CChar -> CULLong ->
                       Ptr CChar -> Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_box_beforenm"
  c_crypto_box_beforenm :: Ptr Word8 -> Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_box_afternm"
  c_crypto_box_afternm :: Ptr Word8 -> Ptr CChar -> CULLong ->
                          Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_box_open_afternm"
  c_crypto_box_open_afternm :: Ptr Word8 -> Ptr CChar -> CULLong ->
                               Ptr CChar -> Ptr CChar -> IO Int


--
-- Private-key encryption
--

-- | Length of a 'Nonce' needed for encryption/decryption
skNonceLength :: Int
skNonceLength = #{const crypto_secretbox_NONCEBYTES}

-- | Length of a 'SecretKey' needed for encryption/decryption.
skKeyLength :: Int
skKeyLength        = #{const crypto_secretbox_KEYBYTES}

sk_msg_ZEROBYTES,sk_msg_BOXZEROBYTES :: Int
sk_msg_ZEROBYTES    = #{const crypto_secretbox_ZEROBYTES}
sk_msg_BOXZEROBYTES = #{const crypto_secretbox_BOXZEROBYTES}

foreign import ccall unsafe "glue_crypto_secretbox"
  c_crypto_secretbox :: Ptr Word8 -> Ptr CChar -> CULLong ->
                        Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_secretbox_open"
  c_crypto_secretbox_open :: Ptr Word8 -> Ptr CChar -> CULLong ->
                             Ptr CChar -> Ptr CChar -> IO Int

--
-- Streaming encryption
--

-- | Length of a 'SecretKey' needed for streaming encryption/decryption.
streamKeyLength :: Int
streamKeyLength = #{const crypto_stream_xsalsa20_KEYBYTES}

-- | Length of a 'Nonce' needed for streaming encryption/decryption.
streamNonceLength :: Int
streamNonceLength = #{const crypto_stream_xsalsa20_NONCEBYTES}

foreign import ccall unsafe "glue_crypto_stream_xsalsa20"
  c_crypto_stream_xsalsa20 :: Ptr Word8 -> CULLong -> Ptr CChar ->
                              Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_stream_xsalsa20_xor"
  c_crypto_stream_xsalsa20_xor :: Ptr Word8 -> Ptr CChar ->
                                  CULLong -> Ptr CChar -> Ptr CChar -> IO Int

--
-- Authentication
--

-- | @authKeyLength@ is the required key length for a key given
-- to 'authenticate' or 'verify'. Using any other key length will
-- result in error.
authKeyLength :: Int
authKeyLength = #{const crypto_auth_KEYBYTES}

auth_BYTES :: Int
auth_BYTES = #{const crypto_auth_BYTES}

foreign import ccall unsafe "glue_crypto_auth"
  c_crypto_auth :: Ptr Word8 -> Ptr CChar -> CULLong ->
                   Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_auth_verify"
  c_crypto_auth_verify :: Ptr CChar -> Ptr CChar -> CULLong ->
                          Ptr CChar -> IO Int

--
-- One-Time Authentication
--

-- | @oneTimeAuthKeyLength@ is the required key length for a key given
-- to 'authenticateOnce' or 'verifyOnce'. Using any other key length
-- will result in error.
oneTimeAuthKeyLength :: Int
oneTimeAuthKeyLength = #{const crypto_onetimeauth_KEYBYTES}

onetimeauth_BYTES :: Int
onetimeauth_BYTES = #{const crypto_onetimeauth_BYTES}

foreign import ccall unsafe "glue_crypto_onetimeauth"
  c_crypto_onetimeauth :: Ptr Word8 -> Ptr CChar -> CULLong ->
                          Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_onetimeauth_verify"
  c_crypto_onetimeauth_verify :: Ptr CChar -> Ptr CChar -> CULLong ->
                                 Ptr CChar -> IO Int

--
-- Signatures
--

-- | Length of a signers 'PublicKey', in bytes.
signPublicKeyLength :: Int
signPublicKeyLength = #{const crypto_sign_PUBLICKEYBYTES}

-- | Length of a signers 'SecretKey', in bytes.
signSecretKeyLength :: Int
signSecretKeyLength = #{const crypto_sign_SECRETKEYBYTES}

sign_BYTES :: Int
sign_BYTES = #{const crypto_sign_BYTES}

foreign import ccall unsafe "glue_crypto_sign_keypair"
  c_crypto_sign_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "glue_crypto_sign"
  c_crypto_sign :: Ptr Word8 -> Ptr CChar ->
                   CULLong -> Ptr CChar -> IO CULLong

foreign import ccall unsafe "glue_crypto_sign_open"
  c_crypto_sign_open :: Ptr Word8 -> Ptr CULLong ->
                        Ptr CChar -> CULLong -> Ptr CChar -> IO CInt

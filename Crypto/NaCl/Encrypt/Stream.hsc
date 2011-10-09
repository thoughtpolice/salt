-- |
-- Module      : Crypto.NaCl.Encrypt.Stream
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Fast stream encryption.
-- 
module Crypto.NaCl.Encrypt.Stream
       ( -- * Types
         SecretKey       -- :: *
         -- * Stream generation
       , cryptoStream    -- :: Nonce -> SecretKey -> ByteString
         -- * Encryption and decryption
       , encryptXor      -- :: Nonce -> ByteString -> SecretKey -> ByteString
       , decryptXor      -- :: Nonce -> ByteString -> SecretKey -> ByteString
       , keyLength       -- :: Int
       , nonceLength     -- :: Int
       ) where
import Foreign.Ptr
import Foreign.C.Types
import Data.Word
import Control.Monad (void)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import Crypto.NaCl.Nonce

#include "crypto_stream.h"

type SecretKey = ByteString

-- | Given a 'Nonce' @n@, size @s@ and 'SecretKey' @sk@, @cryptoStream n
-- s sk@ generates a cryptographic stream of length @s@.
cryptoStream :: Nonce
             -- ^ Nonce
             -> Int
             -- ^ Size
             -> SecretKey
             -- ^ Input
             -> ByteString
             -- ^ Resulting crypto stream
cryptoStream n sz sk =
  unsafePerformIO . SI.create sz $ \out ->
    SU.unsafeUseAsCString (toBS n) $ \pn ->
      SU.unsafeUseAsCString sk $ \psk ->
        void $ glue_crypto_stream out (fromIntegral sz) pn psk
{-# INLINEABLE cryptoStream #-}

-- | Given a 'Nonce' @n@, plaintext @p@ and 'SecretKey' @sk@, @encryptXor n p sk@ encrypts the message @p@ using 'SecretKey' @sk@ and returns the result.
-- 
-- 'encryptXor' guarantees the resulting ciphertext is the plaintext
-- bitwise XOR'd with the result of 'cryptoStream'. As a result,
-- 'encryptXor' can also be used to decrypt messages.
encryptXor :: Nonce
           -- ^ Nonce
           -> ByteString
           -- ^ Input plaintext
           -> SecretKey
           -- ^ Secret key
           -> ByteString
           -- ^ Ciphertext
encryptXor n msg sk =
  let l = S.length msg
  in unsafePerformIO . SI.create l $ \out ->
    SU.unsafeUseAsCString msg $ \cstr -> 
      SU.unsafeUseAsCString (toBS n) $ \pn ->
        SU.unsafeUseAsCString sk $ \psk ->
          void $ glue_crypto_stream_xor out cstr (fromIntegral l) pn psk
{-# INLINEABLE encryptXor #-}

-- | Simple alias for 'encryptXor'.
decryptXor :: Nonce
           -- ^ Nonce
           -> ByteString
           -- ^ Input ciphertext
           -> SecretKey
           -- ^ Secret key
           -> ByteString
           -- ^ Plaintext
decryptXor = encryptXor
{-# INLINEABLE decryptXor #-}


-- 
-- FFI
-- 

-- | Length of a 'SecretKey' needed for encryption/decryption.
keyLength :: Int
keyLength = #{const crypto_stream_KEYBYTES}

-- | Length of a 'Nonce' needed for encryption/decryption.
nonceLength :: Int
nonceLength = #{const crypto_stream_NONCEBYTES}


foreign import ccall unsafe "glue_crypto_stream"
  glue_crypto_stream :: Ptr Word8 -> CULLong -> Ptr CChar ->
                        Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_stream_xor"
  glue_crypto_stream_xor :: Ptr Word8 -> Ptr CChar -> CULLong ->
                            Ptr CChar -> Ptr CChar -> IO Int

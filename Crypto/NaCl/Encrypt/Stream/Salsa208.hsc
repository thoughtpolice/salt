-- |
-- Module      : Crypto.NaCl.Encrypt.Stream.Salsa208
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Fast stream encryption.
-- 
module Crypto.NaCl.Encrypt.Stream.Salsa208
       ( -- * Types
         SecretKey       -- :: *
         -- * Stream generation
       , streamGen       -- :: Nonce -> SecretKey -> ByteString
         -- * Encryption and decryption
       , encrypt         -- :: Nonce -> ByteString -> SecretKey -> ByteString
       , decrypt         -- :: Nonce -> ByteString -> SecretKey -> ByteString
       , keyLength       -- :: Int
       , nonceLength     -- :: Int
       ) where
import Data.ByteString

import Crypto.NaCl.Encrypt.Stream.Internal as Internal
import Crypto.NaCl.Nonce

#include "crypto_stream_salsa208.h"

type SecretKey = ByteString

-- | Given a 'Nonce' @n@, size @s@ and 'SecretKey' @sk@, @streamGen n
-- s sk@ generates a cryptographic stream of length @s@.
streamGen :: Nonce
          -- ^ Nonce
          -> Int
          -- ^ Size
          -> SecretKey
          -- ^ Input
          -> ByteString
          -- ^ Resulting crypto stream
streamGen n sz sk 
  = Internal.streamGenWrapper c_crypto_stream_salsa208 n sz sk
{-# INLINEABLE streamGen #-}


-- | Given a 'Nonce' @n@, plaintext @p@ and 'SecretKey' @sk@, @encrypt n p sk@ encrypts the message @p@ using 'SecretKey' @sk@ and returns the result.
-- 
-- 'encrypt' guarantees the resulting ciphertext is the plaintext
-- bitwise XOR'd with the result of 'streamGen'. As a result,
-- 'encrypt' can also be used to decrypt messages.
encrypt :: Nonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input plaintext
        -> SecretKey
        -- ^ Secret key
        -> ByteString
        -- ^ Ciphertext
encrypt n p sk
  = Internal.encryptWrapper c_crypto_stream_xor_salsa208 n p sk
{-# INLINEABLE encrypt #-}

-- | Simple alias for 'encrypt'.
decrypt :: Nonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input ciphertext
        -> SecretKey
        -- ^ Secret key
        -> ByteString
        -- ^ Plaintext
decrypt n c sk = encrypt n c sk
{-# INLINEABLE decrypt #-}


-- 
-- FFI
-- 

-- | Length of a 'SecretKey' needed for encryption/decryption.
keyLength :: Int
keyLength = #{const crypto_stream_salsa208_KEYBYTES}

-- | Length of a 'Nonce' needed for encryption/decryption.
nonceLength :: Int
nonceLength = #{const crypto_stream_salsa208_NONCEBYTES}



foreign import ccall unsafe "glue_crypto_stream_salsa208"
  c_crypto_stream_salsa208 :: NaclStreamFfiType

foreign import ccall unsafe "glue_crypto_stream_salsa208_xor"
  c_crypto_stream_xor_salsa208 :: NaclStreamXorFfiType

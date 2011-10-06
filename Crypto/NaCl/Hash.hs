-- |
-- Module      : Crypto.NaCl.Hash
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Fast, cryptographically strong hashing functions.
-- 
module Crypto.NaCl.Hash
       ( -- * Selected primitive
         cryptoHash        -- :: ByteString -> ByteString
         -- * Alternate primitives
       , cryptoHash_SHA256 -- :: ByteString -> ByteString
       ) where
import Foreign.C
import Foreign.Ptr
import Data.Word
import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

-- | Strong cryptographic hash - currently an implementation
-- of SHA-512.
cryptoHash :: ByteString -> ByteString
cryptoHash xs
  | S.null xs = S.empty
  | otherwise = hashByteString glue_crypto_hash xs
      
-- | Alternative cryptographic hash function, providing only
-- SHA-256.
cryptoHash_SHA256 :: ByteString -> ByteString
cryptoHash_SHA256 xs
  | S.null xs = S.empty
  | otherwise = hashByteString glue_crypto_hash_sha256 xs


--
-- Internals
--

-- The type of hashing functions exposed by the C code.
type HashFunc = Ptr CChar -> Int -> Ptr Word8 -> IO Int

hashByteString :: HashFunc -> ByteString -> ByteString
hashByteString f xs = 
  -- NOTE: 64 is the max result size exposed by NaCl hashing functions.
  -- The default primitive of SHA512 has 64 bytes of output.
  unsafePerformIO . SI.createAndTrim 64 $ \out ->
    SU.unsafeUseAsCStringLen xs $ \(cstr,clen) ->
      f cstr clen out
{-# INLINE hashByteString #-}

-- FFI imports

foreign import ccall unsafe "glue_crypto_hash"
  glue_crypto_hash :: HashFunc

foreign import ccall unsafe "glue_crypto_hash_sha256"
  glue_crypto_hash_sha256 :: HashFunc

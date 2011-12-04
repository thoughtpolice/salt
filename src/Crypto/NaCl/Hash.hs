-- |
-- Module      : Crypto.NaCl.Hash
-- Copyright   : (c) Austin Seipp 2011
-- License     : MIT
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
       , cryptoHashSHA256 -- :: ByteString -> ByteString
       ) where
import Foreign.C
import Foreign.Ptr
import Control.Monad (void)
import Data.Word
import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

-- | Strong cryptographic hash - currently an implementation
-- of SHA-512.
cryptoHash :: ByteString -> ByteString
cryptoHash xs =
  -- The default primitive of SHA512 has 64 bytes of output.      
  unsafePerformIO . SI.create 64 $ \out ->
    SU.unsafeUseAsCStringLen xs $ \(cstr,clen) ->
      void $ c_crypto_hash_sha512 out cstr (fromIntegral clen)
{-# INLINEABLE cryptoHash #-}

-- | Alternative cryptographic hash function, providing only
-- SHA-256.
cryptoHashSHA256 :: ByteString -> ByteString
cryptoHashSHA256 xs =
  -- SHA256 has 32 bytes of output
  unsafePerformIO . SI.create 32 $ \out ->
    SU.unsafeUseAsCStringLen xs $ \(cstr,clen) ->
      void $ c_crypto_hash_sha256 out cstr (fromIntegral clen)
{-# INLINEABLE cryptoHashSHA256 #-}

--
-- FFI
--

type HashFunc = Ptr Word8 -> Ptr CChar -> CULLong -> IO CInt

foreign import ccall unsafe "glue_crypto_hash_sha512"
  c_crypto_hash_sha512 :: HashFunc

foreign import ccall unsafe "glue_crypto_hash_sha256"
  c_crypto_hash_sha256 :: HashFunc

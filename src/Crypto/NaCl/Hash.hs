-- |
-- Module      : Crypto.NaCl.Hash
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
-- 
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable
-- 
-- Fast, cryptographically strong hashing functions. Currently
-- only provides SHA-512 and SHA-256.
-- 
module Crypto.NaCl.Hash
       ( sha512 -- :: ByteString -> ByteString
       , sha256 -- :: ByteString -> ByteString
       ) where
import Foreign.C
import Foreign.Ptr
import Control.Monad (void)
import Data.Word
import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

sha512 :: ByteString -> ByteString
sha512 xs =
  -- The default primitive of SHA512 has 64 bytes of output.      
  unsafePerformIO . SI.create 64 $ \out ->
    SU.unsafeUseAsCStringLen xs $ \(cstr,clen) ->
      void $ c_crypto_hash_sha512 out cstr (fromIntegral clen)
{-# INLINEABLE sha512 #-}

sha256 :: ByteString -> ByteString
sha256 xs =
  -- SHA256 has 32 bytes of output
  unsafePerformIO . SI.create 32 $ \out ->
    SU.unsafeUseAsCStringLen xs $ \(cstr,clen) ->
      void $ c_crypto_hash_sha256 out cstr (fromIntegral clen)
{-# INLINEABLE sha256 #-}

--
-- FFI
--

type HashFunc = Ptr Word8 -> Ptr CChar -> CULLong -> IO CInt

foreign import ccall unsafe "glue_crypto_hash_sha512"
  c_crypto_hash_sha512 :: HashFunc

foreign import ccall unsafe "glue_crypto_hash_sha256"
  c_crypto_hash_sha256 :: HashFunc

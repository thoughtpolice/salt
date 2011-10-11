-- |
-- Module      : Crypto.NaCl.Random
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Obtaining random bytes via @\/dev\/urandom@. Useful for nonces or similar.
-- 
-- A package like @mwc-random@ would also work for getting at
-- randomness.  This is really only here for completeness because
-- internally certain NaCl primitives use the @randombytes@ call.
-- 

module Crypto.NaCl.Random
       ( randomBytes -- :: Int -> IO ByteString
       ) where
import Foreign.C.Types
import Foreign.Ptr
import Control.Monad (void)
import Data.Word

import Data.ByteString as S
import Data.ByteString.Internal as SI

-- | Generate a random ByteString which is internally based on @\/dev\/urandom@.
randomBytes :: Int -> IO ByteString
randomBytes n 
  | n < 0     = error "Crypto.NaCl.Random.randomBytes: length must be greater than 0"
  | otherwise = SI.create n $ \out -> void $ c_randombytes out (fromIntegral n)

--
-- FFI
-- 

foreign import ccall unsafe "randombytes"
  c_randombytes :: Ptr Word8 -> CULLong -> IO Int

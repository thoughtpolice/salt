-- |
-- Module      : Crypto.NaCl.Random
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Obtaining random bytes via @/dev/urandom@. Useful for nonces or similar.
-- 
-- A package like `mwc-random` would also work for getting at
-- randomness.  This is really only here for completeness because
-- internally certain NaCl primitives use the @randombytes@ call.
-- 
module Crypto.NaCl.Random
       ( randomBytes -- :: Int -> IO ByteString
       ) where
import Foreign.Ptr

import Data.ByteString as S
import Data.ByteString.Internal as SI

-- | Generate a random ByteString which is internally based on @/dev/urandom@.
randomBytes :: Int -> IO ByteString
randomBytes n 
  | n <= 0    = error "Crypto.NaCl.Random.randomBytes: length must be greater than 0"
  | otherwise = SI.createAndTrim n $ \out -> glue_randombytes out n

-- FFI imports

foreign import ccall unsafe "glue_randombytes"
  glue_randombytes :: Ptr a -> Int -> IO Int

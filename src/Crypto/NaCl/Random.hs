-- |
-- Module      : Crypto.NaCl.Random
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
-- 
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable
-- 
-- Obtaining random bytes via @\/dev\/urandom@ on unix systems.
--
-- While you may feel safer by throwing a package like @mwc-random@
-- into the mix, this API is provided in-line with the design of
-- @nacl@: centralization of entropy is safer. While there are many
-- implementations of secure randomness, having a singular source
-- of code to audit and rely on is generally more robust and
-- sensible.
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

-- | Generate a random ByteString, using @\/dev\/urandom@ as your entropy
-- source.
randomBytes :: Int -> IO ByteString
randomBytes n
  | n < 0     = error "Crypto.NaCl.Random.randomBytes: invalid length"
  | otherwise = SI.create n $ \out -> void $ c_randombytes out (fromIntegral n)

--
-- FFI
-- 

foreign import ccall unsafe "randombytes"
  c_randombytes :: Ptr Word8 -> CULLong -> IO Int

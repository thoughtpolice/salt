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
import Control.Monad (void)
import Data.ByteString (ByteString)
import Data.ByteString.Internal (create)
import Crypto.NaCl.FFI (c_randombytes)

-- | Generate a random ByteString, using @\/dev\/urandom@ as your entropy
-- source.
randomBytes :: Int -> IO ByteString
randomBytes n
  | n < 0     = error "Crypto.NaCl.Random.randomBytes: invalid length"
  | otherwise = create n $ \out -> void $ c_randombytes out (fromIntegral n)

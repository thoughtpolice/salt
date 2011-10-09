-- |
-- Module      : Crypto.NaCl.Nonce
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Simple API for cryptographic nonces.
-- 

module Crypto.NaCl.Nonce
       ( -- * Types
         Nonce              -- :: *
         -- * Creation
       , createZeroNonce    -- :: Int -> Nonce
       , createRandomNonce  -- :: Int -> Nonce
         -- * Incrementing a nonce
       , incNonce           -- :: Nonce -> Nonce
       ) where
import Foreign.C
import Foreign.Ptr
import Control.Monad (void)
import Data.Word
import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

-- | A cryptographic nonce used for client-server communication.
data Nonce = Nonce !Int !ByteString
              deriving Eq

instance Show Nonce where
  show (Nonce l bs) = "nonce["++show l++"]" ++ show (S.unpack bs)

-- | Create an 'empty' nonce of length @n@ where
-- all the bytes are zero.
createZeroNonce :: Int -> Nonce
createZeroNonce = undefined

-- | Create a random nonce of length @n@.
createRandomNonce :: Int -> IO Nonce
createRandomNonce = undefined

-- | Increment a nonce by 1.
incNonce :: Nonce -> Nonce
incNonce = undefined

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
       , createRandomNonce  -- :: Int -> IO Nonce
       , fromBS             -- :: ByteString -> Nonce
         -- * Incrementing a nonce
       , incNonce           -- :: Nonce -> Nonce
       ) where
import Foreign.C.Types
import Foreign.Ptr
import Control.Monad (void)
import Data.Word

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import Crypto.NaCl.Random (randomBytes)

-- | A cryptographic nonce used for client-server communication.
data Nonce = Nonce !Int !ByteString
              deriving Eq

instance Show Nonce where
  show (Nonce l bs) = "nonce["++show l++"]" ++ show (S.unpack bs)

-- | Create an empty 'Nonce' of length @n@ where
-- all the bytes are zero.
createZeroNonce :: Int -> Nonce
createZeroNonce n =
  Nonce n $ SI.unsafeCreate n $ \out ->
    void $ SI.memset out 0x0 (fromIntegral n)
{-# INLINEABLE createZeroNonce #-}

-- | Create a random 'Nonce' of length @n@.
createRandomNonce :: Int -> IO Nonce
createRandomNonce n = do
  b <- randomBytes n
  return $! Nonce n b
{-# INLINEABLE createRandomNonce #-}

-- | Create a 'Nonce' from a 'ByteString'.
fromBS :: ByteString -> Nonce
fromBS bs = Nonce (S.length bs) bs
{-# INLINEABLE fromBS #-}

-- | Increment a 'Nonce' by 1.
incNonce :: Nonce -> Nonce
incNonce (Nonce l bs) =
  Nonce l $ SI.unsafeCreate l $ \out -> do
    SU.unsafeUseAsCStringLen bs $ \(b,blen) ->
      SI.memcpy out (castPtr b) (fromIntegral blen)
    glue_incnonce out (fromIntegral l)
{-# INLINEABLE incNonce #-}

-- 
-- FFI
-- 
foreign import ccall unsafe "glue_incnonce"
  glue_incnonce :: Ptr Word8 -> CSize -> IO ()

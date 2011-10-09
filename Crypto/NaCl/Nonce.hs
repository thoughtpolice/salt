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
         -- * Clearing the lower bytes of a Nonce
       , clearBytes         -- :: Int -> Nonce -> Nonce
         -- * Incrementing a nonce
       , incNonce           -- :: Nonce -> Nonce
         -- * Nonce size
       , nonceLen           -- :: Nonce -> Int
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
createZeroNonce n 
  | n < 0 = error "Crypto.NaCl.Nonce.createZeroNonce: n < 0"
  | otherwise = do
      Nonce n $ SI.unsafeCreate n $ \out ->
        void $ SI.memset out 0x0 (fromIntegral n)
{-# INLINEABLE createZeroNonce #-}

-- | Create a random 'Nonce' of length @n@.
createRandomNonce :: Int -> IO Nonce
createRandomNonce n
  | n < 0 = error "Crypto.NaCl.Nonce.createRandomNonce: n < 0"
  | otherwise = do
      b <- randomBytes n
      return $! Nonce n b

-- | Create a 'Nonce' from a 'ByteString'.
fromBS :: ByteString -> Nonce
fromBS bs = Nonce (S.length bs) bs
{-# INLINEABLE fromBS #-}

-- | @clearBytes n nonce@ clears the last @n@ bytes of the 'Nonce' and
-- makes them all 0. This is useful for the pattern of generating a
-- cryptographic nonce randomly, clearing the last @n@ bytes, and then
-- using 'incNonce' to increment the 'Nonce' for communication with
-- another party.
-- 
-- Invariants:
-- 
-- * @n@ must be less than the size of the @nonce@
-- 
-- Properties:
-- 
-- > clearBytes (nonceLen nonce) nonce == createZeroNonce (nonceLen nonce)
-- 
clearBytes :: Int -> Nonce -> Nonce
clearBytes n (Nonce l nonce) 
  | n > l = error "Crypto.NaCl.Nonce.clearBytes: "
  | otherwise =
    Nonce l $ SI.unsafeCreate l $ \out -> do
      SU.unsafeUseAsCString nonce $ \b -> do
        void $ SI.memset out 0x0 (fromIntegral l)
        void $ SI.memcpy out (castPtr b) (fromIntegral n)
{-# INLINEABLE clearBytes #-}

-- | Increment a 'Nonce' by 1.
incNonce :: Nonce -> Nonce
incNonce (Nonce l bs) =
  Nonce l $ SI.unsafeCreate l $ \out -> do
    SU.unsafeUseAsCStringLen bs $ \(b,blen) ->
      SI.memcpy out (castPtr b) (fromIntegral blen)
    glue_incnonce out (fromIntegral l)
{-# INLINEABLE incNonce #-}

-- | Get the length of a 'Nonce'.
nonceLen :: Nonce -> Int
nonceLen (Nonce l _) = l

-- 
-- FFI
-- 
foreign import ccall unsafe "glue_incnonce"
  glue_incnonce :: Ptr Word8 -> CSize -> IO ()

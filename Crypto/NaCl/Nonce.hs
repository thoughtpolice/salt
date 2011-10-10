{-# LANGUAGE CPP #-}
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
       , toBS               -- :: Nonce -> ByteString
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
data Nonce = Nonce !ByteString
              deriving Eq

instance Show Nonce where
  show (Nonce bs) = "nonce["++show (S.length bs)++"]" ++ show (S.unpack bs)

-- | Create an empty 'Nonce' of length @n@ where
-- all the bytes are zero.
createZeroNonce :: Int -> Nonce
createZeroNonce n 
  | n < 0 = error "Crypto.NaCl.Nonce.createZeroNonce: n < 0"
  | otherwise = do
      Nonce $ SI.unsafeCreate n $ \out ->
        void $ SI.memset out 0x0 (fromIntegral n)
{-# INLINEABLE createZeroNonce #-}

-- | Create a random 'Nonce' of length @n@.
createRandomNonce :: Int -> IO Nonce
createRandomNonce n
  | n < 0 = error "Crypto.NaCl.Nonce.createRandomNonce: n < 0"
  | otherwise = do
      b <- randomBytes n
      return $! Nonce b

-- | Create a 'Nonce' from a 'ByteString'.
fromBS :: ByteString -> Nonce
fromBS = Nonce
{-# INLINEABLE fromBS #-}

-- | Get the underlying 'ByteString' from a 'Nonce'.
toBS :: Nonce -> ByteString
toBS (Nonce b) = b
{-# INLINEABLE toBS #-}

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
clearBytes n x@(Nonce nonce) 
  | n > l  = error "Crypto.NaCl.Nonce.clearBytes: n > length of nonce"
  | n < 0  = error "Crypto.NaCl.Nonce.clearBytes: n < 0"  
  | n == 0 = x
  | n == l = Nonce $ S.replicate l 0x0
  | otherwise =
    Nonce $ SI.unsafeCreate l $ \out -> do
      SU.unsafeUseAsCString nonce $ \b -> do
        void $ SI.memset out 0x0 (fromIntegral l)
        void $ SI.memcpy out (castPtr b) (fromIntegral n)
  where
    l = S.length nonce
{-# INLINEABLE clearBytes #-}

-- | Increment a 'Nonce' by 1.
incNonce :: Nonce -> Nonce
incNonce (Nonce nonce) =
  Nonce $ SI.unsafeCreate l $ \out -> do
    SU.unsafeUseAsCStringLen nonce $ \(b,blen) ->
      SI.memcpy out (castPtr b) (fromIntegral blen)
    glue_incnonce out (fromIntegral l)
  where
    l = S.length nonce
{-# INLINEABLE incNonce #-}

-- | Get the length of a 'Nonce'.
nonceLen :: Nonce -> Int
nonceLen (Nonce n) = S.length n

-- 
-- FFI
-- 
foreign import ccall unsafe "glue_incnonce"
  glue_incnonce :: Ptr Word8 -> CSize -> IO ()

{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.NaCl.Nonce
-- Copyright   : (c) Austin Seipp 2011
-- License     : MIT
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Simple API for cryptographic nonces.
-- 
module Crypto.NaCl.Nonce
       ( -- * Types
         Nonce              -- :: * -> *
       , NonceLength        -- :: * -> *
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
       , nonceLen           -- :: Nonce k -> Int
       , nonceLengthToInt   -- :: NonceLength k -> Int
       , nonceToNonceLength -- :: Nonce k -> NonceLength k
       ) where
import Foreign.Ptr
import Control.Monad (void)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import Crypto.NaCl.Random (randomBytes)

import Crypto.NaCl.Nonce.Internal

-- | Create an empty 'Nonce' of length @n@ where
-- all the bytes are zero.
createZeroNonce :: NonceLength k -> Nonce k
createZeroNonce (NonceLength n)
  | n < 0 = error "Crypto.NaCl.Nonce.createZeroNonce: n < 0"
  | otherwise =
      Nonce $ SI.unsafeCreate n $ \out ->
        void $ SI.memset out 0x0 (fromIntegral n)
{-# INLINEABLE createZeroNonce #-}

-- | Create a random 'Nonce' of length @n@.
createRandomNonce :: NonceLength k -> IO (Nonce k)
createRandomNonce (NonceLength n)
  | n < 0 = error "Crypto.NaCl.Nonce.createRandomNonce: n < 0"
  | otherwise = do
      b <- randomBytes n
      return $! Nonce b

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
clearBytes :: Int -> Nonce k -> Nonce k
clearBytes n x@(Nonce nonce) 
  | n > l  = error "Crypto.NaCl.Nonce.clearBytes: n > length of nonce"
  | n < 0  = error "Crypto.NaCl.Nonce.clearBytes: n < 0"  
  | n == 0 = x
  | otherwise =
    Nonce $ SI.unsafeCreate l $ \out ->
      SU.unsafeUseAsCString nonce $ \b -> do
        void $ SI.memset out 0x0 (fromIntegral l)
        void $ SI.memcpy out (castPtr b) (fromIntegral $ l - n)
  where
    l = S.length nonce
{-# INLINEABLE clearBytes #-}

-- | Increment a 'Nonce' by 1.
incNonce :: Nonce k -> Nonce k
incNonce (Nonce nonce) =
  Nonce $ SI.unsafeCreate l $ \out -> do
    SU.unsafeUseAsCStringLen nonce $ \(b,blen) ->
      SI.memcpy out (castPtr b) (fromIntegral blen)
    c_incnonce out (fromIntegral l)
  where
    l = S.length nonce
{-# INLINEABLE incNonce #-}

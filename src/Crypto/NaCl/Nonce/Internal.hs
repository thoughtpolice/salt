{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.NaCl.Nonce.Internal
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Internal datatypes for 'Nonce's
-- 
module Crypto.NaCl.Nonce.Internal
       ( -- * Types
         Nonce(..)          -- :: * -> *
       , NonceLength(..)    -- :: * -> *
       , fromBS             -- :: ByteString -> Nonce
       , toBS               -- :: Nonce -> ByteString
       , nonceLen           -- :: Nonce k -> Int
       , nonceLengthToInt   -- :: NonceLength k -> Int
       , nonceToNonceLength -- :: Nonce k -> NonceLength k
       , c_incnonce
       ) where
import Foreign.C.Types
import Foreign.Ptr
import Data.Word

import Data.ByteString as S

-- | A cryptographic nonce used for client-server communication.
-- 
-- The type @k@ indicates the *kind* of Nonce you're dealing with, to ensure
-- for example you won't confuse a nonce for Secret key encryption with one
-- you use for public key encryption, etc.
newtype Nonce k = Nonce ByteString
        deriving Eq

instance Show (Nonce k) where
  show (Nonce bs) = "nonce["++show (S.length bs)++"]" ++ show (S.unpack bs)

-- | A data type representing the length of a particular type of 'Nonce'
newtype NonceLength k = NonceLength Int
        deriving Eq

instance Show (NonceLength a) where
  show (NonceLength x) = show x

-- | Create a 'Nonce' from a 'ByteString'.
fromBS :: ByteString -> Nonce k
fromBS = Nonce
{-# INLINEABLE fromBS #-}

-- | Get the underlying 'ByteString' from a 'Nonce'.
toBS :: Nonce k -> ByteString
toBS (Nonce b) = b
{-# INLINEABLE toBS #-}

-- | Get the size of a 'Nonce'.
nonceLen :: Nonce k -> Int
nonceLen (Nonce n) = S.length n

nonceLengthToInt :: NonceLength k -> Int
nonceLengthToInt (NonceLength i) = i

nonceToNonceLength :: Nonce k -> NonceLength k
nonceToNonceLength = NonceLength . nonceLen

-- 
-- FFI
-- 
foreign import ccall unsafe "glue_incnonce"
  c_incnonce :: Ptr Word8 -> CSize -> IO ()

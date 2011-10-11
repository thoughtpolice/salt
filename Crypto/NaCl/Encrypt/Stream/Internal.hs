-- |
-- Module      : Crypto.NaCl.Encrypt.Stream.Internal
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Internal abstraction module for the various stream
-- implementations.
-- 
module Crypto.NaCl.Encrypt.Stream.Internal
       ( -- * Types
         NaclStreamFfiType
       , NaclStreamXorFfiType
         -- * Utility wrappers
       , streamGenWrapper
       , encryptWrapper
       ) where
import Foreign.Ptr
import Foreign.C.Types
import Data.Word
import Control.Monad (void)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import Crypto.NaCl.Nonce

type NaclStreamFfiType    = Ptr Word8 -> CULLong -> Ptr CChar -> Ptr CChar -> IO Int
type NaclStreamXorFfiType = Ptr Word8 -> Ptr CChar -> CULLong -> Ptr CChar -> Ptr CChar -> IO Int

-- | Given a 'Nonce' @n@, size @s@ and 'SecretKey' @sk@, @cryptoStream n
-- s sk@ generates a cryptographic stream of length @s@.
streamGenWrapper :: NaclStreamFfiType 
                 -- ^ C function
                 -> Nonce
                 -- ^ Nonce
                 -> Int
                 -- ^ Size of stream
                 -> ByteString
                 -- ^ Secret key
                 -> ByteString
                 -- ^ Resulting crypto stream
streamGenWrapper c_func n sz sk =
  unsafePerformIO . SI.create sz $ \out ->
    SU.unsafeUseAsCString (toBS n) $ \pn ->
      SU.unsafeUseAsCString sk $ \psk ->
        void $ c_func out (fromIntegral sz) pn psk
{-# INLINEABLE streamGenWrapper #-}

encryptWrapper :: NaclStreamXorFfiType
               -- ^ C Function
               ->  Nonce
               -- ^ Nonce
               -> ByteString
               -- ^ Input plaintext
               -> ByteString
               -- ^ Secret key
               -> ByteString
               -- ^ Ciphertext
encryptWrapper c_func n msg sk =
  let l = S.length msg
  in unsafePerformIO . SI.create l $ \out ->
    SU.unsafeUseAsCString msg $ \cstr -> 
      SU.unsafeUseAsCString (toBS n) $ \pn ->
        SU.unsafeUseAsCString sk $ \psk ->
          void $ c_func out cstr (fromIntegral l) pn psk
{-# INLINEABLE encryptWrapper #-}

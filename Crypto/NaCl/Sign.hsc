-- |
-- Module      : Crypto.NaCl.Sign
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- 
module Crypto.NaCl.Sign
       ( PublicKey, SecretKey, KeyPair -- :: *
       , createKeypair                 -- :: IO KeyPair
       , sign                          -- :: 
       , verify                        -- :: 
       -- * Misc
       , signPublicKeyLength           -- :: Int
       , signSecretKeyLength           -- :: Int
       ) where
import Foreign.Ptr
import Foreign.C.Types
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Storable
import Data.Word
import Control.Monad (void, liftM)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

type PublicKey = ByteString
type SecretKey = ByteString

type KeyPair = (PublicKey, SecretKey)

#include "crypto_sign.h"

-- | Randomly generate a public and private key
-- for doing authenticated encryption.
createKeypair :: IO KeyPair
createKeypair = do
  pk <- SI.mallocByteString signPublicKeyLength
  sk <- SI.mallocByteString signSecretKeyLength

  void $ withForeignPtr pk $ \ppk ->
    void $ withForeignPtr sk $ \psk ->
      glue_crypto_sign_keypair ppk psk
      
  return (SI.fromForeignPtr pk 0 signPublicKeyLength,
          SI.fromForeignPtr sk 0 signSecretKeyLength)

sign :: SecretKey -> ByteString -> ByteString
sign sk xs = 
  unsafePerformIO $ SU.unsafeUseAsCStringLen xs $ \(mstr,mlen) ->
    SU.unsafeUseAsCString sk $ \psk ->
      SI.createAndTrim (mlen+sign_BYTES) $ \out ->
       fromIntegral `liftM` glue_crypto_sign out mstr (fromIntegral mlen) psk
{-# INLINEABLE sign #-}

verify :: PublicKey -> ByteString -> Maybe ByteString
verify pk xs =
  unsafePerformIO $ SU.unsafeUseAsCStringLen xs $ \(smstr,smlen) ->
    SU.unsafeUseAsCString pk $ \ppk ->
      alloca $ \pmlen -> do
        out <- SI.mallocByteString smlen
        
        r <- withForeignPtr out $ \pout -> 
               glue_crypto_sign_open pout pmlen smstr (fromIntegral smlen) ppk
        
        if r /= 0 then return Nothing
          else do
            l <- peek pmlen
            return $ Just $ SI.fromForeignPtr out 0 (fromIntegral l)
{-# INLINEABLE verify #-}

--
-- FFI
-- 

signPublicKeyLength :: Int
signPublicKeyLength = #{const crypto_sign_PUBLICKEYBYTES}
signSecretKeyLength :: Int
signSecretKeyLength = #{const crypto_sign_SECRETKEYBYTES}

sign_BYTES :: Int
sign_BYTES = #{const crypto_sign_BYTES}

foreign import ccall unsafe "glue_crypto_sign_keypair"
  glue_crypto_sign_keypair :: Ptr Word8 -> Ptr Word8 -> IO Int

foreign import ccall unsafe "glue_crypto_sign"
  glue_crypto_sign :: Ptr Word8 -> Ptr CChar ->  
                      CULLong -> Ptr CChar -> IO CULLong

foreign import ccall unsafe "glue_crypto_sign_open"
  glue_crypto_sign_open :: Ptr Word8 -> Ptr CULLong -> 
                           Ptr CChar -> CULLong -> Ptr CChar -> IO Int

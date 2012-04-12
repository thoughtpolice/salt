{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.NaCl.Sign
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
-- 
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable
-- 
-- This module gives you the ability to create signed
-- messages and verify them against a signer's public key.
-- 
-- This module uses an optimized implementation of Ed25519. It is over
-- 200x faster than the reference edwards implementation that comes
-- with nacl-20110221. It will be the default signature primitive in
-- the next version of nacl. You must be aware of this if you
-- interoperate with any services that use the unpatched version of
-- nacl-20110221.
-- 
-- For more information (including how to get a copy of the software)
-- visit <http://ed25519.cr.yp.to>.
-- 
module Crypto.NaCl.Sign
       ( -- * Keypair creation
         createKeypair                 -- :: IO KeyPair
         -- * Signing and verifying messages
       , sign                          -- :: SecretKey -> ByteString -> ByteString
       , verify                        -- :: PublicKey -> ByteString -> Maybe ByteString
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

import Crypto.NaCl.Key

#include <crypto_sign.h>

-- | Randomly generate a public and private key for doing
-- authenticated signing and verification.
createKeypair :: IO KeyPair
createKeypair = do
  pk <- SI.mallocByteString signPublicKeyLength
  sk <- SI.mallocByteString signSecretKeyLength

  void $ withForeignPtr pk $ \ppk ->
    void $ withForeignPtr sk $ \psk ->
      c_crypto_sign_keypair ppk psk
      
  return (PublicKey $ SI.fromForeignPtr pk 0 signPublicKeyLength,
          SecretKey $ SI.fromForeignPtr sk 0 signSecretKeyLength)

-- | Sign a message with a particular 'SecretKey'.
sign :: SecretKey 
     -- ^ Signers secret key
     -> ByteString 
     -- ^ Input message
     -> ByteString
     -- ^ Resulting signed message
sign (SecretKey sk) xs =
  unsafePerformIO $ SU.unsafeUseAsCStringLen xs $ \(mstr,mlen) ->
    SU.unsafeUseAsCString sk $ \psk ->
      SI.createAndTrim (mlen+sign_BYTES) $ \out ->
       fromIntegral `liftM` c_crypto_sign out mstr (fromIntegral mlen) psk
{-# INLINEABLE sign #-}

-- | Verifies a signed message with a 'PublicKey'. Returns @Nothing@ if
-- verification fails, or @Just xs@ where @xs@ is the original message if it
-- succeeds.
verify :: PublicKey
       -- ^ Signers public key
       -> ByteString
       -- ^ Signed message
       -> Maybe ByteString
       -- ^ Verification check
verify (PublicKey pk) xs =
  unsafePerformIO $ SU.unsafeUseAsCStringLen xs $ \(smstr,smlen) ->
    SU.unsafeUseAsCString pk $ \ppk ->
      alloca $ \pmlen -> do
        out <- SI.mallocByteString smlen
        
        r <- withForeignPtr out $ \pout -> 
               c_crypto_sign_open pout pmlen smstr (fromIntegral smlen) ppk
        
        if r /= 0 then return Nothing
          else do
            l <- peek pmlen
            return $ Just $ SI.fromForeignPtr out 0 (fromIntegral l)
{-# INLINEABLE verify #-}

--
-- FFI
-- 

-- | Length of a signers 'PublicKey', in bytes.
signPublicKeyLength :: Int
signPublicKeyLength = #{const crypto_sign_PUBLICKEYBYTES}

-- | Length of a signers 'SecretKey', in bytes.
signSecretKeyLength :: Int
signSecretKeyLength = #{const crypto_sign_SECRETKEYBYTES}

sign_BYTES :: Int
sign_BYTES = #{const crypto_sign_BYTES}

foreign import ccall unsafe "glue_crypto_sign_keypair"
  c_crypto_sign_keypair :: Ptr Word8 -> Ptr Word8 -> IO Int

foreign import ccall unsafe "glue_crypto_sign"
  c_crypto_sign :: Ptr Word8 -> Ptr CChar ->  
                   CULLong -> Ptr CChar -> IO CULLong

foreign import ccall unsafe "glue_crypto_sign_open"
  c_crypto_sign_open :: Ptr Word8 -> Ptr CULLong -> 
                        Ptr CChar -> CULLong -> Ptr CChar -> IO Int

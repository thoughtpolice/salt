-- |
-- Module      : Crypto.NaCl.Encrypt.PublicKey
-- Copyright   : (c) Austin Seipp 2011
-- License     : MIT
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Public-key encryption.
-- 
module Crypto.NaCl.Encrypt.PublicKey
       (
       -- ** Types
         PublicKey, SecretKey, KeyPair -- :: *
       -- ** Keypair creation
       , createKeypair                 -- :: IO (ByteString, ByteString)
       -- ** Encryption, Decryption                   
       , encrypt                       -- :: ByteString -> ByteString -> PublicKey -> SecretKey -> ByteString -- ^ Ciphertext
       , decrypt                       -- :: ByteString -> ByteString -> PublicKey -> SecretKey -> ByteString -- ^ Ciphertext
       -- ** Miscellaneous
       , publicKeyLength               -- :: Int
       , secretKeyLength               -- :: Int
       , nonceLength                   -- :: Int
       ) where
import Foreign.Ptr
import Foreign.C.Types
import Foreign.ForeignPtr (withForeignPtr)
import Data.Word
import Control.Monad (void)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import Crypto.NaCl.Nonce

type PublicKey = ByteString
type SecretKey = ByteString

type KeyPair = (PublicKey, SecretKey)

#include "crypto_box.h"

-- | Randomly generate a public and private key
-- for doing authenticated encryption.
createKeypair :: IO KeyPair
createKeypair = do
  pk <- SI.mallocByteString publicKeyLength
  sk <- SI.mallocByteString secretKeyLength

  void $ withForeignPtr pk $ \ppk ->
    void $ withForeignPtr sk $ \psk ->
      c_crypto_box_keypair ppk psk
      
  return (SI.fromForeignPtr pk 0 publicKeyLength, 
          SI.fromForeignPtr sk 0 secretKeyLength)

encrypt :: Nonce
        -- ^ Nonce
        -> ByteString
        -- ^ Message
        -> PublicKey
        -- ^ Recievers public key
        -> SecretKey
        -- ^ Senders secret key
        -> ByteString 
        -- ^ Ciphertext
encrypt n msg pk sk = unsafePerformIO $ do
  let mlen = S.length msg + msg_ZEROBYTES
  c <- SI.mallocByteString mlen
  
  -- inputs to crypto_box must be padded
  let m = (S.replicate msg_ZEROBYTES 0x0) `S.append` msg
  
  -- as you can tell, this is unsafe
  void $ withForeignPtr c $ \pc ->
    SU.unsafeUseAsCString m $ \pm ->
      SU.unsafeUseAsCString (toBS n) $ \pn -> 
        SU.unsafeUseAsCString pk $ \ppk ->
          SU.unsafeUseAsCString sk $ \psk ->
            c_crypto_box pc pm (fromIntegral mlen) pn ppk psk
  
  let r = SI.fromForeignPtr c 0 mlen
  return $ SU.unsafeDrop msg_BOXZEROBYTES r
{-# INLINEABLE encrypt #-}
  
decrypt :: Nonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input ciphertext
        -> PublicKey
        -- ^ Senders public key
        -> SecretKey
        -- ^ Recievers secret key
        -> Maybe ByteString -- ^ Ciphertext
decrypt n cipher pk sk = unsafePerformIO $ do
  let clen = S.length cipher + msg_BOXZEROBYTES
  m <- SI.mallocByteString clen
  
  -- inputs to crypto_box must be padded
  let c = (S.replicate msg_BOXZEROBYTES 0x0) `S.append` cipher
  
  -- as you can tell, this is unsafe
  r <- withForeignPtr m $ \pm ->
    SU.unsafeUseAsCString c $ \pc ->
      SU.unsafeUseAsCString (toBS n) $ \pn -> 
        SU.unsafeUseAsCString pk $ \ppk ->
          SU.unsafeUseAsCString sk $ \psk ->
            c_crypto_box_open pm pc (fromIntegral clen) pn ppk psk
  
  return $ if r /= 0 then Nothing
            else
             let bs = SI.fromForeignPtr m 0 clen
             in Just $ SU.unsafeDrop msg_ZEROBYTES bs
{-# INLINEABLE decrypt #-}

--
-- FFI
-- 
  
-- | Length of a 'Nonce' needed for encryption/decryption
nonceLength :: Int
nonceLength      = #{const crypto_box_NONCEBYTES}

-- | Length of a 'PublicKey' in bytes.
publicKeyLength :: Int
publicKeyLength  = #{const crypto_box_PUBLICKEYBYTES}

-- | Length of a 'SecretKey' in bytes.
secretKeyLength :: Int
secretKeyLength = #{const crypto_box_SECRETKEYBYTES}
  

msg_ZEROBYTES,msg_BOXZEROBYTES :: Int
msg_ZEROBYTES    = #{const crypto_box_ZEROBYTES}
msg_BOXZEROBYTES = #{const crypto_box_BOXZEROBYTES}


foreign import ccall unsafe "glue_crypto_box_keypair"
  c_crypto_box_keypair :: Ptr Word8 -> Ptr Word8 -> IO Int

foreign import ccall unsafe "glue_crypto_box"
  c_crypto_box :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                  Ptr CChar -> Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_box_open"
  c_crypto_box_open :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                       Ptr CChar -> Ptr CChar -> Ptr CChar -> IO Int

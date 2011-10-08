-- |
-- Module      : Crypto.NaCl.Public.Sign
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- 
module Crypto.NaCl.Public.Sign
       ( PublicKey, SecretKey, KeyPair -- :: *
       , createKeypair                 -- :: IO KeyPair
       , sign                          -- :: 
       , verify                        -- :: 
       -- * Misc
       , sign_pk_size, sign_sk_size    -- :: Int
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

type PublicKey = ByteString
type SecretKey = ByteString

type KeyPair = (PublicKey, SecretKey)

#include "crypto_sign.h"

-- | Randomly generate a public and private key
-- for doing authenticated encryption.
createKeypair :: IO KeyPair
createKeypair = do
  pk <- SI.mallocByteString sign_pk_size
  sk <- SI.mallocByteString sign_sk_size

  void $ withForeignPtr pk $ \ppk ->
    void $ withForeignPtr sk $ \psk ->
      glue_crypto_sign_keypair ppk psk
      
  return (SI.fromForeignPtr pk 0 sign_pk_size, 
          SI.fromForeignPtr sk 0 sign_sk_size)

sign = undefined
verify = undefined

{-
encrypt :: ByteString
        -> ByteString
        -> PublicKey
        -> SecretKey
        -> ByteString -- ^ Ciphertext
encrypt n msg pk sk = unsafePerformIO $ do
  let mlen = S.length msg + msg_ZEROBYTES
  c <- SI.mallocByteString mlen
  
  -- inputs to crypto_box must be padded
  let m = (S.replicate msg_ZEROBYTES 0x0) `S.append` msg
  
  -- as you can tell, this is unsafe
  void $ withForeignPtr c $ \pc ->
    SU.unsafeUseAsCString m $ \pm ->
      SU.unsafeUseAsCString n $ \pn -> 
        SU.unsafeUseAsCString pk $ \ppk ->
          SU.unsafeUseAsCString sk $ \psk ->
            glue_crypto_box pc pm (fromIntegral mlen) pn ppk psk
  
  let r = SI.fromForeignPtr c 0 mlen
  return $ SU.unsafeDrop msg_BOXZEROBYTES r
  
decrypt :: ByteString
        -> ByteString
        -> PublicKey
        -> SecretKey
        -> Maybe ByteString -- ^ Ciphertext
decrypt n cipher pk sk = unsafePerformIO $ do
  let clen = S.length cipher + msg_BOXZEROBYTES
  m <- SI.mallocByteString clen
  
  -- inputs to crypto_box must be padded
  let c = (S.replicate msg_BOXZEROBYTES 0x0) `S.append` cipher
  
  -- as you can tell, this is unsafe
  r <- withForeignPtr m $ \pm ->
    SU.unsafeUseAsCString c $ \pc ->
      SU.unsafeUseAsCString n $ \pn -> 
        SU.unsafeUseAsCString pk $ \ppk ->
          SU.unsafeUseAsCString sk $ \psk ->
            glue_crypto_box_open pm pc (fromIntegral clen) pn ppk psk
  
  return $ if r /= 0 then Nothing
            else
             let bs = SI.fromForeignPtr m 0 clen
             in Just $ SU.unsafeDrop msg_ZEROBYTES bs
-}

--
-- FFI
-- 

sign_pk_size, sign_sk_size :: Int
sign_pk_size = #{const crypto_sign_PUBLICKEYBYTES}
sign_sk_size = #{const crypto_sign_SECRETKEYBYTES}

foreign import ccall unsafe "glue_crypto_sign_keypair"
  glue_crypto_sign_keypair :: Ptr Word8 -> Ptr Word8 -> IO Int

foreign import ccall unsafe "glue_crypto_sign"
  glue_crypto_sign :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                      Ptr CChar -> Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_sign_open"
  glue_crypto_sign_open :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                           Ptr CChar -> Ptr CChar -> Ptr CChar -> IO Int

{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.NaCl.Encrypt.SecretKey
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
-- 
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable
-- 
-- Authenticated, secret-key encryption. The selected underlying
-- primitive used is @crypto_secretbox_xsalsa20poly1305@, a particular
-- combination of Salsa20 and Poly1305. See the specification,
-- \"Cryptography in NaCl\":
-- <http://cr.yp.to/highspeed/naclcrypto-20090310.pdf>
-- 
module Crypto.NaCl.Encrypt.SecretKey
       ( -- * Types
        SKNonce            -- :: *
         -- * Encryption/decryption
       , encrypt
       , decrypt
         -- * Misc
       , keyLength
       ) where
import Foreign.Ptr
import Foreign.C.Types
import Foreign.ForeignPtr (withForeignPtr)
import Data.Tagged
import Data.Word
import Control.Monad (void)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import Crypto.NaCl.Nonce

import Crypto.NaCl.Key

#include <crypto_secretbox.h>

data SKNonce = SKNonce ByteString deriving (Show, Eq)
instance Nonce SKNonce where
  {-# SPECIALIZE instance Nonce SKNonce #-}
  size = Tagged nonceLength
  toBS (SKNonce b)   = b
  fromBS x
    | S.length x == nonceLength = Just (SKNonce x)
    | otherwise                 = Nothing


encrypt :: SKNonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input
        -> SecretKey
        -- ^ Secret key
        -> ByteString
        -- ^ Ciphertext
encrypt (SKNonce n) msg (SecretKey k) = unsafePerformIO $ do
  let mlen = S.length msg + msg_ZEROBYTES
  c <- SI.mallocByteString mlen
  
  -- inputs to crypto_box must be padded
  let m = S.replicate msg_ZEROBYTES 0x0 `S.append` msg
  
  -- as you can tell, this is unsafe
  void $ withForeignPtr c $ \pc ->
    SU.unsafeUseAsCString m $ \pm ->
      SU.unsafeUseAsCString n $ \pn -> 
        SU.unsafeUseAsCString k $ \pk ->
          c_crypto_secretbox pc pm (fromIntegral mlen) pn pk
  
  let r = SI.fromForeignPtr c 0 mlen
  return $ SU.unsafeDrop msg_BOXZEROBYTES r
{-# INLINEABLE encrypt #-}

decrypt :: SKNonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input
        -> SecretKey        
        -- ^ Secret key
        -> Maybe ByteString 
        -- ^ Ciphertext
decrypt (SKNonce n) cipher (SecretKey k) = unsafePerformIO $ do
  let clen = S.length cipher + msg_BOXZEROBYTES
  m <- SI.mallocByteString clen
  
  -- inputs to crypto_box must be padded
  let c = S.replicate msg_BOXZEROBYTES 0x0 `S.append` cipher
  
  -- as you can tell, this is unsafe
  r <- withForeignPtr m $ \pm ->
    SU.unsafeUseAsCString c $ \pc ->
      SU.unsafeUseAsCString n $ \pn -> 
        SU.unsafeUseAsCString k $ \pk ->
          c_crypto_secretbox_open pm pc (fromIntegral clen) pn pk
  
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
nonceLength = #{const crypto_secretbox_NONCEBYTES}

-- | Length of a 'SecretKey' needed for encryption/decryption.
keyLength :: Int
keyLength        = #{const crypto_secretbox_KEYBYTES}


msg_ZEROBYTES,msg_BOXZEROBYTES :: Int
msg_ZEROBYTES    = #{const crypto_secretbox_ZEROBYTES}
msg_BOXZEROBYTES = #{const crypto_secretbox_BOXZEROBYTES}


foreign import ccall unsafe "glue_crypto_secretbox"
  c_crypto_secretbox :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                        Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_secretbox_open"
  c_crypto_secretbox_open :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                             Ptr CChar -> Ptr CChar -> IO Int

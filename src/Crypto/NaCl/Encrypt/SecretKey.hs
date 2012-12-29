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
-- combination of XSalsa20 and Poly1305. See the specification,
-- \"Cryptography in NaCl\":
-- <http://cr.yp.to/highspeed/naclcrypto-20090310.pdf>
--
module Crypto.NaCl.Encrypt.SecretKey
       ( -- * Nonces
         SKNonce             -- :: *
       , zeroNonce           -- :: SKNonce
       , randomNonce         -- :: IO SKNonce
       , incNonce            -- :: SKNonce -> SKNonce

         -- * Encryption/decryption
       , SecretEncryptionKey -- :: *
       , encrypt             -- :: SKNonce -> ByteString -> SecretKey -> ByteString
       , decrypt             -- :: SKNonce -> ByteString -> SecretKey -> Maybe ByteString

         -- * Misc
       , keyLength           -- :: Int
       ) where
import Foreign.ForeignPtr (withForeignPtr)
import Data.Tagged

import Control.Monad (void)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import qualified Crypto.NaCl.Internal as I

import Crypto.NaCl.Key
import Crypto.NaCl.FFI

--
-- Nonces
--
data SKNonce = SKNonce ByteString deriving (Show, Eq)
instance I.Nonce SKNonce where
  {-# SPECIALIZE instance I.Nonce SKNonce #-}
  size = Tagged skNonceLength
  toBS (SKNonce b)   = b
  fromBS x
    | S.length x == skNonceLength = Just (SKNonce x)
    | otherwise                   = Nothing

-- | A nonce which is just a byte array of zeroes.
zeroNonce :: SKNonce
zeroNonce = I.createZeroNonce

-- | Create a random nonce for public key encryption
randomNonce :: IO SKNonce
randomNonce = I.createRandomNonce

-- | Increment a nonce by one.
incNonce :: SKNonce -> SKNonce
incNonce x = I.incNonce x

--
-- Main interface
--

-- | A type which represents the appropriate index for
-- a 'Crypto.NaCl.Key.Key' for signatures.
data SecretEncryptionKey -- :: *

-- | TODO FIXME
encrypt :: SKNonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input
        -> Key Secret SecretEncryptionKey
        -- ^ Secret key
        -> ByteString
        -- ^ Ciphertext
encrypt (SKNonce n) msg (Key k) = unsafePerformIO $ do
  let mlen = S.length msg + sk_msg_ZEROBYTES
  c <- SI.mallocByteString mlen

  -- inputs to crypto_box must be padded
  let m = S.replicate sk_msg_ZEROBYTES 0x0 `S.append` msg

  -- as you can tell, this is unsafe
  void $ withForeignPtr c $ \pc ->
    SU.unsafeUseAsCString m $ \pm ->
      SU.unsafeUseAsCString n $ \pn ->
        SU.unsafeUseAsCString k $ \pk ->
          c_crypto_secretbox pc pm (fromIntegral mlen) pn pk

  let r = SI.fromForeignPtr c 0 mlen
  return $ SU.unsafeDrop sk_msg_BOXZEROBYTES r
{-# INLINEABLE encrypt #-}

-- | TODO FIXME
decrypt :: SKNonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input
        -> Key Secret SecretEncryptionKey
        -- ^ Secret key
        -> Maybe ByteString
        -- ^ Ciphertext
decrypt (SKNonce n) cipher (Key k) = unsafePerformIO $ do
  let clen = S.length cipher + sk_msg_BOXZEROBYTES
  m <- SI.mallocByteString clen

  -- inputs to crypto_box must be padded
  let c = S.replicate sk_msg_BOXZEROBYTES 0x0 `S.append` cipher

  -- as you can tell, this is unsafe
  r <- withForeignPtr m $ \pm ->
    SU.unsafeUseAsCString c $ \pc ->
      SU.unsafeUseAsCString n $ \pn ->
        SU.unsafeUseAsCString k $ \pk ->
          c_crypto_secretbox_open pm pc (fromIntegral clen) pn pk

  return $ if r /= 0 then Nothing
            else
             let bs = SI.fromForeignPtr m 0 clen
             in Just $ SU.unsafeDrop sk_msg_ZEROBYTES bs
{-# INLINEABLE decrypt #-}

-- | Length of a 'SecretKey' needed for encryption/decryption.
keyLength :: Int
keyLength = skKeyLength

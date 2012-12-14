{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.NaCl.Encrypt.Stream
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
-- 
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable
-- 
-- Fast streaming encryption. The underlying primitive is
-- @crypto_stream_xsalsa20@, a particular cipher specified in,
-- \"Cryptography in NaCl\":
-- <http://cr.yp.to/highspeed/naclcrypto-20090310.pdf>
-- 
module Crypto.NaCl.Encrypt.Stream
       ( -- * Nonces
         StreamNonce            -- :: * -> *
       , zeroNonce              -- :: StreamNonce
       , randomNonce            -- :: IO StreamNonce
       , incNonce               -- :: StreamNonce -> StreamNonce
         
         -- * Stream generation
       , streamGen              -- :: Nonce -> SecretKey -> ByteString

         -- * Encryption and decryption
       , StreamingEncryptionKey -- :: *
       , encrypt                -- :: Nonce -> ByteString -> SecretKey -> ByteString
       , decrypt                -- :: Nonce -> ByteString -> SecretKey -> ByteString
         
         -- * Misc
       , keyLength              -- :: Int
       ) where
import Foreign.Ptr
import Foreign.C.Types
import Data.Word
import Data.Tagged
import Control.Monad (void)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import qualified Crypto.NaCl.Internal as I

import Crypto.NaCl.Key

#include <crypto_stream_xsalsa20.h>

--
-- Nonces
--
data StreamNonce = StreamNonce ByteString deriving (Show, Eq)
instance I.Nonce StreamNonce where
  {-# SPECIALIZE instance I.Nonce StreamNonce #-}
  size = Tagged nonceLength
  toBS (StreamNonce b)   = b
  fromBS x
    | S.length x == nonceLength = Just (StreamNonce x)
    | otherwise                 = Nothing

-- | A nonce which is just a byte array of zeroes.
zeroNonce :: StreamNonce
zeroNonce = I.createZeroNonce

-- | Create a random nonce for public key encryption
randomNonce :: IO StreamNonce
randomNonce = I.createRandomNonce

-- | Increment a nonce by one.
incNonce :: StreamNonce -> StreamNonce
incNonce x = I.incNonce x

--
-- Main interface
--

-- | A type which represents the appropriate index for
-- a 'Crypto.NaCl.Key.Key' for signatures.
data StreamingEncryptionKey -- :: *

-- | Given a 'Nonce' @n@, size @s@ and 'SecretKey' @sk@, @streamGen n
-- s sk@ generates a cryptographic stream of length @s@.
streamGen :: StreamNonce
          -- ^ Nonce
          -> Int
          -- ^ Size
          -> Key Secret StreamingEncryptionKey
          -- ^ Input
          -> ByteString
          -- ^ Resulting crypto stream
streamGen (StreamNonce n) sz (Key sk)
  | S.length sk /= keyLength
  = error "Crypto.NaCl.Encrypt.Stream.XSalsa20.streamGen: bad key length"
  | otherwise
  = unsafePerformIO . SI.create sz $ \out ->
    SU.unsafeUseAsCString n $ \pn ->
      SU.unsafeUseAsCString sk $ \psk ->
        void $ c_crypto_stream_xsalsa20 out (fromIntegral sz) pn psk
{-# INLINEABLE streamGen #-}

-- | Given a 'Nonce' @n@, plaintext @p@ and 'SecretKey' @sk@, @encrypt
-- n p sk@ encrypts the message @p@ using 'SecretKey' @sk@ and returns
-- the result.
-- 
-- 'encrypt' guarantees the resulting ciphertext is the plaintext
-- bitwise XOR'd with the result of 'streamGen'. As a result,
-- 'encrypt' can also be used to decrypt messages.
encrypt :: StreamNonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input plaintext
        -> Key Secret StreamingEncryptionKey
        -- ^ Secret key
        -> ByteString
        -- ^ Ciphertext
encrypt (StreamNonce n) msg (Key sk)
  | S.length sk /= keyLength
  = error "Crypto.NaCl.Encrypt.Stream.XSalsa20.encrypt: bad key length"
  | otherwise
  = let l = S.length msg
    in unsafePerformIO . SI.create l $ \out ->
      SU.unsafeUseAsCString msg $ \cstr -> 
        SU.unsafeUseAsCString n $ \pn ->
          SU.unsafeUseAsCString sk $ \psk ->
            void $ c_crypto_stream_xsalsa20_xor out cstr (fromIntegral l) pn psk
{-# INLINEABLE encrypt #-}

-- | Simple alias for 'encrypt'.
decrypt :: StreamNonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input ciphertext
        -> Key Secret StreamingEncryptionKey
        -- ^ Secret key
        -> ByteString
        -- ^ Plaintext
decrypt n c sk = encrypt n c sk
{-# INLINEABLE decrypt #-}


-- 
-- FFI
-- 

-- | Length of a 'SecretKey' needed for encryption/decryption.
keyLength :: Int
keyLength = #{const crypto_stream_xsalsa20_KEYBYTES}

-- | Length of a 'Nonce' needed for encryption/decryption.
nonceLength :: Int
nonceLength = #{const crypto_stream_xsalsa20_NONCEBYTES}

foreign import ccall unsafe "glue_crypto_stream_xsalsa20"
  c_crypto_stream_xsalsa20 :: Ptr Word8 -> CULLong -> Ptr CChar -> 
                              Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_stream_xsalsa20_xor"
  c_crypto_stream_xsalsa20_xor :: Ptr Word8 -> Ptr CChar -> 
                                  CULLong -> Ptr CChar -> Ptr CChar -> IO Int

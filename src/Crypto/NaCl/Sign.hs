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
       ( -- * Types
         SigningKey                    -- :: *
       , Signature(..)                 -- :: *
         -- * Keypair creation
       , createKeypair                 -- :: IO (KeyPair SigningKey)
         -- * Signing and verifying messages
       , sign                          -- :: Key Secret SigningKey -> ByteString -> ByteString
       , sign'                         -- :: Key Secret SigningKey -> ByteString -> Signature
       , verify                        -- :: Key Public SigningKey -> ByteString -> Maybe ByteString
       , verify'                       -- :: Key Public SigningKey -> ByteString -> Signature
       , signPublicKeyLength           -- :: Int
       , signSecretKeyLength           -- :: Int
       ) where
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Storable
import Control.Monad (void, liftM)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import Crypto.NaCl.Key
import Crypto.NaCl.FFI

-- | A type which represents the appropriate index for
-- a 'Crypto.NaCl.Key.Key' for signatures.
data SigningKey -- :: *

-- | A 'Signature'. Used with 'sign\'' and 'verify\''.
newtype Signature = Signature { unSignature :: ByteString }
        deriving (Eq, Show, Ord)

-- | Randomly generate a public and private key for doing
-- authenticated signing and verification.
createKeypair :: IO (KeyPair SigningKey)
createKeypair = do
  pk <- SI.mallocByteString signPublicKeyLength
  sk <- SI.mallocByteString signSecretKeyLength

  void $ withForeignPtr pk $ \ppk ->
    void $ withForeignPtr sk $ \psk ->
      c_crypto_sign_keypair ppk psk

  return (Key $ SI.fromForeignPtr pk 0 signPublicKeyLength,
          Key $ SI.fromForeignPtr sk 0 signSecretKeyLength)

-- | Sign a message with a particular 'SecretKey'.
sign :: Key Secret SigningKey
     -- ^ Signers secret key
     -> ByteString
     -- ^ Input message
     -> ByteString
     -- ^ Resulting signed message
sign (Key sk) xs =
  unsafePerformIO $ SU.unsafeUseAsCStringLen xs $ \(mstr,mlen) ->
    SU.unsafeUseAsCString sk $ \psk ->
      SI.createAndTrim (mlen+sign_BYTES) $ \out ->
       fromIntegral `liftM` c_crypto_sign out mstr (fromIntegral mlen) psk
{-# INLINEABLE sign #-}

-- | Sign a message with a particular 'SecretKey', only returning the signature
-- without the message.
sign' :: Key Secret SigningKey
      -- ^ Signers secret key
      -> ByteString
      -- ^ Input message
      -> Signature
      -- ^ Message signature, without the message
sign' sk xs =
  let sm = sign sk xs
      l  = S.length sm
  in Signature $! S.take (l - S.length xs) sm
{-# INLINEABLE sign' #-}

-- | Verifies a signed message with a 'PublicKey'. Returns @Nothing@ if
-- verification fails, or @Just xs@ where @xs@ is the original message if it
-- succeeds.
verify :: Key Public SigningKey
       -- ^ Signers public key
       -> ByteString
       -- ^ Signed message
       -> Maybe ByteString
       -- ^ Verification check
verify (Key pk) xs =
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

-- | Verify that a message came from someone\'s 'PublicKey'
-- using an input message and a signature derived from 'sign\''
verify' :: Key Public SigningKey
        -- ^ Signers\' public key
        -> ByteString
        -- ^ Input message, without signature
        -> Signature
        -- ^ Message signature
        -> Maybe ByteString
verify' pk xs (Signature sig) = verify pk (sig `S.append` xs)
{-# INLINEABLE verify' #-}

{-# LANGUAGE CPP #-}
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
         PublicKey, SecretKey, KeyPair -- :: *
       , PKNonce                       -- :: *
       -- ** Keypair creation
       , createKeypair                 -- :: IO KeyPair
       -- ** Encryption, Decryption
       , encrypt                       -- :: Nonce -> ByteString -> PublicKey -> SecretKey -> ByteString
       , decrypt                       -- :: Nonce -> ByteString -> PublicKey -> SecretKey -> Maybe ByteString

       -- ** Precomputation interface
       -- $precomp
       , NM                            -- :: *
       , createNM                      -- :: KeyPair -> NM
       , encryptNM                     -- :: NM -> Nonce -> ByteString -> ByteString
       , decryptNM                     -- :: NM -> Nonce -> ByteString -> Maybe ByteString
         
       -- ** Miscellaneous
       , publicKeyLength               -- :: Int
       , secretKeyLength               -- :: Int
       , nonceLength                   -- :: NonceLength PKNonce
       , nmLength                      -- :: Int
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

data PKNonce

#include <crypto_box.h>

-- TODO:
--  * internal refactors (try to reduce boilerplate)

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

encrypt :: Nonce PKNonce
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
  
decrypt :: Nonce PKNonce
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
-- Precomputation interface
-- 

{- $precomp

If you send many messages to the same receiver, or receive many
messages from the same sender, you can gain speed increases by instead
using the following precomputation interface, which splits the
encryption and decryption steps into two parts.

For encryption, you first create an 'NM' by using 'createNM', using
the senders secret key, and receivers public key. You can then use
'encryptNM' to encrypt data.

For decryption, you first create an 'NM' by using 'createNM', using
the recievers secret key, and the senders publickey. You can then use
'decryptNM' to decrypt data.

-}

-- | An 'NM' is intermediate data computed by 'createNM' given a
-- public and private key which can be used to encrypt/decrypt
-- information via 'encryptNM' or 'decryptNM'.
-- 
-- An 'NM' can be re-used between two communicators for any number of
-- messages.
-- 
-- Its name is not particularly enlightening as to its purpose, it is merely the same
-- identifier used in the NaCl source code for this interface.
newtype NM = NM ByteString deriving (Eq, Show)

-- | Creates an intermediate piece of 'NM' data for sending/receiving
-- messages to/from the same person. The resulting 'NM' can be used for
-- any number of messages between client/server.
createNM :: KeyPair -> NM
createNM (pk, sk) = unsafePerformIO $ do
  nm <- SI.mallocByteString nmLength
  void $ withForeignPtr nm $ \pnm ->
    SU.unsafeUseAsCString pk $ \ppk ->
      SU.unsafeUseAsCString sk $ \psk ->
        c_crypto_box_beforenm pnm ppk psk
  return $ NM $ SI.fromForeignPtr nm 0 nmLength
{-# INLINEABLE createNM #-}

-- | Encrypt data from a specific sender to a specific receiver with
-- some precomputed 'NM' data.
encryptNM :: NM -> Nonce PKNonce -> ByteString -> ByteString
encryptNM (NM nm) n msg = unsafePerformIO $ do
  let mlen = S.length msg + msg_ZEROBYTES
  c <- SI.mallocByteString mlen
  
  -- inputs to crypto_box_afternm must be padded
  let m = (S.replicate msg_ZEROBYTES 0x0) `S.append` msg
  
  -- as you can tell, this is unsafe
  void $ withForeignPtr c $ \pc ->
    SU.unsafeUseAsCString m $ \pm ->
      SU.unsafeUseAsCString (toBS n) $ \pn -> 
        SU.unsafeUseAsCString nm $ \pnm ->
          c_crypto_box_afternm pc pm (fromIntegral mlen) pn pnm
  
  let r = SI.fromForeignPtr c 0 mlen
  return $ SU.unsafeDrop msg_BOXZEROBYTES r
{-# INLINEABLE encryptNM #-}

-- | Decrypt data from a specific sender for a specific receiver with
-- some precomputed 'NM' data.
decryptNM :: NM -> Nonce PKNonce -> ByteString -> Maybe ByteString
decryptNM (NM nm) n cipher = unsafePerformIO $ do
  let clen = S.length cipher + msg_BOXZEROBYTES
  m <- SI.mallocByteString clen
  
  -- inputs to crypto_box must be padded
  let c = (S.replicate msg_BOXZEROBYTES 0x0) `S.append` cipher
  
  -- as you can tell, this is unsafe
  r <- withForeignPtr m $ \pm ->
    SU.unsafeUseAsCString c $ \pc ->
      SU.unsafeUseAsCString (toBS n) $ \pn -> 
        SU.unsafeUseAsCString nm $ \pnm ->
          c_crypto_box_open_afternm pm pc (fromIntegral clen) pn pnm

  return $ if r /= 0 then Nothing
            else
             let bs = SI.fromForeignPtr m 0 clen
             in Just $ SU.unsafeDrop msg_ZEROBYTES bs
{-# INLINEABLE decryptNM #-}


--
-- FFI
-- 
  
-- | Length of a 'Nonce' needed for encryption/decryption
nonceLength :: NonceLength PKNonce
nonceLength      = NonceLength #{const crypto_box_NONCEBYTES}

-- | Length of a 'PublicKey' in bytes.
publicKeyLength :: Int
publicKeyLength  = #{const crypto_box_PUBLICKEYBYTES}

-- | Length of a 'SecretKey' in bytes.
secretKeyLength :: Int
secretKeyLength  = #{const crypto_box_SECRETKEYBYTES}

-- | Length of the intermediate 'NM' data used by the precomputation
-- interface.
nmLength :: Int
nmLength         = #{const crypto_box_BEFORENMBYTES}

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

foreign import ccall unsafe "glue_crypto_box_beforenm"
  c_crypto_box_beforenm :: Ptr Word8 -> Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_box_afternm"
  c_crypto_box_afternm :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                          Ptr CChar -> Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_box_open_afternm"
  c_crypto_box_open_afternm :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                               Ptr CChar -> Ptr CChar -> IO Int

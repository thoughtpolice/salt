{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.NaCl.Encrypt.Stream
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Simple, high level API for streaming encryption with a secret
-- key. Allows selection of the underlying primitive; always defaults
-- to 'Crypto.NaCl.Encrypt.Stream.XSalsa20'.
-- 
-- You can either use this module or import the individual encryption
-- modules themselves directly; this is just a convenient high-level
-- interface for picking a particular streaming encryption method at
-- runtime.
-- 
module Crypto.NaCl.Encrypt.Stream
       ( -- * Types
         SecretKey      -- :: *
       , CryptoMode(..) -- :: *
         -- * Stream generation
       , streamGen      -- 
         -- * Encryption and decryption
       , encrypt        -- :: Nonce -> ByteString -> SecretKey -> ByteString
       , decrypt        -- :: Nonce -> ByteString -> SecretKey -> ByteString
       , keyLength      -- :: Maybe CryptoMode -> Int
       , nonceLength    -- :: Maybe CryptoMode -> Int
       ) where
import Data.ByteString

import Crypto.NaCl.Nonce
import qualified Crypto.NaCl.Encrypt.Stream.AES128CTR as AES128CTR
import qualified Crypto.NaCl.Encrypt.Stream.Salsa20 as Salsa20
import qualified Crypto.NaCl.Encrypt.Stream.Salsa2012 as Salsa2012
import qualified Crypto.NaCl.Encrypt.Stream.Salsa208 as Salsa208
import qualified Crypto.NaCl.Encrypt.Stream.XSalsa20 as XSalsa20

type SecretKey = ByteString

-- | Cryptographic modes. The streaming interface always defaults
-- to 'XSalsa20'.
data CryptoMode = AES128CTR
                | Salsa20
                | Salsa2012
                | Salsa208
                | XSalsa20
            deriving (Eq, Show)

-- | Given a 'Nonce' @n@, size @s@ and 'SecretKey' @sk@, @streamGen n
-- s sk@ generates a cryptographic stream of length @s@.
-- 
-- Defaults to 'XSalsa20'.
streamGen :: Maybe CryptoMode
          -- ^ Cryptographic mode to use.
          -- Defaults to 'Crypto.NaCl.Encrypt.Stream.XSalsa20'
          -> Nonce
          -- ^ Nonce
          -> Int
          -- ^ Size
          -> SecretKey
          -- ^ Input
          -> ByteString
          -- ^ Resulting crypto stream
streamGen  Nothing         = XSalsa20.streamGen
streamGen (Just AES128CTR) = AES128CTR.streamGen
streamGen (Just Salsa20)   = Salsa20.streamGen
streamGen (Just Salsa2012) = Salsa2012.streamGen
streamGen (Just Salsa208)  = Salsa208.streamGen
streamGen (Just XSalsa20)  = XSalsa20.streamGen
{-# INLINEABLE streamGen #-}

-- | Given a 'CryptoMode' m, 'Nonce' @n@, plaintext @p@ and 'SecretKey' @sk@, @encrypt n p sk@ encrypts the message @p@ using 'SecretKey' @sk@ and returns the result.
-- 
-- If no 'CryptoMode' is explicitly given, then the default mode is
-- 'XSalsa20'.
-- 
-- 'encrypt' guarantees the resulting ciphertext is the plaintext
-- bitwise XOR'd with the result of 'streamGen'. As a result,
-- 'encrypt' can also be used to decrypt messages.
encrypt :: Maybe CryptoMode
        -- ^ Cryptographic mode to use.
        -- Defaults to 'Crypto.NaCl.Encrypt.Stream.XSalsa20'  
        -> Nonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input plaintext
        -> SecretKey
        -- ^ Secret key
        -> ByteString
        -- ^ Ciphertext
encrypt  Nothing         = XSalsa20.encrypt
encrypt (Just AES128CTR) = AES128CTR.encrypt
encrypt (Just Salsa20)   = Salsa20.encrypt
encrypt (Just Salsa2012) = Salsa2012.encrypt
encrypt (Just Salsa208)  = Salsa208.encrypt
encrypt (Just XSalsa20)  = XSalsa20.encrypt
{-# INLINEABLE encrypt #-}

-- | Simple alias for 'encrypt'.
-- Defaults to 'XSalsa20'.
decrypt :: Maybe CryptoMode
        -- ^ Cryptographic mode to use.
        -- Defaults to 'Crypto.NaCl.Decrypt.Stream.XSalsa20'  
        -> Nonce
        -- ^ Nonce
        -> ByteString
        -- ^ Input plaintext
        -> SecretKey
        -- ^ Secret key
        -> ByteString
        -- ^ Ciphertext
decrypt  Nothing         = XSalsa20.decrypt
decrypt (Just AES128CTR) = AES128CTR.decrypt
decrypt (Just Salsa20)   = Salsa20.decrypt
decrypt (Just Salsa2012) = Salsa2012.decrypt
decrypt (Just Salsa208)  = Salsa208.decrypt
decrypt (Just XSalsa20)  = XSalsa20.decrypt
{-# INLINEABLE decrypt #-}

-- | Get the key length of a particular crypto mode.
-- Defaults to 'XSalsa20'.
keyLength :: Maybe CryptoMode -> Int
keyLength  Nothing         = XSalsa20.keyLength
keyLength (Just AES128CTR) = AES128CTR.keyLength
keyLength (Just Salsa20)   = Salsa20.keyLength
keyLength (Just Salsa2012) = Salsa2012.keyLength
keyLength (Just Salsa208)  = Salsa208.keyLength
keyLength (Just XSalsa20)  = XSalsa20.keyLength
{-# INLINEABLE keyLength #-}

-- | Get the length of a 'Nonce' of a particular crypto mode.
-- Defaults to 'XSalsa20'.
nonceLength :: Maybe CryptoMode -> Int
nonceLength  Nothing         = XSalsa20.nonceLength
nonceLength (Just AES128CTR) = AES128CTR.nonceLength
nonceLength (Just Salsa20)   = Salsa20.nonceLength
nonceLength (Just Salsa2012) = Salsa2012.nonceLength
nonceLength (Just Salsa208)  = Salsa208.nonceLength
nonceLength (Just XSalsa20)  = XSalsa20.nonceLength
{-# INLINEABLE nonceLength #-}

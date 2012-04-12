-- |
-- Module      : Crypto.NaCl.Key
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
--
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable
--
-- This module exports two simple types, 'PublicKey' and 'SecretKey'
-- which are merely @newtype@s for 'ByteString'. This is for type safety
-- so you never confuse your keys or accidentally give them 'ByteString's
-- when you shouldn't have.
module Crypto.NaCl.Key
       ( -- * Types
         PublicKey(..)
       , SecretKey(..)
       , KeyPair
       ) where
import Data.ByteString

newtype PublicKey = PublicKey { unPublicKey :: ByteString }
        deriving (Eq, Show)

newtype SecretKey = SecretKey { unSecretKey :: ByteString }
        deriving (Eq, Show)

type KeyPair = (PublicKey, SecretKey)
-- |
-- Module      : Crypto.NaCl.Sign
-- Copyright   : (c) Austin Seipp 2011
-- License     : MIT
--
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
--
-- This module exports two simple types, 'PublicKey' and 'SecretKey'
-- which are merely @newtype@s for 'ByteString'. This is for type safety
-- so you never confuse your keys or accidentally give them 'ByteString's
-- when you shouldn't have.
module Crypto.NaCl.Key
       ( PublicKey(..)
       , SecretKey(..)
       ) where
import Data.ByteString

newtype PublicKey = PublicKey { unPublicKey :: ByteString }
        deriving Eq

newtype SecretKey = SecretKey { unSecretKey :: ByteString }
        deriving Eq

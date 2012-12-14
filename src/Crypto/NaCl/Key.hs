-- |
-- Module      : Crypto.NaCl.Key
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
--
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable
--
-- Type-safe cryptographic keys via phantom types.
-- 
module Crypto.NaCl.Key
       ( -- * Types
         Key(..) -- :: k -> k -> *
       , Public  -- :: *
       , Secret  -- :: *
       , KeyPair -- :: k -> *
       ) where
import Data.ByteString

-- | A 'Key' is a type which is parametric in its *secrecy* and
-- its *index*. The type variable @s@ determines if a key is either
-- 'Secret' or 'Public'. This phantom type ensures you cannot mix
-- up two kinds of keys.
--
-- The @i@ parameter is the 'index' of the key type, which essentially
-- determines in which API it is used. For example, the Sign module
-- will only accept 'Key' types like 'Key s SigningKey', while the
-- encryption modules may only want a 'Key Secret StreamKey'.
newtype Key s i = Key { unKey :: ByteString }
        deriving (Eq, Show, Ord)

-- | A vacuous data type used to represent the secrecy of a 'Key'.
-- This is also typically called the \'private key\'.
data Secret -- :: *

-- | A vacuous data type used to represent the secrecy of a 'Key'.
data Public -- :: *

-- | A convenient type synonym for a public and secret key pair.
type KeyPair i = (Key Public i, Key Secret i)

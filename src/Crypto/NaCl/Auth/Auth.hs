-- |
-- Module      : Crypto.NaCl.Auth.Auth
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
--
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable
--
-- Fast, cryptographically strong authentication.
--
module Crypto.NaCl.Auth.Auth
       ( AuthKey           -- :: *
       , Authenticator(..) -- :: *
       , authenticate      -- :: ByteString -> ByteString -> ByteString
       , verify            -- :: ByteString -> ByteString -> ByteString -> Bool
       , authKeyLength     -- :: Int
       ) where
import Control.Monad (void)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString (ByteString)
import Data.ByteString.Internal (create)
import Data.ByteString.Unsafe (unsafeUseAsCString, unsafeUseAsCStringLen)

import Crypto.NaCl.Key
import Crypto.NaCl.FFI

-- | A type which represents the appropriate index for
-- a 'Crypto.NaCl.Key.Key' for signatures.
data AuthKey -- :: *

-- | An authenticator.
data Authenticator = Authenticator { unAuthenticator :: ByteString }
     deriving (Eq, Show, Ord)

authenticate :: Key Secret AuthKey
             -- ^ Secret key
             -> ByteString
             -- ^ Message
             -> Authenticator
             -- ^ Authenticator
authenticate (Key k) msg = Authenticator $
  unsafePerformIO . create auth_BYTES $ \out ->
    unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      unsafeUseAsCString k $ \pk ->
        void $ c_crypto_auth out cstr (fromIntegral clen) pk
{-# INLINEABLE authenticate #-}

verify :: Key Secret AuthKey
       -- ^ Key
       -> Authenticator
       -- ^ Authenticator returned via 'authenticate'
       -> ByteString
       -- ^ Message
       -> Bool
       -- ^ Result: @True@ if properly verified, @False@ otherwise
verify (Key k) (Authenticator auth) msg =
  unsafePerformIO $ unsafeUseAsCString auth $ \pauth ->
    unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      unsafeUseAsCString k $ \pk -> do
        b <- c_crypto_auth_verify pauth cstr (fromIntegral clen) pk
        return (b == 0)
{-# INLINEABLE verify #-}

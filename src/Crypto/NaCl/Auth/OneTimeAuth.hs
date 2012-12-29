-- |
-- Module      : Crypto.NaCl.Auth.OneTimeAuth
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
--
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable
--
-- Fast, cryptographically strong one-time authentication
--
module Crypto.NaCl.Auth.OneTimeAuth
       ( OneTimeAuthKey           -- :: *
       , OneTimeAuthenticator(..) -- :: *
       , authenticateOnce         -- :: ByteString -> ByteString -> ByteString
       , verifyOnce               -- :: ByteString -> ByteString -> ByteString -> Bool
       , oneTimeAuthKeyLength     -- :: Int
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
data OneTimeAuthKey -- :: *

-- | An authenticator.
data OneTimeAuthenticator
     = OneTimeAuthenticator { unOneTimeAuthenticator :: ByteString }
     deriving (Eq, Show, Ord)

authenticateOnce :: Key Secret OneTimeAuthKey
                 -- ^ Secret key
                 -> ByteString
                 -- ^ Message
                 -> OneTimeAuthenticator
                 -- ^ Authenticator
authenticateOnce (Key k) msg = OneTimeAuthenticator $
  unsafePerformIO . create onetimeauth_BYTES $ \out ->
    unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      unsafeUseAsCString k $ \pk ->
        void $ c_crypto_onetimeauth out cstr (fromIntegral clen) pk
{-# INLINEABLE authenticateOnce #-}

verifyOnce :: Key Secret OneTimeAuthKey
           -- ^ Secret key
           -> OneTimeAuthenticator
           -- ^ Authenticator returned via 'authenticateOnce'
           -> ByteString
           -- ^ Message
           -> Bool
           -- ^ Result: @True@ if verified, @False@ otherwise
verifyOnce (Key k) (OneTimeAuthenticator auth) msg =
  unsafePerformIO $ unsafeUseAsCString auth $ \pauth ->
    unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      unsafeUseAsCString k $ \pk -> do
        b <- c_crypto_onetimeauth_verify pauth cstr (fromIntegral clen) pk
        return (b == 0)
{-# INLINEABLE verifyOnce #-}

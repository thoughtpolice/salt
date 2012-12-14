{-# LANGUAGE CPP #-}
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
import Foreign.Ptr
import Foreign.C.Types
import Data.Word
import Control.Monad (void)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import Crypto.NaCl.Key

#include <crypto_onetimeauth.h>

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
  unsafePerformIO . SI.create auth_BYTES $ \out ->
    SU.unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      SU.unsafeUseAsCString k $ \pk ->
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
  unsafePerformIO $ SU.unsafeUseAsCString auth $ \pauth ->
    SU.unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      SU.unsafeUseAsCString k $ \pk -> do
        b <- c_crypto_onetimeauth_verify pauth cstr (fromIntegral clen) pk
        return (b == 0)
{-# INLINEABLE verifyOnce #-}

--
-- FFI
--
-- | @oneTimeAuthKeyLength@ is the required key length for a key given
-- to 'authenticateOnce' or 'verifyOnce'. Using any other key length
-- will result in error.
oneTimeAuthKeyLength :: Int
oneTimeAuthKeyLength = #{const crypto_onetimeauth_KEYBYTES}

auth_BYTES :: Int
auth_BYTES = #{const crypto_onetimeauth_BYTES}


foreign import ccall unsafe "glue_crypto_onetimeauth"
  c_crypto_onetimeauth :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                          Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_onetimeauth_verify"
  c_crypto_onetimeauth_verify :: Ptr CChar -> Ptr CChar -> CULLong -> 
                                 Ptr CChar -> IO Int

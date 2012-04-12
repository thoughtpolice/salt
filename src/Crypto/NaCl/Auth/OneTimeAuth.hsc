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
       ( authenticateOnce     -- :: ByteString -> ByteString -> ByteString
       , verifyOnce           -- :: ByteString -> ByteString -> ByteString -> Bool
       , oneTimeAuthKeyLength -- :: Int
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

authenticateOnce :: SecretKey
                 -- ^ Secret key
                 -> ByteString 
                 -- ^ Message
                 -> ByteString
                 -- ^ Authenticator
authenticateOnce (SecretKey k) msg = 
  unsafePerformIO . SI.create auth_BYTES $ \out ->
    SU.unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      SU.unsafeUseAsCString k $ \pk ->
        void $ c_crypto_onetimeauth out cstr (fromIntegral clen) pk
{-# INLINEABLE authenticateOnce #-}

verifyOnce :: SecretKey
           -- ^ Secret key 
           -> ByteString 
           -- ^ Authenticator returned via 'authenticateOnce'
           -> ByteString 
           -- ^ Message
           -> Bool
           -- ^ Result: @True@ if verified, @False@ otherwise
verifyOnce (SecretKey k) auth msg =
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
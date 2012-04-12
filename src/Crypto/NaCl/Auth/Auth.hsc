{-# LANGUAGE CPP #-}
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
       ( authenticate   -- :: ByteString -> ByteString -> ByteString
       , verify         -- :: ByteString -> ByteString -> ByteString -> Bool
       , authKeyLength  -- :: Int
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

#include <crypto_auth.h>

authenticate :: SecretKey
             -- ^ Secret key
             -> ByteString
             -- ^ Message 
             -> ByteString
             -- ^ Authenticator
authenticate (SecretKey k) msg = 
  unsafePerformIO . SI.create auth_BYTES $ \out ->
    SU.unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      SU.unsafeUseAsCString k $ \pk ->
        void $ c_crypto_auth out cstr (fromIntegral clen) pk
{-# INLINEABLE authenticate #-}

verify :: SecretKey
       -- ^ Key
       -> ByteString 
       -- ^ Authenticator returned via 'authenticate'
       -> ByteString 
       -- ^ Message
       -> Bool
       -- ^ Result: @True@ if properly verified, @False@ otherwise
verify (SecretKey k) auth msg =
  unsafePerformIO $ SU.unsafeUseAsCString auth $ \pauth ->
    SU.unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      SU.unsafeUseAsCString k $ \pk -> do
        b <- c_crypto_auth_verify pauth cstr (fromIntegral clen) pk
        return (b == 0)
{-# INLINEABLE verify #-}

--
-- FFI
--

-- | @authKeyLength@ is the required key length for a key given
-- to 'authenticate' or 'verify'. Using any other key length will
-- result in error.
authKeyLength :: Int
authKeyLength = #{const crypto_auth_KEYBYTES}

auth_BYTES :: Int
auth_BYTES = #{const crypto_auth_BYTES}


foreign import ccall unsafe "glue_crypto_auth"
  c_crypto_auth :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                   Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_auth_verify"
  c_crypto_auth_verify :: Ptr CChar -> Ptr CChar -> CULLong -> 
                          Ptr CChar -> IO Int
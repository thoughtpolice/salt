{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.NaCl.Auth.Auth
-- Copyright   : (c) Austin Seipp 2011
-- License     : MIT
-- 
-- Maintainer  : as@hacks.yi.org
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

#include <crypto_auth.h>

authenticate :: ByteString
             -- ^ Message
             -> ByteString 
             -- ^ Secret key
             -> ByteString
             -- ^ Authenticator
authenticate msg k = 
  unsafePerformIO . SI.create auth_BYTES $ \out ->
    SU.unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      SU.unsafeUseAsCString k $ \pk ->
        void $ c_crypto_auth out cstr (fromIntegral clen) pk
{-# INLINEABLE authenticate #-}

verify :: ByteString 
       -- ^ Authenticator
       -> ByteString 
       -- ^ Message
       -> ByteString 
       -- ^ Key
       -> Bool
       -- ^ Result: @True@ if properly verified, @False@ otherwise
verify auth msg k =
  unsafePerformIO $ SU.unsafeUseAsCString auth $ \pauth ->
    SU.unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      SU.unsafeUseAsCString k $ \pk -> do
        b <- c_crypto_auth_verify pauth cstr (fromIntegral clen) pk
        return $ if b == 0 then True else False
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

-- |
-- Module      : Crypto.NaCl.Auth.Auth
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
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

#include "crypto_auth.h"

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
        void $ glue_crypto_auth out cstr (fromIntegral clen) pk

verify :: ByteString 
       -- ^ Authenticator
       -> ByteString 
       -- ^ Message
       -> ByteString 
       -- ^ Key
       -> Bool
verify auth msg k =
  unsafePerformIO $ SU.unsafeUseAsCString auth $ \pauth ->
    SU.unsafeUseAsCStringLen msg $ \(cstr, clen) ->
      SU.unsafeUseAsCString k $ \pk -> do
        b <- glue_crypto_auth_verify pauth cstr (fromIntegral clen) pk
        return $ if b == 0 then True else False

--
-- FFI
--

authKeyLength :: Int
authKeyLength = #{const crypto_auth_KEYBYTES}

auth_BYTES :: Int
auth_BYTES = #{const crypto_auth_BYTES}


foreign import ccall unsafe "glue_crypto_auth"
  glue_crypto_auth :: Ptr Word8 -> Ptr CChar -> CULLong -> 
                      Ptr CChar -> IO Int

foreign import ccall unsafe "glue_crypto_auth_verify"
  glue_crypto_auth_verify :: Ptr CChar -> Ptr CChar -> CULLong -> 
                             Ptr CChar -> IO Int

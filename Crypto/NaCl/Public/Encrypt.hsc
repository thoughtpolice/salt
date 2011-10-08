-- |
-- Module      : Crypto.NaCl.Public.Encrypt
-- Copyright   : (c) Austin Seipp 2011
-- License     : BSD3
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Public-key encryption.
-- 
module Crypto.NaCl.Public.Encrypt 
       (  PublicKey, PrivateKey -- :: *
       ,  createKeypair         -- :: IO (ByteString, ByteString)
       -- * Miscellaneous
       , keypair_pk_size, keypair_sk_size
       ) where
import Foreign.Ptr
import Foreign.ForeignPtr (withForeignPtr)
import Data.Word
import Control.Monad (void)

import Data.ByteString as S
import Data.ByteString.Internal as SI

type PublicKey  = ByteString
type PrivateKey = ByteString

-- | Randomly generate a public and private key
-- for doing authenticated encryption.
createKeypair :: IO (PublicKey, PrivateKey)
createKeypair = do
  pk <- SI.mallocByteString keypair_pk_size
  sk <- SI.mallocByteString keypair_sk_size

  void $ withForeignPtr pk $ \ppk ->
    void $ withForeignPtr sk $ \psk ->
      glue_crypto_box_keypair ppk psk
      
  return (SI.fromForeignPtr pk 0 keypair_pk_size, 
          SI.fromForeignPtr sk 0 keypair_sk_size)

--
-- FFI
-- 

#include "crypto_box.h"

keypair_sk_size, keypair_pk_size :: Int
keypair_sk_size = #{const crypto_box_SECRETKEYBYTES}
keypair_pk_size = #{const crypto_box_PUBLICKEYBYTES}

foreign import ccall unsafe "glue_crypto_box_keypair"
  glue_crypto_box_keypair :: Ptr Word8 -> Ptr Word8 -> IO Int

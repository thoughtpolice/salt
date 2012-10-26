{-# LANGUAGE ScopedTypeVariables #-}
-- |
-- Module      : Crypto.NaCl.Internal
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
-- 
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : GHC (ScopedTypeVariables)
-- 
-- Internal module.
-- 
module Crypto.NaCl.Internal
  ( -- * Nonce class
    Nonce, size, toBS, fromBS
  , createZeroNonce   -- :: Nonce k => k
  , createRandomNonce -- :: Nonce k => IO k
  , incNonce          -- :: Nonce k => k -> k
  ) where
import Foreign.Ptr
import Foreign.C.Types
import Control.Monad (liftM)
import Data.Word
import Data.Maybe
import Data.Tagged
import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

import Crypto.NaCl.Random (randomBytes)

class Nonce k where
  size              :: Tagged k Int
  toBS              :: k -> ByteString
  fromBS            :: ByteString -> (Maybe k)

  -- | Create an empty nonce of length @n@ where all the bytes are zero.
  createZeroNonce :: k
  createZeroNonce
    = fromJust . fromBS $ S.replicate sz 0x0
    where sz = unTagged (size :: Tagged k Int)
  {-# INLINEABLE createZeroNonce #-}

  -- | Create a random nonce, seeded by @/dev/urandom@.
  createRandomNonce :: IO k
  createRandomNonce
    = (fromJust . fromBS) `liftM` randomBytes sz
    where sz = unTagged (size :: Tagged k Int)
  {-# INLINEABLE createRandomNonce #-}
  
  -- | Increment a Nonce by 1.
  incNonce :: k -> k
  incNonce n =
    (fromJust . fromBS) $ SI.unsafeCreate l $ \out -> do
      SU.unsafeUseAsCStringLen (toBS n) $ \(b,blen) ->
        SI.memcpy out (castPtr b) (fromIntegral blen)
      c_incnonce out (fromIntegral l)
    where l = unTagged (size :: Tagged k Int)
  {-# INLINEABLE incNonce #-}


-- 
-- FFI
-- 

foreign import ccall unsafe "glue_incnonce"
  c_incnonce :: Ptr Word8 -> CSize -> IO ()

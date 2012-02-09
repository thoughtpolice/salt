{-# LANGUAGE ScopedTypeVariables #-}
-- |
-- Module      : Crypto.NaCl.Nonce
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
-- 
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : GHC (ScopedTypeVariables)
-- 
-- Simple API for cryptographic nonces.
-- 
module Crypto.NaCl.Nonce where
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
  
  -- | @clearBytes n nonce@ clears the last @n@ bytes of the Nonce and
  -- makes them all 0. This is useful for the pattern of generating a
  -- cryptographic nonce randomly, clearing the last @n@ bytes, and then
  -- using 'incNonce' to increment the 'Nonce' for communication with
  -- another party.
  -- 
  -- Invariants:
  -- 
  -- * @n@ must be less than the size of the @nonce@
  -- 
  -- Properties:
  -- 
  -- > clearBytes (nonceLen nonce) nonce == createZeroNonce (nonceLen nonce)
  -- 
  clearBytes :: Int -> k -> k
  clearBytes n x
    | n > l  = error "Crypto.NaCl.Nonce.clearBytes: n > length of nonce"
    | n < 0  = error "Crypto.NaCl.Nonce.clearBytes: n < 0"  
    | n == 0 = x
    | otherwise = (fromJust . fromBS) $! S.take (l - n) (toBS x) `S.append` S.replicate n 0x0
    where l = unTagged (size :: Tagged k Int)
  {-# INLINEABLE clearBytes #-}

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

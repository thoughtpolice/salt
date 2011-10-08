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
       ) where
import Foreign.Ptr
import Foreign.C.Types
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Storable
import Data.Word
import Control.Monad (void, liftM)

import System.IO.Unsafe (unsafePerformIO)

import Data.ByteString as S
import Data.ByteString.Internal as SI
import Data.ByteString.Unsafe as SU

#include "crypto_auth.h"

authenticate :: ByteString -> ByteString -> ByteString
authenticate = undefined

verify :: ByteString -> ByteString -> ByteString -> Bool
verify = undefined

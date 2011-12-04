-- |
-- Module      : Crypto.NaCl.Auth
-- Copyright   : (c) Austin Seipp 2011
-- License     : MIT
-- 
-- Maintainer  : as@hacks.yi.org
-- Stability   : experimental
-- Portability : portable
-- 
-- Fast, cryptographically strong authentication and one-time
-- authentication.
-- 
module Crypto.NaCl.Auth
       ( -- * Secret-key authentication
         module Crypto.NaCl.Auth.Auth
         -- * Secret-key one-time authentication
       , module Crypto.NaCl.Auth.OneTimeAuth
       ) where
import Crypto.NaCl.Auth.Auth
import Crypto.NaCl.Auth.OneTimeAuth

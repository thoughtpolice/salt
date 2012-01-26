-- |
-- Module      : Crypto.NaCl.Auth
-- Copyright   : (c) Austin Seipp 2011-2012
-- License     : MIT
-- 
-- Maintainer  : mad.one@gmail.com
-- Stability   : experimental
-- Portability : portable
-- 
-- Fast, cryptographically strong authentication and one-time
-- authentication.
-- 
-- This module exports both 'Crypto.NaCl.Auth.Auth' and
-- 'Crypto.NaCl.Auth.OneTimeAuth' for convenience.
module Crypto.NaCl.Auth
       ( -- * Secret-key authentication
         module Crypto.NaCl.Auth.Auth
         -- * Secret-key one-time authentication
       , module Crypto.NaCl.Auth.OneTimeAuth
       ) where
import Crypto.NaCl.Auth.Auth
import Crypto.NaCl.Auth.OneTimeAuth

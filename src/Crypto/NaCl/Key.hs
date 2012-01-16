module Crypto.NaCl.Key
       ( PublicKey(..)
       , SecretKey(..)
       ) where
import Data.ByteString

newtype PublicKey = PublicKey { unPublicKey :: ByteString }
        deriving Eq

newtype SecretKey = SecretKey { unSecretKey :: ByteString }
        deriving Eq

module Main
       ( main -- :: IO ()
       ) where
import Data.Word
import Control.Monad (liftM)
import Data.ByteString (pack, ByteString)
import Test.QuickCheck

import Test.Framework (defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Crypto.NaCl.Hash (cryptoHash, cryptoHash_SHA256)

main :: IO ()
main = defaultMain [ 
  testGroup "Public key" [
                         ]
  , testGroup "Secret key" [
                           ]
  , testGroup "Hashing" [
       testProperty "sha256/pure" prop_sha256_pure
     , testProperty "sha512/pure" prop_sha512_pure
     ]
  ]

instance Arbitrary ByteString where
  arbitrary = pack `liftM` (arbitrary :: Gen [Word8])

prop_sha256_pure :: ByteString -> Bool
prop_sha256_pure xs = cryptoHash_SHA256 xs == cryptoHash_SHA256 xs
  
prop_sha512_pure :: ByteString -> Bool
prop_sha512_pure xs = cryptoHash xs == cryptoHash xs

module Main
       ( main -- :: IO ()
       ) where
import Data.Word
import Control.Monad (liftM)
import Data.ByteString as S (pack, length, ByteString)

import Test.Framework (defaultMain, testGroup)
import Test.QuickCheck
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.HUnit
import Test.Framework.Providers.HUnit (testCase)

import Crypto.NaCl.Hash (cryptoHash, cryptoHash_SHA256)
import Crypto.NaCl.Random (randomBytes)

main :: IO ()
main = defaultMain [ 
  testGroup "Public key" [
                         ]
  , testGroup "Secret key" [
                           ]
  , testGroup "Hashing" [
       testProperty "sha256/pure"   prop_sha256_pure
     , testProperty "sha256/length" prop_sha256_length
     , testProperty "sha512/pure"   prop_sha512_pure
     , testProperty "sha512/length" prop_sha512_length
     ]
  , testCase "randomness" case_random
  ]

-- Orphan arbitrary instance for ByteString
instance Arbitrary ByteString where
  arbitrary = pack `liftM` (arbitrary :: Gen [Word8])


-- Hashing properties
prop_sha256_pure :: ByteString -> Bool
prop_sha256_pure xs = cryptoHash_SHA256 xs == cryptoHash_SHA256 xs
  
prop_sha256_length :: ByteString -> Bool
prop_sha256_length xs = S.length (cryptoHash_SHA256 xs) == 32

prop_sha512_pure :: ByteString -> Bool
prop_sha512_pure xs = cryptoHash xs == cryptoHash xs

prop_sha512_length :: ByteString -> Bool
prop_sha512_length xs = S.length (cryptoHash xs) == 64

-- Randomness
case_random :: Assertion
case_random = do
  sequence_ $ flip map [1..20] $ \i -> do
    x <- randomBytes i
    S.length x @?= i

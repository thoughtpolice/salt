module Main
       ( main -- :: IO ()
       ) where
import Data.Word
import Control.Monad (liftM)
import Data.ByteString as S (pack, length, ByteString)
import Data.Maybe

import Test.Framework (defaultMain, testGroup)
import Test.QuickCheck
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.HUnit
import Test.Framework.Providers.HUnit (testCase)

import Crypto.NaCl.Hash (cryptoHash, cryptoHash_SHA256)
import Crypto.NaCl.Random (randomBytes)
import Crypto.NaCl.Encrypt as PEnc
import Crypto.NaCl.Sign as Sign

main :: IO ()
main = do
  k1 <- PEnc.createKeypair
  k2 <- PEnc.createKeypair
  n  <- randomBytes nonceBytes
  
  s1 <- Sign.createKeypair
  defaultMain [ testGroup "Public key" 
                [ testCase "generated key length (encryption)" case_pubkey_len
                , testCase "generated key length (signatures)" case_signkey_len
                , testProperty "encrypt/decrypt" (prop_pubkey_pure k1 k2 n)
                , testProperty "sign/verify" (prop_sign_verify s1)
                ]
              , testGroup "Secret key" 
                [
                ]
              , testGroup "Hashing" 
                [ testProperty "sha256/pure"   prop_sha256_pure
                , testProperty "sha256/length" prop_sha256_length
                , testProperty "sha512/pure"   prop_sha512_pure
                , testProperty "sha512/length" prop_sha512_length
                ]
                
                -- Misc
              , testCase "Randomness" case_random
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
case_random = doit 20 $ \i -> do
  x <- randomBytes i
  S.length x @?= i

-- Public-key encryption etc

case_pubkey_len :: Assertion
case_pubkey_len = doit 20 $ \_ -> do
  (pk,sk) <- PEnc.createKeypair
  S.length pk @?= keypair_pk_size
  S.length sk @?= keypair_sk_size

case_signkey_len :: Assertion
case_signkey_len = doit 20 $ \_ -> do
  (pk,sk) <- Sign.createKeypair
  S.length pk @?= sign_pk_size
  S.length sk @?= sign_sk_size

prop_pubkey_pure :: PEnc.KeyPair -> PEnc.KeyPair -> ByteString -> ByteString -> Bool
prop_pubkey_pure (pk1,sk1) (pk2,sk2) n xs
  = let enc = encrypt n xs pk2 sk1
        dec = decrypt n enc pk1 sk2
    in maybe False (== xs) dec

prop_sign_verify :: Sign.KeyPair -> ByteString -> Bool
prop_sign_verify (pk,sk) xs
  = let s = sign sk xs
        d = verify pk s
    in maybe False (== xs) d

-- Utilities
  
doit :: Int -> (Int -> IO a) -> IO ()
doit n f = sequence_ $ map f [1..n]

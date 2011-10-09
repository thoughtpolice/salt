module Main
       ( main -- :: IO ()
       ) where
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
import Crypto.NaCl.Encrypt.PublicKey as PubKey
import Crypto.NaCl.Encrypt.SecretKey as SecretKey
import Crypto.NaCl.Sign as Sign
import Crypto.NaCl.Nonce
import Crypto.NaCl.Auth as Auth

main :: IO ()
main = do
  k1 <- PubKey.createKeypair
  k2 <- PubKey.createKeypair
  n  <- randomBytes PubKey.nonceLength
  
  s1 <- Sign.createKeypair
  
  key <- randomBytes SecretKey.keyLength
  n2  <- randomBytes SecretKey.nonceLength
  
  defaultMain [ testGroup "Public key"
                [ testCase "generated key length (encryption)" case_pubkey_len
                , testCase "generated key length (signatures)" case_signkey_len
                , testProperty "encrypt/decrypt" (prop_pubkey_pure k1 k2 n)
                , testProperty "sign/verify" (prop_sign_verify s1)
                ]
              , testGroup "Secret key" 
                [ testProperty "authenticated encrypt/decrypt" (prop_secretkey_pure key n2)
                ]
              , testGroup "Authentication"
                [ testProperty "auth works" prop_auth_works
                , testProperty "onetimeauth works" prop_onetimeauth_works
                ]
              , testGroup "Nonce"
                [ testProperty "incNonce/pure"    prop_nonce_pure
                , testProperty "length"  prop_nonce_length
                , testProperty "clearBytes invariant" prop_nonce_clear_inv
                , testProperty "clearBytes/pure" prop_nonce_clear_pure
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

-- Orphan Arbitrary instances
instance Arbitrary ByteString where
  arbitrary = pack `liftM` arbitrary

instance Arbitrary Nonce where
  -- Nonces shouldn't be arbitrarily huge
  arbitrary = do
    n <- choose (0, 128) :: Gen Int
    (fromBS . pack) `liftM` (vectorOf n arbitrary)
newtype AuthKey = AuthKey ByteString deriving (Eq, Show)
instance Arbitrary AuthKey where
  arbitrary = (AuthKey . pack) `liftM` (vectorOf authKeyLength arbitrary)

newtype OneTimeAuthKey = OneTimeAuthKey ByteString deriving (Eq, Show)
instance Arbitrary OneTimeAuthKey where
  arbitrary = (OneTimeAuthKey . pack) `liftM` (vectorOf oneTimeAuthKeyLength arbitrary)
    



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
  (pk,sk) <- PubKey.createKeypair
  S.length pk @?= publicKeyLength
  S.length sk @?= secretKeyLength

case_signkey_len :: Assertion
case_signkey_len = doit 20 $ \_ -> do
  (pk,sk) <- Sign.createKeypair
  S.length pk @?= signPublicKeyLength
  S.length sk @?= signSecretKeyLength

prop_pubkey_pure :: PubKey.KeyPair -> PubKey.KeyPair -> ByteString -> ByteString -> Bool
prop_pubkey_pure (pk1,sk1) (pk2,sk2) n xs
  = let enc = PubKey.encrypt n xs pk2 sk1
        dec = PubKey.decrypt n enc pk1 sk2
    in maybe False (== xs) dec

-- Signatures

prop_sign_verify :: Sign.KeyPair -> ByteString -> Bool
prop_sign_verify (pk,sk) xs
  = let s = Sign.sign sk xs
        d = Sign.verify pk s
    in maybe False (== xs) d

-- Secret-key authenticated encryption

prop_secretkey_pure :: SecretKey.SecretKey -> ByteString -> ByteString -> Bool
prop_secretkey_pure k n xs
  = let enc = SecretKey.encrypt n xs k
        dec = SecretKey.decrypt n enc k
    in maybe False (== xs) dec

-- Nonces

prop_nonce_pure :: Nonce -> Bool
prop_nonce_pure n = incNonce n == incNonce n

prop_nonce_length :: Property
prop_nonce_length
  -- We don't want to generate absurdly large nonces in this test.
  -- Unless you like running out of memory, that is.
  = forAll (choose (0, 128)) $ \x -> nonceLen (createZeroNonce x) == x

prop_nonce_clear_inv :: Nonce -> Bool
prop_nonce_clear_inv n
  = clearBytes (nonceLen n) n == createZeroNonce (nonceLen n)

prop_nonce_clear_pure :: Nonce -> NonNegative Int -> Property
prop_nonce_clear_pure n (NonNegative i)
  = i <= nonceLen n ==> clearBytes i n == clearBytes i n

-- Authentication

prop_auth_works :: AuthKey -> ByteString -> Bool
prop_auth_works (AuthKey k) msg
  = Auth.verify (Auth.authenticate msg k) msg k

prop_onetimeauth_works :: OneTimeAuthKey -> ByteString -> Bool
prop_onetimeauth_works (OneTimeAuthKey k) msg
  = Auth.verifyOnce (Auth.authenticateOnce msg k) msg k
-- Utilities
  
doit :: Int -> (Int -> IO a) -> IO ()
doit n f = sequence_ $ map f [1..n]

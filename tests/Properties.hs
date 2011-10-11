{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main
       ( main -- :: IO ()
       ) where
import Control.Monad (liftM)
import Data.ByteString as S (pack, length, ByteString, zipWith)
import Data.Maybe
import Data.Bits

import Test.Framework (defaultMain, testGroup)
import Test.QuickCheck
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.HUnit
import Test.Framework.Providers.HUnit (testCase)

import Crypto.NaCl.Hash (cryptoHash, cryptoHash_SHA256)
import Crypto.NaCl.Random (randomBytes)
import Crypto.NaCl.Encrypt.PublicKey as PubKey
import Crypto.NaCl.Encrypt.SecretKey as SecretKey

import Crypto.NaCl.Encrypt.Stream as Stream
import qualified Crypto.NaCl.Encrypt.Stream.AES128CTR as AES128CTR
import qualified Crypto.NaCl.Encrypt.Stream.Salsa20 as Salsa20
import qualified Crypto.NaCl.Encrypt.Stream.Salsa2012 as Salsa2012
import qualified Crypto.NaCl.Encrypt.Stream.Salsa208 as Salsa208
import qualified Crypto.NaCl.Encrypt.Stream.XSalsa20 as XSalsa20

import Crypto.NaCl.Sign as Sign
import Crypto.NaCl.Nonce
import Crypto.NaCl.Auth as Auth

main :: IO ()
main = do
  k1 <- PubKey.createKeypair
  k2 <- PubKey.createKeypair
  n  <- createRandomNonce PubKey.nonceLength
  
  s1 <- Sign.createKeypair
  
  key <- randomBytes SecretKey.keyLength
  n2  <- createRandomNonce SecretKey.nonceLength
  
  n3_aes128ctr <- createRandomNonce $ Stream.nonceLength $ Just AES128CTR
  n3_salsa20 <- createRandomNonce $ Stream.nonceLength $ Just Salsa20
  n3_salsa2012 <- createRandomNonce $ Stream.nonceLength $ Just Salsa2012
  n3_salsa208 <- createRandomNonce $ Stream.nonceLength $ Just Salsa208
  n3_xsalsa20 <- createRandomNonce $ Stream.nonceLength $ Just XSalsa20
  defaultMain [ testGroup "Public key"
                [ testCase "generated key length (encryption)" case_pubkey_len
                , testCase "generated key length (signatures)" case_signkey_len
                , testProperty "encrypt/decrypt" (prop_pubkey_pure k1 k2 n)
                , testProperty "sign/verify" (prop_sign_verify s1)
                ]
              , testGroup "Secret key" 
                [ testProperty "authenticated encrypt/decrypt" (prop_secretkey_pure key n2)
                , testGroup "Stream"
                  [ testGroup "high level API" 
                    [
                    ]
                  , testGroup "aes128ctr"
                    [ testProperty "stream/pure" (prop_stream_stream_pure_aes128ctr n3_aes128ctr)
                    , testProperty "stream/xor" (prop_stream_xor_aes128ctr n3_aes128ctr)
                    , testProperty "encrypt/decrypt" (prop_stream_enc_pure_aes128ctr n3_aes128ctr)
                    ]
                  , testGroup "salsa20"
                    [ testProperty "stream/pure" (prop_stream_stream_pure_salsa20 n3_salsa20)
                    , testProperty "stream/xor" (prop_stream_xor_salsa20 n3_salsa20)
                    , testProperty "encrypt/decrypt" (prop_stream_enc_pure_salsa20 n3_salsa20)
                    ]
                  , testGroup "salsa2012"
                    [ testProperty "stream/pure" (prop_stream_stream_pure_salsa2012 n3_salsa2012)
                    , testProperty "stream/xor" (prop_stream_xor_salsa2012 n3_salsa2012)
                    , testProperty "encrypt/decrypt" (prop_stream_enc_pure_salsa2012 n3_salsa2012)
                    ]                  
                  , testGroup "salsa208"
                    [ testProperty "stream/pure" (prop_stream_stream_pure_salsa208 n3_salsa208)
                    , testProperty "stream/xor" (prop_stream_xor_salsa208 n3_salsa208)
                    , testProperty "encrypt/decrypt" (prop_stream_enc_pure_salsa208 n3_salsa208)
                    ]              
                  , testGroup "xsalsa20"
                    [ testProperty "stream/pure" (prop_stream_stream_pure_xsalsa20 n3_xsalsa20)
                    , testProperty "stream/xor" (prop_stream_xor_xsalsa20 n3_xsalsa20)
                    , testProperty "encrypt/decrypt" (prop_stream_enc_pure_xsalsa20 n3_xsalsa20)
                    ]
                  ]
                ]
              , testGroup "Authentication"
                [ testProperty "auth works" prop_auth_works
                , testProperty "onetimeauth works" prop_onetimeauth_works
                ]
              , testGroup "Nonce"
                [ testCase "randomNonce" case_nonce_random
                , testProperty "incNonce/pure"    prop_nonce_pure
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

newtype SmallBS = SBS ByteString deriving (Eq, Show)
instance Arbitrary SmallBS where
  arbitrary = do
    n <- choose (0, 256) :: Gen Int
    (SBS . pack) `liftM` (vectorOf n arbitrary)

newtype AuthKey = AuthKey ByteString deriving (Eq, Show)
instance Arbitrary AuthKey where
  arbitrary = (AuthKey . pack) `liftM` (vectorOf authKeyLength arbitrary)

newtype OneTimeAuthKey = OneTimeAuthKey ByteString deriving (Eq, Show)
instance Arbitrary OneTimeAuthKey where
  arbitrary = (OneTimeAuthKey . pack) `liftM` (vectorOf oneTimeAuthKeyLength arbitrary)
    
newtype AES128StreamKey = AES128SK ByteString deriving (Eq, Show)
instance Arbitrary AES128StreamKey where
  arbitrary = (AES128SK . pack) `liftM` (vectorOf AES128CTR.keyLength arbitrary)

newtype Salsa20StreamKey = Salsa20SK ByteString deriving (Eq, Show)
instance Arbitrary Salsa20StreamKey where
  arbitrary = (Salsa20SK . pack) `liftM` (vectorOf Salsa20.keyLength arbitrary)

newtype Salsa2012StreamKey = Salsa2012SK ByteString deriving (Eq, Show)
instance Arbitrary Salsa2012StreamKey where
  arbitrary = (Salsa2012SK . pack) `liftM` (vectorOf Salsa2012.keyLength arbitrary)

newtype Salsa208StreamKey = Salsa208SK ByteString deriving (Eq, Show)
instance Arbitrary Salsa208StreamKey where
  arbitrary = (Salsa208SK . pack) `liftM` (vectorOf Salsa208.keyLength arbitrary)

newtype XSalsa20StreamKey = XSalsa20SK ByteString deriving (Eq, Show)
instance Arbitrary XSalsa20StreamKey where
  arbitrary = (XSalsa20SK . pack) `liftM` (vectorOf XSalsa20.keyLength arbitrary)



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

prop_pubkey_pure :: PubKey.KeyPair -> PubKey.KeyPair -> Nonce -> ByteString -> Bool
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

prop_secretkey_pure :: SecretKey.SecretKey -> Nonce -> ByteString -> Bool
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

case_nonce_random :: Assertion
case_nonce_random = doit 20 $ \i -> do
  n <- createRandomNonce i
  nonceLen n @?= i

-- Authentication

prop_auth_works :: AuthKey -> ByteString -> Bool
prop_auth_works (AuthKey k) msg
  = Auth.verify (Auth.authenticate msg k) msg k

prop_onetimeauth_works :: OneTimeAuthKey -> ByteString -> Bool
prop_onetimeauth_works (OneTimeAuthKey k) msg
  = Auth.verifyOnce (Auth.authenticateOnce msg k) msg k

-- Streaming encryption

-- aes128ctr
prop_stream_enc_pure_aes128ctr :: Nonce -> AES128StreamKey -> ByteString -> Bool
prop_stream_enc_pure_aes128ctr n (AES128SK sk) p
  = let enc = AES128CTR.encrypt n p sk
        dec = AES128CTR.decrypt n enc sk
    in dec == p

prop_stream_stream_pure_aes128ctr :: Nonce -> AES128StreamKey -> Property
prop_stream_stream_pure_aes128ctr n (AES128SK sk)
  -- Don't generate massive streams
  = forAll (choose (0, 256)) $ \i -> AES128CTR.streamGen n i sk == AES128CTR.streamGen n i sk

prop_stream_xor_aes128ctr :: Nonce -> AES128StreamKey -> SmallBS -> Bool
prop_stream_xor_aes128ctr n (AES128SK sk) (SBS p)
  = let enc = AES128CTR.encrypt n p sk
        str = AES128CTR.streamGen n (S.length p) sk
    in enc == (p `xorBS` str)

-- salsa20
prop_stream_enc_pure_salsa20 :: Nonce -> Salsa20StreamKey -> ByteString -> Bool
prop_stream_enc_pure_salsa20 n (Salsa20SK sk) p
  = let enc = Salsa20.encrypt n p sk
        dec = Salsa20.decrypt n enc sk
    in dec == p

prop_stream_stream_pure_salsa20 :: Nonce -> Salsa20StreamKey -> Property
prop_stream_stream_pure_salsa20 n (Salsa20SK sk)
  -- Don't generate massive streams
  = forAll (choose (0, 256)) $ \i -> Salsa20.streamGen n i sk == Salsa20.streamGen n i sk

prop_stream_xor_salsa20 :: Nonce -> Salsa20StreamKey -> SmallBS -> Bool
prop_stream_xor_salsa20 n (Salsa20SK sk) (SBS p)
  = let enc = Salsa20.encrypt n p sk
        str = Salsa20.streamGen n (S.length p) sk
    in enc == (p `xorBS` str)

-- salsa2012
prop_stream_enc_pure_salsa2012 :: Nonce -> Salsa2012StreamKey -> ByteString -> Bool
prop_stream_enc_pure_salsa2012 n (Salsa2012SK sk) p
  = let enc = Salsa2012.encrypt n p sk
        dec = Salsa2012.decrypt n enc sk
    in dec == p

prop_stream_stream_pure_salsa2012 :: Nonce -> Salsa2012StreamKey -> Property
prop_stream_stream_pure_salsa2012 n (Salsa2012SK sk)
  -- Don't generate massive streams
  = forAll (choose (0, 256)) $ \i -> Salsa2012.streamGen n i sk == Salsa2012.streamGen n i sk

prop_stream_xor_salsa2012 :: Nonce -> Salsa2012StreamKey -> SmallBS -> Bool
prop_stream_xor_salsa2012 n (Salsa2012SK sk) (SBS p)
  = let enc = Salsa2012.encrypt n p sk
        str = Salsa2012.streamGen n (S.length p) sk
    in enc == (p `xorBS` str)


-- salsa208
prop_stream_enc_pure_salsa208 :: Nonce -> Salsa208StreamKey -> ByteString -> Bool
prop_stream_enc_pure_salsa208 n (Salsa208SK sk) p
  = let enc = Salsa208.encrypt n p sk
        dec = Salsa208.decrypt n enc sk
    in dec == p

prop_stream_stream_pure_salsa208 :: Nonce -> Salsa208StreamKey -> Property
prop_stream_stream_pure_salsa208 n (Salsa208SK sk)
  -- Don't generate massive streams
  = forAll (choose (0, 256)) $ \i -> Salsa208.streamGen n i sk == Salsa208.streamGen n i sk

prop_stream_xor_salsa208 :: Nonce -> Salsa208StreamKey -> SmallBS -> Bool
prop_stream_xor_salsa208 n (Salsa208SK sk) (SBS p)
  = let enc = Salsa208.encrypt n p sk
        str = Salsa208.streamGen n (S.length p) sk
    in enc == (p `xorBS` str)

-- xsalsa20
prop_stream_enc_pure_xsalsa20 :: Nonce -> XSalsa20StreamKey -> ByteString -> Bool
prop_stream_enc_pure_xsalsa20 n (XSalsa20SK sk) p
  = let enc = XSalsa20.encrypt n p sk
        dec = XSalsa20.decrypt n enc sk
    in dec == p

prop_stream_stream_pure_xsalsa20 :: Nonce -> XSalsa20StreamKey -> Property
prop_stream_stream_pure_xsalsa20 n (XSalsa20SK sk)
  -- Don't generate massive streams
  = forAll (choose (0, 256)) $ \i -> XSalsa20.streamGen n i sk == XSalsa20.streamGen n i sk

prop_stream_xor_xsalsa20 :: Nonce -> XSalsa20StreamKey -> SmallBS -> Bool
prop_stream_xor_xsalsa20 n (XSalsa20SK sk) (SBS p)
  = let enc = XSalsa20.encrypt n p sk
        str = XSalsa20.streamGen n (S.length p) sk
    in enc == (p `xorBS` str)



-- Utilities

xorBS :: ByteString -> ByteString -> ByteString
xorBS x1 x2 = S.pack $ S.zipWith xor x1 x2

doit :: Int -> (Int -> IO a) -> IO ()
doit n f = sequence_ $ map f [1..n]

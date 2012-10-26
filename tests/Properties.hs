{-# LANGUAGE FlexibleInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main
       ( main -- :: IO ()
       ) where
import Control.Monad (liftM)
import Data.ByteString as S (append, pack, 
                             length, ByteString, 
                             zipWith, splitAt, replicate, drop)
import Data.Bits
import Data.Maybe
import Data.Tagged

import Test.Framework (defaultMain, testGroup)
import Test.QuickCheck
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.HUnit
import Test.Framework.Providers.HUnit (testCase)

import Crypto.NaCl.Hash (sha512, sha256)
import Crypto.NaCl.Random (randomBytes)

import Crypto.NaCl.Encrypt.PublicKey as PK
import Crypto.NaCl.Encrypt.SecretKey as SK
import Crypto.NaCl.Encrypt.Stream as Stream

import Crypto.NaCl.Sign as Sign
import qualified Crypto.NaCl.Internal as I
import Crypto.NaCl.Auth as Auth
import Crypto.NaCl.Key as K

main :: IO ()
main = do
  k1 <- PK.createKeypair
  k2 <- PK.createKeypair
  n  <- I.createRandomNonce
  
  s1 <- Sign.createKeypair
  
  key <- SecretKey `liftM` randomBytes SK.keyLength
  n2  <- I.createRandomNonce
  
  n3_xsalsa20 <- I.createRandomNonce
  defaultMain [ testGroup "Secret key" 
                [ testProperty "authenticated encrypt/decrypt" (prop_secretkey_pure key n2)
                , testGroup "Stream encryption"
                  [ testProperty "stream/pure" (prop_stream_stream_pure_xsalsa20 n3_xsalsa20)
                  , testProperty "stream/xor" (prop_stream_xor_xsalsa20 n3_xsalsa20)
                  , testProperty "encrypt/decrypt" (prop_stream_enc_pure_xsalsa20 n3_xsalsa20)
                  ]
                ]
              , testGroup "Authentication"
                [ testProperty "auth works" prop_auth_works
                , testProperty "onetimeauth works" prop_onetimeauth_works
                ]
              , testGroup "Nonce"
                [ testProperty "incNonce/pure" prop_nonce_pure
                ]
              , testGroup "Hashing" 
                [ testProperty "sha256/pure"   prop_sha256_pure
                , testProperty "sha256/length" prop_sha256_length
                , testProperty "sha512/pure"   prop_sha512_pure
                , testProperty "sha512/length" prop_sha512_length
                ]
              , testGroup "Public key encryption"
                [ testCase "generated key length (encryption)" case_pubkey_len
                , testCase "generated key length (signatures)" case_signkey_len
                , testProperty "encrypt/decrypt" (prop_pubkey_pure k1 k2 n)
                , testProperty "createNM purity" (prop_createnm_pure k1)
                , testProperty "encryptNM/decryptNM" (prop_pubkey_precomp_pure k1 k2 n)
                ]
              , testGroup "Signing" 
                [ testProperty "roundtrip" (prop_sign_verify s1)
                , testProperty "bug14" (prop_sign_bug14 s1)
                , testProperty "sign' length" (prop_sign'_length s1)
                , testProperty "sign' length #2" (prop_sign'_length2 s1)
                , testProperty "verify' works" (prop_verify' s1)
                ]
                -- Misc
              , testCase "Randomness" case_random
              ]

-- Orphan Arbitrary instances
instance Arbitrary ByteString where
  arbitrary = pack `liftM` arbitrary

instance Arbitrary K.PublicKey where
  arbitrary = PublicKey `liftM` arbitrary

instance Arbitrary K.SecretKey where
  arbitrary = SecretKey `liftM` arbitrary

instance Arbitrary PKNonce where
  arbitrary = do
    let n = unTagged (I.size :: Tagged PKNonce Int)
    (fromJust . I.fromBS . pack) `liftM` vectorOf n arbitrary
instance Arbitrary SKNonce where
  arbitrary = do
    let n = unTagged (I.size :: Tagged SKNonce Int)
    (fromJust . I.fromBS . pack) `liftM` vectorOf n arbitrary
instance Arbitrary StreamNonce where
  arbitrary = do
    let n = unTagged (I.size :: Tagged StreamNonce Int)
    (fromJust . I.fromBS . pack) `liftM` vectorOf n arbitrary

newtype SmallBS = SBS ByteString deriving (Eq, Show)
instance Arbitrary SmallBS where
  arbitrary = do
    n <- choose (0, 256) :: Gen Int
    (SBS . pack) `liftM` vectorOf n arbitrary

newtype AuthKey = AuthKey K.SecretKey deriving (Eq, Show)
instance Arbitrary AuthKey where
  arbitrary = (AuthKey . SecretKey . pack) `liftM` vectorOf authKeyLength arbitrary

newtype OneTimeAuthKey = OneTimeAuthKey K.SecretKey deriving (Eq, Show)
instance Arbitrary OneTimeAuthKey where
  arbitrary = (OneTimeAuthKey . SecretKey . pack) `liftM` vectorOf oneTimeAuthKeyLength arbitrary
    
newtype XSalsa20StreamKey = XSalsa20SK K.SecretKey deriving (Eq, Show)
instance Arbitrary XSalsa20StreamKey where
  arbitrary = (XSalsa20SK . SecretKey . pack) `liftM` vectorOf Stream.keyLength arbitrary


-- Hashing properties
prop_sha256_pure :: ByteString -> Bool
prop_sha256_pure xs = sha256 xs == sha256 xs
  
prop_sha256_length :: ByteString -> Bool
prop_sha256_length xs = S.length (sha256 xs) == 32

prop_sha512_pure :: ByteString -> Bool
prop_sha512_pure xs = sha512 xs == sha512 xs

prop_sha512_length :: ByteString -> Bool
prop_sha512_length xs = S.length (sha512 xs) == 64

-- Randomness
case_random :: Assertion
case_random = doit 20 $ \i -> do
  x <- randomBytes i
  S.length x @?= i

-- Public-key encryption etc

case_pubkey_len :: Assertion
case_pubkey_len = doit 20 $ \_ -> do
  (pk,sk) <- PK.createKeypair
  S.length (unPublicKey pk) @?= publicKeyLength
  S.length (unSecretKey sk) @?= secretKeyLength

case_signkey_len :: Assertion
case_signkey_len = doit 20 $ \_ -> do
  (pk,sk) <- Sign.createKeypair
  S.length (unPublicKey pk) @?= signPublicKeyLength
  S.length (unSecretKey sk) @?= signSecretKeyLength

prop_pubkey_pure :: KeyPair -> KeyPair -> PKNonce -> ByteString -> Bool
prop_pubkey_pure (pk1,sk1) (pk2,sk2) n xs
  = let enc = PK.encrypt n xs pk2 sk1
        dec = PK.decrypt n enc pk1 sk2
    in maybe False (== xs) dec
       
prop_pubkey_precomp_pure :: KeyPair -> KeyPair -> PKNonce -> ByteString -> Bool
prop_pubkey_precomp_pure (pk1,sk1) (pk2,sk2) n xs
  = let nm1 = PK.createNM (pk2,sk1)
        nm2 = PK.createNM (pk1,sk2)
        enc = PK.encryptNM nm1 n xs
        dec = PK.decryptNM nm2 n enc
    in maybe False (== xs) dec

prop_createnm_pure :: KeyPair -> Bool
prop_createnm_pure kp = createNM kp == createNM kp

-- Signatures

-- Verify short, invalid signatures are rejected.
-- Bug #14
prop_sign_bug14 :: KeyPair -> ByteString -> Bool
prop_sign_bug14 (pk,sk) xs
  = let s = Sign.sign sk xs
        d = Sign.verify pk $ S.drop (S.length s-1) s
    in isNothing d

prop_sign_verify :: KeyPair -> ByteString -> Bool
prop_sign_verify (pk,sk) xs
  = let s = Sign.sign sk xs
        d = Sign.verify pk s
    in maybe False (== xs) d

-- Generally the signature format is '<signature><original message>'
-- and <signature> is of a fixed length (crypto_sign_BYTES), which in
-- ed25519's case is 64. sign' drops the message appended at the end,
-- so we just make sure we have constant length signatures.
prop_sign'_length :: KeyPair -> ByteString -> ByteString -> Bool
prop_sign'_length (_,sk) xs xs2
  = let s1 = Sign.sign' sk xs
        s2 = Sign.sign' sk xs2
    in (S.length s1 == S.length s2)

-- FIXME: specific to ed25519; maybe the sign module should export
-- crypto_sign_BYTES?
prop_sign'_length2 :: KeyPair -> ByteString -> Bool
prop_sign'_length2 (_,sk) xs = 64 == (S.length $ Sign.sign' sk xs)

prop_verify' :: KeyPair -> ByteString -> Bool
prop_verify' (pk,sk) xs = Sign.verify' pk xs $ Sign.sign' sk xs

-- Secret-key authenticated encryption

prop_secretkey_pure :: SecretKey -> SKNonce -> ByteString -> Bool
prop_secretkey_pure k n xs
  = let enc = SK.encrypt n xs k
        dec = SK.decrypt n enc k
    in maybe False (== xs) dec

-- Nonces

prop_nonce_pure :: StreamNonce -> Bool
prop_nonce_pure n = I.incNonce n == I.incNonce n

-- Authentication

prop_auth_works :: AuthKey -> ByteString -> Bool
prop_auth_works (AuthKey k) msg
  = Auth.verify k (Auth.authenticate k msg) msg

prop_onetimeauth_works :: OneTimeAuthKey -> ByteString -> Bool
prop_onetimeauth_works (OneTimeAuthKey k) msg
  = Auth.verifyOnce k (Auth.authenticateOnce k msg) msg

-- Streaming encryption

-- xsalsa20
prop_stream_enc_pure_xsalsa20 :: StreamNonce -> XSalsa20StreamKey -> ByteString -> Bool
prop_stream_enc_pure_xsalsa20 n (XSalsa20SK sk) p
  = let enc = Stream.encrypt n p sk
        dec = Stream.decrypt n enc sk
    in dec == p

prop_stream_stream_pure_xsalsa20 :: StreamNonce -> XSalsa20StreamKey -> Property
prop_stream_stream_pure_xsalsa20 n (XSalsa20SK sk)
  -- Don't generate massive streams
  = forAll (choose (0, 256)) $ \i -> streamGen n i sk == streamGen n i sk

prop_stream_xor_xsalsa20 :: StreamNonce -> XSalsa20StreamKey -> SmallBS -> Bool
prop_stream_xor_xsalsa20 n (XSalsa20SK sk) (SBS p)
  = let enc = Stream.encrypt n p sk
        str = Stream.streamGen n (S.length p) sk
    in enc == (p `xorBS` str)



-- Utilities

xorBS :: ByteString -> ByteString -> ByteString
xorBS x1 x2 = S.pack $ S.zipWith xor x1 x2

doit :: Int -> (Int -> IO a) -> IO ()
doit n f = mapM_ f [1..n]

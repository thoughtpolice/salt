{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main
       ( main -- :: IO ()
       ) where
import Data.Int
import System.IO
import Control.Monad (liftM)
import Criterion.Main hiding (run)
import Data.ByteString as S
import qualified Data.ByteString.Char8 as S8

import Control.Monad.Trans

import Crypto.NaCl.Hash as H
import Crypto.NaCl.Nonce as N
import Crypto.NaCl.Random as R
import Crypto.NaCl.Key
import Crypto.NaCl.Sign as Sign
import Crypto.NaCl.Encrypt.Stream as Stream

import qualified OpenSSL as OpenSSL
import qualified OpenSSL.Cipher as OpenSSL (newAESCtx, aesCTR, Mode(Encrypt), AESCtx)
import qualified OpenSSL.RSA as OpenSSL
import qualified OpenSSL.EVP.Digest as OpenSSL (getDigestByName, digestBS', Digest)
import qualified OpenSSL.EVP.Verify as OpenSSL
import qualified OpenSSL.EVP.Sign as OpenSSL
import qualified OpenSSL.Random as OpenSSL

import Control.DeepSeq

import Data.Enumerator hiding (map)
import Data.Enumerator.Binary hiding (map)
import qualified Data.Enumerator.List as EL

instance NFData ByteString where
instance NFData SecretKey where
instance NFData PublicKey where
instance NFData OpenSSL.RSAKeyPair where

main :: IO ()
main = OpenSSL.withOpenSSL $ do
  s1 <- Sign.createKeypair
  streamk1 <- SecretKey `liftM` randomBytes Stream.keyLength 
  
  fourkb <- randomBytes 4096
  let !znonce = createZeroNonce :: StreamNonce
      
  Just ssl_sha256 <- OpenSSL.getDigestByName "SHA256"
  Just ssl_sha512 <- OpenSSL.getDigestByName "SHA512"
  aeskey <- R.randomBytes 16
  aesiv  <- R.randomBytes 16
  aesctx <- OpenSSL.newAESCtx OpenSSL.Encrypt aeskey aesiv
  rsak   <- OpenSSL.generateRSAKey 1024 17 Nothing
  defaultMain [ bgroup "hash"
                [ versus "sha256"
                    [ ( "64", nf sha256 $ pack [1..64]
                            , nf (OpenSSL.digestBS' ssl_sha256) $ pack [1..64])
                    , ( "128", nf sha256 $ pack [1..128] 
                             , nf (OpenSSL.digestBS' ssl_sha256) $ pack [1..128])                               
                    , ( "256", nf sha256 $ pack [1..256] 
                             , nf (OpenSSL.digestBS' ssl_sha256) $ pack [1..256])
                    , ( "512", nf sha256 $ pack [1..512] 
                             , nf (OpenSSL.digestBS' ssl_sha256) $ pack [1..512])
                    ]
                , versus "sha512"
                    [ ( "64", nf sha512 $ pack [1..64]
                            , nf (OpenSSL.digestBS' ssl_sha256) $ pack [1..64])
                    , ( "128", nf sha512 $ pack [1..128] 
                             , nf (OpenSSL.digestBS' ssl_sha256) $ pack [1..128])
                    , ( "256", nf sha512 $ pack [1..256] 
                             , nf (OpenSSL.digestBS' ssl_sha256) $ pack [1..256])
                    , ( "512", nf sha512 $ pack [1..512] 
                             , nf (OpenSSL.digestBS' ssl_sha256) $ pack [1..512])
                    ]
                ]
              , versus "random"
                  [ ( "32", nfIO $ R.randomBytes 32
                          , nfIO $ OpenSSL.randBytes 32)
                  ,
                    ( "64", nfIO $ R.randomBytes 64
                          , nfIO $ OpenSSL.randBytes 64)
                  ,
                    ( "128", nfIO $ R.randomBytes 128
                           , nfIO $ OpenSSL.randBytes 128)
                  ,
                    ( "256", nfIO $ R.randomBytes 256
                           , nfIO $ OpenSSL.randBytes 256)
                  ]
              , versus "sign"
                  [ ( "createKeypair", nfIO Sign.createKeypair
                                     , nfIO (OpenSSL.generateRSAKey 1024 17 Nothing))
                  , ( "verify/512", nfIO $ signBenchRef ssl_sha512 rsak $ pack [1..512]
                                  , nfIO $ return $ signBench s1 $ pack [1..512])
                  ]
              , versus "encrypt"
                  [ ( "enumerator/1gb", nfIO $ streamEncBench1 streamk1
                                      , nfIO $ streamEncRef1 aesctx)
                  ]
              , bgroup "misc"
                [ bench "pure streamgen 4096/10000" $ nf (streamGenBench streamk1 4096) 10000
                , bench "pure encrypt 4kB random data" $ nf (pureEncBench znonce streamk1) fourkb
--              , bench "enum2 encrypt 1gb random data" $ nfIO $ streamEncBench2 streamk1
                ]
              ]
  
  where {-
        incNonceBench :: NonceLength StreamNonce -> Int -> Nonce StreamNonce
        incNonceBench sz x 
          = go (createZeroNonce sz) x
          where go n 0 = n
                go n i = go (incNonce n) $! i-1
        -}
    
        signBenchRef :: OpenSSL.Digest -> OpenSSL.RSAKeyPair -> ByteString -> IO Bool
        signBenchRef d k xs = do
          -- this is a stupid api
          sm <- OpenSSL.signBS d k xs
          v <- OpenSSL.verifyBS d (S8.unpack sm) k xs
          return $ if (v == OpenSSL.VerifySuccess) then True else False
          
        signBench :: KeyPair -> ByteString -> Bool
        signBench (pk, sk) xs
          = let sm = Sign.sign sk xs
                v  = Sign.verify pk sm
            in maybe False (== xs) v

        streamGenBench :: SecretKey -> Int -> Int -> ByteString
        streamGenBench sk sz i 
          = go createZeroNonce empty i
          where go !_ !bs 0  = bs
                go !n !_ !x = go (incNonce n) (Stream.streamGen n sz sk) (x-1)

        pureEncBench :: StreamNonce -> SecretKey -> ByteString -> ByteString
        pureEncBench n k bs = Stream.encrypt n bs k

        -- Reference encryption function that uses OpenSSL ciphers
        streamEncRef1 :: OpenSSL.AESCtx -> IO ByteString
        streamEncRef1 ctx = do
          let goI :: ByteString -> Iteratee ByteString IO ByteString
              goI !_ = do
                v <- EL.head
                case v of
                  Nothing -> return S.empty
                  Just _v -> liftIO (OpenSSL.aesCTR ctx _v) >>= goI 
          run_ (enumFile "./testdata" $$ goI S.empty)
          
        streamEncBench1 :: SecretKey -> IO ByteString
        streamEncBench1 sk = do
          let nonce = createZeroNonce
              goI :: ByteString -> StreamNonce -> Iteratee ByteString IO ByteString
              goI !_ !n = do
                v <- EL.head
                case v of
                  Nothing -> return S.empty
                  Just _v -> goI (Stream.encrypt n _v sk) (incNonce n)
          run_ (enumFile "./testdata" $$ goI S.empty nonce)

        streamEncBench2 :: SecretKey -> IO ()
        streamEncBench2 sk = do 
            h <- openBinaryFile "/dev/null" WriteMode
            let n = createZeroNonce
            run_ (encryptFileEnum "./testdata" sk n $$ iterHandle h)
            hClose h
            
encryptFileEnum :: FilePath -> SecretKey -> StreamNonce -> Enumerator ByteString IO b
encryptFileEnum f sk n = enumFile f $= encryptEnee sk n

encryptEnee :: Monad m => SecretKey -> StreamNonce -> Enumeratee ByteString ByteString m b
encryptEnee k = EL.mapAccum $ \n bs -> (incNonce n, Stream.encrypt n bs k)

versus x zs = bgroup x $ Prelude.map to $ zs
  where to (name,nacl,ossl) 
          = bgroup name [ bcompare [ bench "openssl" ossl
                                   , bench "nacl" nacl
                                   ]
                        ]

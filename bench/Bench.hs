{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main
       ( main -- :: IO ()
       ) where
import Data.Int
import System.IO

import Criterion.Main hiding (run)
import Data.ByteString as S

import Crypto.NaCl.Hash as H
import Crypto.NaCl.Nonce as N
import Crypto.NaCl.Random as R

import Crypto.NaCl.Sign as Sign

import Crypto.NaCl.Encrypt.Stream as Stream

import Control.DeepSeq

import Data.Enumerator
import Data.Enumerator.Binary
import qualified Data.Enumerator.List as EL

instance NFData (Nonce k) where
instance NFData ByteString where

main :: IO ()
main = do
  s1 <- Sign.createKeypair
  streamk1 <- randomBytes $ Stream.keyLength 
  
  defaultMain [ bgroup "Signing"
                [ bench "createKeypair" $ nfIO Sign.createKeypair
                , bench "verify 64"  $ nf (signBench s1) $ pack [1..64]
                , bench "verify 128" $ nf (signBench s1) $ pack [1..128]
                , bench "verify 256" $ nf (signBench s1) $ pack [1..256]
                , bench "verify 512" $ nf (signBench s1) $ pack [1..512]
                ]
              , bgroup "Stream"
                [ bgroup "xsalsa20"
                  [ bench "pure streamgen 4094/10000" $ nf (streamGenBench streamk1 4094) 10000
                  , bench "enum1 encrypt 1gb random data" $ nfIO $ streamEncBench1 streamk1
                  , bench "enum2 encrypt 1gb random data" $ nfIO $ streamEncBench2 streamk1
                  ]
                ]
              , bgroup "Hashing"
                [ bgroup "sha512"
                  [ bench "64"  $ nf cryptoHash (pack [1..64])
                  , bench "128" $ nf cryptoHash (pack [1..128])
                  , bench "256" $ nf cryptoHash (pack [1..256])
                  , bench "512" $ nf cryptoHash (pack [1..512])
                  ]
                , bgroup "sha256"
                  [ bench "64"  $ nf cryptoHash_SHA256 (pack [1..64])
                  , bench "128" $ nf cryptoHash_SHA256 (pack [1..128])
                  , bench "256" $ nf cryptoHash_SHA256 (pack [1..256])
                  , bench "512" $ nf cryptoHash_SHA256 (pack [1..512])
                  ]
                ]
              , bgroup "Random bytes"
                [ bench "32"  $ nfIO $ randomBytes 32
                , bench "64"  $ nfIO $ randomBytes 64
                , bench "128" $ nfIO $ randomBytes 128
                , bench "256" $ nfIO $ randomBytes 256
                ]
              ]
  where {-
        incNonceBench :: NonceLength StreamNonce -> Int -> Nonce StreamNonce
        incNonceBench sz x 
          = go (createZeroNonce sz) x
          where go n 0 = n
                go n i = go (incNonce n) $! i-1
        -}
    
        signBench :: Sign.KeyPair -> ByteString -> Bool
        signBench (pk, sk) xs
          = let sm = Sign.sign sk xs
                v  = Sign.verify pk sm
            in maybe False (== xs) v

        streamGenBench :: Stream.SecretKey -> Int -> Int -> ByteString
        streamGenBench sk sz i 
          = go (createZeroNonce Stream.nonceLength) empty i
          where go !_ !bs 0  = bs
                go !n !_ !x = go (incNonce n) (Stream.streamGen n sz sk) (x-1)

        streamEncBench1 :: Stream.SecretKey -> IO ByteString
        streamEncBench1 sk = do
          let nonce = createZeroNonce Stream.nonceLength
              goI :: ByteString -> Nonce StreamNonce -> Iteratee ByteString IO ByteString
              goI !_ !n = do
                v <- EL.head
                case v of
                  Nothing -> return S.empty
                  Just _v -> goI (Stream.encrypt n _v sk) (incNonce n)
          run_ (enumFile "./testdata" $$ (goI S.empty nonce))

        streamEncBench2 :: Stream.SecretKey -> IO ()
        streamEncBench2 sk = do 
            h <- openBinaryFile "/dev/null" WriteMode
            let n = createZeroNonce Stream.nonceLength
            run_ (encryptFileEnum "./testdata" sk n $$ iterHandle h)
            hClose h
            
encryptFileEnum :: FilePath -> Stream.SecretKey -> Nonce StreamNonce -> Enumerator ByteString IO b
encryptFileEnum f sk n = enumFile f $= encryptEnee sk n

encryptEnee :: Monad m => Stream.SecretKey -> Nonce StreamNonce -> Enumeratee ByteString ByteString m b
encryptEnee k = EL.mapAccum $ \n bs -> (incNonce n, Stream.encrypt n bs k)

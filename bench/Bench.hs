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

import Crypto.NaCl.Hash as H
import Crypto.NaCl.Nonce as N
import Crypto.NaCl.Random as R
import Crypto.NaCl.Key

import Crypto.NaCl.Sign as Sign

import Crypto.NaCl.Encrypt.Stream as Stream

import Control.DeepSeq

import Data.Enumerator
import Data.Enumerator.Binary
import qualified Data.Enumerator.List as EL

instance NFData ByteString where
instance NFData SecretKey where
instance NFData PublicKey where

main :: IO ()
main = do
  s1 <- Sign.createKeypair
  streamk1 <- SecretKey `liftM` randomBytes Stream.keyLength 
  
  fourkb <- randomBytes 4096
  let !znonce = createZeroNonce
  defaultMain [ bgroup "Signing"
                [ bench "createKeypair" $ nfIO Sign.createKeypair
                , bench "verify 64"  $ nf (signBench s1) $ pack [1..64]
                , bench "verify 128" $ nf (signBench s1) $ pack [1..128]
                , bench "verify 256" $ nf (signBench s1) $ pack [1..256]
                , bench "verify 512" $ nf (signBench s1) $ pack [1..512]
                ]
              , bgroup "Stream"
                [ bgroup "xsalsa20"
                  [ bench "pure streamgen 4096/10000" $ nf (streamGenBench streamk1 4096) 10000
                  , bench "pure encrypt 4kB random data" $ nf (pureEncBench znonce streamk1) fourkb
                  , bench "enum1 encrypt 1gb random data" $ nfIO $ streamEncBench1 streamk1
                  , bench "enum2 encrypt 1gb random data" $ nfIO $ streamEncBench2 streamk1
                  ]
                ]
              , bgroup "Hashing"
                [ bgroup "sha512"
                  [ bench "64"  $ nf sha512 (pack [1..64])
                  , bench "128" $ nf sha512 (pack [1..128])
                  , bench "256" $ nf sha512 (pack [1..256])
                  , bench "512" $ nf sha512 (pack [1..512])
                  ]
                , bgroup "sha256"
                  [ bench "64"  $ nf sha256 (pack [1..64])
                  , bench "128" $ nf sha256 (pack [1..128])
                  , bench "256" $ nf sha256 (pack [1..256])
                  , bench "512" $ nf sha256 (pack [1..512])
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

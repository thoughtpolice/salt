{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main
       ( main -- :: IO ()
       ) where
import Data.Int
import Criterion.Main
import Data.ByteString as S

import Crypto.NaCl.Hash as H
import Crypto.NaCl.Nonce as N
import Crypto.NaCl.Random as R

import Crypto.NaCl.Sign as Sign

import Crypto.NaCl.Encrypt.Stream as Stream

import Control.DeepSeq

import Control.Monad.Trans

import Data.Enumerator
import Data.Enumerator.Binary
import qualified Data.Enumerator.List as EL

instance NFData Nonce where
instance NFData ByteString where

main :: IO ()
main = do
  s1 <- Sign.createKeypair
  streamk1 <- randomBytes Stream.keyLength
  
  defaultMain [ bgroup "Signing"
                [ bench "createKeypair" $ nfIO Sign.createKeypair
                , bench "verify 64"  $ nf (signBench s1) $ pack [1..64]
                , bench "verify 128" $ nf (signBench s1) $ pack [1..128]
                , bench "verify 256" $ nf (signBench s1) $ pack [1..256]
                , bench "verify 512" $ nf (signBench s1) $ pack [1..512]
                ]
              , bgroup "Stream"
                [ bench "pure streamgen 64/1000" $ nf (cryptoStreamBench streamk1  64) 1000
                , bench "enum encrypt 512mb /dev/null" $ nfIO $ streamEncBench streamk1 512
                  --  This takes 45 minutes on my core i5.
--              , bench "enum encrypt 10gb /dev/null" $ nfIO $ streamEncBench streamk1 (1024*10)
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
              , bgroup "Nonces"
                [ bench "zeroNonce 64" $ nf createZeroNonce 64
                , bench "zeroNonce 128" $ nf createZeroNonce 128
                , bench "incNonce 8/64" $ nf (incNonceBench 8) 64
                , bench "incNonce 8/256" $ nf (incNonceBench 8) 256
                , bench "incNonce 64/10000" $ nf (incNonceBench 64) 10000
                ]
              , bgroup "Random bytes"
                [ bench "32"  $ nfIO $ randomBytes 32
                , bench "64"  $ nfIO $ randomBytes 64
                , bench "128" $ nfIO $ randomBytes 128
                , bench "256" $ nfIO $ randomBytes 256
                ]
              ]
  where incNonceBench :: Int -> Int -> Nonce
        incNonceBench sz x 
          = go (createZeroNonce sz) x
          where go n 0 = n
                go n i = go (incNonce n) $! i-1
        
        signBench :: Sign.KeyPair -> ByteString -> Bool
        signBench (pk, sk) xs
          = let sm = Sign.sign sk xs
                v  = Sign.verify pk sm
            in maybe False (== xs) v

        cryptoStreamBench :: Stream.SecretKey -> Int -> Int -> ByteString
        cryptoStreamBench sk sz i 
          = go (createZeroNonce Stream.nonceLength) empty i
          where go !_ !bs 0  = bs
                go !n !_ !x = go (incNonce n) (Stream.cryptoStream n sz sk) (x-1)

        streamEncBench :: Stream.SecretKey -> Int64 -> IO Int
        streamEncBench sk mb = do
          let total = mb*1024*1024 :: Int64
              goI :: Int -> Int64 -> Nonce -> Iteratee ByteString IO Int
              goI !x !t !n = do
                v <- EL.head_
                let !_ = Stream.encryptXor n v sk
                let l = fromIntegral $ S.length v
                if (t+l) > total then
                  return x
                 else
                  goI (x+1) (t+l) (incNonce n)
          Data.Enumerator.run_
                 (enumFile "/dev/zero"
                  $$ (goI 0 0 $ createZeroNonce Stream.nonceLength))

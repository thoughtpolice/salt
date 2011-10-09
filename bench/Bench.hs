{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main
       ( main -- :: IO ()
       ) where
import Control.Monad (void)
import Criterion.Main
import Data.ByteString

import Crypto.NaCl.Hash
import Crypto.NaCl.Nonce
import Crypto.NaCl.Random

import Control.DeepSeq

instance NFData Nonce where
instance NFData ByteString where

main :: IO ()
main = 
  defaultMain [ bgroup "Hashing"
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
              , bgroup "random bytes"
                [ bench "32"  $ nfIO $ randomBytes 32
                , bench "64"  $ nfIO $ randomBytes 64
                , bench "128" $ nfIO $ randomBytes 128
                , bench "256" $ nfIO $ randomBytes 256
                ]
              ]
  where incNonceBench :: Int -> Int -> Nonce
        incNonceBench sz x = go (createZeroNonce sz) x
          where go n 0 = n
                go n i = go (incNonce n) $! i-1

{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main
       ( main -- :: IO ()
       ) where
import Data.Int
import System.IO
import System.FilePath

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

instance NFData Nonce where
instance NFData ByteString where

main :: IO ()
main = do
  s1 <- Sign.createKeypair
  streamk1 <- randomBytes $ Stream.keyLength $ Just AES128CTR
  streamk2 <- randomBytes $ Stream.keyLength $ Just Salsa20
  streamk3 <- randomBytes $ Stream.keyLength $ Just Salsa2012
  streamk4 <- randomBytes $ Stream.keyLength $ Just Salsa208
  streamk5 <- randomBytes $ Stream.keyLength $ Just XSalsa20
  
  defaultMain [ bgroup "Signing"
                [ bench "createKeypair" $ nfIO Sign.createKeypair
                , bench "verify 64"  $ nf (signBench s1) $ pack [1..64]
                , bench "verify 128" $ nf (signBench s1) $ pack [1..128]
                , bench "verify 256" $ nf (signBench s1) $ pack [1..256]
                , bench "verify 512" $ nf (signBench s1) $ pack [1..512]
                ]
              , bgroup "Stream"
                [ bgroup "aes128ctr"
                  [ bench "pure streamgen 4094/10000" $ nf (streamGenBench (Just AES128CTR) streamk1 4094) 10000
                  , bench "enum1 encrypt 1gb random data" $ nfIO $ streamEncBench1 (Just AES128CTR) streamk1
                  , bench "enum2 encrypt 1gb random data" $ nfIO $ streamEncBench2 (Just AES128CTR) streamk1                    
                  ]
                , bgroup "salsa20"
                  [ bench "pure streamgen 4094/10000" $ nf (streamGenBench (Just Salsa20) streamk2 4094) 10000
                  , bench "enum1 encrypt 1gb random data" $ nfIO $ streamEncBench1 (Just Salsa20) streamk2
                  , bench "enum2 encrypt 1gb random data" $ nfIO $ streamEncBench2 (Just Salsa20) streamk2
                  ]
                , bgroup "salsa2012"
                  [ bench "pure streamgen 4094/10000" $ nf (streamGenBench (Just Salsa2012) streamk3 4094) 10000
                  , bench "enum1 encrypt 1gb random data" $ nfIO $ streamEncBench1 (Just Salsa2012) streamk3
                  , bench "enum2 encrypt 1gb random data" $ nfIO $ streamEncBench2 (Just Salsa2012) streamk3
                  ]
                , bgroup "salsa208"
                  [ bench "pure streamgen 4094/10000" $ nf (streamGenBench (Just Salsa208) streamk4 4094) 10000
                  , bench "enum1 encrypt 1gb random data" $ nfIO $ streamEncBench1 (Just Salsa208) streamk4
                  , bench "enum2 encrypt 1gb random data" $ nfIO $ streamEncBench2 (Just Salsa208) streamk4
                  ]
                , bgroup "default xsalsa20"
                  [ bench "pure streamgen 4094/10000" $ nf (streamGenBench (Just XSalsa20) streamk5 4094) 10000
                  , bench "enum1 encrypt 1gb random data" $ nfIO $ streamEncBench1 (Just XSalsa20) streamk5
                  , bench "enum2 encrypt 1gb random data" $ nfIO $ streamEncBench2 (Just XSalsa20) streamk5
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

        streamGenBench :: Maybe CryptoMode -> Stream.SecretKey -> Int -> Int -> ByteString
        streamGenBench mode sk sz i 
          = go (createZeroNonce $ Stream.nonceLength mode) empty i
          where go !_ !bs 0  = bs
                go !n !_ !x = go (incNonce n) (Stream.streamGen mode n sz sk) (x-1)

        streamEncBench1 :: Maybe CryptoMode -> Stream.SecretKey -> IO ByteString
        streamEncBench1 mode sk = do
          let nonce = createZeroNonce $ Stream.nonceLength mode
              goI :: ByteString -> Nonce -> Iteratee ByteString IO ByteString
              goI !_ !n = do
                v <- EL.head
                case v of
                  Nothing -> return S.empty
                  Just v_ -> goI (Stream.encrypt mode n v_ sk) (incNonce n)
          run_ (enumFile "./testdata" $$ (goI S.empty nonce))

        streamEncBench2 :: Maybe CryptoMode -> Stream.SecretKey -> IO ()
        streamEncBench2 mode sk = do 
            h <- openBinaryFile "/dev/null" WriteMode
            let n = createZeroNonce $ Stream.nonceLength mode
            run_ (encryptFileEnum "./testdata" mode sk n $$ iterHandle h)
            hClose h
            
encryptFileEnum :: FilePath -> Maybe CryptoMode -> Stream.SecretKey -> Nonce -> Enumerator ByteString IO b
encryptFileEnum f m sk n = enumFile f $= encryptEnee m sk n

encryptEnee :: Monad m => Maybe CryptoMode -> Stream.SecretKey -> Nonce -> Enumeratee ByteString ByteString m b
encryptEnee m k = EL.mapAccum $ \n bs -> (incNonce n, Stream.encrypt m n bs k)

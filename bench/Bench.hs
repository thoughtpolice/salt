module Main
       ( main -- :: IO ()
       ) where
import Control.Monad (void)
import Criterion.Main

import Crypto.NaCl.Random

main :: IO ()
main = 
  defaultMain [ bgroup "" 
                [
                ]
              , bgroup "randomBytes"
                [ bench "32"  $ void $ randomBytes 32
                , bench "64"  $ void $ randomBytes 64
                , bench "128" $ void $ randomBytes 128
                , bench "256" $ void $ randomBytes 256
                ]
              ]

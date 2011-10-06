module Main
       ( main -- :: IO ()
       ) where
import Test.Framework (defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

main :: IO ()
main = defaultMain [ testGroup "" [
                                  ]
                   ]

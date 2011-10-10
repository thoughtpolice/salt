module Main
       ( main -- :: IO ()
       ) where
import Control.Monad (when, liftM)
import System.Environment (getArgs)
import System.Exit
import Data.ByteString.Char8 as S hiding (putStrLn)
import Crypto.NaCl.Encrypt.Stream
import Crypto.NaCl.Nonce

import System.FilePath

main :: IO ()
main = putStrLn ("Key length is " ++ show keyLength) >> getArgs >>= go
  where go []         = error "Try --help"
        go ["--help"] =
          putStrLn "USAGE ./encfile [encrypt|decrypt <nonce>] <key> <infile>"
        go ("encrypt":key:file:[]) = do
          checkKey key
          bs <- S.readFile file
          n <- createRandomNonce nonceLength
          let e = encryptXor n bs (pack key)
          S.writeFile (file <.> "enc") e
          S.writeFile (file <.> "nonce") (toBS n)
        go ("decrypt":nonce:key:file:[]) = do
          checkKey key
          n  <- fromBS `liftM` (S.readFile nonce)
          checkNonce n
          bs <- S.readFile file
          let e = decryptXor n bs (pack key)
          S.writeFile (dropExtension file <.> "dec") e
        go _ = error "Try --help"

checkKey :: String -> IO ()
checkKey k = 
  when (Prelude.length k /= keyLength) $
    putStrLn "Invalid key length" >> exitWith (ExitFailure 1)

checkNonce :: Nonce -> IO ()
checkNonce k = 
  when (nonceLen k /= nonceLength) $
    putStrLn "Invalid nonce length" >> exitWith (ExitFailure 1)

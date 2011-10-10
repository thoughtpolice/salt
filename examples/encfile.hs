module Main
       ( main -- :: IO ()
       ) where
import Control.Monad (when, liftM)
import System.Environment (getArgs)
import System.Exit
import Data.ByteString.Char8 as S hiding (putStrLn)
import Crypto.NaCl.Encrypt.Stream
import Crypto.NaCl.Nonce

import System.IO
import System.FilePath

import Data.Enumerator
import Data.Enumerator.Binary
import qualified Data.Enumerator.List as EL

main :: IO ()
main = putStrLn ("Key length is " ++ show keyLength) >> getArgs >>= go
  where go []         = error "Try --help"
        go ["--help"] =
          putStrLn "USAGE ./encfile [encrypt|decrypt <nonce>] <key> <infile>"
        go ("encrypt":key:file:[]) = do
          checkKey key
          -- create nonce and write it
          n <- clearBytes 8 `liftM` createRandomNonce nonceLength
          S.writeFile (file <.> "nonce") (toBS n)
          h <- openFile (file <.> "enc") WriteMode
          run_ $ pipeline file key n h
          hClose h
        go ("decrypt":nonce:key:file:[]) = do
          checkKey key
          n  <- fromBS `liftM` (S.readFile nonce)
          checkNonce n
          h <- openFile (dropExtension file <.> "dec") WriteMode
          run_ $ pipeline file key n h
          hClose h
        go _ = error "Try --help"

pipeline :: FilePath -> String -> Nonce -> Handle -> Iteratee ByteString IO ()
pipeline file k n h = (enumFile file $= encrypt (pack k) n) $$ iterHandle h

encrypt :: Monad m => SecretKey -> Nonce -> Enumeratee ByteString ByteString m b
encrypt k = EL.mapAccum $ \n bs -> (incNonce n, encryptXor n bs k)

checkKey :: String -> IO ()
checkKey k = 
  when (Prelude.length k /= keyLength) $
    putStrLn "Invalid key length" >> exitWith (ExitFailure 1)

checkNonce :: Nonce -> IO ()
checkNonce k = 
  when (nonceLen k /= nonceLength) $
    putStrLn "Invalid nonce length" >> exitWith (ExitFailure 1)

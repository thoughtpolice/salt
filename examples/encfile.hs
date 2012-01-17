module Main
       ( main -- :: IO ()
       ) where
import Control.Monad (when)
import System.Environment (getArgs)
import System.Exit
import Data.ByteString.Char8 as S hiding (putStrLn)
import Crypto.NaCl.Encrypt.Stream
import Crypto.NaCl.Nonce
import Crypto.NaCl.Key

import System.IO
import System.FilePath

import Data.Enumerator
import Data.Enumerator.Binary
import qualified Data.Enumerator.List as EL

main :: IO ()
main = putStrLn ("Key length is " ++ show keyLength) >> 
       getArgs >>= go
  where go []         = error "Try --help"
        go ["--help"] =
          putStrLn "USAGE ./encfile [encrypt|decrypt] <key> <file>"
        go ("encrypt":key:file:[]) = do
          checkKey key
          let n = createZeroNonce nonceLength
          body n key file (file <.> "enc")
        go ("decrypt":key:file:[]) = do
          checkKey key
          let n = createZeroNonce nonceLength
          body n key file (dropExtension file <.> "dec")
        go _ = error "Try --help"
        body n k fin fout = do
          h <- openFile fout WriteMode
          run $ pipeline fin k n h
          hClose h

pipeline :: FilePath -> String -> Nonce StreamNonce -> Handle -> Iteratee ByteString IO ()
pipeline file k n h = (enumFile file $= encryptE (pack k) n) $$ iterHandle h

encryptE :: Monad m => ByteString -> Nonce StreamNonce -> Enumeratee ByteString ByteString m b
encryptE k = EL.mapAccum $ \n bs -> (incNonce n, encrypt n bs sk)
  where sk = SecretKey k

checkKey :: String -> IO ()
checkKey k = 
  when (Prelude.length k /= keyLength) $
    putStrLn "Invalid key length" >> exitWith (ExitFailure 1)

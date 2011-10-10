#!/usr/bin/env runghc
{-# LANGUAGE OverloadedStrings, TupleSections #-}
module Main
       ( main -- :: IO ()
       ) where
import Prelude hiding (head, id, div)
import Control.Monad (forM, forM_, liftM)
import System.Environment (getArgs)
import System.FilePath

import Data.ByteString.Char8 as S (append, concat, ByteString, unpack)
import Data.ByteString.Lazy.Char8 as L(putStrLn, readFile, toChunks)
import Data.ByteString.Base64 (encode)

import Text.Blaze.Html4.Strict hiding (map)
import Text.Blaze.Html4.Strict.Attributes hiding (title)

import Text.Blaze.Renderer.Utf8 (renderHtml)

import Data.List (intersperse)
import Data.List.Split (splitOn)

exttype :: String
exttype = ".png"

main :: IO ()
main = do
  (gitsha1:date:machine:cpu:rest) <- getArgs
  
  let pngs = filter (\f -> exttype == takeExtension f) rest
  let files = flip map pngs $ \f -> 
        (init . splitOn "-" . dropExtension $ f, f)
  files' <- forM files $ \(x,f) -> do
    bs <- (encode . S.concat . L.toChunks) `liftM` (L.readFile f)
    return (x,bs)
  
  let values = map (\(x,f) -> (gather " " x, gather "-" x, f)) files'
  L.putStrLn $ renderHtml $ page gitsha1 date machine cpu values
 where gather s x = Prelude.concat $ intersperse s x
       
page :: String -> String -> String -> String -> [(String, String, S.ByteString)] -> Html
page sha1 date machine cpu lnks = html $ do
  head $ title "hs-NaCl benchmark results"
  body $ do
    h1 $ str "Criterion results"
    p $ do
      b (str "Date: ") >> toHtml date >> br
      b (str "Host machine: ") >> str machine >> br
      b (str "Host CPU: ") >> str cpu >> br
      let sha1' = a ! href (toValue ghcommit) $ toHtml sha1
      b (str "Commit: ") >> toHtml sha1' >> br
      br
      b (str "Results:") >> br
      ul $ forM_ lnks $ \(n,anc,_) -> 
        li $ a ! href (toValue $ '#':anc) $ (toHtml n)
      br
      b (str "Graphs:") >> br
      p $ ul $ forM_ lnks $ \(n,anc,image) -> 
        li $ do
          a ! name (toValue anc) $ p (toHtml n)
          br
          img ! alt "Image data" ! 
            (src $ toValue $ "data:Image/png;base64,"++(unpack image))
  where
    ghcommit = ("https://github.com/thoughtpolice/hs-nacl/commit/"++sha1)
    str :: String -> Html
    str = toHtml

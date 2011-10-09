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
  (date:machine:rest) <- getArgs
  
  let pngs = filter (\f -> exttype == takeExtension f) rest
  let files = map (\f -> (init . splitOn "-" . fst $ splitExtension f, f)) pngs
  files' <- forM files $ \(x,f) -> do
    bs <- (encode . S.concat . L.toChunks) `liftM` (L.readFile f)
    return (x,bs)
  
  let values = map (\(x,f) -> (toHtml $ Prelude.concat $ intersperse " " x, f)) files'
  L.putStrLn $ renderHtml $ page date machine values

page :: String -> String -> [(Html, S.ByteString)] -> Html
page date machine lnks = html $ do
  head $ title "hs-NaCl benchmark results"
  body $ do
    h1 $ toHtml ("Criterion results" :: String)
    p $ do
      b (toHtml ("Date: " :: String)) >> toHtml date >> br
      b (toHtml ("Run on: " :: String)) >> toHtml machine >> br
      br
      b (toHtml ("Results:" :: String)) >> br
      p $ ul $ forM_ lnks $ \(n,image) -> 
        li $ do
          p n >> br
          img ! alt "Image data" ! 
            (src $ toValue $ "data:Image/png;base64,"++(unpack image))

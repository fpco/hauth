{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

{-|
Module      : Main
Description : Hauth Client (test hauth server)
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

module Main where

import           Control.Lens
import           Control.Monad (join)
import qualified Data.ByteString.Char8 as BC
import           Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Time (getCurrentTime)
import           Data.Time.Clock.POSIX (getPOSIXTime)
import           Data.UUID (toString)
import           Data.UUID.V4 (nextRandom)
import           Distribution.PackageDescription.TH
       (PackageDescription(..), PackageIdentifier(..), packageVariable)
import           Language.Haskell.TH (runIO, stringE)
import           Network.HAuth
import           Network.HTTP.Types (methodGet)
import           Network.Wreq
import qualified Network.Wreq as NW
import           Options.Applicative
import qualified Options.Applicative as OA
import           URI.ByteString

-- | Main entry point.
main :: IO ()
main = (join . execParser) optParser
  where
    optParser =
        info
            (helper <*>
             (doReq <$>
              OA.argument str (metavar "URL") <*>
              OA.argument str (metavar "ID") <*>
              OA.argument str (metavar "SECRET")))
            (fullDesc <>
             OA.header ("hauth-client " <> packageVersion <> " " <> buildDate) <>
             progDesc "Login to an hauth server")

-- | Embed the project package version number in the code.
packageVersion :: String
packageVersion =
  $(packageVariable (pkgVersion . package))

-- | Embed the build date in the code.
buildDate :: String
buildDate =
  $(stringE =<<
    runIO (show `fmap` Data.Time.getCurrentTime))

-- | Encode headers, make the request & print the result
doReq :: String -> String -> String -> IO ()
doReq url id secret = do
    case parseURI strictURIParserOptions (BC.pack url) of
        (Left err) -> putStrLn "Invalid URL"
        (Right uri) -> do
            ts <- floor <$> getPOSIXTime
            nonce <- toString <$> nextRandom
            let scheme = uri ^. uriSchemeL . schemeBSL
                host = uri ^. uriAuthorityL . _Just . authorityHostL . hostBSL
                port =
                    maybe
                        (if scheme == "https" then "443" else "80")
                        (BC.pack . show)
                        (uri ^? uriAuthorityL . _Just . authorityPortL . _Just .
                         portNumberL)
                path = "/" <> uri ^. uriPathL
                (AuthMAC mac) =
                    hmacDigest
                        (AuthTS ts)
                        (AuthNonce (T.pack nonce))
                        Nothing
                        (AcctSecret (T.pack secret))
                        methodGet
                        path
                        host
                        port
                opts =
                    defaults &
                    (NW.header "Authorization" .~
                     ([ "MAC" <> (" id=" <> BC.pack id) <>
                        (" ts=" <> BC.pack (show ts)) <>
                        (" nonce=" <> BC.pack nonce) <>
                        (" mac=" <> T.encodeUtf8 mac)]))
            r <- getWith opts url
            print (r ^. responseBody)

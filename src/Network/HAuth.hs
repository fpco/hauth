{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}

{-|
Module      : Network.HAuth
Description : Middleware for HMAC SHA256 Authentication
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

module Network.HAuth
       (module Network.HAuth.Auth, module Network.HAuth.Types,
        hauthMiddleware)
       where

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative ((<$>), (<*))
#endif

import           Control.Exception.Enclosed (tryAny)
import           Control.Monad.IO.Class (MonadIO(liftIO))
import           Control.Monad.Logger (runLoggingT, logInfo, logError, Loc, LogSource, LogLevel, LogStr, logDebug)
import           Data.Aeson (encode)
import           Data.Attoparsec.Text (parseOnly, endOfInput)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import           Data.Monoid ((<>))
import           Data.Pool (Pool)
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Lazy.Encoding as TL
import qualified Data.Text.Lazy as TL
import           Data.Time.Clock.POSIX (getPOSIXTime)
import           Data.UUID (UUID)
import           Database.Persist.Postgresql (SqlBackend)
import           Network.Consul (ConsulClient)
import           Network.HAuth.Auth
import           Network.HAuth.Consul
import           Network.HAuth.Parse
import           Network.HAuth.Postgres
import           Network.HAuth.Types
import           Network.HTTP.Types
       (status400, status401, status500, hAuthorization)
import           Network.Wai (responseLBS, Middleware, Request(..))
import           Network.Wai.Request (appearsSecure)
import           STMContainers.Map (Map)

-- | WAI middleware to authenicate requests according to the spec laid out in
-- https://confluence.amgencss.fpcomplete.com/display/HMST/Authentication+system+requirements
-- Takes a ConsulClient for accessing Consul, STMContainers.Map.Map
-- used as a cache and a pool of Postgres database connections used
-- for queries.
hauthMiddleware :: ConsulClient
                -> Map (AuthID Text) Account
                -> Pool SqlBackend
                -> (Loc -> LogSource -> LogLevel -> LogStr -> IO ()) -- ^ log function
                -> (Request -> IO UUID) -- ^ get request ID
                -> Middleware
hauthMiddleware client cache pool logFunc getRequestId app rq respond =
    runLoggingT checkAuthHeader logFunc
  where
    checkAuthHeader = do
        reqId <- liftIO (getRequestId rq)
        case lookup hAuthorization (requestHeaders rq) of
            Nothing -> authFailure status401 reqId "missing header"
            Just bs ->
                case parseOnly (authHeaderP <* endOfInput) (T.decodeUtf8 bs) of
                    Left err -> authFailure status401 reqId (T.pack err)
                    Right authHeader ->
                        case authHeaderToAuth authHeader of
                            Left err ->
                                authFailure status400 reqId (T.pack err)
                            Right auth -> checkAuthMAC reqId auth
    checkAuthMAC reqId auth@Auth{..} = do
        eres <- tryAny $ do
            maybeAcct <- getAccount client cache authID
            case maybeAcct of
                Nothing -> return (authFailure status401 reqId "invalid id")
                Just Account{..} -> do
                    case splitHostPort rq of
                        Nothing -> return (authFailure status400 reqId "bad request")
                        Just (host,port) -> do
                            $logDebug $ T.pack $ "hmacDigest input: " ++
                                show ( authTS
                                     , authNonce
                                     , authExt
                                     , acctSecret
                                     , requestMethod rq
                                     , rawPathInfo rq
                                     , host
                                     , port
                                     )
                            let computedMAC =
                                    hmacDigest
                                        authTS
                                        authNonce
                                        authExt
                                        acctSecret
                                        (requestMethod rq)
                                        (rawPathInfo rq)
                                        host
                                        port
                            if authMAC /= computedMAC
                                   then return (authFailure status401 reqId "invalid mac")
                                   else checkAuthTS reqId auth
        case eres of
            Left e -> do
                $logError (T.pack (show e))
                authFailure status500 reqId "internal error"
            Right x -> x
    checkAuthTS reqId auth@Auth{authTS = AuthTS ts,..} = do
        timeSpread <- abs . (-) ts . floor <$> liftIO getPOSIXTime
        if timeSpread > 120
            then return (authFailure status401 reqId "invalid timestamp")
            else checkAuthStore reqId auth
    checkAuthStore reqId auth = do
        dupe <- isDupeAuth pool auth
        if dupe
            then return (authFailure status401 reqId "duplicate request")
            else logAndStoreAuth reqId auth
    logAndStoreAuth reqId auth = do
        $logInfo
            ((TL.toStrict . TL.decodeUtf8) (encode (AuthSuccess reqId auth)))
        storeAuth pool auth
        let rq' = rq
                -- FIXME modify vault with the creds
                { vault = vault rq
                }
        return (liftIO (app rq' respond))
    authFailure status reqId message = do
        let jsonMsg = encode (AuthFailure reqId message)
        $logError ((TL.toStrict . TL.decodeUtf8) jsonMsg)
        liftIO
            (respond
                 (responseLBS
                      status
                      [ ( "WWW-Authenticate"
                        , "MAC error=\"" <> T.encodeUtf8 message <> "\"")]
                      jsonMsg))

splitHostPort :: Request -> Maybe (ByteString, ByteString)
splitHostPort rq =
    case (BC.split ':' <$> lookup "Host" (requestHeaders rq)) of
        (Just [host]) ->
            Just
                ( host
                , if appearsSecure rq
                      then "443"
                      else "80")
        (Just [host,port]) -> Just (host, port)
        _ -> Nothing

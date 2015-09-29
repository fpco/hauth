{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}

module Network.HAuth (module Network.HAuth.Types, hauthMiddleware)
       where

{-|
Module      : Network.HAuth
Description : Middleware for HMAC SHA256 Authentication
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative ((<$>), (<*))
#endif

import           Control.Monad.IO.Class (MonadIO(liftIO))
import           Control.Monad.Logger (runStdoutLoggingT, logInfo, logError)
import           Data.Aeson (encode)
import           Data.Attoparsec.Text (parseOnly, endOfInput)
import           Data.Monoid ((<>))
import           Data.Pool (Pool)
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Lazy.Encoding as TL
import qualified Data.Text.Lazy as TL
import           Data.Time.Clock.POSIX (getPOSIXTime)
import           Data.UUID.V4 (nextRandom)
import           Database.Persist.Postgresql (SqlBackend)
import           Network.Consul (ConsulClient)
import           Network.HAuth.Auth
import           Network.HAuth.Consul
import           Network.HAuth.Parse
import           Network.HAuth.Postgres
import           Network.HAuth.Types
import           Network.HTTP.Types
       (status400, status401, status403, hAuthorization)
import           Network.Wai (responseLBS, requestHeaders, Middleware)
import           STMContainers.Map (Map)

-- | WAI middleware to authenicate requests according to the spec laid out in
-- https://confluence.amgencss.fpcomplete.com/display/HMST/Authentication+system+requirements
-- Takes a ConsulClient for accessing Consul, STMContainers.Map.Map
-- used as a cache and a pool of Postgres database connections used
-- for queries.
hauthMiddleware :: ConsulClient
                -> Map (AuthID Text) Account
                -> Pool SqlBackend
                -> Middleware
hauthMiddleware client cache pool app rq respond =
    runStdoutLoggingT checkAuthHeader
  where
    checkAuthHeader = do
        reqId <- liftIO nextRandom
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
        maybeAcct <- getAccount client cache authID
        case maybeAcct of
            Nothing -> authFailure status403 reqId "invalid id"
            Just Account{..} -> do
                let computedMAC =
                        hmacDigest authTS authNonce authExt rq acctSecret
                if authMAC /= computedMAC
                    then authFailure status403 reqId "invalid mac"
                    else checkAuthTS reqId auth
    checkAuthTS reqId auth@Auth{authTS = AuthTS ts,..} = do
        timeSpread <- abs . (-) ts . floor <$> liftIO getPOSIXTime
        if timeSpread > 120
            then authFailure status403 reqId "invalid timestamp"
            else checkAuthStore reqId auth
    checkAuthStore reqId auth = do
        dupe <- isDupeAuth pool auth
        if dupe
            then authFailure status403 reqId "duplicate request"
            else logAndStoreAuth reqId auth
    logAndStoreAuth reqId auth = do
        $logInfo
            ((TL.toStrict . TL.decodeUtf8) (encode (AuthSuccess reqId auth)))
        storeAuth pool auth
        liftIO (app rq respond)
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

{-# LANGUAGE CPP                        #-}
{-# LANGUAGE EmptyDataDecls             #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

module Network.HAuth (module Network.HAuth.Types, hauthMiddleware)
       where

-- TODO check that I'm returning the right 40x code as per the wiki doc

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
import           Network.HTTP.Types (status401, hAuthorization)
import           Network.Wai (responseLBS, requestHeaders, Middleware)
import           STMContainers.Map (Map)

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
            Nothing -> authFailure reqId "missing"
            Just bs ->
                case parseOnly (authHeaderP <* endOfInput) (T.decodeUtf8 bs) of
                    Left err -> authFailure reqId (T.pack err)
                    Right authHeader ->
                        case authHeaderToAuth authHeader of
                            Left err -> authFailure reqId (T.pack err)
                            Right auth -> do
                                checkAuthMAC reqId auth
    checkAuthMAC reqId auth@Auth{..} = do
        maybeAcct <- getAccount client cache authID
        case maybeAcct of
            Nothing -> authFailure reqId "invalid id"
            Just Account{..} -> do
                let computedMAC =
                        hmacDigest authTS authNonce authExt rq acctSecret
                liftIO (print computedMAC)
                if authMAC /= computedMAC
                    then authFailure reqId "invalid mac"
                    else checkAuthTS reqId auth
    checkAuthTS reqId auth@Auth{authTS = AuthTS ts,..} = do
        timeSpread <- abs . (-) ts . floor <$> liftIO getPOSIXTime
        if timeSpread > 120
            then authFailure reqId "invalid timestamp"
            else checkAuthStore reqId auth
    checkAuthStore reqId auth = do
        dupe <- isDupeAuth pool auth
        if dupe
            then authFailure reqId "duplicate request"
            else logAndStoreAuth reqId auth
    logAndStoreAuth reqId auth = do
        $logInfo
            ((TL.toStrict . TL.decodeUtf8) (encode (AuthSuccess reqId auth)))
        storeAuth pool auth
        liftIO (app rq respond)
    authFailure reqId message = do
        let jsonMsg = encode (AuthFailure reqId message)
        $logError ((TL.toStrict . TL.decodeUtf8) jsonMsg)
        liftIO
            (respond
                 (responseLBS
                      status401
                      [ ( "WWW-Authenticate"
                        , "MAC error=\"" <> T.encodeUtf8 message <> "\"")]
                      jsonMsg))

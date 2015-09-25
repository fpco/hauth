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

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative ((<$>), pure)
#endif

import           Control.Concurrent.Lifted (fork, threadDelay)
import           Control.Exception.Enclosed (catchAny)
import           Control.Monad (void)
import           Control.Monad.IO.Class (MonadIO(liftIO))
import           Control.Monad.Logger (runStdoutLoggingT, logInfo)
import           Control.Monad.Trans.Control (MonadBaseControl(..))
import           Control.Monad.STM (atomically)
import           Data.Aeson (encode)
import           Data.Attoparsec.ByteString (parseOnly)
import           Data.ByteString (ByteString)
import           Data.ByteString.Char8 (pack)
import           Data.Byteable (toBytes)
import           Data.Monoid ((<>))
import           Data.Pool (Pool)
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Time.Clock.POSIX (getPOSIXTime)
import           Data.UUID (toString)
import           Data.UUID.V4 (nextRandom)
import           Data.Void (Void, vacuous)
import           Database.Persist
       (Entity, PersistStore(insert), selectList, (||.), (==.))
import           Database.Persist.Postgresql (SqlBackend, runSqlPool)
import           Database.Persist.Sql ()
import           Database.Persist.TH ()
import           GHC.Word
import           Network.Consul (ConsulClient(..), KeyValue(..), getKey)
import           Network.HAuth.Auth (hmacDigest)
import           Network.HAuth.Parse (authP, authHeaderToAuth)
import           Network.HAuth.Types
import           Network.HTTP.Types (status401, hAuthorization)
import           Network.Wai (responseLBS, requestHeaders, Middleware)
import           STMContainers.Map (Map)
import qualified STMContainers.Map as Map

hauthMiddleware :: Pool SqlBackend -> Middleware
hauthMiddleware dbpool app rq respond = runStdoutLoggingT checkAuthHeader
  where
    checkAuthHeader = do
        reqId <- liftIO nextRandom
        case lookup hAuthorization (requestHeaders rq) of
            Nothing -> liftIO (respond (authHeaderInvalid "missing" reqId))
            Just authHeader ->
                case either
                         (const Nothing)
                         authHeaderToAuth
                         (parseOnly authP authHeader) of
                    Nothing ->
                        liftIO (respond (authHeaderInvalid "missing" reqId))
                    Just auth -> do
                        $logInfo ((T.pack . show) auth)
                        checkAuthMac reqId auth
    checkAuthMac reqId auth@Auth{..} = do
        secret <- getSecret undefined undefined authId'
        case secret of
            Nothing -> liftIO (respond (authHeaderInvalid "invalid id" reqId))
            Just secret' ->
                if authMac /=
                   toBytes (hmacDigest authTs authNonce authExt rq secret')
                    then liftIO
                             (respond (authHeaderInvalid "invalid mac" reqId))
                    else checkAuthTS reqId auth
    checkAuthTS reqId auth@Auth{..} = do
        timeSpread <- abs . (-) authTs . floor <$> liftIO getPOSIXTime
        if timeSpread > 120
            then liftIO (respond (authHeaderInvalid "invalid timestamp" reqId))
            else checkAuthStore reqId auth
    checkAuthStore reqId auth@Auth{..} = do
        results <-
            runSqlPool
                (selectList
                     ([AuthId' ==. authId', AuthTs ==. authTs] ||.
                      [AuthId' ==. authId', AuthNonce ==. authNonce])
                     [])
                dbpool
        if (not . null) (results :: [Entity Auth])
            then liftIO (respond (authHeaderInvalid "duplicate request" reqId))
            else logAndStoreAuth reqId auth
    logAndStoreAuth reqId auth = do
        $logInfo
            ("authorization successful " <> T.pack (toString reqId) <> " " <>
             T.pack (show auth))
        void (runSqlPool (insert auth) dbpool)
        liftIO (app rq respond)
    authHeaderInvalid message reqId =
        responseLBS
            status401
            [("WWW-Authenticate", "MAC error=\"" <> pack message <> "\"")]
            (encode
                 (AuthInvalid
                      ("invalid authorization header: " <> message)
                      (toString reqId)))

getSecret
    :: (MonadBaseControl IO m, MonadIO m)
    => ConsulClient -> Map ByteString KeyValue -> ByteString -> m (Maybe Secret)
getSecret client cache authId = do
    maybeCachedKeyValue <- (liftIO . atomically) (Map.lookup authId cache)
    case maybeCachedKeyValue of
        Just KeyValue{kvValue = v,..} -> (pure . Just . Secret) v
        Nothing -> do
            let key = T.decodeUtf8 authId
            maybeConsulKeyVal <- getKey client key Nothing Nothing Nothing
            case maybeConsulKeyVal of
                Just consulKeyVal -> do
                    (liftIO . atomically)
                        (Map.insert consulKeyVal authId cache)
                    (void . fork . vacuous)
                        (watch key (kvModifyIndex consulKeyVal) second)
                    (pure . Just . Secret . kvValue) consulKeyVal
                Nothing -> pure Nothing
  where
    second = 1000 * 1000
    watch
        :: (MonadBaseControl IO m, MonadIO m)
        => Text -> Word64 -> Int -> m Void
    watch key idx backoff
      | backoff < second = watch key idx second
    watch key idx backoff
      | backoff > (30 * second) = watch key idx (30 * second)
    watch key idx backoff = do
        catchAny
            (do maybeKeyVal <- getKey client key (Just idx) Nothing Nothing
                case maybeKeyVal of
                    (Just keyValue) -> do
                        (liftIO . atomically)
                            (Map.insert keyValue authId cache)
                        watchAgain key (kvModifyIndex keyValue) backoff
                    Nothing -> watchAgain key idx (backoff * 2))
            (const (watchAgain key idx (backoff * 2)))
    watchAgain
        :: (MonadBaseControl IO m, MonadIO m)
        => Text -> Word64 -> Int -> m Void
    watchAgain key idx backoff = do
        threadDelay backoff
        watch key idx backoff

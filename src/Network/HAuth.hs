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

import           Control.Monad (void)
import           Control.Monad.IO.Class (MonadIO(liftIO))
import           Control.Monad.Logger (runStdoutLoggingT, logInfo)
import           Data.Aeson (encode)
import           Data.Attoparsec.ByteString (parseOnly)
import           Data.ByteString.Char8 (pack)
import           Data.Byteable (toBytes)
import           Data.Monoid ((<>))
import           Data.Pool (Pool)
import qualified Data.Text as T (pack)
import           Data.Time.Clock.POSIX (getPOSIXTime)
import           Data.UUID (toString)
import           Data.UUID.V4 (nextRandom)
import           Database.Persist
       (Entity, PersistStore(insert), selectList, (||.), (==.))
import           Database.Persist.Postgresql (SqlBackend, runSqlPool)
import           Database.Persist.Sql ()
import           Database.Persist.TH ()
import           Network.HAuth.Auth (hmacDigest)
import           Network.HAuth.Parse (authP, authHeaderToAuth)
import           Network.HAuth.Types
import           Network.HTTP.Types (status401, hAuthorization)
import           Network.Wai (responseLBS, requestHeaders, Middleware)

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
        -- TODO query & cache changes from Consul
        secret <- (pure . Just) (Secret "abc123")
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

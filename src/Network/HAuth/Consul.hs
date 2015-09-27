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

module Network.HAuth.Consul where

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative (pure)
#endif

import           Control.Concurrent.Lifted (fork, threadDelay)
import           Control.Exception.Enclosed (catchAny)
import           Control.Monad (void)
import           Control.Monad.IO.Class (MonadIO(liftIO))
import           Control.Monad.Logger (MonadLogger, logInfo)
import           Control.Monad.Trans.Control (MonadBaseControl(..))
import           Control.Monad.STM (atomically)
import           Data.Monoid ((<>))
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Void (vacuous)
import           Network.Consul (ConsulClient(..), KeyValue(..), getKey)
import           Network.HAuth.Types
import           STMContainers.Map (Map)
import qualified STMContainers.Map as Map

getSecret
    :: (MonadBaseControl IO m, MonadIO m, MonadLogger m)
    => ConsulClient -> Map AuthID Secret -> AuthID -> m (Maybe Secret)
getSecret client cache authId = do
    maybeCachedKeyValue <- (liftIO . atomically) (Map.lookup authId cache)
    case maybeCachedKeyValue of
        s@(Just _) -> pure s
        Nothing -> do
            let key = T.decodeUtf8 (id' authId)
            maybeConsulKeyVal <- getKey client key Nothing Nothing Nothing
            case maybeConsulKeyVal of
                Just consulKeyVal -> do
                    let secret = Secret (kvValue consulKeyVal)
                    (liftIO . atomically) (Map.insert secret authId cache)
                    (void . fork . vacuous)
                        (watch key (kvModifyIndex consulKeyVal) second)
                    (pure . Just) secret
                Nothing -> pure Nothing
  where
    second = 1000 * 1000
    watch key idx backoff
      | backoff < second = watch key idx second
    watch key idx backoff
      | backoff > (30 * second) = watch key idx (30 * second)
    watch key idx backoff = do
        catchAny
            (do maybeKeyVal <- getKey client key (Just idx) Nothing Nothing
                $logInfo
                    ("Background for " <> key <> " : " <>
                     (T.pack . show) maybeKeyVal)
                case maybeKeyVal of
                    (Just keyValue) -> do
                        (liftIO . atomically)
                            (Map.insert
                                 (Secret (kvValue keyValue))
                                 authId
                                 cache)
                        watchAgain key (kvModifyIndex keyValue) backoff
                    Nothing -> watchAgain key idx (backoff * 2))
            (const (watchAgain key idx (backoff * 2)))
    watchAgain key idx backoff = do
        threadDelay backoff
        watch key idx backoff

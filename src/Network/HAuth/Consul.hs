{-# LANGUAGE CPP               #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}

{-|
Module      : Network.HAuth.Consul
Description : Functions for querying/watching Consul data
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

module Network.HAuth.Consul where

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative (pure)
#endif

import           Control.Concurrent.Lifted (fork, threadDelay)
import           Control.Exception.Enclosed (catchAny)
import           Control.Monad (void)
import           Control.Monad.IO.Class (MonadIO(liftIO))
import           Control.Monad.Logger (MonadLogger, logDebug, logWarn)
import           Control.Monad.STM (atomically)
import           Control.Monad.Trans.Control (MonadBaseControl(..))
import           Data.Aeson (decode)
import           Data.ByteString.Lazy (fromStrict)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Void (vacuous)
import           Network.Consul (ConsulClient(..), KeyValue(..), getKey)
import           Network.HAuth.Types
import           STMContainers.Map (Map)
import qualified STMContainers.Map as Map

-- | Retrieve an account from the STM Map cache or directly from Consul.
-- Background threads watch Consul for data changes on accounts we've
-- previously looked up.
getAccount
    :: (MonadBaseControl IO m, MonadIO m, MonadLogger m)
    => ConsulClient
    -> Map (AuthID Text) Account
    -> AuthID Text
    -> m (Maybe Account)
getAccount client cache authId@(AuthID id') = do
    maybeAccount <- (liftIO . atomically) (Map.lookup authId cache)
    case maybeAccount of
        s@(Just _) -> pure s
        Nothing -> do
            maybeConsulKeyVal <- getKey client id' Nothing Nothing Nothing
            case maybeConsulKeyVal of
                Just consulKeyVal ->
                    case decode (fromStrict (kvValue consulKeyVal)) :: Maybe Account of
                        Just acct -> do
                            (liftIO . atomically)
                                (Map.insert acct authId cache)
                            (void . fork . vacuous)
                                (watch id' (kvModifyIndex consulKeyVal) second)
                            (pure . Just) acct
                        Nothing -> pure Nothing
                Nothing -> pure Nothing
  where
    second = 1000 * 1000
    watch key idx backoff
      | backoff < second = watch key idx second
    watch key idx backoff
      | backoff > (30 * second) = watch key idx (30 * second)
    watch key idx backoff =
        catchAny
            (do maybeKeyVal <- getKey client key (Just idx) Nothing Nothing
                $logDebug
                    ("Background for " <> key <> " : " <>
                     (T.pack . show) maybeKeyVal)
                case maybeKeyVal of
                    (Just keyValue) ->
                        case decode (fromStrict (kvValue keyValue)) :: Maybe Account of
                            Just acct -> do
                                (liftIO . atomically)
                                    (Map.insert acct authId cache)
                                watchAgain key (kvModifyIndex keyValue) second
                            Nothing -> watchAgain key idx (backoff * 2)
                    Nothing -> watchAgain key idx (backoff * 2))
            (\ex ->
                  do $logWarn (T.pack (show ex))
                     watchAgain key idx (backoff * 2))
    watchAgain key idx backoff = do
        threadDelay backoff
        watch key idx backoff

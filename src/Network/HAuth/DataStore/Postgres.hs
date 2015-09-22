{-# LANGUAGE CPP                        #-}
{-# LANGUAGE EmptyDataDecls             #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

module Network.HAuth.DataStore.Postgres
       (PostgresConfig, defaultPostgresConfig, getPostgresHostName,
        setPostgresHostName, getPostgresPortNumber, setPostgresPortNumber,
        mkPostgresAuthDataStore)
       where

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative (Applicative, pure)
#endif
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.Logger (MonadLogger, runStderrLoggingT)
import qualified Data.Map.Strict as Map
import           Database.Persist
import           Database.Persist.Postgresql
import           Database.Persist.Sql
import           Database.Persist.TH
import           Network.HAuth.Types
import           Network.Socket (HostName(..), PortNumber(..))

data PostgresConfig = PostgresConfig
    { postgresHostName :: HostName
    , postgresPortNumber :: PortNumber
    } deriving (Show)

defaultPostgresConfig :: PostgresConfig
defaultPostgresConfig = PostgresConfig "127.0.0.1" 5432

setPostgresHostName :: PostgresConfig -> HostName -> PostgresConfig
setPostgresHostName cfg name =
    cfg
    { postgresHostName = name
    }

setPostgresPortNumber :: PostgresConfig -> PortNumber -> PostgresConfig
setPostgresPortNumber cfg port =
    cfg
    { postgresPortNumber = port
    }

getPostgresHostName :: PostgresConfig -> HostName
getPostgresHostName PostgresConfig{..} = postgresHostName

getPostgresPortNumber :: PostgresConfig -> PortNumber
getPostgresPortNumber PostgresConfig{..} = postgresPortNumber

mkPostgresAuthDataStore
    :: (Applicative m)
    => PostgresConfig -> m AuthDataStore
mkPostgresAuthDataStore _cfg = pure AuthDataStore{..}
  where
    addAuth auth = pure ()
    isAuth auth = pure False

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
AuthEntry
    authId String
    ts Int
    nonce String
    ext String Maybe
    mac String
    deriving Show
|]

runPostgresTest :: IO ()
runPostgresTest =
    runStderrLoggingT
        (withPostgresqlPool
             "host=localhost dbname=test user=test password=test port=5432"
             10
             (\pool ->
                   liftIO
                       (do flip
                               runSqlPersistMPool
                               pool
                               (do runMigration migrateAll
                                   testId <-
                                       insert
                                           (AuthEntry
                                                "test"
                                                11
                                                "nonce"
                                                Nothing
                                                "1238g7019381023980123")
                                   test <- get testId
                                   liftIO (print test)))))

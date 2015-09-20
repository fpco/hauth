{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.HAuth.DataStore.Postgres
       (PostgresConfig, defaultPostgresConfig, getPostgresHostName,
        setPostgresHostName, getPostgresPortNumber, setPostgresPortNumber,
        mkPostgresAuthDataStore)
       where

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative (Applicative, pure)
#endif
import           Control.Monad.IO.Class (MonadIO)
import           Control.Monad.Logger (MonadLogger)
import qualified Data.Map.Strict as Map
import           Network.HAuth.DataStore.Memory
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
    :: (Applicative m, MonadIO m, MonadLogger m)
    => PostgresConfig -> m AuthDataStore
mkPostgresAuthDataStore _cfg = mkMemoryAuthDataStore Map.empty

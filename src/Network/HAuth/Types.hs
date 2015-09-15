{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.HAuth.Types
       (ConsulConfig, defaultConsulConfig, setConsulHost, setConsulPort,
        getConsulHost, getConsulPort, PostgresConfig,
        defaultPostgresConfig, setPostgresHost, setPostgresPort,
        getPostgresHost, getPostgresPort)
       where

import           Data.Text (Text)
import qualified Data.Text as Text
import           Network.HAuth.Types.Internal
import           Network.Socket

data ConsulConfig = ConsulConfig
    { consulHost :: Text
    , consulPort :: PortNumber
    } deriving (Show)

defaultConsulConfig :: ConsulConfig
defaultConsulConfig = ConsulConfig "127.0.0.1" 8500

setConsulHost :: ConsulConfig -> Text -> ConsulConfig
setConsulHost cc h =
    cc
    { consulHost = h
    }

setConsulPort :: ConsulConfig -> PortNumber -> ConsulConfig
setConsulPort cc p =
    cc
    { consulPort = p
    }

getConsulHost :: ConsulConfig -> Text
getConsulHost = consulHost

getConsulPort :: ConsulConfig -> PortNumber
getConsulPort = consulPort

data PostgresConfig = PostgresConfig
    { postgresHost :: Text
    , postgresPort :: PortNumber
    } deriving (Show)

defaultPostgresConfig :: PostgresConfig
defaultPostgresConfig = PostgresConfig "127.0.0.1" 5432

setPostgresHost :: PostgresConfig -> Text -> PostgresConfig
setPostgresHost cc h =
    cc
    { postgresHost = h
    }

setPostgresPort :: PostgresConfig -> PortNumber -> PostgresConfig
setPostgresPort cc p =
    cc
    { postgresPort = p
    }

getPostgresHost :: PostgresConfig -> Text
getPostgresHost = postgresHost

getPostgresPort :: PostgresConfig -> PortNumber
getPostgresPort = postgresPort

{-# LANGUAGE OverloadedStrings #-}

module Network.HAuth.DataStore.Postgres where

import Data.Text (Text)
import Network.HAuth.Types.DataStore
import Network.Socket (PortNumber)

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

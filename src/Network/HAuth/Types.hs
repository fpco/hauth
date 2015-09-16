{-# LANGUAGE OverloadedStrings #-}

module Network.HAuth.Types
       (ID(..), TS(..), Nonce(..), Ext(..), mkAuth, Auth, ConsulConfig,
        defaultConsulConfig, setConsulHost, setConsulPort, getConsulHost,
        getConsulPort, PostgresConfig, defaultPostgresConfig,
        setPostgresHost, setPostgresPort, getPostgresHost, getPostgresPort)
       where

import           Crypto.Hash
import           Crypto.MAC
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import           Data.Byteable
import           Data.Text (Text)
import qualified Data.Text as Text
import           Network.HAuth.Types.Internal
import           Network.Socket

mkAuth :: ByteString -> ID -> TS -> Nonce -> Maybe Ext -> Auth
mkAuth key id ts nonce ext =
  Auth id ts nonce ext (authMac key id ts nonce ext)

authMac :: ByteString -> ID -> TS -> Nonce -> Maybe Ext -> Mac
authMac key (ID i) (TS t) (Nonce n) e =
    let attrs = [i, BC.pack (show t), n]
        hmac' :: HMAC SHA256
        hmac' =
            hmac
                key
                (B.intercalate
                     "\n"
                     (case e of
                          (Just (Ext e')) -> attrs ++ [e']
                          Nothing -> attrs))
    in Mac (toBytes hmac')

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
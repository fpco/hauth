{-# LANGUAGE OverloadedStrings #-}

module Network.HAuth.DataStore.Consul where

import Network.Socket (PortNumber)
import Data.Text (Text)

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

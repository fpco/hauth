{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.HAuth.DataStore.Consul
       (ConsulConfig, defaultConsulConfig, getConsulHostName,
        setConsulHostName, getConsulPortNumber, setConsulPortNumber,
        mkConsulSecretDataStore)
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

data ConsulConfig = ConsulConfig
    { consulHostName :: HostName
    , consulPortNumber :: PortNumber
    } deriving (Show)

defaultConsulConfig :: ConsulConfig
defaultConsulConfig = ConsulConfig "127.0.0.1" 8500

setConsulHostName :: ConsulConfig -> HostName -> ConsulConfig
setConsulHostName cfg name =
    cfg
    { consulHostName = name
    }

setConsulPortNumber :: ConsulConfig -> PortNumber -> ConsulConfig
setConsulPortNumber cfg port =
    cfg
    { consulPortNumber = port
    }

getConsulHostName :: ConsulConfig -> HostName
getConsulHostName ConsulConfig{..} = consulHostName

getConsulPortNumber :: ConsulConfig -> PortNumber
getConsulPortNumber ConsulConfig{..} = consulPortNumber

mkConsulSecretDataStore
    :: (Applicative m, MonadIO m, MonadLogger m)
    => ConsulConfig -> m SecretDataStore
mkConsulSecretDataStore _cfg = mkMemorySecretDataStore Map.empty

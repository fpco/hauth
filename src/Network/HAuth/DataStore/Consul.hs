{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.HAuth.DataStore.Consul
       (ConsulConfig, mkConsulConfig, getConsulSockAddr,
        setConsulSockAddr, mkConsulAuthDataStore)
       where

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative (Applicative, pure)
#endif
import           Control.Monad.IO.Class (MonadIO)
import           Control.Monad.Logger (MonadLogger)
import qualified Data.Map.Strict as Map
import           Network.HAuth.DataStore.Memory
import           Network.HAuth.Types
import           Network.Socket (SockAddr(..))

data ConsulConfig = ConsulConfig SockAddr

mkConsulConfig :: SockAddr -> ConsulConfig
mkConsulConfig = ConsulConfig

setConsulSockAddr :: ConsulConfig -> SockAddr -> ConsulConfig
setConsulSockAddr _ = ConsulConfig

getConsulSockAddr :: ConsulConfig -> SockAddr
getConsulSockAddr (ConsulConfig addr) = addr

mkConsulAuthDataStore
    :: (Applicative m, MonadIO m, MonadLogger m)
    => ConsulConfig -> m AuthDataStore
mkConsulAuthDataStore _cfg = mkMemoryAuthDataStore Map.empty

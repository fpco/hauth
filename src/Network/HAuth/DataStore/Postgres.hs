{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.HAuth.DataStore.Postgres
       (PostgresConfig, mkPostgresConfig, getPostgresSockAddr,
        setPostgresSockAddr, mkPostgresAuthDataStore)
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

data PostgresConfig = PostgresConfig SockAddr

mkPostgresConfig :: SockAddr -> PostgresConfig
mkPostgresConfig = PostgresConfig

setPostgresSockAddr :: PostgresConfig -> SockAddr -> PostgresConfig
setPostgresSockAddr _ = PostgresConfig

getPostgresSockAddr :: PostgresConfig -> SockAddr
getPostgresSockAddr (PostgresConfig addr) = addr

mkPostgresAuthDataStore
    :: (Applicative m, MonadIO m, MonadLogger m)
    => PostgresConfig -> m AuthDataStore
mkPostgresAuthDataStore _cfg = mkMemoryAuthDataStore Map.empty

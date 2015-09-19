{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}

module Network.HAuth.DataStore.Memory where

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative ((<$>), (<*>), Applicative, pure)
#endif
import           Control.Concurrent.MVar (newMVar, putMVar, takeMVar)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.Logger (MonadLogger)
import           Data.Map (Map)
import qualified Data.Map.Strict as Map
import           Network.HAuth.Types

mkMemorySecretDataStore
    :: (Applicative m, MonadIO m, MonadLogger m)
    => Map ID Secret -> m SecretDataStore
mkMemorySecretDataStore = pure . mkSecretStore
  where
    mkSecretStore m =
        SecretDataStore
        { getSecret = pure . flip Map.lookup m
        }

mkMemoryAuthDataStore
    :: (Applicative m, MonadIO m, MonadLogger m)
    => Map (ID, TS, Nonce) Auth -> m AuthDataStore
mkMemoryAuthDataStore = fmap mkAuthStore . liftIO . newMVar
  where
    mkAuthStore m =
        AuthDataStore
        { addAuth = \a@Auth{..} ->
                         liftIO
                             (takeMVar m >>=
                              putMVar m . Map.insert (id', ts, nonce) a)
        , isAuth = \k ->
                        Map.member k <$> liftIO (takeMVar m)
        }

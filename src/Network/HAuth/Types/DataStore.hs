{-# LANGUAGE CPP #-}
{-# LANGUAGE RankNTypes #-}

module Network.HAuth.Types.DataStore where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative (Applicative)
#endif
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Logger (MonadLogger)
import Network.HAuth.Types.Auth
import Network.HAuth.Types.Secret

data SecretDataStore = SecretDataStore
    { getSecret :: (Applicative m, MonadIO m, MonadLogger m) => ID -> m (Maybe Secret)
    }

data AuthDataStore = AuthDataStore
    { addAuth :: (Applicative m, MonadIO m, MonadLogger m) => Auth -> m ()
    , isAuth :: (Applicative m, MonadIO m, MonadLogger m) => (ID, TS, Nonce) -> m Bool
    }

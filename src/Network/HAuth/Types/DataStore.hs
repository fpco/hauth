{-# LANGUAGE RankNTypes #-}

module Network.HAuth.Types.DataStore where

import Network.HAuth.Types.Auth
import Network.HAuth.Types.Secret

data AuthDataStore = AuthDataStore
    { findAuth :: Monad m => ID -> TS -> Nonce -> Mac -> m (Maybe [Auth])
    , addAuth :: Monad m => Auth -> m ()
    }

data SecretDataStore = SecretDataStore
    { listSecrets :: Monad m => m (Either String [Secret])
    , watchSecret :: Monad m => (Secret -> m ())
    }

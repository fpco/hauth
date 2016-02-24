{-# LANGUAGE CPP               #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}

{-|
Module      : Network.HAuth.Postgres
Description : Functions for querying/recording Auth attempts.
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

module Network.HAuth.Postgres where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative ((<$>))
#endif

import Control.Monad (void)
import Control.Monad.Trans.Control (MonadBaseControl)
import Database.Persist
       (PersistStore(insert), selectList, (||.), (==.))
import Database.Persist.Postgresql (SqlBackend, runSqlPool)
import Database.Persist.Sql ()
import Data.Pool (Pool)
import Network.HAuth.Types
import Control.Monad.IO.Class (MonadIO)

-- | Convert an Auth type to a database ready AuthRegistry type.
authToRegistry :: Auth -> AuthRegistry
authToRegistry (Auth (AuthID id') (AuthTS ts) (AuthNonce nonce) maybeExt (AuthMAC mac)) =
    AuthRegistry
        id'
        (fromIntegral ts)
        nonce
        (fmap
             (\(AuthExt e) ->
                   e)
             maybeExt)
        mac

-- | Query the database to determine if we have seen this
-- authentication attempt before.
isDupeAuth
    :: (MonadBaseControl IO m, MonadIO m)
    => Pool SqlBackend -> Auth -> m Bool
isDupeAuth pool = isDupe . authToRegistry
  where
    isDupe AuthRegistry{..} =
        not . null <$>
        -- TODO query only the row ID and also limit results to 1 row
        runSqlPool
            (selectList
                 ([ AuthRegistryId' ==. authRegistryId'
                  , AuthRegistryNonce ==. authRegistryNonce] ||.
                  [ AuthRegistryId' ==. authRegistryId'
                  , AuthRegistryMac ==. authRegistryMac])
                 [])
            pool

-- | Store the authentication attempt so we can match it with future
-- authentication requests.
storeAuth
    :: (MonadBaseControl IO m, MonadIO m)
    => Pool SqlBackend -> Auth -> m ()
storeAuth pool auth = void (runSqlPool (insert (authToRegistry auth)) pool)

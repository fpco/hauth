{-# LANGUAGE CPP                        #-}
{-# LANGUAGE EmptyDataDecls             #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

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

authToRegistry :: Auth -> AuthRegistry
authToRegistry Auth{..} =
    AuthRegistry
        (id' authID)
        (fromIntegral (ts authTS))
        (nonce authNonce)
        (fmap ext authExt)
        (mac authMAC)

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
                  , AuthRegistryTs ==. authRegistryTs] ||.
                  [ AuthRegistryId' ==. authRegistryId'
                  , AuthRegistryNonce ==. authRegistryNonce] ||.
                  [ AuthRegistryId' ==. authRegistryId'
                  , AuthRegistryMac ==. authRegistryMac])
                 [])
            pool

storeAuth
    :: (MonadBaseControl IO m, MonadIO m)
    => Pool SqlBackend -> Auth -> m ()
storeAuth pool auth = void (runSqlPool (insert (authToRegistry auth)) pool)

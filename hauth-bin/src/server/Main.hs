{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

{-|
Module      : Main
Description : HAuth Server (test server)
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

module Main where

import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Logger (runNoLoggingT, runStderrLoggingT)
import           Control.Monad.STM (atomically)
import qualified Data.ByteString.Char8 as BC
import           Data.Monoid ((<>))
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Database.Persist ()
import           Database.Persist.Postgresql (withPostgresqlPool)
import           Database.Persist.Sql (runMigration, runSqlPool)
import           Network.BSD (getHostName)
import           Network.Consul (initializeConsulClient)
import           Network.HAuth
import           Network.HTTP.Types (status200)
import           Network.Socket (PortNumber(..))
import           Network.Wai (responseLBS)
import           Network.Wai.Handler.Warp (run)
import           Network.Wai.Middleware.RequestLogger (logStdoutDev)
import qualified STMContainers.Map as Map
import           System.Environment (getEnv)

main :: IO ()
main = do
    hostname <- getHostName
    -- NOTE: Using PortNum is needed right now due to a bug
    -- consul-haskell-0.2.1 but will be fixed as soon as
    -- consul-haskell-0.3 is released.
    client <- initializeConsulClient (T.pack hostname) (PortNum 8500) Nothing
    cache <- atomically Map.new
    runStderrLoggingT
        (withPostgresqlPool
             ("host=" <> (BC.pack hostname) <>
              " dbname=hauth user=hauth password=hauth port=5432")
             10
             (\pool ->
                   do runNoLoggingT (runSqlPool (runMigration migrateAll) pool)
                      let middleware =
                              logStdoutDev . hauthMiddleware client cache pool
                          webApp rq respond =
                              liftIO
                                  (respond
                                       (responseLBS
                                            status200
                                            [("Content-Type", "text/plain")]
                                            "Win!"))
                      liftIO (run 8443 (middleware webApp))))

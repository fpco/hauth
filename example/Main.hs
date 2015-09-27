{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.Logger (runNoLoggingT, runStderrLoggingT)
import           Control.Monad.STM (atomically)
import           Network.Consul (initializeConsulClient)
import           Network.HAuth
import           Network.Wai.Application.Static
       (staticApp, defaultWebAppSettings)
import           Network.Wai.Handler.Warp (run)
import           Network.Wai.Middleware.RequestLogger (logStdoutDev)
import           Network.Socket (PortNumber(..))
import           Database.Persist ()
import           Database.Persist.Postgresql (withPostgresqlPool)
import           Database.Persist.Sql (runMigration, runSqlPool)
import qualified STMContainers.Map as Map

main :: IO ()
main = do
    client <- initializeConsulClient "localhost" (PortNum 8500) Nothing
    cache <- atomically Map.new
    runStderrLoggingT
        (withPostgresqlPool
             "host=localhost dbname=hauth user=hauth password=hauth port=5432"
             10
             (\pool ->
                   do runNoLoggingT (runSqlPool (runMigration migrateAll) pool)
                      let middleware =
                              logStdoutDev . hauthMiddleware client cache pool
                          webApp = staticApp (defaultWebAppSettings ".")
                      liftIO (run 4321 (middleware webApp))))

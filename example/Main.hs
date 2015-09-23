{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Logger (runNoLoggingT, runStderrLoggingT)
import Network.HAuth (migrateAll, hauthMiddleware)
import Network.Wai.Application.Static
       (staticApp, defaultWebAppSettings)
import Network.Wai.Handler.Warp (run)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Database.Persist ()
import Database.Persist.Postgresql (withPostgresqlPool)
import Database.Persist.Sql (runMigration, runSqlPool)

main :: IO ()
main = do
    -- TODO opt.parse & yaml options for
    --   Postgres: host, db, user, pass & port
    --   Consul: host, acl
    runStderrLoggingT
        (withPostgresqlPool
             "host=localhost dbname=hauth user=hauth password=hauth port=5432"
             10
             (\pool ->
                   do runNoLoggingT (runSqlPool (runMigration migrateAll) pool)
                      let middleware = logStdoutDev . hauthMiddleware pool
                          webApp = staticApp (defaultWebAppSettings ".")
                      liftIO (run 8080 (middleware webApp))))

{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative ((<$>), (<*>), Applicative, pure)
#endif
import Control.Monad (void)
import Control.Monad.IO.Class (MonadIO(..))
import Control.Monad.Logger
       (runStdoutLoggingT, MonadLoggerIO, logDebug, logInfo)
import Control.Monad.Trans.Control (MonadBaseControl(..))
import Network.HAuth
import Network.HAuth.DataStore.Consul
import Network.HAuth.DataStore.Postgres
import Network.Wai (Application, Middleware)
import Network.Wai.Application.Static
       (staticApp, defaultWebAppSettings)
import Network.Wai.Handler.Warp (run)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)

main :: IO ()
main = do
    authenticate <-
        mkConsulPostgresAuthMiddleware
            defaultConsulConfig
            defaultPostgresConfig
    let middleWare = logStdoutDev . authenticate
        webApp = middleWare (staticApp (defaultWebAppSettings "."))
        runApp = runStdoutLoggingT . void . liftIO . run 8080
    runApp webApp

mkConsulPostgresAuthMiddleware
    :: Applicative m
    => ConsulConfig -> PostgresConfig -> m Middleware
mkConsulPostgresAuthMiddleware _consulCfg _postgresCfg = do
    pure undefined

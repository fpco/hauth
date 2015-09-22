{-# LANGUAGE CPP               #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative ((<$>), (<*>), Applicative, pure)
#endif
import Control.Monad (void)
import Control.Monad.IO.Class (MonadIO(..))
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
    secretDS <- mkConsulSecretDataStore defaultConsulConfig
    authDS <- mkPostgresAuthDataStore defaultPostgresConfig
    let middleware = logStdoutDev . hauthMiddleware secretDS authDS
        webApp = staticApp (defaultWebAppSettings ".")
    run 8080 (middleware webApp)

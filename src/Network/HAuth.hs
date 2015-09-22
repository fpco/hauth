{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}

module Network.HAuth (module Network.HAuth.Types, hauthMiddleware)
       where

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative (Applicative, (<$>), (<*>), pure)
#endif
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.Logger
       (runStdoutLoggingT, MonadLogger, MonadLoggerIO, logDebug, logInfo)
import           Data.Aeson (encode)
import           Data.Attoparsec.ByteString (parseOnly)
import           Data.Monoid ((<>))
import qualified Data.Text as T
import           Data.Time.Clock.POSIX (getPOSIXTime)
import           Data.UUID (toString)
import           Data.UUID.V4 (nextRandom)
import           Network.HAuth.Auth
import           Network.HAuth.Parse
import           Network.HAuth.Types
import           Network.HTTP.Types (hAuthorization, status400, status401)
import           Network.Wai (responseLBS, requestHeaders, Middleware)

hauthMiddleware :: SecretDataStore -> AuthDataStore -> Middleware
hauthMiddleware secretDS authDS app rq respond = do
    reqId <- toString <$> nextRandom
    runStdoutLoggingT (checkAuthHeader secretDS authDS reqId app rq respond)

checkAuthHeader secretDS authDS reqId app rq respond =
    case lookup hAuthorization (requestHeaders rq) of
        Nothing -> liftIO (respond authHeaderMissing)
        Just authHeader ->
            case authHeaderToAuth <$> parseOnly authP authHeader of
                Left err ->
                    liftIO
                        (respond
                             (authHeaderInvalid
                                  "invalid authorization header"
                                  reqId))
                Right Nothing ->
                    liftIO
                        (respond
                             (authHeaderInvalid
                                  "invalid authorization header"
                                  reqId))
                Right (Just auth) -> do
                    $logInfo ((T.pack . show) auth)
                    checkAuthMac secretDS authDS reqId auth app rq respond

checkAuthMac secretDS authDS reqId auth app rq respond = do
    secret <- getSecret secretDS (id' auth)
    case secret of
        Nothing -> liftIO (respond (authHeaderInvalid "no key" reqId))
        Just (Secret key) ->
            let computedMac = authMac key (ts auth) (nonce auth)
            in if computedMac /= mac auth
                   then liftIO
                            (respond (authHeaderInvalid "invalid mac" reqId))
                   else checkAuthTS secretDS authDS reqId auth app rq respond

checkAuthTS secretDS authDS reqId auth@Auth{ts=TS ts',..} app rq respond = do
    currentTS <- round <$> liftIO getPOSIXTime
    if abs (currentTS - ts') > 120
        then liftIO (respond (authHeaderInvalid "invalid ts" reqId))
        else checkAuthStore secretDS authDS reqId auth app rq respond

checkAuthStore secretDS authDS reqId auth app rq respond = do
    dupe <- isAuth authDS auth
    if dupe
        then liftIO (respond (authHeaderInvalid "duplicate request" reqId))
        else logAndStoreAuth secretDS authDS reqId auth app rq respond

logAndStoreAuth secretDS authDS reqId auth app rq respond = do
    addAuth authDS auth
    $logInfo ("Authorization successful " <> T.pack (show auth))
    liftIO (app rq respond)

authHeaderMissing = responseLBS status401 [("WWW-Authenticate", "MAC")] ""

authHeaderInvalid message reqId =
    responseLBS status400 [] (encode (AuthInvalid message reqId))

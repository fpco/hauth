{-# LANGUAGE CPP #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
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
import           Data.UUID (UUID, toString)
import           Data.UUID.V4 (nextRandom)
import           Network.HAuth.Auth
import           Network.HAuth.Parse
import           Network.HAuth.Types
import           Network.HTTP.Types (hAuthorization, status400, status401)
import           Network.Wai (responseLBS, requestHeaders, Middleware)

hauthMiddleware :: SecretDataStore -> AuthDataStore -> Middleware
hauthMiddleware secretDS authDS app rq respond =
    runStdoutLoggingT checkAuthHeader
  where
    checkAuthHeader = do
        reqId <- liftIO nextRandom
        case lookup hAuthorization (requestHeaders rq) of
            Nothing -> liftIO (respond authHeaderMissing)
            Just authHeader -> do
                case either
                         (const Nothing)
                         authHeaderToAuth
                         (parseOnly authP authHeader) of
                    Nothing ->
                        liftIO
                            (respond
                                 (authHeaderInvalid
                                      "invalid authorization header"
                                      reqId))
                    Just auth -> do
                        $logInfo ((T.pack . show) auth)
                        checkAuthMac reqId auth
    checkAuthMac reqId auth = do
        secret <- getSecret secretDS (id' auth)
        case secret of
            Nothing -> liftIO (respond (authHeaderInvalid "key missing" reqId))
            Just (Secret key) ->
                let computedMac = authMac key (ts auth) (nonce auth)
                in if computedMac /= mac auth
                       then liftIO
                                (respond
                                     (authHeaderInvalid "invalid mac" reqId))
                       else checkAuthTS reqId auth
    checkAuthTS reqId auth@Auth{ts = TS ts',..} = do
        timeSpread <- abs . (-) ts' . floor <$> liftIO getPOSIXTime
        if timeSpread > 120
            then liftIO (respond (authHeaderInvalid "invalid timestamp" reqId))
            else checkAuthStore reqId auth
    checkAuthStore reqId auth = do
        dupe <- isAuth authDS auth
        if dupe
            then liftIO (respond (authHeaderInvalid "duplicate request" reqId))
            else logAndStoreAuth reqId auth
    logAndStoreAuth reqId auth = do
        addAuth authDS auth
        $logInfo ("Authorization successful " <> T.pack (show auth))
        liftIO (app rq respond)
    authHeaderMissing = responseLBS status401 [("WWW-Authenticate", "MAC")] ""
    authHeaderInvalid message reqId =
        responseLBS
            status400
            []
            (encode (AuthInvalid message (toString reqId)))

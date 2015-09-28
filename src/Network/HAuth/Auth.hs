{-# LANGUAGE OverloadedStrings #-}

module Network.HAuth.Auth where

{-|
Module      : Network.HAuth.Auth
Description : Functions for validating Auth
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

import           Crypto.Hash (SHA256(..))
import           Crypto.MAC (HMAC(..), hmac)
import           Data.ByteString (intercalate)
import           Data.ByteString.Char8 (pack)
import           Data.Maybe (fromMaybe)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Network.HAuth.Types
import           Network.HTTP.Types ()
import           Network.Wai
       (Request(rawPathInfo, requestHeaders, requestMethod))

-- | Produce a HMAC SHA256 digest of the given parameters.  Used to
-- validate the 'mac' value given in the authentication header.
hmacDigest
    :: AuthTS Integer
    -> AuthNonce Text
    -> Maybe (AuthExt Text)
    -> Request
    -> AcctSecret Text
    -> AuthMAC Text
hmacDigest (AuthTS ts) (AuthNonce nonce) maybeExt rq (AcctSecret secret) =
    (AuthMAC . T.pack . show . hmacGetDigest) hmac'
  where
    hmac' :: HMAC SHA256
    hmac' =
        hmac
            (T.encodeUtf8 secret)
            (intercalate
                 "\n"
                 [ (pack . show) ts
                 , T.encodeUtf8 nonce
                 , requestMethod rq
                 , rawPathInfo rq
                 , fromMaybe "" (lookup "host" (requestHeaders rq))
                 , (pack . show) (443 :: Integer)
                 , maybe
                       ""
                       (\(AuthExt e) ->
                             T.encodeUtf8 e)
                       maybeExt] <>
             "\n")

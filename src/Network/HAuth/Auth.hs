{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Network.HAuth.Auth where

import           Crypto.Hash (SHA256(..))
import           Crypto.MAC (HMAC(..), hmac)
import           Data.ByteString (intercalate)
import           Data.ByteString.Char8 (pack)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Network.HAuth.Types
import           Network.HTTP.Types ()
import           Network.Wai
       (Request(rawPathInfo, requestHeaders, requestMethod))

hmacDigest
    :: AuthTS Integer
    -> AuthNonce Text
    -> Maybe (AuthExt Text)
    -> Request
    -> AcctSecret Text
    -> AuthMAC Text
hmacDigest (AuthTS ts) (AuthNonce nonce) maybeExt rq (AcctSecret secret) =
    (AuthMAC . T.pack . show . hmacGetDigest)
        (hmac
             (T.encodeUtf8 secret)
             ((intercalate
                   "\n"
                   [ (pack . show) ts
                   , T.encodeUtf8 nonce
                   , (requestMethod rq)
                   , (rawPathInfo rq)
                   , maybe "" id (lookup "host" (requestHeaders rq))
                   , (pack . show) (443 :: Integer)
                   , maybe
                         ""
                         (\(AuthExt e) ->
                               T.encodeUtf8 e)
                         maybeExt]) <>
              "\n") :: HMAC SHA256)

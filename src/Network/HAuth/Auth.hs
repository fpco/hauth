{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.HAuth.Auth where

import Crypto.Hash (SHA256(..))
import Crypto.MAC (HMAC(..), hmac)
import Data.ByteString (ByteString, intercalate)
import Data.ByteString.Char8 (pack)
import Data.Byteable (toBytes)
import Data.Monoid ((<>))
import Network.HAuth.Types
import Network.HTTP.Types
import Network.Wai

authMac :: Auth -> Request -> Secret -> Mac
authMac Auth{ts = (TS t),nonce = (Nonce n),..} rq (Secret key) =
    let attrs =
            [ (pack . show) t
            , n
            , (requestMethod rq)
            , (rawPathInfo rq)
            , maybe "" id (lookup "host" (requestHeaders rq))
            , (pack . show) 443
            , maybe
                  ""
                  (\(Ext e) ->
                        e)
                  ext]
        hmac' :: HMAC SHA256
        hmac' = hmac key ((intercalate "\n" attrs) <> "\n")
    in Mac (toBytes hmac')

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

authMac :: TS -> Nonce -> Maybe Ext -> Request -> Secret -> Mac
authMac (TS ts) (Nonce nonce) ext rq (Secret key) =
    let attrs =
            [ (pack . show) ts
            , nonce
            , (requestMethod rq)
            , (rawPathInfo rq)
            , maybe "" id (lookup "host" (requestHeaders rq))
            , (pack . show) 443
            , maybe "" (\(Ext e) -> e) ext]
        hmac' :: HMAC SHA256
        hmac' = hmac key ((intercalate "\n" attrs) <> "\n")
    in Mac (toBytes hmac')

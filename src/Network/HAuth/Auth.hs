{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Network.HAuth.Auth where

import Crypto.Hash (SHA256(..))
import Crypto.MAC (HMAC(..), hmac)
import Data.ByteString (ByteString, intercalate)
import Data.ByteString.Base16 (encode)
import Data.ByteString.Char8 (pack)
import Data.Byteable (toBytes)
import Data.Monoid ((<>))
import Network.HAuth.Types
import Network.HTTP.Types ()
import Network.Wai
       (Request(rawPathInfo, requestHeaders, requestMethod))

hmacDigest :: Int -> ByteString -> Maybe ByteString -> Request -> Secret -> ByteString
hmacDigest ts nonce ext rq (Secret key) =
    let attrs =
            [ (pack . show) ts
            , nonce
            , (requestMethod rq)
            , (rawPathInfo rq)
            , maybe "" id (lookup "host" (requestHeaders rq))
            , (pack . show) (443 :: Integer)
            , maybe "" id ext]
    in (encode . toBytes)
           (hmac key ((intercalate "\n" attrs) <> "\n") :: HMAC SHA256)

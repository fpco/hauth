{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Network.HAuth.Auth where

import Crypto.Hash (SHA256(..))
import Crypto.MAC (HMAC(..), hmac)
import Data.ByteString (intercalate)
import Data.ByteString.Char8 (pack)
import Data.Monoid ((<>))
import Network.HAuth.Types
import Network.HTTP.Types ()
import Network.Wai
       (Request(rawPathInfo, requestHeaders, requestMethod))

hmacDigest :: AuthTS
           -> AuthNonce
           -> Maybe AuthExt
           -> Request
           -> Secret
           -> AuthMAC
hmacDigest AuthTS{..} AuthNonce{..} maybeExt rq (Secret key) =
    (AuthMAC . pack . show . hmacGetDigest)
        (hmac
             key
             ((intercalate
                   "\n"
                   [ (pack . show) ts
                   , nonce
                   , (requestMethod rq)
                   , (rawPathInfo rq)
                   , maybe "" id (lookup "host" (requestHeaders rq))
                   , (pack . show) (443 :: Integer)
                   , maybe "" ext maybeExt]) <>
              "\n") :: HMAC SHA256)

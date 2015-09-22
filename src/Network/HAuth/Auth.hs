{-# LANGUAGE OverloadedStrings #-}

module Network.HAuth.Auth where

import Crypto.Hash (SHA256(..))
import Crypto.MAC (HMAC(..), hmac)
import Data.ByteString (ByteString, intercalate)
import Data.ByteString.Char8 (pack)
import Data.Byteable (toBytes)
import Network.HAuth.Types.Auth

mkAuth :: ByteString -> ID -> TS -> Nonce -> Maybe Ext -> Auth
mkAuth key id ts nonce ext = Auth id ts nonce ext (authMac key ts nonce)

authMac :: ByteString -> TS -> Nonce -> Mac
authMac key (TS t) (Nonce n) =
  -- TODO: intercalate "\n" [ts, nonce, requestMethod, rawPathInfo,
  -- lookup "host" requestHeaders, 443, ""]
    let attrs = [pack (show t), n]
        hmac' :: HMAC SHA256
        hmac' = hmac key (intercalate "\n" attrs)
    in Mac (toBytes hmac')

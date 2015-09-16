{-# LANGUAGE OverloadedStrings #-}

module Network.HAuth.Auth where

import Crypto.Hash (SHA256(..))
import Crypto.MAC (HMAC(..), hmac)
import Data.ByteString (ByteString, intercalate)
import Data.ByteString.Char8 (pack)
import Data.Byteable (toBytes)
import Network.HAuth.Types.Auth

mkAuth :: ByteString -> ID -> TS -> Nonce -> Maybe Ext -> Auth
mkAuth key id ts nonce ext =
  Auth id ts nonce ext (authMac key id ts nonce ext)

authMac :: ByteString -> ID -> TS -> Nonce -> Maybe Ext -> Mac
authMac key (ID i) (TS t) (Nonce n) e =
    let attrs = [i, pack (show t), n]
        hmac' :: HMAC SHA256
        hmac' =
            hmac
                key
                (intercalate
                     "\n"
                     (case e of
                          (Just (Ext e')) -> attrs ++ [e']
                          Nothing -> attrs))
    in Mac (toBytes hmac')

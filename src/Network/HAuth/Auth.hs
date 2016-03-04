{-# LANGUAGE OverloadedStrings #-}

{-|
Module      : Network.HAuth.Auth
Description : Functions for validating Auth
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

module Network.HAuth.Auth where

import           Crypto.Hash (SHA256(..))
import           Crypto.MAC (HMAC(..), hmac)
import           Data.ByteString (ByteString, intercalate)
import           Data.ByteString.Char8 (pack)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Network.HAuth.Types
import           Network.HTTP.Types (Method)

-- | Produce a HMAC SHA256 digest of the given parameters.  Used to
-- validate the 'mac' value given in the authentication header.
hmacDigest
    :: AuthTS Integer
    -> AuthNonce Text
    -> Maybe (AuthExt Text)
    -> AcctSecret Text
    -> Method
    -> ByteString
    -> ByteString
    -> ByteString
    -> AuthMAC Text
hmacDigest ts nonce maybeExt (AcctSecret secret) method path host port =
    (AuthMAC . T.pack . show . hmacGetDigest) hmac'
  where
    hmac' :: HMAC SHA256
    hmac' =
        hmac
            (T.encodeUtf8 secret)
            (hmacRawMessage ts nonce maybeExt method path host port)

-- | Returns the message to be hashed, in hauth-compliant format
--   Useful for debugging
hmacRawMessage
    :: AuthTS Integer
    -> AuthNonce Text
    -> Maybe (AuthExt Text)
    -> Method
    -> ByteString
    -> ByteString
    -> ByteString
    -> ByteString
hmacRawMessage (AuthTS ts) (AuthNonce nonce) maybeExt method path host port =
    intercalate
        "\n"
        [ (pack . show) ts
        , T.encodeUtf8 nonce
        , method
        , path
        , host
        , port
        , maybe
              ""
              (\(AuthExt e) ->
                    T.encodeUtf8 e)
              maybeExt] <>
     "\n"

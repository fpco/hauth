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
    :: AuthTS Integer -- ^ timestamp of request in epoch time
    -> AuthNonce Text -- ^ the nonce - a unique value that should only be used
                      --   once, used to prevent replay attacks
    -> Maybe (AuthExt Text) -- ^ the auth scheme extension, if any
    -> AcctSecret Text -- ^ the authorized entity's secret
    -> Method -- ^ the HTTP 'Method' of the request,
              --   such as 'Network.HTTP.Types.POST'
    -> ByteString -- ^ the path of the request, without the host
                  --   ex. @\/api\/v1\/status@
    -> ByteString -- ^ the hostname of the request
    -> ByteString -- ^ the port on which the request is being made - likely 443
    -> AuthMAC Text -- ^ the hashed MAC ready for transmission and verification
hmacDigest ts nonce maybeExt (AcctSecret secret) method path host port =
    (AuthMAC . T.pack . show . hmacGetDigest) hmac'
  where
    hmac' :: HMAC SHA256
    hmac' =
        hmac
            (T.encodeUtf8 secret)
            (hmacRawMessage ts nonce maybeExt method path host port)

-- | Returns the message to be hashed, in hauth-compliant format.
--   Useful for debugging
hmacRawMessage
    :: AuthTS Integer -- ^ timestamp of request in UTC epoch time
    -> AuthNonce Text -- ^ the nonce, a unique value that should only be used
                      --   once, used to prevent replay attacks
    -> Maybe (AuthExt Text) -- ^ the auth scheme extension, if any
    -> Method -- ^ the HTTP 'Method' of the request,
              --   such as 'Network.HTTP.Types.POST'
    -> ByteString -- ^ the path of the request, without the host
                  --   ex. @\/api\/v1\/status@
    -> ByteString -- ^ the hostname of the request
    -> ByteString -- ^ the port on which the request is being made - likely 443
    -> ByteString -- ^ the concatenated auth message, ready to be hashed
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

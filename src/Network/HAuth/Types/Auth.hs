{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

module Network.HAuth.Types.Auth where

{-|
Module      : Network.HAuth.Types.Auth
Description : Types for Authentication
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

import Data.Aeson (ToJSON(..), Value(..))
import Data.Aeson.TH
       (deriveToJSON, defaultOptions, fieldLabelModifier)
import Data.Hashable (Hashable(..))
import Data.Text (Text)
import Data.UUID (UUID, toText)
import Database.Persist.TH
       (sqlSettings, share, persistLowerCase, mkPersist, mkMigrate)
import Network.HAuth.Types.JSON

-- | The auth attribute key: used to label auth attribute values
data AuthAttrKey
    = IdKey
    | TsKey
    | NonceKey
    | ExtKey
    | MacKey
    deriving (Enum,Eq,Ord,Show)

-- | The auth attribute val: used to contain auth attribute values
-- as they are being parsed with attoparsec from the header.
data AuthAttrVal
    = IdVal { idVal :: Text}
    | TsVal { tsVal :: Integer}
    | NonceVal { nonceVal :: Text}
    | ExtVal { extVal :: Text}
    | MacVal { macVal :: Text}
    deriving (Eq,Show)

-- | An attribute consists of the pair of key & value.  This type is
-- only used during parsing with attoparsec.
type AuthAttribute = (AuthAttrKey, AuthAttrVal)

-- | An auth header is a list of auth attributes.  This type is only
-- used during parsing with attoparsec.
type AuthHeader = [AuthAttribute]

-- | An auth id - also could be called an account id.  It's how we
-- identify the partner when looking up their account.
data AuthID a =
    AuthID a
    deriving (Eq,Functor,Ord,Show)

-- | We use AuthID in a Map as the key.  We need it to be Hashable.
instance Hashable a => Hashable (AuthID a) where
    hashWithSalt salt (AuthID id') = hashWithSalt salt id'
    hash (AuthID id') = hash id'

-- | An auth timestamp - the timestamp of the authorazition request.
data AuthTS a =
    AuthTS a
    deriving (Eq,Functor,Show)

-- | An auth nonce - a unique value that should be used only once.
data AuthNonce a =
    AuthNonce a
    deriving (Eq,Functor,Show)

-- | An auth extension - this is here to satisfy the spec but we are
-- not currently using it for anything in HAuth.
data AuthExt a =
    AuthExt a
    deriving (Eq,Functor,Show)

-- | An auth MAC - this is the computed HMAC SHA256 digest of parts of
-- the request & auth attributes. (as per the spec).
data AuthMAC a =
    AuthMAC a
    deriving (Eq,Functor,Show)

-- | A authentication as parsed & converted from request headers.
data Auth = Auth
    { authID :: AuthID Text
    , authTS :: AuthTS Integer
    , authNonce :: AuthNonce Text
    , authExt :: Maybe (AuthExt Text)
    , authMAC :: AuthMAC Text
    } deriving (Eq,Show)

-- | A successful authentication with it's request id
data AuthSuccess = AuthSuccess
    { authSuccessRequestId :: UUID
    , authSuccessAuth :: Auth
    } deriving (Eq,Show)

-- | A failed authentication with it's request id & reason why
data AuthFailure = AuthFailure
    { authFailureRequestId :: UUID
    , authFailureMessage :: Text
    } deriving (Eq,Show)

-- | Data.UUID doesn't have JSON instances - sorry for the orphan
instance ToJSON UUID where
  toJSON = String . toText

$(deriveToJSON defaultOptions ''AuthID)
$(deriveToJSON defaultOptions ''AuthTS)
$(deriveToJSON defaultOptions ''AuthNonce)
$(deriveToJSON defaultOptions ''AuthExt)
$(deriveToJSON defaultOptions ''AuthMAC)

$(deriveToJSON
      (defaultOptions
       { fieldLabelModifier = camelToKabob . drop 4
       })
      ''Auth)

$(deriveToJSON
      (defaultOptions
       { fieldLabelModifier = camelToKabob . drop 11
       })
      ''AuthSuccess)

$(deriveToJSON
      (defaultOptions
       { fieldLabelModifier = camelToKabob . drop 11
       })
      ''AuthFailure)

-- | Persistent TH for Authentication attempts.  We'll use this to
-- both persist and lookup previous authentication requests.
share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
AuthRegistry
    id' Text
    ts Int
    nonce Text
    ext Text Maybe
    mac Text
    deriving Eq Ord Show
|]

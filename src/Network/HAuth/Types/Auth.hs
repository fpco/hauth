{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE EmptyDataDecls             #-}
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

import Data.Aeson (ToJSON(..), Value(..))
import Data.Aeson.TH
       (deriveToJSON, defaultOptions, fieldLabelModifier)
import Data.Hashable (Hashable(..))
import Data.Text (Text)
import Data.UUID (UUID, toText)
import Database.Persist.TH
       (sqlSettings, share, persistLowerCase, mkPersist, mkMigrate)

data AuthAttrKey
    = IdKey
    | TsKey
    | NonceKey
    | ExtKey
    | MacKey
    deriving (Enum,Eq,Ord,Show)

data AuthAttrVal
    = IdVal { idVal :: Text}
    | TsVal { tsVal :: Integer}
    | NonceVal { nonceVal :: Text}
    | ExtVal { extVal :: Text}
    | MacVal { macVal :: Text}
    deriving (Eq,Show)

type AuthAttribute = (AuthAttrKey, AuthAttrVal)

type AuthHeader = [AuthAttribute]

data AuthID a =
    AuthID a
    deriving (Eq,Functor,Ord,Show)

instance Hashable a => Hashable (AuthID a) where
    hashWithSalt salt (AuthID id') = hashWithSalt salt id'
    hash (AuthID id') = hash id'

data AuthTS a =
    AuthTS a
    deriving (Eq,Functor,Show)

data AuthNonce a =
    AuthNonce a
    deriving (Eq,Functor,Show)

data AuthExt a =
    AuthExt a
    deriving (Eq,Functor,Show)

data AuthMAC a =
    AuthMAC a
    deriving (Eq,Functor,Show)

data Auth = Auth
    { authID :: AuthID Text
    , authTS :: AuthTS Integer
    , authNonce :: AuthNonce Text
    , authExt :: Maybe (AuthExt Text)
    , authMAC :: AuthMAC Text
    } deriving (Eq,Show)

data AuthSuccess = AuthSuccess
    { authSuccessRequestId :: UUID
    , authSuccessAuth :: Auth
    } deriving (Eq,Show)

data AuthFailure = AuthFailure
    { authFailureRequestId :: UUID
    , authFailureMessage :: Text
    } deriving (Eq,Show)

instance ToJSON UUID where
  toJSON = String . toText

$(deriveToJSON defaultOptions ''AuthID)
$(deriveToJSON defaultOptions ''AuthTS)
$(deriveToJSON defaultOptions ''AuthNonce)
$(deriveToJSON defaultOptions ''AuthExt)
$(deriveToJSON defaultOptions ''AuthMAC)

$(deriveToJSON
      (defaultOptions
       { fieldLabelModifier = drop 4
       })
      ''Auth)

$(deriveToJSON
      (defaultOptions
       { fieldLabelModifier = drop 11
       })
      ''AuthSuccess)

$(deriveToJSON
      (defaultOptions
       { fieldLabelModifier = drop 11
       })
      ''AuthFailure)

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
AuthRegistry
    id' Text
    ts Int
    nonce Text
    ext Text Maybe
    mac Text
    deriving Eq Ord Show
|]

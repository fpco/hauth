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

import Data.Aeson.TH
       (deriveJSON, defaultOptions, fieldLabelModifier)
import Data.Hashable (Hashable(..))
import Data.Text (Text)
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

data AuthInvalid = AuthInvalid
    { authInvalidRequest :: Text
    , authInvalidMessage :: Text
    } deriving (Eq,Show)

$(deriveJSON defaultOptions ''AuthID)
$(deriveJSON defaultOptions ''AuthTS)
$(deriveJSON defaultOptions ''AuthNonce)
$(deriveJSON defaultOptions ''AuthExt)
$(deriveJSON defaultOptions ''AuthMAC)
$(deriveJSON
      (defaultOptions
       { fieldLabelModifier = drop 4
       })
      ''Auth)

$(deriveJSON
      (defaultOptions
       { fieldLabelModifier = drop 11
       })
      ''AuthInvalid)

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
AuthRegistry
    id' Text
    ts Int
    nonce Text
    ext Text Maybe
    mac Text
    deriving Eq Ord Show
|]

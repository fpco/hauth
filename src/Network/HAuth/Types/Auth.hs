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

import Data.Aeson.TH (deriveJSON, defaultOptions)
import Data.ByteString (ByteString)
import Data.Hashable (Hashable(..))
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
    = IdVal { idVal :: ByteString }
    | TsVal { tsVal :: Integer }
    | NonceVal { nonceVal :: ByteString }
    | ExtVal { extVal :: ByteString }
    | MacVal { macVal :: ByteString }
    deriving (Eq,Ord,Show)

type AuthAttribute = (AuthAttrKey, AuthAttrVal)

type AuthHeader = [AuthAttribute]

data AuthID = AuthID
    { id' :: ByteString
    } deriving (Eq,Ord,Show)

instance Hashable AuthID where
    hashWithSalt salt AuthID{..} = hashWithSalt salt id'
    hash AuthID{..} = hash id'

data AuthTS = AuthTS
    { ts :: Integer
    } deriving (Eq,Ord,Show)

data AuthNonce = AuthNonce
    { nonce :: ByteString
    } deriving (Eq,Ord,Show)

data AuthExt = AuthExt
    { ext :: ByteString
    } deriving (Eq,Ord,Show)

data AuthMAC = AuthMAC
    { mac :: ByteString
    } deriving (Eq,Ord,Show)

data Auth = Auth
    { authID :: AuthID
    , authTS :: AuthTS
    , authNonce :: AuthNonce
    , authExt :: Maybe AuthExt
    , authMAC :: AuthMAC
    } deriving (Eq,Ord,Show)

data AuthInvalid = AuthInvalid
    { message :: String
    , requestId :: String
    } deriving (Eq,Ord,Show)

$( deriveJSON defaultOptions ''AuthInvalid )

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
AuthRegistry
    id' ByteString
    ts Int
    nonce ByteString
    ext ByteString Maybe
    mac ByteString
    deriving Eq Ord Show
|]

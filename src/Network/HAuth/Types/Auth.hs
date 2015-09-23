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

import Data.ByteString (ByteString)
import Data.Aeson.TH (deriveJSON, defaultOptions)
import Database.Persist ()
import Database.Persist.Sql ()
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

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
Auth
    id' ByteString
    ts Int
    nonce ByteString
    ext ByteString Maybe
    mac ByteString
    deriving Eq Ord Show
|]

data AuthInvalid = AuthInvalid
    { message :: String
    , requestId :: String
    }
    deriving (Eq,Ord,Show)

$( deriveJSON defaultOptions ''AuthInvalid )

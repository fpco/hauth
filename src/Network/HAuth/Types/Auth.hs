{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Network.HAuth.Types.Auth where

import Data.ByteString (ByteString(..))
import Data.Aeson
import Data.Aeson.TH

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

data ID =
    ID ByteString
    deriving (Eq,Ord,Show)

data TS =
    TS Integer
    deriving (Eq,Ord,Show)

data Nonce =
    Nonce ByteString
    deriving (Eq,Ord,Show)

data Ext =
    Ext ByteString
    deriving (Eq,Ord,Show)

data Mac =
    Mac ByteString
    deriving (Eq,Ord,Show)

data Auth = Auth
    { id' :: ID
    , ts :: TS
    , nonce :: Nonce
    , ext :: Maybe Ext
    , mac :: Mac
    }
    deriving (Eq,Ord,Show)

data AuthInvalid = AuthInvalid
    { message :: String
    , requestId :: String
    }
    deriving (Eq,Ord,Show)

$( deriveJSON defaultOptions ''AuthInvalid )

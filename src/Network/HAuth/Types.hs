{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.HAuth.Types where

import Data.ByteString

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
    deriving (Eq,Show)

type AuthAttribute = (AuthAttrKey, AuthAttrVal)

type AuthHeader = [AuthAttribute]

data ID =
    ID ByteString
    deriving (Eq,Show)

data TS =
    TS Integer
    deriving (Eq,Show)

data Nonce =
    Nonce ByteString
    deriving (Eq,Show)

data Ext =
    Ext ByteString
    deriving (Eq,Show)

data Mac =
    Mac ByteString
    deriving (Eq,Show)

data Auth = Auth
    { id' :: ID
    , ts :: TS
    , nonce :: Nonce
    , ext :: Maybe Ext
    , mac :: Mac
    } deriving (Eq,Show)

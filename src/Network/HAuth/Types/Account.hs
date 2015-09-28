{-# LANGUAGE DeriveFunctor     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Network.HAuth.Types.Account where

import Data.Aeson.TH
       (deriveFromJSON, defaultOptions, fieldLabelModifier)
import Data.Text (Text)
import Network.HAuth.Types.JSON

data AcctName a =
    AcctName a
    deriving (Eq,Functor,Show)

data AcctSecret a =
    AcctSecret a
    deriving (Eq,Functor,Show)

data Account = Account
    { acctName :: AcctName Text
    , acctSecret :: AcctSecret Text
    } deriving (Eq,Show)

$(deriveFromJSON defaultOptions ''AcctName)
$(deriveFromJSON defaultOptions ''AcctSecret)
$(deriveFromJSON
      (defaultOptions
       { fieldLabelModifier = camelToKabob . drop 4
       })
      ''Account)

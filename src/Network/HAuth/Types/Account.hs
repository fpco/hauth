{-# LANGUAGE DeriveFunctor     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Network.HAuth.Types.Account where

import Data.Aeson.TH
       (deriveJSON, defaultOptions, fieldLabelModifier)
import Data.Text (Text)

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

$(deriveJSON defaultOptions ''AcctName)
$(deriveJSON defaultOptions ''AcctSecret)
$(deriveJSON
      (defaultOptions
       { fieldLabelModifier = drop 4
       })
      ''Account)

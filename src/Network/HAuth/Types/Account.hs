{-# LANGUAGE DeriveFunctor     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Network.HAuth.Types.Account where

{-|
Module      : Network.HAuth.Types.Account
Description : Types for an Account
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

import Data.Aeson.TH
       (deriveFromJSON, defaultOptions, fieldLabelModifier)
import Data.Text (Text)
import Network.HAuth.Types.JSON

-- | The Account Name - needed to print in log output
data AcctName a =
    AcctName a
    deriving (Eq,Functor,Show)

-- | The Account Secret - used to authenticate requests
data AcctSecret a =
    AcctSecret a
    deriving (Eq,Functor,Show)

-- | The Account - consisting of name & secret
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

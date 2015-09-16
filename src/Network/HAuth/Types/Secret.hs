module Network.HAuth.Types.Secret where

import Data.ByteString (ByteString(..))

data Secret =
    Secret ByteString
    deriving (Eq,Show)

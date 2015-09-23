module Network.HAuth.Types.Secret where

import Data.ByteString (ByteString)

data Secret =
    Secret { secretKey :: ByteString }
    deriving (Eq,Show)

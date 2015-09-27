{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}

module Network.HAuth.Parse where

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative ((<$>), (<*>), (<|>), (<*), (*>), pure)
#else
import           Control.Applicative ((<|>))
#endif

import           Data.Attoparsec.ByteString
       (takeWhile1, Parser, skipMany, skipMany1, option, many1,
        string, skip, inClass)
import           Data.Attoparsec.ByteString.Char8 (char, decimal, space)
import           Data.ByteString (ByteString)
import           Data.ByteString.Char8 ()
import           Data.Map ()
import qualified Data.Map as Map (lookup, fromList, size)
import           Data.Set ()
import qualified Data.Set as Set (fromList, size)
import           Network.HAuth.Types

plainTextP :: Parser ByteString
plainTextP = takeWhile1 (inClass "a-zA-Z0-9+/=-")

attrP
    :: forall a.
       ByteString -> Parser a -> Parser a
attrP key valP =
    skipMany space *>
    string key *> char '=' *> quoteP *> valP <* quoteP
    <* skipMany space
  where
    quoteP = option () (skip isQuote)
    isQuote = (==) 34

idP :: Parser AuthAttribute
idP = (,) <$> pure IdKey <*> (IdVal <$> (attrP "id" plainTextP))

tsP :: Parser AuthAttribute
tsP = (,) <$> pure TsKey <*> (TsVal <$> (attrP "ts" decimal))

nonceP :: Parser AuthAttribute
nonceP = (,) <$> pure NonceKey <*> (NonceVal <$> (attrP "nonce" plainTextP))

extP :: Parser AuthAttribute
extP = (,) <$> pure ExtKey <*> (ExtVal <$> (attrP "ext" plainTextP))

macP :: Parser AuthAttribute
macP = (,) <$> pure MacKey <*> (MacVal <$> (attrP "mac" plainTextP))

authHeaderP :: Parser AuthHeader
authHeaderP =
    skipMany space *> string "MAC" *> skipMany1 space *>
    many1 (idP <|> tsP <|> nonceP <|> extP <|> macP)

authHeaderToAuth :: AuthHeader -> Either String Auth
authHeaderToAuth hdr =
    let keySet = Set.fromList (map fst hdr)
        hdrMap = Map.fromList hdr
    in if Set.size keySet /= Map.size hdrMap
           then Left "duplicate attributes"
           else maybe
                    (Left "invalid authorization")
                    Right
                    (Auth <$>
                     (AuthID . idVal <$> Map.lookup IdKey hdrMap) <*>
                     (AuthTS . fromInteger . tsVal <$> Map.lookup TsKey hdrMap) <*>
                     (AuthNonce . nonceVal <$> Map.lookup NonceKey hdrMap) <*>
                     Just (AuthExt . extVal <$> Map.lookup ExtKey hdrMap) <*>
                     (AuthMAC . macVal <$> Map.lookup MacKey hdrMap))

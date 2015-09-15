{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Network.HAuth.Parse where

#if __GLASGOW_HASKELL__ >= 710
import           Control.Applicative ((<|>))
#else
import           Control.Applicative ((<$>), (<*>), (<|>), (<*), (*>), pure)
#endif
import           Data.Attoparsec.ByteString
import           Data.Attoparsec.ByteString.Char8 (char, decimal, space)
import           Data.ByteString (ByteString)
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Set (Set)
import qualified Data.Set as Set
import           Network.HAuth.Types
import           Network.HAuth.Types.Internal

plainTextP :: Parser ByteString
plainTextP = takeWhile1 (inClass "a-zA-Z0-9+/=")
             -- TODO comparing Word8 #s is "faster"

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
tsP = (,) <$> pure TsKey <*> (TsVal <$> (attrP "ts" decimalP))
  where
    decimalP = toInteger <$> decimal

nonceP :: Parser AuthAttribute
nonceP = (,) <$> pure NonceKey <*> (NonceVal <$> (attrP "nonce" plainTextP))

extP :: Parser AuthAttribute
extP = (,) <$> pure ExtKey <*> (ExtVal <$> (attrP "ext" plainTextP))

macP :: Parser AuthAttribute
macP = (,) <$> pure MacKey <*> (MacVal <$> (attrP "mac" plainTextP))

authP :: Parser AuthHeader
authP = many1 (idP <|> tsP <|> nonceP <|> extP <|> macP)

authHeaderToAuth :: AuthHeader -> Maybe Auth
authHeaderToAuth hdr =
    let keySet = Set.fromList (map fst hdr)
        hdrMap = Map.fromList hdr
    in if Set.size keySet /= Map.size hdrMap
          then Nothing
          else Auth <$>
               (ID . idVal <$> Map.lookup IdKey hdrMap) <*>
               (TS . tsVal <$> Map.lookup TsKey hdrMap) <*>
               (Nonce . nonceVal <$> Map.lookup NonceKey hdrMap) <*>
               Just (Ext . extVal <$> Map.lookup ExtKey hdrMap) <*>
               (Mac . macVal <$> Map.lookup MacKey hdrMap)

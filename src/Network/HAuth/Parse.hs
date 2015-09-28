{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}

module Network.HAuth.Parse where

{-|
Module      : Network.HAuth.Parse
Description : Functions for parsing an Authentication header
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

#if __GLASGOW_HASKELL__ < 710
import           Control.Applicative ((<$>), (<*>), (<|>), (<*), (*>), pure)
#else
import           Control.Applicative ((<|>))
#endif

import           Data.Attoparsec.Text
       (char, decimal, space, takeWhile1, Parser, skipMany, skipMany1,
        option, many1, string, skip, inClass)
import           Data.Text (Text)
import           Data.Map ()
import qualified Data.Map as Map (lookup, fromList, size)
import           Data.Set ()
import qualified Data.Set as Set (fromList, size)
import           Network.HAuth.Types

-- | A parser for plain-string ABNF (without spaces)
plainTextP :: Parser Text
plainTextP = takeWhile1 (inClass "!#-[]-}")

-- | Abstraction of an authentication header attribute parser
attrP
    :: forall a.
       Text -> Parser a -> Parser a
attrP key valP =
    skipMany space *>
    string key *> char '=' *> quoteP *> valP <* quoteP
    <* skipMany space
  where
    quoteP = option () (skip isQuote)
    isQuote = (==) '"'

-- | Authentication header attribute parser for 'id'
idP :: Parser AuthAttribute
idP = (,) <$> pure IdKey <*> (IdVal <$> attrP "id" plainTextP)

-- | Authentication header attribute parser for 'ts'
tsP :: Parser AuthAttribute
tsP = (,) <$> pure TsKey <*> (TsVal <$> attrP "ts" decimal)

-- | Authentication header attribute parser for 'nonce'
nonceP :: Parser AuthAttribute
nonceP = (,) <$> pure NonceKey <*> (NonceVal <$> attrP "nonce" plainTextP)

-- | Authentication header attribute parser for 'ext'
extP :: Parser AuthAttribute
extP = (,) <$> pure ExtKey <*> (ExtVal <$> attrP "ext" plainTextP)

-- | Authentication header attribute parser for 'mac'
macP :: Parser AuthAttribute
macP = (,) <$> pure MacKey <*> (MacVal <$> attrP "mac" plainTextP)

-- | Authentication header parser
authHeaderP :: Parser AuthHeader
authHeaderP =
    skipMany space *> string "MAC" *> skipMany1 space *>
    many1 (idP <|> tsP <|> nonceP <|> extP <|> macP)

-- | Validate & convert a loose array of header attributes into the
-- Auth datatype.
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

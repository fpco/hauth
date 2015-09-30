{-|
Module      : Network.HAuth.Types.JSON
Description : Functions to use with Data.Aeson.TH derive options
Copyright   : (c) FPComplete, 2015
License     : MIT
Maintainer  : Tim Dysinger <tim@fpcomplete.com>
Stability   : experimental
Portability : POSIX
-}

module Network.HAuth.Types.JSON (camelToKabob, camelToSnake) where

import Data.Char

-- | Convert a field label from camelCase to kabob-case
camelToKabob :: String -> String
camelToKabob = camelTo '-'

-- | Convert a field label from camelCase to snake_case
camelToSnake :: String -> String
camelToSnake = camelTo '_'

-- | Convert a field label from camelCase to lowercase separated by
-- the given character.
camelTo :: Char -> String -> String
camelTo _ [] = []
camelTo sep (x:xs) = toLower x : kabob xs
  where
    kabob [] = []
    kabob (y:ys)
      | isUpper y = sep : toLower y : kabob ys
      | otherwise = y : kabob ys

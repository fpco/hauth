module Network.HAuth.Wai where

import Network.HAuth.Types
import Network.Wai

import Network.Wai.Middleware.Consul ( withConsul )

hauth :: ConsulConfig -> PostgresConfig -> Middleware
hauth cc pc app = app

-- Create a mvar to house the keys
-- Callback from consulconfig goes to the function that closes over the mvar
-- Query consulconfig & register a callback for each keys
-- How do we find out about new keys
-- Create a request UUID
-- Check for the authentication header
   -- Reply 4xx if it's not there
-- Parse the authentication header
   -- Log to low & middle levers if authentication is not there
   -- Reply 2xx if authorization is ok
-- Create a function to calculate the crytpographic hash
-- Check the cryptohash
-- Check the timestamp against the local epoch timestamp
-- 400 on invalid auth header with body of
--   {"message":"Invalid authorization header","request-id":requestId}
-- Confirm that none of mac, ts, or nonce have been used previously by id (postgres)
--   Add these values to the database for future requests.
-- Log the request ID, partner name, MAC ID, and a message
--   Stating that authentication validation is complete

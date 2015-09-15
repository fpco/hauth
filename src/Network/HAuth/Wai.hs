module Network.HAuth.Wai where

import Network.HAuth.Types
import Network.Wai

import Network.Wai.Middleware.Consul ( withConsul )

hauth :: ConsulConfig -> PostgresConfig -> Middleware
hauth cc pc app = app

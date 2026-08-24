"""Socle réseau partagé par les serveurs MCP d'ARGUS.

Chaque serveur interroge des sources publiques avec les mêmes contraintes :
un débit à respecter, des réponses volumineuses à mettre en cache, et des
pannes à traiter sans faire échouer l'investigation entière. Rassembler ces
mécanismes ici évite qu'une correction n'atteigne qu'un serveur sur cinq.
"""

from .console import forcer_utf8
from .feeds import FeedCache, FeedError
from .http import HttpError, PublicHttpClient
from .ratelimit import QuotaExceededError, RateLimiterRegistry, TokenBucket

#: Version du produit, source unique pour tout le depot.
#:
#: Les serveurs l'annoncent au client MCP, le manifeste du paquet la
#: reprend, et un test verifie qu'aucune copie ne diverge. Un numero
#: recopie a la main devient faux au premier oubli, et le destinataire
#: ne sait plus quelle version il a installee.
VERSION = "1.0.0"

__all__ = [
    "VERSION",
    "FeedCache",
    "FeedError",
    "HttpError",
    "PublicHttpClient",
    "QuotaExceededError",
    "RateLimiterRegistry",
    "TokenBucket",
    "forcer_utf8",
]

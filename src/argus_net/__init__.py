"""Socle réseau partagé par les serveurs MCP d'ARGUS.

Chaque serveur interroge des sources publiques avec les mêmes contraintes :
un débit à respecter, des réponses volumineuses à mettre en cache, et des
pannes à traiter sans faire échouer l'investigation entière. Rassembler ces
mécanismes ici évite qu'une correction n'atteigne qu'un serveur sur cinq.
"""

from .feeds import FeedCache, FeedError
from .http import HttpError, PublicHttpClient
from .ratelimit import QuotaExceededError, RateLimiterRegistry, TokenBucket

__all__ = [
    "FeedCache",
    "FeedError",
    "HttpError",
    "PublicHttpClient",
    "QuotaExceededError",
    "RateLimiterRegistry",
    "TokenBucket",
]

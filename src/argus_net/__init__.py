"""Socle partagé par les serveurs MCP d'ARGUS.

Chaque serveur interroge des sources publiques avec les mêmes contraintes :
un débit à respecter, des réponses volumineuses à mettre en cache, et des
pannes à traiter sans faire échouer l'investigation entière. Rassembler ces
mécanismes ici évite qu'une correction n'atteigne qu'un serveur sur cinq.

Le même raisonnement vaut pour les corpus embarqués : trois serveurs figent
des référentiels officiels à la construction, et tous doivent dire leur âge
de la même façon. D'où `fraicheur`, ici plutôt que recopié trois fois.
"""

from .console import forcer_utf8
from .feeds import FeedCache, FeedError
from .fraicheur import (
    SEUIL_PERIME_JOURS,
    SEUIL_VIEILLISSANT_JOURS,
    Fraicheur,
)
from .fraicheur import evaluer as evaluer_fraicheur
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
    "SEUIL_PERIME_JOURS",
    "SEUIL_VIEILLISSANT_JOURS",
    "VERSION",
    "FeedCache",
    "FeedError",
    "Fraicheur",
    "HttpError",
    "PublicHttpClient",
    "QuotaExceededError",
    "RateLimiterRegistry",
    "TokenBucket",
    "evaluer_fraicheur",
    "forcer_utf8",
]

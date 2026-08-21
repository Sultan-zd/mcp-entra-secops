"""Catalogues publics volumineux, gardés en mémoire.

Le catalogue CISA des vulnérabilités activement exploitées pèse un peu plus
d'un mégaoctet et change une fois par jour. Le télécharger à chaque appel
d'outil serait absurde : l'analyste attendrait plusieurs secondes pour une
donnée identique à celle d'il y a trente secondes, et la source recevrait un
trafic qu'elle n'a pas mérité.

Le cache est **en mémoire, pas sur disque**. Un fichier de cache est un
fichier de plus à sécuriser, à purger et à faire tourner ; le gain — survivre
à un redémarrage — ne le justifie pas pour un serveur qu'on relance en deux
secondes.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


class FeedError(RuntimeError):
    """Un catalogue public n'a pas pu être chargé."""


@dataclass
class _Entree:
    valeur: Any
    expire_a: float


class FeedCache:
    """Charge un catalogue à la demande, et le garde le temps convenu.

    Deux comportements méritent d'être explicités.

    **Un seul téléchargement à la fois.** Sans verrou par catalogue, cinq
    outils appelés en parallèle au démarrage lanceraient cinq téléchargements
    du même mégaoctet. Le verrou fait attendre les quatre autres.

    **Une donnée périmée vaut mieux qu'une panne.** Si le rafraîchissement
    échoue alors qu'une version périmée est en mémoire, on rend l'ancienne en
    le signalant. Un catalogue de la veille répond correctement à l'immense
    majorité des questions ; une erreur, à aucune.
    """

    def __init__(self, ttl_seconds: float = 6 * 3600) -> None:
        self._ttl = ttl_seconds
        self._entrees: dict[str, _Entree] = {}
        self._verrous: dict[str, asyncio.Lock] = {}
        self._perimes: set[str] = set()

    async def get(self, nom: str, charger: Callable[[], Awaitable[Any]]) -> Any:
        """Rend le catalogue, en le chargeant si nécessaire."""
        entree = self._entrees.get(nom)
        if entree is not None and entree.expire_a > time.monotonic():
            return entree.valeur

        verrou = self._verrous.setdefault(nom, asyncio.Lock())
        async with verrou:
            # Un autre appel a pu recharger pendant l'attente du verrou.
            entree = self._entrees.get(nom)
            if entree is not None and entree.expire_a > time.monotonic():
                return entree.valeur

            try:
                valeur = await charger()
            except Exception as exc:
                if entree is not None:
                    self._perimes.add(nom)
                    logger.warning(
                        "Catalogue « %s » non rafraîchi (%s) : la version précédente est servie.",
                        nom,
                        exc,
                    )
                    return entree.valeur
                raise FeedError(f"Catalogue « {nom} » indisponible : {exc}") from exc

            self._entrees[nom] = _Entree(valeur, time.monotonic() + self._ttl)
            self._perimes.discard(nom)
            logger.info("Catalogue « %s » chargé.", nom)
            return valeur

    def est_perime(self, nom: str) -> bool:
        """Indique si la version servie n'a pas pu être rafraîchie.

        Les outils le rapportent dans leur sortie : une réponse fondée sur des
        données périmées doit le dire, sans quoi elle se fait passer pour ce
        qu'elle n'est pas.
        """
        return nom in self._perimes

    def vider(self) -> None:
        self._entrees.clear()
        self._perimes.clear()

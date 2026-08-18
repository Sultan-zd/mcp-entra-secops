"""Limitation de débit par source.

Le palier gratuit de VirusTotal tourne autour de quatre requêtes par minute.
Le dépassement ne se traduit pas par un ralentissement : l'API renvoie des 429
qui consomment quand même le quota journalier. Le limiteur protège donc la
ressource externe, pas notre serveur.

L'algorithme retenu est celui du seau à jetons : il autorise une courte rafale
puis lisse le débit, ce qui correspond au comportement réel d'une
investigation — plusieurs indicateurs d'un coup, puis une pause.
"""

from __future__ import annotations

import asyncio
import logging
import time

logger = logging.getLogger(__name__)


class QuotaExceededError(RuntimeError):
    """L'attente nécessaire dépasse le budget accordé à l'appel."""


class TokenBucket:
    """Seau à jetons asynchrone, sûr en présence de tâches concurrentes."""

    def __init__(self, rate_per_minute: int, name: str) -> None:
        self._capacite = float(max(1, rate_per_minute))
        self._jetons = self._capacite
        self._par_seconde = self._capacite / 60.0
        self._dernier = time.monotonic()
        self._verrou = asyncio.Lock()
        self._nom = name

    def _recharger(self) -> None:
        maintenant = time.monotonic()
        self._jetons = min(
            self._capacite, self._jetons + (maintenant - self._dernier) * self._par_seconde
        )
        self._dernier = maintenant

    async def acquire(self, max_wait_seconds: float = 10.0) -> None:
        """Attend un jeton, ou lève QuotaExceededError si l'attente est trop longue.

        Le plafond d'attente est indispensable : sans lui, un enrichissement
        groupé de vingt indicateurs sur une source limitée à quatre par minute
        bloquerait l'agent pendant cinq minutes. Mieux vaut répondre
        « quota épuisé » sur quelques indicateurs que faire attendre l'analyste.
        """
        async with self._verrou:
            self._recharger()
            if self._jetons >= 1.0:
                self._jetons -= 1.0
                return

            attente = (1.0 - self._jetons) / self._par_seconde
            if attente > max_wait_seconds:
                raise QuotaExceededError(
                    f"{self._nom} : quota atteint, il faudrait patienter {attente:.0f} s."
                )
            logger.debug("%s : attente de %.1f s pour respecter le quota.", self._nom, attente)
            await asyncio.sleep(attente)
            self._recharger()
            self._jetons = max(0.0, self._jetons - 1.0)


class RateLimiterRegistry:
    """Un seau par source, chacun avec son propre débit."""

    def __init__(self, rates: dict[str, int]) -> None:
        self._seaux = {nom: TokenBucket(rpm, nom) for nom, rpm in rates.items()}

    async def acquire(self, source: str, max_wait_seconds: float = 10.0) -> None:
        seau = self._seaux.get(source)
        if seau is not None:
            await seau.acquire(max_wait_seconds)

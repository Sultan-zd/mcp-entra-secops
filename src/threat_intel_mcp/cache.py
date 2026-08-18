"""Cache des verdicts.

Un incident fait revenir sans cesse les mêmes adresses IP : celle du serveur
de messagerie, celle du VPN, celle de l'attaquant. Sans cache, chacune est
redemandée à VirusTotal à chaque appel d'outil, et le quota gratuit — de
l'ordre de quelques requêtes par minute — est épuisé au milieu de la première
investigation.

Deux implémentations partagent la même interface : un cache mémoire, actif par
défaut, et un cache Redis pour les déploiements à plusieurs instances.
"""

from __future__ import annotations

import abc
import json
import logging
import time
from collections import OrderedDict
from typing import Any

from .config import Settings
from .models import IndicatorVerdict

logger = logging.getLogger(__name__)


class VerdictCache(abc.ABC):
    """Interface commune aux implémentations de cache."""

    @abc.abstractmethod
    async def get(self, key: str) -> IndicatorVerdict | None:
        """Retourne le verdict mémorisé, ou None s'il est absent ou périmé."""

    @abc.abstractmethod
    async def set(self, key: str, verdict: IndicatorVerdict) -> None:
        """Mémorise un verdict."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Libère les ressources détenues."""


def cache_key(kind: str, indicator: str) -> str:
    """Clé stable et insensible à la casse pour un indicateur.

    Les condensats et les noms de domaine s'écrivent indifféremment en
    majuscules ou en minuscules : sans normalisation, le même indicateur
    occuperait deux entrées et provoquerait deux appels d'API.
    """
    return f"ti:{kind}:{indicator.strip().lower()}"


class MemoryVerdictCache(VerdictCache):
    """Cache en mémoire, à éviction des entrées les moins récemment utilisées.

    Suffisant pour un poste de travail ou une instance unique. La borne sur le
    nombre d'entrées évite qu'une longue session ne fasse enfler le processus
    sans limite.
    """

    def __init__(self, ttl_seconds: int, max_entries: int) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._data: OrderedDict[str, tuple[float, IndicatorVerdict]] = OrderedDict()

    async def get(self, key: str) -> IndicatorVerdict | None:
        entree = self._data.get(key)
        if entree is None:
            return None

        expire_a, verdict = entree
        if time.monotonic() > expire_a:
            del self._data[key]
            return None

        self._data.move_to_end(key)
        return verdict.model_copy(update={"cached": True})

    async def set(self, key: str, verdict: IndicatorVerdict) -> None:
        if self._ttl <= 0:
            return
        self._data[key] = (time.monotonic() + self._ttl, verdict)
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    async def aclose(self) -> None:
        self._data.clear()


class RedisVerdictCache(VerdictCache):
    """Cache partagé entre processus.

    Une panne de Redis ne doit jamais empêcher une investigation : toute erreur
    est journalisée puis ignorée, et le serveur retombe sur un appel réel.
    """

    def __init__(self, url: str, ttl_seconds: int) -> None:
        import redis.asyncio as redis  # import tardif : dépendance facultative

        self._ttl = ttl_seconds
        self._client = redis.from_url(url, decode_responses=True)

    async def get(self, key: str) -> IndicatorVerdict | None:
        try:
            brut = await self._client.get(key)
        except Exception as exc:
            logger.warning("Cache Redis indisponible en lecture (%s) : %s", key, exc)
            return None
        if not brut:
            return None
        try:
            donnees: dict[str, Any] = json.loads(brut)
        except ValueError:
            logger.warning("Entrée de cache illisible, ignorée : %s", key)
            return None
        return IndicatorVerdict.model_validate(donnees).model_copy(update={"cached": True})

    async def set(self, key: str, verdict: IndicatorVerdict) -> None:
        if self._ttl <= 0:
            return
        try:
            await self._client.set(key, verdict.model_dump_json(), ex=self._ttl)
        except Exception as exc:
            logger.warning("Cache Redis indisponible en écriture (%s) : %s", key, exc)

    async def aclose(self) -> None:
        try:
            await self._client.aclose()
        except Exception as exc:
            # La fermeture du cache ne doit jamais masquer le resultat d'une
            # investigation deja produite : on trace et on poursuit.
            logger.debug("Fermeture du cache Redis en echec : %s", exc)


def build_cache(settings: Settings) -> VerdictCache:
    """Instancie le cache correspondant à la configuration."""
    if settings.redis_url:
        try:
            cache = RedisVerdictCache(settings.redis_url, settings.cache_ttl_seconds)
        except ImportError:
            logger.warning(
                "TI_REDIS_URL est renseigné mais le paquet redis n'est pas installé "
                "(pip install '.[cache]'). Repli sur le cache mémoire."
            )
        else:
            logger.info("Cache : Redis (TTL %d s).", settings.cache_ttl_seconds)
            return cache

    logger.info(
        "Cache : mémoire (TTL %d s, %d entrées max).",
        settings.cache_ttl_seconds,
        settings.cache_max_entries,
    )
    return MemoryVerdictCache(settings.cache_ttl_seconds, settings.cache_max_entries)

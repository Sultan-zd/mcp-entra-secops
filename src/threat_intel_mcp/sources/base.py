"""Interface commune aux sources de renseignement.

Chaque source traduit sa réponse dans un `SourceSignal` : un score de 0 à 100,
et le cas échéant un verdict imposé. Le reste du serveur ne sait rien des
particularités de chaque API.

Principe directeur : **une source qui échoue ne fait jamais échouer l'enquête.**
Une panne, un délai dépassé ou un quota épuisé produisent un signal explicite,
pas une exception qui remonte jusqu'à l'agent.
"""

from __future__ import annotations

import abc
import logging

import httpx

from ..fusion import SourceSignal
from ..models import IndicatorKind, SourceResult, SourceStatus, Verdict
from ..ratelimit import QuotaExceededError, RateLimiterRegistry

logger = logging.getLogger(__name__)


class ThreatIntelSource(abc.ABC):
    """Une source interrogeable pour un ou plusieurs types d'indicateurs."""

    #: Nom court, utilisé dans les rapports et par le limiteur de débit.
    name: str = "source"

    #: Types d'indicateurs que cette source sait traiter.
    supports: tuple[IndicatorKind, ...] = ()

    def __init__(
        self,
        client: httpx.AsyncClient,
        limiter: RateLimiterRegistry,
        api_key: str | None,
    ) -> None:
        self._client = client
        self._limiter = limiter
        self._api_key = api_key

    @property
    def configured(self) -> bool:
        """La source dispose-t-elle de quoi fonctionner ?"""
        return bool(self._api_key)

    def handles(self, kind: IndicatorKind) -> bool:
        return kind in self.supports

    @abc.abstractmethod
    async def _lookup(self, indicator: str, kind: IndicatorKind) -> SourceSignal:
        """Interroge réellement l'API et traduit la réponse en signal."""

    async def query(self, indicator: str, kind: IndicatorKind) -> SourceSignal:
        """Interroge la source en absorbant toutes les défaillances possibles."""
        if not self.configured:
            return self._signal("not_configured", detail="Aucune clé d'API renseignée.")

        try:
            await self._limiter.acquire(self.name)
        except QuotaExceededError as exc:
            logger.info("%s : %s", self.name, exc)
            return self._signal("quota_exceeded", detail=str(exc))

        try:
            return await self._lookup(indicator, kind)
        except httpx.TimeoutException:
            logger.warning("%s : délai dépassé pour %s.", self.name, indicator)
            return self._signal("unavailable", detail="Délai dépassé.")
        except httpx.HTTPError as exc:
            logger.warning("%s : erreur réseau pour %s : %s", self.name, indicator, exc)
            return self._signal("unavailable", detail=f"Erreur réseau : {type(exc).__name__}")
        except Exception as exc:
            # Filet de sécurité délibérément large : une source tierce qui
            # change son format de réponse ne doit pas interrompre une
            # investigation en cours.
            logger.exception("%s : réponse inattendue pour %s.", self.name, indicator)
            return self._signal("unavailable", detail=f"Réponse inattendue : {type(exc).__name__}")

    def _signal(
        self,
        status: SourceStatus,
        score: float | None = None,
        detail: str | None = None,
        override: Verdict | None = None,
        override_reason: str | None = None,
        bonus: int = 0,
    ) -> SourceSignal:
        """Fabrique un signal en factorisant le nom de la source.

        Les types sont volontairement restreints aux valeurs admises : une
        faute de frappe dans un statut est ainsi detectee par mypy, et non
        decouverte en production sous la forme d'un verdict incoherent.
        """
        return SourceSignal(
            result=SourceResult(
                source=self.name,
                status=status,
                score=score,
                detail=detail,
            ),
            override=override,
            override_reason=override_reason,
            bonus=bonus,
        )

    def _handle_status(self, response: httpx.Response) -> SourceSignal | None:
        """Traduit les codes d'erreur communs à toutes les API interrogées."""
        if response.status_code == 404:
            return self._signal("not_found", detail="Indicateur inconnu de cette source.")
        if response.status_code == 429:
            return self._signal("quota_exceeded", detail="Quota de l'API atteint (429).")
        if response.status_code in (401, 403):
            return self._signal("unavailable", detail="Clé d'API refusée ou expirée.")
        if response.status_code >= 400:
            return self._signal("unavailable", detail=f"Erreur HTTP {response.status_code}.")
        return None

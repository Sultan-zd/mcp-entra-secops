"""Orchestration de l'enrichissement : cache, sources en parallèle, fusion.

C'est ici que se joue la différence avec un relais d'API. Un relais transmet
une question et rend une réponse. Ce module :

1. écarte les adresses internes avant tout appel externe ;
2. sert le cache quand il le peut ;
3. interroge les sources pertinentes **en parallèle** ;
4. fusionne les signaux par du code déterministe ;
5. mémorise le verdict.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from importlib import resources
from typing import Any

import httpx

from .cache import VerdictCache, cache_key
from .config import Settings
from .fusion import SourceSignal, classify_private_ip, fuse
from .models import IndicatorKind, IndicatorVerdict, SourceResult
from .ratelimit import RateLimiterRegistry
from .sources import AbuseIPDBSource, GreyNoiseSource, ThreatIntelSource, VirusTotalSource

logger = logging.getLogger(__name__)

#: Motifs de reconnaissance des condensats, par longueur hexadécimale.
_HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
_HEX = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$")


class InvalidIndicatorError(ValueError):
    """L'indicateur fourni n'a pas une forme exploitable."""


def detect_kind(indicator: str) -> IndicatorKind:
    """Déduit la nature d'un indicateur, ou refuse explicitement.

    Deviner le type à la place de l'agent évite un aller-retour, et surtout
    évite qu'un condensat soit interrogé comme un domaine — ce qui renverrait
    « inconnu » au lieu d'une erreur claire.
    """
    valeur = indicator.strip()
    if not valeur:
        raise InvalidIndicatorError("Indicateur vide.")

    import ipaddress

    try:
        ipaddress.ip_address(valeur)
    except ValueError:
        pass
    else:
        return "ip"

    if _HEX.match(valeur) and len(valeur) in _HASH_LENGTHS:
        return "file_hash"

    if _DOMAIN.match(valeur):
        return "domain"

    raise InvalidIndicatorError(
        f"« {indicator} » n'est ni une adresse IP, ni un domaine, ni un condensat "
        "MD5, SHA-1 ou SHA-256. Fournir un indicateur brut, sans schéma ni chemin."
    )


def hash_algorithm(value: str) -> str | None:
    """Nom de l'algorithme d'un condensat, d'après sa longueur."""
    return _HASH_LENGTHS.get(len(value.strip()))


class EnrichmentService:
    """Point d'entrée unique des outils d'enrichissement."""

    def __init__(self, settings: Settings, cache: VerdictCache) -> None:
        self._settings = settings
        self._cache = cache
        self._fixtures = settings.data_source == "fixture"

        limiter = RateLimiterRegistry(
            {
                "virustotal": settings.virustotal_rpm,
                "abuseipdb": settings.abuseipdb_rpm,
                "greynoise": settings.greynoise_rpm,
            }
        )

        timeout = settings.request_timeout_seconds
        self._clients: list[httpx.AsyncClient] = []

        def client(base_url: str) -> httpx.AsyncClient:
            c = httpx.AsyncClient(base_url=base_url, timeout=timeout)
            self._clients.append(c)
            return c

        self._sources: list[ThreatIntelSource] = [
            VirusTotalSource(
                client(settings.virustotal_base_url), limiter, settings.virustotal_api_key
            ),
            AbuseIPDBSource(
                client(settings.abuseipdb_base_url), limiter, settings.abuseipdb_api_key
            ),
            GreyNoiseSource(
                client(settings.greynoise_base_url), limiter, settings.greynoise_api_key
            ),
        ]

    # ------------------------------------------------------------------ API
    async def enrich(self, indicator: str, kind: IndicatorKind | None = None) -> IndicatorVerdict:
        """Enrichit un indicateur et retourne son verdict consolidé."""
        valeur = indicator.strip()

        # La validation s'applique même lorsque l'outil impose un type. Sans
        # cela, `enrich_domain("https://site.example/page")` transmettait l'URL
        # entière au point d'entrée « domaine » de VirusTotal, qui répondait
        # « inconnu » — une réponse rassurante et fausse.
        detectee = detect_kind(valeur)
        if kind is not None and detectee != kind:
            raise InvalidIndicatorError(
                f"« {indicator} » ressemble à un indicateur de type « {detectee} », "
                f"mais l'outil appelé attend un « {kind} ». Utiliser l'outil correspondant."
            )
        nature = detectee

        # 1. Les adresses non routables ne quittent jamais le réseau.
        if nature == "ip":
            interne = classify_private_ip(valeur)
            if interne is not None:
                return interne

        # 2. Le cache évite la grande majorité des appels réels.
        cle = cache_key(nature, valeur)
        memorise = await self._cache.get(cle)
        if memorise is not None:
            logger.debug("Verdict servi depuis le cache : %s", valeur)
            return memorise

        # 3. Sources pertinentes, interrogées en parallèle.
        verdict = (
            self._from_fixtures(valeur, nature)
            if self._fixtures
            else await self._from_live_sources(valeur, nature)
        )

        if nature == "file_hash":
            algo = hash_algorithm(valeur)
            if algo:
                verdict.attributes.setdefault("algorithme", algo)

        await self._cache.set(cle, verdict)
        return verdict

    async def enrich_many(self, indicators: list[str]) -> list[IndicatorVerdict]:
        """Enrichit plusieurs indicateurs simultanément.

        L'exécution concurrente est bornée par les limiteurs de débit de chaque
        source : lancer vingt requêtes d'un coup ne les envoie pas toutes en
        même temps à VirusTotal.
        """
        taches = [self.enrich(valeur) for valeur in indicators]
        resultats = await asyncio.gather(*taches, return_exceptions=True)

        verdicts: list[IndicatorVerdict] = []
        for valeur, issue in zip(indicators, resultats, strict=True):
            if isinstance(issue, InvalidIndicatorError):
                verdicts.append(
                    IndicatorVerdict(
                        indicator=valeur,
                        kind="domain",
                        verdict="unknown",
                        score=0,
                        confidence="low",
                        explanation=str(issue),
                        sources=[],
                        notes=["Indicateur ignoré : forme non reconnue."],
                    )
                )
            elif isinstance(issue, BaseException):
                logger.exception("Enrichissement en échec pour %s.", valeur)
                verdicts.append(
                    IndicatorVerdict(
                        indicator=valeur,
                        kind="domain",
                        verdict="unknown",
                        score=0,
                        confidence="low",
                        explanation=f"Enrichissement impossible : {type(issue).__name__}.",
                        sources=[],
                    )
                )
            else:
                verdicts.append(issue)
        return verdicts

    async def health(self) -> list[tuple[str, bool, str]]:
        """État de configuration de chaque source, pour le diagnostic."""
        etat = []
        for source in self._sources:
            if self._fixtures:
                etat.append((source.name, True, "Mode fixture : réponses locales."))
            elif source.configured:
                etat.append((source.name, True, "Clé d'API renseignée."))
            else:
                etat.append((source.name, False, "Aucune clé d'API."))
        return etat

    async def aclose(self) -> None:
        for client in self._clients:
            await client.aclose()

    # -------------------------------------------------------------- interne
    async def _from_live_sources(self, valeur: str, nature: IndicatorKind) -> IndicatorVerdict:
        pertinentes = [s for s in self._sources if s.handles(nature)]
        signaux = list(await asyncio.gather(*(s.query(valeur, nature) for s in pertinentes)))
        verdict = fuse(valeur, nature, signaux)
        verdict.attributes.update(self._attributes_from(signaux))
        return verdict

    @staticmethod
    def _attributes_from(signaux: list[SourceSignal]) -> dict[str, str]:
        """Rassemble les attributs d'enquête publiés par les sources."""
        attributs: dict[str, str] = {}
        for signal in signaux:
            if signal.result.status == "ok" and signal.result.detail:
                attributs.setdefault(signal.result.source, signal.result.detail[:120])
        return attributs

    def _from_fixtures(self, valeur: str, nature: IndicatorKind) -> IndicatorVerdict:
        """Rejoue des réponses enregistrées, pour démontrer sans clé d'API."""
        source = resources.files("threat_intel_mcp.fixtures").joinpath("indicators.json")
        catalogue: dict[str, Any] = json.loads(source.read_text(encoding="utf-8"))

        entree = catalogue.get("indicators", {}).get(valeur.lower())
        if entree is None:
            # Même chemin de fusion que le mode réel : un indicateur qu'aucune
            # source ne connaît reste un « unknown » de confiance élevée, et non
            # un verdict incertain. Dupliquer la logique ici produisait une
            # confiance erronée.
            interrogeables = [s for s in self._sources if s.handles(nature)]
            signaux_vides = [
                SourceSignal(
                    result=SourceResult(
                        source=s.name,
                        status="not_found",
                        detail="Indicateur inconnu de cette source.",
                    )
                )
                for s in interrogeables
            ]
            verdict = fuse(valeur, nature, signaux_vides)
            verdict.notes.append("Mode démonstration : seuls quelques indicateurs sont référencés.")
            return verdict

        signaux = [
            SourceSignal(
                result=SourceResult(**brut["result"]),
                override=brut.get("override"),
                override_reason=brut.get("override_reason"),
                bonus=brut.get("bonus", 0),
            )
            for brut in entree["signals"]
        ]
        verdict = fuse(valeur, nature, signaux)
        verdict.attributes.update(entree.get("attributes", {}))
        return verdict

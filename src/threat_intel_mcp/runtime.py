"""Cycle de vie du service d'enrichissement, partagé par tous les outils.

Ce module existe pour éviter une dépendance circulaire : ``server`` importe les
outils pour les enregistrer, et les outils doivent atteindre le service. Les
deux passent donc par ici.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from .cache import build_cache
from .config import get_settings
from .enrichment import EnrichmentService

logger = logging.getLogger(__name__)

_service: EnrichmentService | None = None


def get_service() -> EnrichmentService:
    """Retourne le service actif, créé par le cycle de vie du serveur."""
    if _service is None:
        raise RuntimeError(
            "Aucun service d'enrichissement actif : les outils doivent être appelés "
            "pendant l'exécution du serveur."
        )
    return _service


@asynccontextmanager
async def lifespan(_server: Any) -> AsyncIterator[EnrichmentService]:
    """Ouvre le service au démarrage, le referme proprement à l'arrêt."""
    # Un seul service par processus, porté par le serveur.
    global _service

    settings = get_settings()
    cache = build_cache(settings)
    _service = EnrichmentService(settings, cache)

    logger.info(
        "Sources configurées : %s.",
        ", ".join(settings.configured_sources()) or "aucune",
    )
    try:
        yield _service
    finally:
        await _service.aclose()
        await cache.aclose()
        _service = None


def configure_logging(level: str = "INFO") -> None:
    """Dirige toute la journalisation vers stderr.

    En transport stdio, le protocole JSON-RPC circule sur **stdout**. Un seul
    octet parasite sur ce flux corrompt la trame et déconnecte le client.
    """
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        force=True,
    )

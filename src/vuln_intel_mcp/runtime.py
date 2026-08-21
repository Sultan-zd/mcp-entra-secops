"""Cycle de vie : le client HTTP et le cache de catalogues, partagés."""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from argus_net import FeedCache, PublicHttpClient

from .config import get_settings
from .sources import VulnSources

logger = logging.getLogger(__name__)

_sources: VulnSources | None = None


def get_sources() -> VulnSources:
    """Rend l'accès aux sources, créé par le cycle de vie du serveur."""
    if _sources is None:
        raise RuntimeError(
            "Les sources ne sont pas initialisées : le serveur n'a pas démarré son cycle de vie."
        )
    return _sources


def build_sources() -> VulnSources:
    reglages = get_settings()
    http = PublicHttpClient(timeout=reglages.request_timeout_seconds)
    feeds = FeedCache(ttl_seconds=reglages.feed_ttl_seconds)
    return VulnSources(http, feeds)


@asynccontextmanager
async def lifespan(_server: Any) -> AsyncIterator[VulnSources]:
    """Ouvre les ressources réseau pour la durée de vie du serveur."""
    global _sources
    _sources = build_sources()
    logger.info("Sources de vulnérabilités prêtes (NVD, CISA KEV, EPSS).")
    try:
        yield _sources
    finally:
        await _sources._http.aclose()
        _sources = None


def configure_logging(level: str = "INFO") -> None:
    """Journalisation sur stderr.

    En transport stdio, stdout porte le protocole JSON-RPC : un seul octet
    parasite corrompt la trame et la conversation casse.
    """
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s : %(message)s",
        force=True,
    )

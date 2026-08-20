"""Cycle de vie du résolveur DNS, partagé par tous les outils."""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from .config import Settings, get_settings
from .dns_client import DnsResolver, FixtureDnsResolver, LiveDnsResolver

logger = logging.getLogger(__name__)

_resolver: DnsResolver | None = None


def get_resolver() -> DnsResolver:
    """Retourne le résolveur actif, créé par le cycle de vie du serveur."""
    if _resolver is None:
        raise RuntimeError(
            "Aucun résolveur DNS actif : les outils doivent être appelés pendant "
            "l'exécution du serveur."
        )
    return _resolver


def build_resolver(settings: Settings) -> DnsResolver:
    """Instancie le résolveur correspondant à la configuration."""
    if settings.data_source == "fixture":
        logger.info("Résolution DNS : zones locales (aucune requête réseau).")
        return FixtureDnsResolver()
    logger.info("Résolution DNS : réelle (délai %.1f s).", settings.dns_timeout_seconds)
    return LiveDnsResolver(settings.dns_timeout_seconds, settings.nameserver_list())


@asynccontextmanager
async def lifespan(_server: Any) -> AsyncIterator[DnsResolver]:
    """Ouvre le résolveur au démarrage, le referme proprement à l'arrêt."""
    # Un seul résolveur par processus, porté par le serveur.
    global _resolver

    _resolver = build_resolver(get_settings())
    try:
        yield _resolver
    finally:
        await _resolver.aclose()
        _resolver = None


def configure_logging(level: str = "INFO") -> None:
    """Dirige toute la journalisation vers stderr.

    En transport stdio, le protocole JSON-RPC circule sur **stdout** : un seul
    octet parasite corrompt la trame et déconnecte le client.
    """
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        force=True,
    )

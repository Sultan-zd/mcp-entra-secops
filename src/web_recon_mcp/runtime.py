"""Cycle de vie : le client HTTP partagé."""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from argus_net import PublicHttpClient

logger = logging.getLogger(__name__)

_http: PublicHttpClient | None = None


def get_http() -> PublicHttpClient:
    """Rend le client partagé, créé par le cycle de vie du serveur."""
    if _http is None:
        raise RuntimeError(
            "Le client HTTP n'est pas initialisé : le serveur n'a pas démarré son cycle de vie."
        )
    return _http


def build_http() -> PublicHttpClient:
    return PublicHttpClient(timeout=30.0)


@asynccontextmanager
async def lifespan(_server: Any) -> AsyncIterator[PublicHttpClient]:
    """Ouvre le client pour la durée de vie du serveur."""
    global _http
    _http = build_http()
    logger.info("Reconnaissance web prête (TLS direct, DNS, transparence).")
    try:
        yield _http
    finally:
        await _http.aclose()
        _http = None


def configure_logging(level: str = "INFO") -> None:
    """Journalisation sur stderr : stdout porte le protocole JSON-RPC."""
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s : %(message)s",
        force=True,
    )

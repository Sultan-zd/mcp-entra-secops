"""Cycle de vie de la source de données, partagé par tous les outils.

Ce module existe pour éviter une dépendance circulaire : ``server`` doit
importer les outils pour les enregistrer, et les outils doivent atteindre le
client Graph. Les deux passent donc par ici.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from .config import get_settings
from .graph import GraphClient, build_client

logger = logging.getLogger(__name__)

_client: GraphClient | None = None


def get_client() -> GraphClient:
    """Retourne le client actif, créé par le cycle de vie du serveur."""
    if _client is None:
        raise RuntimeError(
            "Aucune source de données active : les outils doivent être appelés "
            "pendant l'exécution du serveur."
        )
    return _client


@asynccontextmanager
async def lifespan(_server: Any) -> AsyncIterator[GraphClient]:
    """Ouvre la source de données au démarrage, la referme proprement à l'arrêt."""
    # Une seule source de données par processus, portée par le serveur.
    global _client
    _client = build_client(get_settings())
    try:
        yield _client
    finally:
        await _client.aclose()
        _client = None


def configure_logging(level: str = "INFO") -> None:
    """Dirige toute la journalisation vers stderr.

    En transport stdio, le protocole JSON-RPC circule sur **stdout**. Un seul
    octet parasite sur ce flux corrompt la trame et déconnecte le client. Toute
    sortie de diagnostic doit donc passer par stderr, sans exception.
    """
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        force=True,
    )

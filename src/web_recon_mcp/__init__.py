"""Reconnaissance web et TLS, sans clé d'API.

Trois des six outils n'interrogent aucune API : ils ouvrent eux-mêmes la
connexion et lisent ce que l'hôte présente. Cela les rend utilisables sur un
hôte interne, et garantit que la note ne change pas parce qu'un prestataire a
modifié son barème.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - uniquement pour le typage
    from mcp.server import MCPServer

__all__ = ["build_server"]


def build_server() -> MCPServer:
    """Réexport paresseux : importer le serveur charge tout le SDK MCP."""
    from .server import build_server as _build

    return _build()

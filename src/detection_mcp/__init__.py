"""Ingénierie de détection : indicateurs, règles Sigma, couverture ATT&CK.

Entièrement hors ligne. Un rapport de menace encore confidentiel, un courriel
signalé par un utilisateur, une règle en cours d'écriture : rien de tout cela
ne quitte le poste.
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

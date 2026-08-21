"""MITRE ATT&CK, entièrement hors ligne.

Le corpus officiel pèse 51 Mo et change quatre fois par an. Il est distillé à
1 Mo et embarqué : ces outils répondent en quelques millisecondes, sans réseau,
et leurs réponses ne varient pas d'un appel à l'autre.
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

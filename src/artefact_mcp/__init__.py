"""Analyse d'artefacts : jetons, charges obfusquées — entièrement hors ligne.

Un jeton est un secret ; une charge obfusquée peut être une pièce à conviction.
Ni l'un ni l'autre ne quitte le poste.
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

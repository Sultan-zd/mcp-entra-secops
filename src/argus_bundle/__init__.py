"""ARGUS en un seul serveur, pour la distribution.

Les sept serveurs restent la bonne architecture sur un poste d'analyste. Ce
paquet les réunit sans les réécrire, pour qu'une équipe n'ait qu'un fichier à
installer au lieu de six déclarations à recopier.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - uniquement pour le typage
    from mcp.server import MCPServer

__all__ = ["build_server"]


def build_server() -> MCPServer:
    from .server import build_server as _build

    return _build()

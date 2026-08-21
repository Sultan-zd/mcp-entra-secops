"""Renseignement sur les vulnérabilités : NVD, CISA KEV, EPSS.

Aucune source n'exige de clé. Ce serveur ne se contente pas de les relayer :
il recalcule les notes CVSS localement, croise les trois sources, et rend un
**ordre de correction** — la seule chose dont un analyste ait réellement besoin.
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

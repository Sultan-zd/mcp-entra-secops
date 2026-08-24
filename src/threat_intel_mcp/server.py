"""Assemblage du serveur MCP de renseignement sur les menaces."""

from __future__ import annotations

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from argus_net import VERSION

from .runtime import lifespan
from .tools import bulk_enrich, enrich_domain, enrich_file_hash, enrich_ip

INSTRUCTIONS = """\
Ce serveur établit la réputation d'indicateurs de compromission — adresses IP,
domaines, condensats de fichiers — en croisant plusieurs sources publiques.

Tous les outils sont en LECTURE SEULE.

Le verdict est calculé par du code déterministe, pas déduit d'un texte : le
champ `score` (0 à 100) et le champ `verdict` sont fiables et reproductibles.
Utilisez-les tels quels plutôt que de réinterpréter le détail par source.

Lisez toujours `confidence` avant de conclure :
  high   : trois sources ont répondu
  medium : deux sources
  low    : une seule source — à confirmer autrement

Le verdict `internal` signale une adresse privée : elle n'a volontairement pas
été soumise aux services externes, pour ne pas divulguer la topologie du réseau.

Le verdict `unknown` signifie qu'aucune source ne connaît l'indicateur. Ce
n'est PAS un verdict d'innocuité.

Quand une investigation produit plusieurs indicateurs, appelez `bulk_enrich`
plutôt que d'enchaîner les appels unitaires : les quotas des sources publiques
sont étroits, et l'appel groupé les interroge en parallèle.
"""

#: Aucun outil ne modifie quoi que ce soit. `open_world_hint` signale que les
#: réponses proviennent de services externes et peuvent varier dans le temps.
READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)

#: Une seule liste à tenir à jour ; l'enregistrement est identique pour chacun.
TOOLS = (enrich_ip, enrich_domain, enrich_file_hash, bulk_enrich)


def build_server() -> MCPServer:
    """Construit le serveur et y enregistre l'ensemble des outils."""
    server: MCPServer = MCPServer(
        name="ThreatIntel",
        title="Renseignement sur les menaces",
        version=VERSION,
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
    )

    for tool in TOOLS:
        server.tool(annotations=READ_ONLY)(tool)

    return server

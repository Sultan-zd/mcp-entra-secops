"""Assemblage du serveur MCP de sécurité de la messagerie."""

from __future__ import annotations

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from .runtime import lifespan
from .tools import (
    analyze_email_headers,
    check_dkim,
    check_dmarc,
    check_domain_posture,
    check_spf,
)

INSTRUCTIONS = """\
Ce serveur analyse la sécurité de la messagerie : SPF, DKIM, DMARC, et les
en-têtes d'un message reçu.

Tous les outils sont en LECTURE SEULE et n'interrogent que le DNS public.

Deux questions distinctes, deux familles d'outils :

  « Notre domaine est-il usurpable ? »
      → check_domain_posture, qui combine check_spf, check_dkim et check_dmarc

  « Ce message est-il usurpé ? »
      → analyze_email_headers

Trois pièges que les rapports signalent explicitement :

  · SPF au-delà de 10 résolutions DNS renvoie `permerror` et ne protège PLUS,
    alors que l'enregistrement paraît correct.
  · DMARC `p=none` est un mode d'observation : il ne bloque rien.
  · DMARC `pct=` inférieur à 100 n'applique la politique qu'à une fraction du
    trafic.

Les verdicts et les notes sont calculés par du code déterministe. Le champ
`severity` (high, medium, low, none) est fiable : utilisez-le tel quel.

Après `analyze_email_headers`, le champ `indicators` contient les adresses IP
et domaines extraits : les passer au serveur de renseignement sur les menaces
complète l'analyse.
"""

#: Aucun outil ne modifie quoi que ce soit. `open_world_hint` signale que les
#: réponses proviennent du DNS public et peuvent changer dans le temps.
READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)

TOOLS = (
    check_domain_posture,
    check_spf,
    check_dkim,
    check_dmarc,
    analyze_email_headers,
)


def build_server() -> MCPServer:
    """Construit le serveur et y enregistre l'ensemble des outils."""
    server: MCPServer = MCPServer(
        name="EmailSecurity",
        title="Sécurité de la messagerie",
        version="0.3.0",
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
    )

    for tool in TOOLS:
        server.tool(annotations=READ_ONLY)(tool)

    return server

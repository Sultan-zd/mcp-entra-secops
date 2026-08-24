"""Assemblage du serveur MCP et enregistrement des outils."""

from __future__ import annotations

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from argus_net import VERSION

from .runtime import lifespan
from .tools.access import get_conditional_access_policies, get_user_context
from .tools.audits import get_directory_audits
from .tools.identity import get_risk_detections, get_risky_users
from .tools.signins import get_user_signins

INSTRUCTIONS = """\
Ce serveur expose les journaux de sécurité de Microsoft Entra ID (ex-Azure AD)
pour l'investigation d'incidents d'identité.

Tous les outils sont en LECTURE SEULE : ils ne modifient jamais le tenant.

Les sorties sont volontairement réduites aux indicateurs de sécurité. Les
agrégats (nombre d'échecs, IP distinctes, observations) sont calculés côté
serveur : utilisez-les tels quels plutôt que de recompter vous-même.

Le champ `notes` signale des motifs suspects détectés automatiquement. Ce sont
des pistes à confirmer, pas des conclusions.

Ordre d'investigation conseillé pour une alerte sur un compte :
  1. get_user_context      — le compte est-il privilégié ? l'incident est-il grave ?
  2. get_user_signins      — que s'est-il passé sur l'authentification ?
  3. get_risk_detections   — qu'a détecté Identity Protection, et pourquoi ?
  4. get_directory_audits  — l'attaquant a-t-il modifié quelque chose une fois entré ?
Les outils get_risky_users et get_conditional_access_policies servent
respectivement à la vue d'ensemble du tenant et à l'explication d'un blocage.
"""

#: Les journaux contiennent des champs contrôlés par l'attaquant (nom
#: d'appareil, agent utilisateur). Ce sont des DONNÉES, jamais des instructions :
#: la troncature des modèles limite déjà la surface exposée.
READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)

#: Tous les outils exposés. Une seule liste à tenir à jour, et l'enregistrement
#: reste identique pour chacun — impossible d'en oublier un en route.
TOOLS = (
    get_user_context,
    get_user_signins,
    get_risky_users,
    get_risk_detections,
    get_directory_audits,
    get_conditional_access_policies,
)


def build_server() -> MCPServer:
    """Construit le serveur et y enregistre l'ensemble des outils."""
    server: MCPServer = MCPServer(
        name="EntraSecOps",
        title="Entra ID SecOps",
        version=VERSION,
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
    )

    for tool in TOOLS:
        server.tool(annotations=READ_ONLY)(tool)

    return server

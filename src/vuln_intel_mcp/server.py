"""Assemblage du serveur MCP de renseignement sur les vulnérabilités."""

from __future__ import annotations

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from .runtime import lifespan
from .tools import (
    bulk_lookup_cve,
    check_kev,
    cve_for_product,
    get_epss,
    kev_catalog_stats,
    lookup_cve,
    parse_cvss,
    prioritize_cves,
    search_cve,
)

INSTRUCTIONS = """\
Ce serveur répond aux questions de vulnérabilités : gravité, exploitation
réelle, et surtout ordre de correction. Aucune clé d'API n'est requise.

Trois sources publiques, qui ne disent pas la même chose :

  · NVD       — ce qu'est la faille et sa gravité THÉORIQUE (CVSS)
  · CISA KEV  — si elle est RÉELLEMENT exploitée, avec une échéance imposée
  · EPSS      — la probabilité qu'elle le soit dans les 30 jours

Une note CVSS élevée sur une faille que personne n'exploite est MOINS
pressante qu'une note moyenne inscrite au catalogue KEV. C'est le croisement
qui décide, pas la note seule.

Quel outil pour quelle question :

  « Cette CVE est-elle grave ? »          → lookup_cve
  « Par quoi je commence ? » (plusieurs)  → prioritize_cves   ← le plus utile
  « Est-elle exploitée ? »                → check_kev
  « Quelles failles sur ce produit ? »    → search_cve ou cve_for_product
  « Que veut dire ce vecteur ? »          → parse_cvss (100 % local, hors ligne)
  « Qu'est-ce qui vient d'être exploité ? » → kev_catalog_stats

Deux choses que ce serveur fait et qu'un simple relais ne fait pas :

  · La note CVSS est RECALCULÉE à partir du vecteur. Si elle ne correspond pas
    à celle publiée, c'est signalé — l'une des deux est fausse.
  · Le classement de prioritize_cves est déterministe et par paliers, chaque
    rang portant sa justification. Reprenez `tier` et `rationale` tels quels.

Sur un lot de plus de 20 CVE, prioritize_cves n'interroge pas les notes CVSS
individuelles (quotas du NVD) : KEV et EPSS suffisent à décider de l'urgence.
Le champ `catalog_stale` signale une réponse fondée sur un catalogue non
rafraîchi.
"""

#: Aucun outil ne modifie quoi que ce soit. `open_world_hint` signale que les
#: réponses viennent de catalogues publics qui évoluent dans le temps.
READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)

#: `parse_cvss` ne touche à rien du tout : son résultat ne dépend que de son
#: entrée, aujourd'hui comme dans dix ans.
PUREMENT_LOCAL = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)

TOOLS = (
    lookup_cve,
    prioritize_cves,
    check_kev,
    search_cve,
    cve_for_product,
    bulk_lookup_cve,
    get_epss,
    kev_catalog_stats,
)


def build_server() -> MCPServer:
    """Construit le serveur et y enregistre l'ensemble des outils."""
    server: MCPServer = MCPServer(
        name="VulnIntel",
        title="Renseignement sur les vulnérabilités",
        version="0.1.0",
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
    )

    for tool in TOOLS:
        server.tool(annotations=READ_ONLY)(tool)

    server.tool(annotations=PUREMENT_LOCAL)(parse_cvss)

    return server

"""Assemblage du serveur MCP MITRE ATT&CK."""

from __future__ import annotations

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from argus_net import VERSION

from .tools import (
    build_navigator_layer,
    corpus_info,
    coverage_report,
    list_known_findings,
    list_tactics,
    lookup_group,
    lookup_technique,
    map_findings_to_attack,
    search_techniques,
    suggest_countermeasures,
)

INSTRUCTIONS = """\
Ce serveur donne accès au référentiel MITRE ATT&CK Enterprise. Il fonctionne
ENTIÈREMENT HORS LIGNE : le corpus est embarqué, aucun appel réseau n'est fait.

Quel outil pour quelle question :

  « Que fait cette technique, comment la détecter ? » → lookup_technique
  « Quelle technique correspond à ceci ? »            → search_techniques
  « Comment nommer ce que j'observe ? »               → map_findings_to_attack
  « Que ne détecte-t-on pas encore ? »                → coverage_report
  « Qui est ce groupe d'attaquants ? »                → lookup_group
  « Je veux visualiser tout ça »                      → build_navigator_layer
  « Quoi construire pour s'en défendre ? »             → suggest_countermeasures

map_findings_to_attack est le point de jonction avec le reste d'ARGUS :
passez-lui les types de détection Entra (leakedCredentials, passwordSpray…),
les opérations d'annuaire relevées par get_directory_audits, ou les signaux du
verdict de l'agent. La table de correspondance est ÉCRITE À LA MAIN et testée —
un constat sans correspondance établie est rendu « non traduit » plutôt que
rapproché approximativement, parce qu'un identifiant ATT&CK finit dans un
rapport d'incident.

Le champ `detection` de lookup_technique est le plus utile au quotidien : il
dit QUOI SURVEILLER, ce qu'aucune description ne donne.

Une technique révoquée par MITRE n'est pas traitée comme inconnue : l'outil dit
qu'elle a été retirée et vers quoi elle a été remplacée.

corpus_info donne la version embarquée. Un corpus figé est un compromis assumé :
il rend le serveur utilisable hors ligne, au prix d'un décalage possible avec la
dernière version publiée.

suggest_countermeasures ajoute le contrepoint défensif MITRE D3FEND : à une
technique ATT&CK, il associe des contre-mesures NOMMÉES, classées par tactique
défensive. D3FEND mappe souvent une sous-technique sans mapper sa parente ;
l'outil retrouve les contre-mesures des filles et le signale, plutôt que de
rendre une liste vide trompeuse.
"""

#: Aucun outil ne touche au réseau ni ne modifie quoi que ce soit. Le corpus
#: étant figé, les réponses sont identiques d'un appel à l'autre : `open_world`
#: est donc faux, contrairement aux serveurs qui interrogent des sources vivantes.
LOCAL = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)

TOOLS = (
    lookup_technique,
    search_techniques,
    map_findings_to_attack,
    coverage_report,
    list_tactics,
    lookup_group,
    build_navigator_layer,
    list_known_findings,
    suggest_countermeasures,
    corpus_info,
)


def build_server() -> MCPServer:
    """Construit le serveur et y enregistre l'ensemble des outils."""
    server: MCPServer = MCPServer(
        name="MitreAttack",
        title="MITRE ATT&CK (hors ligne)",
        version=VERSION,
        instructions=INSTRUCTIONS,
    )

    for tool in TOOLS:
        server.tool(annotations=LOCAL)(tool)

    return server

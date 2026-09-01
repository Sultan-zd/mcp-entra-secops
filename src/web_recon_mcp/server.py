"""Assemblage du serveur MCP de reconnaissance web et TLS."""

from __future__ import annotations

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from argus_net import VERSION

from .runtime import lifespan
from .tools import (
    check_certificate_expiry,
    check_dns_hygiene,
    check_security_headers,
    check_tls,
    check_web_exposure,
    find_subdomains,
    lookup_domain_registration,
    lookup_ip_owner,
)

INSTRUCTIONS = """\
Ce serveur audite l'exposition web d'un domaine : TLS, en-têtes de sécurité,
hygiène DNS, et sous-domaines. Aucune clé d'API n'est requise.

Trois outils n'interrogent AUCUNE API : ils ouvrent eux-mêmes la connexion.
Ils fonctionnent donc sur un hôte INTERNE, qu'un service en ligne ne pourrait
jamais atteindre, et leur note ne dépend d'aucun prestataire.

Quel outil pour quelle question :

  « Ce domaine est-il bien exposé ? »        → check_web_exposure  ← commence ici
  « Sa configuration TLS tient-elle ? »      → check_tls
  « Mes certificats vont-ils expirer ? »     → check_certificate_expiry
  « Ce site est-il durci ? »                 → check_security_headers
  « Mon DNS a-t-il des failles ? »           → check_dns_hygiene
  « Qu'ai-je exposé sans le savoir ? »       → find_subdomains

Trois constats à ne pas manquer :

  · ALIAS PENDANT (check_dns_hygiene) — un CNAME vers un service infogéré
    libéré. Quiconque le réenregistre reçoit le trafic du sous-domaine ET peut
    faire émettre un certificat valide. C'est le défaut le plus grave que ce
    serveur détecte.
  · VERSIONS TLS DÉPRÉCIÉES — un serveur qui négocie TLS 1.3 avec un navigateur
    moderne peut accepter TLS 1.0 avec un client qui le demande. Chaque version
    est testée SÉPARÉMENT.
  · TRANSFERT DE ZONE OUVERT — livre l'annuaire complet du domaine.

Deux précisions de lecture :

  · Une version TLS « non testable » n'est PAS « refusée » : la bibliothèque
    cliente peut avoir refusé de la proposer. La distinction est maintenue.
  · find_subdomains EXCLUT les noms appartenant à d'autres domaines. Les
    hébergeurs mutualisés en regroupent des dizaines dans un même certificat ;
    les présenter comme vos sous-domaines serait faux. Leur nombre est rapporté
    séparément.

Les notes et les niveaux de gravité sont calculés par du code déterministe :
reprenez-les tels quels.
"""

#: Aucun outil ne modifie quoi que ce soit. `open_world` est vrai : les
#: réponses dépendent de l'état du réseau au moment de l'appel.
READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)

TOOLS = (
    check_web_exposure,
    check_tls,
    check_certificate_expiry,
    check_security_headers,
    check_dns_hygiene,
    find_subdomains,
    lookup_domain_registration,
    lookup_ip_owner,
)


def build_server() -> MCPServer:
    """Construit le serveur et y enregistre l'ensemble des outils."""
    server: MCPServer = MCPServer(
        name="WebRecon",
        title="Reconnaissance web et TLS",
        version=VERSION,
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
    )

    for tool in TOOLS:
        server.tool(annotations=READ_ONLY)(tool)

    return server

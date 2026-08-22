"""Genere le manifest.json du paquet MCPB, avec la liste reelle des outils.

La liste n'est pas recopiee a la main : elle est demandee au serveur lui-meme,
pour qu'elle ne puisse pas diverger du code.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
MCPB = RACINE / "mcpb"

sys.path.insert(0, str(MCPB / "src"))

# Toutes les cles presentes : le manifeste doit annoncer les 39 outils, pas
# seulement ceux disponibles sur cette machine.
os.environ.update(
    {
        "VIRUSTOTAL_API_KEY": "x",
        "ABUSEIPDB_API_KEY": "x",
        "ENTRA_DATA_SOURCE": "fixture",
    }
)

from argus_bundle.server import build_server  # noqa: E402

outils = asyncio.run(build_server().list_tools())


def resumer(description: str | None) -> str:
    """Premiere phrase de la description, pour la vitrine du manifeste."""
    texte = " ".join((description or "").split())
    for fin in (". ", " : "):
        if fin in texte:
            texte = texte.split(fin)[0] + ("." if fin == ". " else "")
            break
    return texte[:180]


manifeste = {
    "manifest_version": "0.4",
    "name": "argus-secops",
    "display_name": "ARGUS — Plateforme SecOps",
    "version": "1.0.0",
    "description": (
        "39 outils SecOps en lecture seule : CVE/KEV/EPSS, MITRE ATT&CK hors "
        "ligne, TLS, DNS, SPF/DKIM/DMARC, reputation d'indicateurs, Entra ID."
    ),
    "long_description": (
        "ARGUS expose la telemetrie de securite comme outils executables par un "
        "agent. Vingt-neuf outils fonctionnent SANS AUCUNE CLE d'API : "
        "vulnerabilites (NVD, catalogue CISA des failles activement exploitees, "
        "probabilite d'exploitation EPSS), MITRE ATT&CK avec son corpus embarque "
        "— donc utilisable hors ligne —, inspection TLS par connexion directe, "
        "hygiene DNS (DNSSEC, CAA, alias pendants), en-tetes de securite, "
        "transparence des certificats, et posture de messagerie SPF/DKIM/DMARC. "
        "Dix outils supplementaires s'activent si vous fournissez vos propres "
        "cles VirusTotal, AbuseIPDB ou un tenant Microsoft Entra.\n\n"
        "Ce n'est pas un relais d'API. Les notes CVSS sont RECALCULEES "
        "localement a partir du vecteur et confrontees a 138 vecteurs reels du "
        "NVD ; le classement des vulnerabilites est deterministe et par paliers ; "
        "l'inspection TLS ouvre sa propre connexion, ce qui fonctionne aussi sur "
        "un hote interne. Tous les outils sont en LECTURE SEULE : rien n'est "
        "jamais modifie."
    ),
    "author": {
        "name": "Sultan Zeineddine",
        "url": "https://github.com/Sultan-zd",
    },
    "homepage": "https://github.com/Sultan-zd/mcp-entra-secops",
    "documentation": "https://github.com/Sultan-zd/mcp-entra-secops#readme",
    "support": "https://github.com/Sultan-zd/mcp-entra-secops/issues",
    "repository": {
        "type": "git",
        "url": "https://github.com/Sultan-zd/mcp-entra-secops",
    },
    "license": "MIT",
    "keywords": [
        "security",
        "secops",
        "cve",
        "kev",
        "epss",
        "mitre",
        "attack",
        "tls",
        "dns",
        "spf",
        "dmarc",
        "dkim",
        "entra",
        "soc",
    ],
    "server": {
        "type": "uv",
        "entry_point": "server/main.py",
        "mcp_config": {
            "command": "uv",
            "args": [
                "run",
                "--directory",
                "${__dirname}",
                "server/main.py",
            ],
            "env": {
                "VIRUSTOTAL_API_KEY": "${user_config.virustotal_api_key}",
                "ABUSEIPDB_API_KEY": "${user_config.abuseipdb_api_key}",
                "AZURE_TENANT_ID": "${user_config.azure_tenant_id}",
                "AZURE_CLIENT_ID": "${user_config.azure_client_id}",
                "AZURE_CLIENT_SECRET": "${user_config.azure_client_secret}",
                "MAIL_DNS_NAMESERVERS": "${user_config.dns_resolvers}",
            },
        },
    },
    "user_config": {
        "virustotal_api_key": {
            "type": "string",
            "title": "Cle VirusTotal (facultatif)",
            "description": (
                "Active les outils de reputation d'indicateurs. Le palier "
                "gratuit suffit. Sans cle, les 29 autres outils fonctionnent."
            ),
            "sensitive": True,
            "required": False,
        },
        "abuseipdb_api_key": {
            "type": "string",
            "title": "Cle AbuseIPDB (facultatif)",
            "description": (
                "Deuxieme source de reputation. Croiser deux sources evite de "
                "conclure sur un avis unique."
            ),
            "sensitive": True,
            "required": False,
        },
        "azure_tenant_id": {
            "type": "string",
            "title": "Identifiant de tenant Entra (facultatif)",
            "description": (
                "Active les six outils d'identite. Exige une licence Entra ID "
                "P1 pour les journaux de connexion, P2 pour Identity Protection."
            ),
            "required": False,
        },
        "azure_client_id": {
            "type": "string",
            "title": "Identifiant d'application Entra (facultatif)",
            "description": "Inscription d'application avec permissions en lecture seule.",
            "required": False,
        },
        "azure_client_secret": {
            "type": "string",
            "title": "Secret client Entra (facultatif)",
            "description": (
                "Ce secret donne acces en LECTURE a la telemetrie d'identite du "
                "tenant. Revoquez-le des qu'il n'est plus necessaire."
            ),
            "sensitive": True,
            "required": False,
        },
        "dns_resolvers": {
            "type": "string",
            "title": "Resolveurs DNS",
            "description": (
                "Beaucoup de resolveurs de fournisseurs d'acces ne rendent pas "
                "les reponses TXT volumineuses, ce qui fait echouer l'analyse "
                "de messagerie sur les gros domaines."
            ),
            "default": "8.8.8.8,1.1.1.1",
            "required": False,
        },
    },
    "compatibility": {
        "platforms": ["win32", "darwin", "linux"],
        "runtimes": {"python": ">=3.11"},
    },
    "tools": [{"name": t.name, "description": resumer(t.description)} for t in outils],
}

chemin = MCPB / "manifest.json"
chemin.write_text(json.dumps(manifeste, indent=2, ensure_ascii=False), encoding="utf-8")

print(f"manifest.json ecrit : {len(manifeste['tools'])} outils declares")
print(f"taille : {chemin.stat().st_size} octets")

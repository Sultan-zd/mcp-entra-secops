"""Point d'entrée : `python -m argus_bundle` ou `argus-mcp`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from argus_net import forcer_utf8

from .server import build_server, domaines_actifs

logger = logging.getLogger(__name__)


def _configure_logging(level: str = "INFO") -> None:
    """Journalisation sur stderr : stdout porte le protocole JSON-RPC."""
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s : %(message)s",
        force=True,
    )


def _run_check() -> int:
    """Affiche les domaines exposés et le nombre d'outils."""
    actifs = domaines_actifs()
    serveur = build_server()

    print()
    print("ARGUS — serveur unique")
    print("─" * 22)
    libelles = {
        "vulnerabilites": "Vulnérabilités (CVE, KEV, EPSS)",
        "mitre": "MITRE ATT&CK (hors ligne)",
        "web": "Web et TLS",
        "messagerie": "Messagerie (SPF, DKIM, DMARC)",
        "renseignement": "Renseignement sur les menaces",
        "identite": "Identité Microsoft Entra",
    }
    for nom, actif in actifs.items():
        marque = "✓" if actif else "·"
        note = "" if actif else "   (clés absentes — domaine non exposé)"
        print(f"  {marque} {libelles[nom]:38}{note}")

    # `list_tools()` est l'API publique du serveur ; lire un attribut interne
    # rendait « ? » en silence dès que le SDK renommait son champ.
    outils = asyncio.run(serveur.list_tools())
    print()
    print(f"  {len(outils)} outils exposés.")
    print()

    if not actifs["renseignement"]:
        print("  Pour le renseignement : VIRUSTOTAL_API_KEY et/ou ABUSEIPDB_API_KEY.")
    if not actifs["identite"]:
        print("  Pour l'identité : AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.")
    print()
    return 0


def main() -> None:
    # Avant tout affichage : la console Windows est en cp1252 par defaut.
    forcer_utf8()
    parser = argparse.ArgumentParser(
        prog="argus-mcp",
        description="ARGUS — plateforme SecOps, tous les domaines en un serveur.",
    )
    parser.add_argument("--check", action="store_true", help="Liste les domaines et quitte.")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    _configure_logging(args.log_level)

    if args.check:
        raise SystemExit(_run_check())

    build_server().run()


if __name__ == "__main__":
    main()

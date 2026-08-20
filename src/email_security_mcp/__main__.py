"""Point d'entrée : `python -m email_security_mcp` ou `email-security-mcp`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .config import Settings, get_settings
from .runtime import configure_logging, lifespan
from .server import build_server
from .tools import check_domain_posture

logger = logging.getLogger(__name__)

#: Domaines de contrôle : une posture exemplaire, une posture défaillante.
_SONDES = ("microsoft.com", "teknologiia.com")


async def _run_check(settings: Settings, domaines: list[str]) -> int:
    """Vérifie la résolution DNS et le chemin complet d'analyse."""
    print()
    print("1. Configuration")
    print("─" * 16)
    print(f"  Source de données  : {settings.data_source}")
    print(f"  Délai DNS          : {settings.dns_timeout_seconds} s")
    print(f"  Résolveurs         : {settings.nameserver_list() or 'ceux du système'}")

    print()
    print("2. Analyse de bout en bout")
    print("─" * 26)

    echecs = 0
    async with lifespan(None):
        for domaine in domaines:
            try:
                posture = await check_domain_posture(domain=domaine)
            # Interception large : le diagnostic doit rapporter l'echec d'un
            # domaine sans interrompre l'analyse des suivants.
            except Exception as exc:
                echecs += 1
                print(f"  {domaine:<24} ÉCHEC — {type(exc).__name__} : {exc}")
                continue

            print(
                f"  {domaine:<24} note {posture.grade} ({posture.score}/100)  "
                f"SPF {posture.spf.dns_lookups}/10 lookups · "
                f"DKIM {posture.dkim.keys_found} clé(s) · "
                f"DMARC {posture.dmarc.policy or 'absent'}"
            )
            for action in posture.priority_actions[:2]:
                print(f"      → {action[:96]}")

    print()
    print("Verdict")
    print("─" * 7)
    if echecs:
        print(f"  {echecs} domaine(s) non analysable(s).")
        return 1
    print(f"  {len(domaines)} domaine(s) analysé(s) sans erreur.")
    return 0


def main() -> None:
    """Démarre le serveur MCP sur le transport demandé."""
    parser = argparse.ArgumentParser(
        prog="email-security-mcp",
        description="Serveur MCP d'analyse SPF, DKIM, DMARC et d'en-têtes de messagerie.",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help=(
            "stdio pour un client local comme Claude Desktop (défaut) ; "
            "streamable-http pour une exposition distante derrière un proxy."
        ),
    )
    parser.add_argument(
        "--check",
        nargs="*",
        metavar="DOMAINE",
        help=(
            "Ne démarre pas le serveur : analyse les domaines fournis et quitte. "
            "Sans argument, utilise des domaines de contrôle."
        ),
    )
    args = parser.parse_args()

    try:
        settings = get_settings()
    except Exception as exc:
        print(f"Configuration invalide.\n\n{exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    if args.check is not None:
        # Diagnostic : les messages vont sur stdout, aucun protocole n'y circule.
        configure_logging("WARNING")
        domaines = args.check or list(_SONDES)
        raise SystemExit(asyncio.run(_run_check(settings, domaines)))

    configure_logging(settings.log_level)
    logger.info(
        "Démarrage du serveur EmailSecurity (transport=%s, source=%s).",
        args.transport,
        settings.data_source,
    )
    build_server().run(transport=args.transport)


if __name__ == "__main__":
    main()

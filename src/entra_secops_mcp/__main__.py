"""Point d'entrée : `python -m entra_secops_mcp` ou `entra-secops-mcp`."""

from __future__ import annotations

import argparse
import logging
import sys

from argus_net import forcer_utf8

from .config import get_settings
from .diagnostics import check
from .runtime import configure_logging
from .server import build_server

logger = logging.getLogger(__name__)


def main() -> None:
    """Démarre le serveur MCP sur le transport demandé."""
    # Avant tout affichage : la console Windows est en cp1252 par defaut.
    forcer_utf8()
    parser = argparse.ArgumentParser(
        prog="entra-secops-mcp",
        description="Serveur MCP exposant les journaux de sécurité Microsoft Entra ID.",
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
        action="store_true",
        help=(
            "Ne démarre pas le serveur : vérifie la configuration, l'authentification, "
            "les permissions consenties et l'accès à chaque endpoint, puis quitte."
        ),
    )
    args = parser.parse_args()

    # La configuration est validée AVANT tout démarrage : une variable
    # manquante doit produire un message clair, pas une panne au premier appel.
    try:
        settings = get_settings()
    # On intercepte largement : toute panne de configuration doit produire
    # un message lisible, pas une trace de pile.
    except Exception as exc:
        print(f"Configuration invalide.\n\n{exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    if args.check:
        # Diagnostic : les messages vont sur stdout, aucun protocole n'y circule.
        configure_logging("WARNING")
        check(settings)
        return

    configure_logging(settings.log_level)
    logger.info(
        "Démarrage du serveur EntraSecOps (transport=%s, source=%s).",
        args.transport,
        settings.data_source,
    )

    build_server().run(transport=args.transport)


if __name__ == "__main__":
    main()

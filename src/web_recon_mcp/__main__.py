"""Point d'entrée : `python -m web_recon_mcp` ou `web-recon-mcp`."""

from __future__ import annotations

import argparse
import asyncio
import logging

from .runtime import build_http, configure_logging
from .server import build_server

logger = logging.getLogger(__name__)

#: Domaine de contrôle : joignable, correctement configuré, stable.
_SONDE = "github.com"


async def _run_check() -> int:
    """Vérifie les trois chemins : TLS direct, HTTP, DNS."""
    from . import ct
    from .dnshygiene import examiner
    from .headers import analyser
    from .tls import inspecter

    echecs = 0
    http = build_http()

    print()
    print("Chemins d'analyse")
    print("─" * 17)

    try:
        tls = await inspecter(_SONDE, tester_versions=False)
        print(f"  ✓ TLS direct   {_SONDE} : {tls.negotiated_version}, {tls.key_type}")
        print(f"                 expire dans {tls.days_until_expiry} jour(s)")
    except Exception as exc:
        print(f"  ✗ TLS direct   {exc}")
        echecs += 1

    try:
        entetes = await analyser(_SONDE)
        print(f"  ✓ En-têtes     note {entetes.grade} ({entetes.score}/100)")
    except Exception as exc:
        print(f"  ✗ En-têtes     {exc}")
        echecs += 1

    try:
        dns_ = await examiner(_SONDE, tester_transfert=False)
        print(f"  ✓ DNS          DNSSEC {dns_.dnssec}, {len(dns_.nameservers)} serveurs de noms")
    except Exception as exc:
        print(f"  ✗ DNS          {exc}")
        echecs += 1

    try:
        transparence = await ct.decouvrir(_SONDE, http, limite=10)
        print(
            f"  ✓ Transparence {len(transparence.subdomains)} sous-domaine(s) "
            f"via {transparence.source}"
        )
        if transparence.foreign_names_excluded:
            print(f"                 {transparence.foreign_names_excluded} nom(s) tiers exclus")
    except Exception as exc:
        print(f"  ✗ Transparence {exc}")
        echecs += 1

    await http.aclose()

    print()
    print(f"{echecs} contrôle(s) en échec." if echecs else "Tous les chemins répondent.")
    print()
    return 1 if echecs else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="web-recon-mcp",
        description="Serveur MCP de reconnaissance web et TLS, sans clé d'API.",
    )
    parser.add_argument("--check", action="store_true", help="Vérifie les chemins et quitte.")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    configure_logging(args.log_level)

    if args.check:
        raise SystemExit(asyncio.run(_run_check()))

    build_server().run()


if __name__ == "__main__":
    main()

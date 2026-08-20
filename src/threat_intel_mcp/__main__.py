"""Point d'entrée : `python -m threat_intel_mcp` ou `threat-intel-mcp`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .config import Settings, get_settings
from .runtime import configure_logging, lifespan
from .server import build_server

logger = logging.getLogger(__name__)

#: Indicateurs de contrôle : un service courant, une adresse privée, et une
#: adresse publique quelconque.
#: Ils vérifient les trois chemins du serveur — enrichissement réel,
#: court-circuit interne, et absence de résultat.
_SONDES = ("8.8.8.8", "10.0.0.1", "185.199.108.153")


async def _run_check(settings: Settings) -> int:
    """Vérifie la configuration, les sources et le chemin complet d'enrichissement."""
    print()
    print("1. Configuration")
    print("─" * 16)
    print(f"  Source de données : {settings.data_source}")
    print(
        f"  Cache             : {'Redis' if settings.redis_url else 'mémoire'} "
        f"(TTL {settings.cache_ttl_seconds} s)"
    )
    print(f"  Plafond groupé    : {settings.max_bulk_indicators} indicateurs")

    configurees = settings.configured_sources()
    print()
    print("2. Sources")
    print("─" * 10)
    for nom, debit in (
        ("virustotal", settings.virustotal_rpm),
        ("abuseipdb", settings.abuseipdb_rpm),
        ("greynoise", settings.greynoise_rpm),
    ):
        marque = "✓" if nom in configurees else "✗"
        etat = f"{debit} req/min" if nom in configurees else "aucune clé d'API"
        print(f"  {marque} {nom:<12} {etat}")

    if not configurees:
        print()
        print("  Aucune source utilisable : le serveur répondrait « inconnu » à tout.")
        return 1

    print()
    print("3. Enrichissement de bout en bout")
    print("─" * 33)
    async with lifespan(None) as service:
        for sonde in _SONDES:
            verdict = await service.enrich(sonde)
            repondu = verdict.answered_sources
            print(
                f"  {sonde:<16} → {verdict.verdict:<10} score {verdict.score:>3} "
                f"| confiance {verdict.confidence:<6} | {repondu} source(s)"
            )

    print()
    print("Verdict")
    print("─" * 7)
    print(f"  {len(configurees)} source(s) opérationnelle(s) : {', '.join(configurees)}.")
    if settings.data_source == "fixture":
        print("  Mode fixture : aucune API externe n'a été contactée.")
    return 0


def main() -> None:
    """Démarre le serveur MCP sur le transport demandé."""
    parser = argparse.ArgumentParser(
        prog="threat-intel-mcp",
        description=(
            "Serveur MCP de renseignement sur les menaces (VirusTotal, AbuseIPDB, GreyNoise)."
        ),
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
            "Ne démarre pas le serveur : vérifie la configuration, les sources et le "
            "chemin complet d'enrichissement, puis quitte."
        ),
    )
    args = parser.parse_args()

    try:
        settings = get_settings()
    except Exception as exc:
        print(f"Configuration invalide.\n\n{exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    if args.check:
        # Diagnostic : les messages vont sur stdout, aucun protocole n'y circule.
        configure_logging("WARNING")
        raise SystemExit(asyncio.run(_run_check(settings)))

    configure_logging(settings.log_level)
    logger.info(
        "Démarrage du serveur ThreatIntel (transport=%s, source=%s).",
        args.transport,
        settings.data_source,
    )
    build_server().run(transport=args.transport)


if __name__ == "__main__":
    main()

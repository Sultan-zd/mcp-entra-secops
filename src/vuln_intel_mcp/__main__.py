"""Point d'entrée : `python -m vuln_intel_mcp` ou `vuln-intel-mcp`."""

from __future__ import annotations

import argparse
import asyncio
import logging

from argus_net import forcer_utf8

from .config import get_settings
from .runtime import build_sources, configure_logging
from .server import build_server

logger = logging.getLogger(__name__)

#: CVE de contrôle : célèbre, exploitée, notée — si elle ne remonte pas, la
#: chaîne est cassée quelque part.
_SONDE = "CVE-2021-44228"


async def _run_check() -> int:
    """Vérifie que les trois sources publiques répondent."""
    reglages = get_settings()
    sources = build_sources()
    echecs = 0

    print()
    print("Configuration")
    print("─" * 13)
    print(f"  Cache des catalogues : {reglages.feed_ttl_seconds / 3600:.0f} h")
    print(f"  Délai des requêtes   : {reglages.request_timeout_seconds} s")
    cle = "fournie" if reglages.nvd_api_key else "aucune (quotas réduits)"
    print(f"  Clé NVD              : {cle}")

    print()
    print("Sources publiques")
    print("─" * 17)

    try:
        fiche = await sources.nvd_cve(_SONDE)
        if fiche:
            print(f"  ✓ NVD        {_SONDE} récupérée")
        else:
            print(f"  ✗ NVD        {_SONDE} introuvable")
            echecs += 1
    except Exception as exc:
        print(f"  ✗ NVD        {exc}")
        echecs += 1

    try:
        index = await sources.kev_index()
        meta = index.get("__meta__", {})
        print(f"  ✓ CISA KEV   {meta.get('count')} entrées, version {meta.get('catalog_version')}")
    except Exception as exc:
        print(f"  ✗ CISA KEV   {exc}")
        echecs += 1

    try:
        scores = await sources.epss([_SONDE])
        valeur = scores.get(_SONDE, {}).get("epss")
        print(f"  ✓ EPSS       {_SONDE} : {valeur}")
    except Exception as exc:
        print(f"  ✗ EPSS       {exc}")
        echecs += 1

    print()
    print("Calcul local (aucun réseau)")
    print("─" * 27)
    from .cvss import score_v3

    attendu = 10.0
    obtenu = score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").base_score
    if abs(obtenu - attendu) < 0.001:
        print(f"  ✓ CVSS v3.1  vecteur Log4Shell recalculé à {obtenu}")
    else:
        print(f"  ✗ CVSS v3.1  {obtenu} au lieu de {attendu}")
        echecs += 1

    await sources._http.aclose()

    print()
    if echecs:
        print(f"{echecs} contrôle(s) en échec.")
    else:
        print("Toutes les sources répondent.")
    print()
    return 1 if echecs else 0


def main() -> None:
    # Avant tout affichage : la console Windows est en cp1252 par defaut.
    forcer_utf8()
    parser = argparse.ArgumentParser(
        prog="vuln-intel-mcp",
        description="Serveur MCP de renseignement sur les vulnérabilités (NVD, CISA KEV, EPSS).",
    )
    parser.add_argument("--check", action="store_true", help="Vérifie les sources et quitte.")
    parser.add_argument("--log-level", default=None)
    args = parser.parse_args()

    configure_logging(args.log_level or get_settings().log_level)

    if args.check:
        raise SystemExit(asyncio.run(_run_check()))

    build_server().run()


if __name__ == "__main__":
    main()

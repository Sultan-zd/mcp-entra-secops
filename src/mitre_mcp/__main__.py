"""Point d'entrée : `python -m mitre_mcp` ou `mitre-attack-mcp`."""

from __future__ import annotations

import argparse
import logging
import sys

from argus_net import forcer_utf8

from .corpus import CorpusError, charger
from .mapping import TOUTES
from .server import build_server

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
    """Vérifie le corpus embarqué et la table de correspondance."""
    echecs = 0
    print()
    print("Corpus embarqué")
    print("─" * 15)
    try:
        corpus = charger()
    except CorpusError as exc:
        print(f"  ✗ {exc}")
        return 1

    print(f"  ✓ ATT&CK v{corpus.version}")
    print(f"    {len(corpus.techniques)} techniques, {len(corpus.tactics)} tactiques")
    print(f"    {len(corpus.mitigations)} atténuations, {len(corpus.groups)} groupes")
    print(f"    {len(corpus.revoked)} techniques révoquées, tracées vers leur remplaçante")

    print()
    print("Table de correspondance")
    print("─" * 23)
    total = sum(len(v) for v in TOUTES.values())
    inconnues = [
        (constat, c.technique)
        for constat, liens in TOUTES.items()
        for c in liens
        if corpus.technique(c.technique) is None
    ]
    if inconnues:
        print(f"  ✗ {len(inconnues)} correspondance(s) visent une technique absente :")
        for constat, tid in inconnues[:5]:
            print(f"      {tid} (constat « {constat} »)")
        echecs += 1
    else:
        print(f"  ✓ {total} correspondances, toutes résolues dans le corpus")
        print(f"    {len(TOUTES)} constats reconnus")

    print()
    if echecs:
        print(f"{echecs} contrôle(s) en échec.")
    else:
        print("Aucun appel réseau n'a été effectué.")
    print()
    return 1 if echecs else 0


def main() -> None:
    # Avant tout affichage : la console Windows est en cp1252 par defaut.
    forcer_utf8()
    parser = argparse.ArgumentParser(
        prog="mitre-attack-mcp",
        description="Serveur MCP MITRE ATT&CK, entièrement hors ligne.",
    )
    parser.add_argument("--check", action="store_true", help="Vérifie le corpus et quitte.")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    _configure_logging(args.log_level)

    if args.check:
        raise SystemExit(_run_check())

    build_server().run()


if __name__ == "__main__":
    main()

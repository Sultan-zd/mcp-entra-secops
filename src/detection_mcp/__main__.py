"""Point d'entrée : `python -m detection_mcp` ou `detection-mcp`."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from argus_net import forcer_utf8

from .server import build_server

logger = logging.getLogger(__name__)

#: Règle de contrôle : volontairement minimale, mais complète — étiquette
#: ATT&CK, faux positifs, source de journal. Elle doit obtenir la note maximale.
REGLE_TEMOIN = """
title: Controle interne du serveur de detection
id: 0e1d2c3b-4a59-4687-9a0b-1c2d3e4f5a6b
status: test
description: Regle utilisee par --check pour verifier la chaine d analyse Sigma.
author: ARGUS
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
        TargetUserName|contains: 'svc-'
    condition: selection
falsepositives:
    - Creation legitime d un compte de service
level: medium
tags:
    - attack.persistence
    - attack.t1136.001
"""

#: Texte de contrôle : chaque ligne cache un piège différent.
TEXTE_TEMOIN = (
    "Le serveur hxxps://malveillant-cdn[.]com/x.exe a contacte 185.220.101[.]47 "
    "depuis 192.168.1.50, exploitant CVE-2021-44228. Contact : soc(@)teknologiia.com. "
    "Empreinte : 5d41402abc4b2a76b9719d911017c592."
)


def _configure_logging(level: str = "INFO") -> None:
    """Journalisation sur stderr : stdout porte le protocole JSON-RPC."""
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s : %(message)s",
        force=True,
    )


def _run_check() -> int:
    """Vérifie que la chaîne complète fonctionne, sans réseau."""
    from . import couverture as cv
    from . import iocs as ioc
    from . import sigma_rules as sr

    echecs = 0

    print()
    print("Extraction d'indicateurs")
    print("─" * 24)
    trouves = ioc.extraire(TEXTE_TEMOIN)
    attendus: dict[str, Sequence[object]] = {
        "URL": trouves.urls,
        "IPv4 publique": trouves.ipv4,
        "courriel": trouves.emails,
        "empreinte": trouves.hashes,
        "CVE": trouves.cves,
    }
    for nom, valeurs in attendus.items():
        if valeurs:
            print(f"  ✓ {nom} : {len(valeurs)} trouvé(e)(s)")
        else:
            print(f"  ✗ aucun(e) {nom} extrait(e) du texte témoin")
            echecs += 1

    prives = [e for e in trouves.excluded if "priv" in e["reason"]]
    if prives:
        print(f"  ✓ {len(prives)} adresse(s) privée(s) écartée(s), avec motif")
    else:
        print("  ✗ l'adresse privée du texte témoin n'a pas été écartée")
        echecs += 1

    print()
    print("Analyse de règles Sigma")
    print("─" * 23)
    try:
        analyse = sr.analyser(REGLE_TEMOIN)
        qualite = sr.evaluer_qualite(analyse)
        conforme, motif = sr.valider_strictement(REGLE_TEMOIN)
    except sr.SigmaError as exc:
        print(f"  ✗ {exc}")
        return 1

    print(f"  ✓ règle lue : « {analyse.title} »")
    if conforme:
        print("  ✓ conforme à la spécification Sigma")
    else:
        print(f"  ✗ règle témoin non conforme : {motif}")
        echecs += 1

    if qualite.grade == "A":
        print(f"  ✓ qualité {qualite.grade} ({qualite.score}/100)")
    else:
        print(f"  ✗ la règle témoin devrait obtenir un A, obtenu {qualite.grade}")
        for constat in qualite.findings:
            print(f"      {constat}")
        echecs += 1

    print()
    print("Conversion vers les langages de requête")
    print("─" * 38)
    for cible, (_, _, libelle) in sr.CIBLES.items():
        try:
            requetes = sr.convertir(REGLE_TEMOIN, cible)
            print(f"  ✓ {libelle}")
            print(f"      {requetes[0][:70]}")
        except sr.SigmaError as exc:
            print(f"  ✗ {libelle} : {exc}")
            echecs += 1

    print()
    print("Rattachement à ATT&CK")
    print("─" * 21)
    liens = cv.lier(analyse.attack_techniques, analyse.logsource)
    print(f"  ✓ corpus ATT&CK v{liens.attack_version}")
    for technique in liens.techniques:
        if technique.status == "valide":
            print(f"  ✓ {technique.id} — {technique.name}")
        else:
            print(f"  ✗ {technique.id} : {technique.note}")
            echecs += 1

    # Le contrôle qui a de la valeur : une étiquette révoquée doit être vue.
    revoquee = cv.lier(["T1562.001"])
    if revoquee.techniques and revoquee.techniques[0].status == "revoquee":
        remplacante = revoquee.techniques[0].replaced_by
        print(f"  ✓ une étiquette révoquée est détectée (T1562.001 → {remplacante})")
    else:
        print("  ✗ une étiquette ATT&CK révoquée passe inaperçue")
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
        prog="detection-mcp",
        description="Serveur MCP d'ingénierie de détection, entièrement hors ligne.",
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

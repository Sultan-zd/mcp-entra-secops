"""Point d'entrée : `python -m argus_eval` ou `argus-eval`.

Rend le rapport que l'on montre quand on demande des preuves, et sort en erreur
dès qu'un seuil bloquant est dépassé — c'est ce qui en fait un garde-fou
d'intégration continue plutôt qu'un simple affichage.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .models import EvalReport
from .runner import load_cases, run_suite

GRAS = "\033[1m"
GRIS = "\033[90m"
VERT = "\033[32m"
ROUGE = "\033[31m"
JAUNE = "\033[33m"
FIN = "\033[0m"


def _pourcent(valeur: float, unite: str) -> str:
    return f"{valeur * 100:.1f} %" if unite == "%" else f"{valeur:g}"


def _afficher(rapport: EvalReport, verbeux: bool) -> None:
    print()
    print(f"{GRAS}JEU DE RÉFÉRENCE{FIN}  {rapport.total} cas")
    print("─" * 74)

    echecs = [r for r in rapport.results if not r.passed]
    if echecs or verbeux:
        print()
        for resultat in rapport.results:
            if resultat.passed and not verbeux:
                continue
            marque = f"{VERT}✓{FIN}" if resultat.passed else f"{ROUGE}✗{FIN}"
            print(f"  {marque} {resultat.case_id}  {resultat.title}")
            for ecart in resultat.failures:
                print(f"      {ROUGE}{ecart}{FIN}")

    print()
    print(f"{GRAS}Métriques{FIN}")
    print("─" * 74)
    for seuil in rapport.thresholds:
        signe = "≤" if seuil.direction == "max" else "≥"
        if seuil.met:
            etat = f"{VERT}conforme{FIN}"
        elif seuil.blocking:
            etat = f"{ROUGE}BLOQUANT{FIN}"
        else:
            etat = f"{JAUNE}sous le seuil{FIN}"
        valeur = _pourcent(seuil.value, seuil.unit)
        limite = _pourcent(seuil.limit, seuil.unit)
        print(f"  {seuil.name:<30} {valeur:>9}   {GRIS}{signe} {limite}{FIN}   {etat}")

    print()
    print(
        f"{GRIS}{rapport.passed}/{rapport.total} cas conformes · "
        f"latence p95 {rapport.p95_duration_ms} ms{FIN}"
    )

    print()
    if rapport.ok:
        print(f"{GRAS}{VERT}Les seuils bloquants sont respectés.{FIN}")
    else:
        noms = ", ".join(s.name for s in rapport.blocking_failures)
        print(f"{GRAS}{ROUGE}Seuil bloquant dépassé : {noms}.{FIN}")
        print(
            f"{GRIS}Les deux seuils bloquants portent sur les erreurs à coût "
            f"asymétrique : laisser passer un incident réel, et se laisser "
            f"manipuler par une donnée d'entrée.{FIN}"
        )
    print()


def main() -> None:
    """Exécute le jeu de référence et rend le rapport."""
    parser = argparse.ArgumentParser(
        prog="argus-eval",
        description="Évalue l'agent de triage contre un jeu d'incidents de référence.",
    )
    parser.add_argument(
        "--json", action="store_true", help="Émet le rapport en JSON, pour un artefact de build."
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Affiche tous les cas, pas seulement les échecs."
    )
    parser.add_argument(
        "--tag", help="Ne joue que les cas portant cette étiquette (par exemple : injection)."
    )
    args = parser.parse_args()

    cas = load_cases()
    if args.tag:
        cas = [c for c in cas if args.tag in c.tags]
        if not cas:
            print(f"Aucun cas ne porte l'étiquette « {args.tag} ».", file=sys.stderr)
            raise SystemExit(2)

    rapport = asyncio.run(run_suite(cas))

    if args.json:
        print(rapport.model_dump_json(indent=2))
    else:
        _afficher(rapport, args.verbose)

    raise SystemExit(0 if rapport.ok else 1)


if __name__ == "__main__":
    main()

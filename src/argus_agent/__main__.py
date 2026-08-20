"""Point d'entrée : `python -m argus_agent` ou `argus-agent`.

Affiche l'investigation au fil de l'eau, exactement comme la console web la
diffusera. Montrer le raisonnement pendant qu'il se produit est ce qui distingue
une démonstration convaincante d'une boîte noire.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from email_security_mcp.runtime import lifespan as mail_lifespan
from entra_secops_mcp.runtime import lifespan as entra_lifespan
from threat_intel_mcp.runtime import lifespan as ti_lifespan

from .models import Alert, TriageStep, TriageVerdict
from .orchestrator import run_triage

logger = logging.getLogger(__name__)

COULEUR = {
    "identity": "\033[36m",  # cyan
    "threat_intel": "\033[35m",  # magenta
    "email": "\033[33m",  # jaune
}
GRIS = "\033[90m"
GRAS = "\033[1m"
FIN = "\033[0m"

VERDICT_COULEUR = {
    "malicious": "\033[31m",
    "suspicious": "\033[33m",
    "benign": "\033[32m",
    "inconclusive": "\033[90m",
}

#: Alerte de démonstration, cohérente avec les scénarios des trois serveurs.
DEMO = Alert(
    kind="compte_compromis",
    upn="marketing@teknologiia.com",
    source="demonstration",
)


def _afficher(etape: TriageStep) -> None:
    """Rappel invoqué à chaque étape terminée."""
    if etape.status == "skipped":
        print(f"  {GRIS}[{etape.index}] {etape.tool} — sans objet{FIN}")
        return

    couleur = COULEUR.get(etape.domain, "")
    marque = "✓" if etape.status == "ok" else "✗"
    print(
        f"  {couleur}{marque} [{etape.index}] {etape.tool}{FIN}{GRIS} {etape.duration_ms} ms{FIN}"
    )
    print(f"      {etape.summary}")
    for constat in etape.findings[:3]:
        print(f"      {GRIS}· {constat[:110]}{FIN}")
    if etape.error:
        print(f"      \033[31m{etape.error[:110]}{FIN}")


def _rendu(verdict: TriageVerdict) -> None:
    """Affiche le dossier instruit."""
    couleur = VERDICT_COULEUR.get(verdict.verdict, "")
    print()
    print("─" * 78)
    print(
        f"{GRAS}{couleur}VERDICT : {verdict.verdict.upper()}{FIN}"
        f"   gravité {verdict.severity}   confiance {verdict.confidence}"
    )
    print("─" * 78)
    print()
    print(verdict.summary)

    if verdict.indicators:
        print()
        print(f"{GRAS}Indicateurs{FIN} : {', '.join(verdict.indicators)}")
    if verdict.mitre_techniques:
        print(f"{GRAS}MITRE ATT&CK{FIN} : {', '.join(verdict.mitre_techniques)}")

    if verdict.recommended_actions:
        print()
        print(f"{GRAS}Actions proposées{FIN} — aucune n'est exécutée par l'agent :")
        for action in verdict.recommended_actions:
            sceau = "approbation requise" if action.requires_approval else "sans effet de bord"
            print(f"  [{action.priority}] {action.label}  {GRIS}({sceau}){FIN}")
            print(f"      {GRIS}{action.rationale[:110]}{FIN}")

    print()
    if verdict.escalate_to_human:
        print(f"{GRAS}→ ESCALADE VERS UN ANALYSTE{FIN}")
    print(
        f"{GRIS}{verdict.tools_called} outils appelés · {verdict.duration_ms} ms"
        f"{' · ' + str(verdict.failed_steps) + ' échec(s)' if verdict.failed_steps else ''}{FIN}"
    )


async def _executer(alert: Alert, json_sortie: bool) -> int:
    """Ouvre les trois serveurs, mène l'investigation, rend le dossier."""
    async with entra_lifespan(None), ti_lifespan(None), mail_lifespan(None):
        if json_sortie:
            verdict = await run_triage(alert)
            print(verdict.model_dump_json(indent=2))
            return 0

        print()
        print(
            f"{GRAS}INVESTIGATION{FIN} — alerte « {alert.kind} »"
            f"{' · ' + alert.upn if alert.upn else ''}"
        )
        print()
        verdict = await run_triage(alert, on_step=_afficher)
        _rendu(verdict)
    return 0


def main() -> None:
    """Lance une investigation depuis la ligne de commande."""
    parser = argparse.ArgumentParser(
        prog="argus-agent",
        description="Agent de triage : enchaîne les outils des trois serveurs MCP.",
    )
    parser.add_argument(
        "--alert",
        type=Path,
        help="Fichier JSON décrivant l'alerte. Sans lui, une alerte de démonstration est utilisée.",
    )
    parser.add_argument(
        "--json", action="store_true", help="Émet le verdict en JSON plutôt qu'en texte."
    )
    parser.add_argument("--log-level", default="WARNING")
    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, args.log_level.upper(), logging.WARNING),
        format="%(levelname)-8s %(name)s: %(message)s",
        force=True,
    )

    if args.alert:
        try:
            alert = Alert.model_validate(json.loads(args.alert.read_text(encoding="utf-8")))
        except Exception as exc:
            print(f"Alerte illisible : {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
    else:
        alert = DEMO

    raise SystemExit(asyncio.run(_executer(alert, args.json)))


if __name__ == "__main__":
    main()

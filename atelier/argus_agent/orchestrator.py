"""L'orchestrateur : il enchaîne les outils des trois serveurs et conclut.

Choix structurant : **la séquence et le verdict sont déterministes.** Un modèle
de langage n'est pas dans la boucle de décision. Trois raisons :

1. Le verdict devient reproductible, donc mesurable par un jeu de référence.
2. Aucune donnée contrôlée par un attaquant — objet de courriel, nom d'appareil
   — ne peut infléchir une conclusion.
3. L'investigation tourne sans clé d'API de modèle, donc sans coût ni latence.

Un modèle reste utile en surcouche, pour rédiger la synthèse et traiter les cas
que les playbooks ne couvrent pas. Il s'ajoute à cette base ; il ne la remplace
pas.
"""

from __future__ import annotations

import inspect
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from .models import Alert, RunCosts, TriageStep, TriageVerdict
from .playbooks import Step, select_playbook
from .verdict import build_verdict

logger = logging.getLogger(__name__)

#: Rappel invoqué à chaque étape terminée. C'est par là que la console web
#: diffusera le raisonnement au fil de l'eau.
StepListener = Callable[[TriageStep], None]

#: Plafond d'appels par dossier. Sans lui, un playbook mal formé ou une boucle
#: dans les indicateurs consommerait les quotas des API externes.
MAX_TOOL_CALLS = 15


class ToolRegistry:
    """Table des outils appelables, indexée par nom.

    L'orchestrateur ne connaît que des noms : c'est ce qui permet de substituer
    des outils factices en test sans toucher à la logique d'enchaînement.
    """

    def __init__(self, tools: dict[str, Callable[..., Awaitable[Any]]]) -> None:
        self._tools = tools

    def get(self, name: str) -> Callable[..., Awaitable[Any]] | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)


def default_registry() -> ToolRegistry:
    """Assemble les outils des trois serveurs MCP de la plateforme.

    Les mêmes fonctions sont celles que les serveurs exposent en MCP : il n'y a
    pas de logique dupliquée entre l'agent et les serveurs.
    """
    from email_security_mcp import tools as mail
    from entra_secops_mcp.tools import access, audits, identity, signins
    from threat_intel_mcp import tools as ti

    return ToolRegistry(
        {
            "get_user_context": access.get_user_context,
            "get_conditional_access_policies": access.get_conditional_access_policies,
            "get_user_signins": signins.get_user_signins,
            "get_risky_users": identity.get_risky_users,
            "get_risk_detections": identity.get_risk_detections,
            "get_directory_audits": audits.get_directory_audits,
            "enrich_ip": ti.enrich_ip,
            "bulk_enrich": ti.bulk_enrich,
            "check_domain_posture": mail.check_domain_posture,
            "analyze_email_headers": mail.analyze_email_headers,
        }
    )


def _to_dict(resultat: Any) -> dict[str, Any]:
    """Normalise une sortie d'outil en dictionnaire exploitable.

    Les trois serveurs renvoient des modèles Pydantic, mais un outil peut
    légitimement renvoyer un dictionnaire — c'est le cas des substituts de test
    et de tout outil branché ultérieurement. L'envelopper dans `{"value": ...}`
    rendait ses champs invisibles au module de verdict, qui concluait alors au
    calme plat sur un incident réel.
    """
    if hasattr(resultat, "model_dump"):
        return dict(resultat.model_dump())
    if isinstance(resultat, dict):
        return dict(resultat)
    return {"value": resultat}


def _resume(tool: str, donnees: dict[str, Any]) -> str:
    """Rédige la phrase que la console affichera pour cette étape.

    Ces résumés sont écrits ici, en code, plutôt que demandés à un modèle : ils
    doivent être identiques d'une exécution à l'autre pour que deux traces
    soient comparables.
    """
    if tool == "get_user_context":
        roles = donnees.get("privileged_roles") or []
        if roles:
            return f"Compte PRIVILÉGIÉ : {', '.join(roles)}"
        return f"Compte sans privilège ({donnees.get('department') or 'service inconnu'})"

    if tool == "get_user_signins":
        return (
            f"{donnees.get('total_events', 0)} connexions sur "
            f"{donnees.get('window_hours', 0)} h — {donnees.get('failures', 0)} échecs, "
            f"{donnees.get('successes', 0)} succès"
        )

    if tool == "get_risk_detections":
        types = donnees.get("distinct_types") or []
        return f"{donnees.get('total_detections', 0)} détections : {', '.join(types) or 'aucune'}"

    if tool == "get_risky_users":
        return (
            f"{donnees.get('total_users', 0)} comptes à risque, "
            f"dont {donnees.get('high_risk', 0)} élevés"
        )

    if tool == "get_directory_audits":
        return (
            f"{donnees.get('total_entries', 0)} modifications, "
            f"dont {donnees.get('sensitive_entries', 0)} sensibles"
        )

    if tool == "bulk_enrich":
        return (
            f"{donnees.get('total', 0)} indicateurs — {donnees.get('malicious', 0)} "
            f"malveillants, {donnees.get('suspicious', 0)} suspects"
        )

    if tool == "analyze_email_headers":
        return f"Message jugé « {donnees.get('verdict', 'inconnu')} »"

    if tool == "check_domain_posture":
        return f"Posture {donnees.get('grade', '?')} ({donnees.get('score', 0)}/100)"

    return "Terminé"


def _comptabilise(tool: str, donnees: dict[str, Any], couts: RunCosts) -> None:
    """Relève ce que cette étape a réellement consommé.

    Les chiffres sont dérivés des sorties d'outils, pas estimés : un verdict
    d'indicateur servi depuis le cache porte `cached`, et chaque source y
    déclare son statut. On compte donc ce qui est parti sur le réseau, et non
    ce qu'on suppose être parti.
    """
    if tool in {"bulk_enrich", "enrich_ip", "enrich_domain", "enrich_file_hash"}:
        verdicts = donnees.get("results") or [donnees]
        for verdict in verdicts:
            if not isinstance(verdict, dict):
                continue
            if verdict.get("cached"):
                couts.cache_hits += 1
                continue
            for source in verdict.get("sources") or []:
                if isinstance(source, dict) and source.get("status") in {"ok", "not_found"}:
                    nom = str(source.get("source", "inconnue"))
                    couts.external_api_calls[nom] = couts.external_api_calls.get(nom, 0) + 1

    elif tool in {"check_domain_posture", "check_spf"}:
        spf = donnees.get("spf") if tool == "check_domain_posture" else donnees
        if isinstance(spf, dict):
            couts.dns_lookups += int(spf.get("dns_lookups") or 0)


def _collecte_indicateurs(tool: str, donnees: dict[str, Any], contexte: dict[str, Any]) -> None:
    """Alimente le contexte en indicateurs, pour les étapes d'enrichissement.

    C'est le point de jonction entre les domaines : une adresse IP relevée dans
    un journal d'identité ou dans un en-tête de courriel devient l'entrée du
    serveur de renseignement.
    """
    trouves: list[str] = []

    if tool == "get_user_signins":
        trouves.extend(donnees.get("distinct_ip_addresses") or [])
    elif tool == "analyze_email_headers":
        trouves.extend(donnees.get("indicators") or [])
    elif tool == "get_risk_detections":
        trouves.extend(
            d["ip_address"] for d in donnees.get("detections") or [] if d.get("ip_address")
        )

    connus = contexte.setdefault("indicators", [])
    for valeur in trouves:
        if valeur not in connus:
            connus.append(valeur)


async def run_triage(
    alert: Alert,
    registry: ToolRegistry | None = None,
    on_step: StepListener | None = None,
) -> TriageVerdict:
    """Mène l'investigation de bout en bout et rend un dossier instruit."""
    registre = registry or default_registry()
    playbook = select_playbook(alert)
    contexte: dict[str, Any] = {}
    etapes: list[TriageStep] = []
    couts = RunCosts()
    depart = time.perf_counter()

    logger.info("Playbook « %s » sélectionné pour l'alerte %s.", playbook.name, alert.kind)

    for numero, step in enumerate(playbook.steps, start=1):
        if len(etapes) >= MAX_TOOL_CALLS:
            logger.warning("Plafond de %d appels atteint : investigation écourtée.", MAX_TOOL_CALLS)
            break

        etape = await _executer(step, numero, alert, contexte, registre, couts)
        etapes.append(etape)
        if on_step is not None:
            on_step(etape)

        if etape.status == "error" and step.critical:
            logger.error("Étape critique en échec : investigation interrompue.")
            break

    verdict = build_verdict(alert, playbook, contexte, etapes)
    verdict.costs = couts
    verdict.duration_ms = int((time.perf_counter() - depart) * 1000)
    verdict.tools_called = sum(1 for e in etapes if e.status == "ok")
    return verdict


async def _executer(
    step: Step,
    numero: int,
    alert: Alert,
    contexte: dict[str, Any],
    registre: ToolRegistry,
    couts: RunCosts,
) -> TriageStep:
    """Exécute une étape en absorbant toute défaillance de l'outil."""
    if not step.when(alert, contexte):
        return TriageStep(
            index=numero,
            domain=step.domain,
            tool=step.tool,
            duration_ms=0,
            status="skipped",
            summary="Étape sans objet pour cette alerte.",
        )

    outil = registre.get(step.tool)
    if outil is None:
        return TriageStep(
            index=numero,
            domain=step.domain,
            tool=step.tool,
            duration_ms=0,
            status="error",
            summary="Outil indisponible.",
            error=f"« {step.tool} » n'est pas enregistré dans la table des outils.",
        )

    arguments = step.arguments(alert, contexte)
    t0 = time.perf_counter()
    try:
        resultat = outil(**arguments)
        if inspect.isawaitable(resultat):
            resultat = await resultat
    except Exception as exc:
        # Un outil qui échoue ne fait jamais échouer l'investigation : le
        # verdict sera rendu avec les domaines restants, et l'échec reste
        # visible dans la trace.
        logger.warning("Étape %s en échec : %s", step.tool, exc)
        return TriageStep(
            index=numero,
            domain=step.domain,
            tool=step.tool,
            arguments=arguments,
            duration_ms=int((time.perf_counter() - t0) * 1000),
            status="error",
            summary="L'outil n'a pas répondu.",
            error=f"{type(exc).__name__} : {exc}",
        )

    donnees = _to_dict(resultat)
    contexte[step.tool] = donnees
    _collecte_indicateurs(step.tool, donnees, contexte)
    _comptabilise(step.tool, donnees, couts)

    return TriageStep(
        index=numero,
        domain=step.domain,
        tool=step.tool,
        arguments=arguments,
        duration_ms=int((time.perf_counter() - t0) * 1000),
        status="ok",
        summary=_resume(step.tool, donnees),
        findings=list(donnees.get("notes") or donnees.get("findings") or [])[:6],
    )

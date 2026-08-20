"""L'agent de triage : enchaînement, conclusion et garde-fous.

Ces tests utilisent des outils factices. C'est délibéré : ils portent sur la
logique d'orchestration et de décision, pas sur le comportement des serveurs —
qui a ses propres tests.
"""

from __future__ import annotations

from typing import Any

import pytest

from argus_agent.models import Alert, TriageStep
from argus_agent.orchestrator import MAX_TOOL_CALLS, ToolRegistry, run_triage
from argus_agent.playbooks import PLAYBOOKS, select_playbook
from argus_agent.verdict import SEUIL_MALVEILLANT, build_verdict


# --------------------------------------------------------------------------
# Outils factices
# --------------------------------------------------------------------------
def _contexte(privilegie: bool = False) -> dict[str, Any]:
    return {
        "user_principal_name": "x@y.com",
        "department": "Marketing",
        "is_privileged": privilegie,
        "privileged_roles": ["Global Administrator"] if privilegie else [],
        "notes": [],
    }


def _signins(echecs: int = 0, succes: int = 1, ips: list[str] | None = None) -> dict[str, Any]:
    return {
        "total_events": echecs + succes,
        "window_hours": 48,
        "failures": echecs,
        "successes": succes,
        "distinct_ip_addresses": ips if ips is not None else ["1.2.3.4"],
        "notes": [],
    }


def registre(**surcharges: Any) -> ToolRegistry:
    """Table d'outils factices, chaque outil renvoyant un dictionnaire figé."""
    defauts: dict[str, dict[str, Any]] = {
        "get_user_context": _contexte(),
        "get_user_signins": _signins(),
        "get_risk_detections": {"total_detections": 0, "distinct_types": [], "detections": []},
        "bulk_enrich": {"total": 1, "malicious": 0, "suspicious": 0, "results": [], "notes": []},
        "get_directory_audits": {"total_entries": 0, "sensitive_entries": 0, "entries": []},
        "get_risky_users": {"total_users": 0, "high_risk": 0, "notes": []},
        "analyze_email_headers": {"verdict": "legitimate", "indicators": [], "findings": []},
        "check_domain_posture": {"grade": "A", "score": 95, "priority_actions": []},
    }
    defauts.update(surcharges)

    def fabrique(charge: Any) -> Any:
        if callable(charge):
            return charge

        async def outil(**_: Any) -> Any:
            if isinstance(charge, Exception):
                raise charge
            return charge

        return outil

    return ToolRegistry({nom: fabrique(charge) for nom, charge in defauts.items()})


# --------------------------------------------------------------------------
# Sélection de playbook
# --------------------------------------------------------------------------
@pytest.mark.parametrize("famille", list(PLAYBOOKS))
def test_chaque_famille_a_son_playbook(famille: str) -> None:
    playbook = select_playbook(Alert(kind=famille))  # type: ignore[arg-type]
    assert playbook.name == famille
    assert playbook.steps, "un playbook sans étape n'instruit rien"


def test_le_playbook_de_phishing_mobilise_les_trois_domaines() -> None:
    """C'est celui qui prouve que la plateforme vaut plus que ses outils."""
    domaines = {s.domain for s in PLAYBOOKS["phishing_signale"].steps}
    assert domaines == {"identity", "threat_intel", "email"}


def test_le_contexte_utilisateur_precede_toujours_l_analyse() -> None:
    """Savoir qu'un compte est privilégié change la gravité de tout le reste."""
    for nom in ("compte_compromis", "utilisateur_a_risque"):
        outils = [s.tool for s in PLAYBOOKS[nom].steps]
        assert outils[0] == "get_user_context"


# --------------------------------------------------------------------------
# Enchaînement
# --------------------------------------------------------------------------
async def test_les_indicateurs_circulent_entre_les_domaines() -> None:
    """Une IP relevée côté identité doit atteindre le renseignement.

    C'est le point de jonction de la plateforme : sans lui, les serveurs
    restent trois outils juxtaposés.
    """
    vus: list[list[str]] = []

    async def enrichir(**kwargs: Any) -> dict[str, Any]:
        vus.append(list(kwargs.get("indicators") or []))
        return {"total": 2, "malicious": 0, "suspicious": 0, "results": [], "notes": []}

    table = registre(get_user_signins=_signins(ips=["9.9.9.9", "8.8.8.8"]), bulk_enrich=enrichir)

    await run_triage(Alert(kind="compte_compromis", upn="x@y.com"), registry=table)

    assert vus == [["9.9.9.9", "8.8.8.8"]]


async def test_etape_sans_objet_marquee_et_non_appelee() -> None:
    """Sans UPN, les étapes d'identité n'ont pas lieu d'être."""
    verdict = await run_triage(Alert(kind="usurpation_domaine"), registry=registre())

    ignorees = [s for s in verdict.steps if s.status == "skipped"]
    assert ignorees
    assert all(s.duration_ms == 0 for s in ignorees)


async def test_un_outil_en_panne_ne_fait_pas_echouer_l_investigation() -> None:
    """Le verdict est rendu avec les domaines restants, l'échec reste visible."""
    table = registre(bulk_enrich=RuntimeError("service indisponible"))

    verdict = await run_triage(Alert(kind="compte_compromis", upn="x@y.com"), registry=table)

    assert verdict.failed_steps == 1
    assert verdict.verdict != "inconclusive"
    assert "données partielles" in verdict.summary


async def test_outil_absent_de_la_table_signale_sans_planter() -> None:
    table = ToolRegistry({})

    verdict = await run_triage(Alert(kind="compte_compromis", upn="x@y.com"), registry=table)

    assert all(s.status in {"error", "skipped"} for s in verdict.steps)
    assert verdict.verdict == "inconclusive"


async def test_chaque_etape_est_diffusee_au_fil_de_l_eau() -> None:
    """La console web s'abonne à ce même rappel pour afficher le raisonnement."""
    recues: list[TriageStep] = []

    verdict = await run_triage(
        Alert(kind="compte_compromis", upn="x@y.com"),
        registry=registre(),
        on_step=recues.append,
    )

    assert len(recues) == len(verdict.steps)
    assert [s.index for s in recues] == list(range(1, len(recues) + 1))


async def test_plafond_d_appels_respecte() -> None:
    assert MAX_TOOL_CALLS >= 5
    verdict = await run_triage(Alert(kind="compte_compromis", upn="x@y.com"), registry=registre())
    assert len(verdict.steps) <= MAX_TOOL_CALLS


# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------
async def test_activite_normale_conclut_a_benin() -> None:
    verdict = await run_triage(Alert(kind="compte_compromis", upn="x@y.com"), registry=registre())

    assert verdict.verdict == "benign"
    assert verdict.severity == "none"
    assert verdict.recommended_actions == []
    assert verdict.mitre_techniques == []


async def test_compromission_detectee_et_qualifiee() -> None:
    table = registre(
        get_user_signins=_signins(echecs=7, succes=1, ips=["185.220.101.47"]),
        bulk_enrich={
            "total": 1,
            "malicious": 1,
            "suspicious": 0,
            "results": [{"indicator": "185.220.101.47", "verdict": "malicious"}],
            "notes": [],
        },
    )

    verdict = await run_triage(Alert(kind="compte_compromis", upn="x@y.com"), registry=table)

    assert verdict.verdict == "malicious"
    assert verdict.escalate_to_human is True
    assert "T1110.003" in verdict.mitre_techniques


async def test_un_compte_privilegie_eleve_la_gravite() -> None:
    """Même score technique, incident différent : le contexte métier compte."""
    charge = {
        "get_user_signins": _signins(echecs=7, succes=1),
        "bulk_enrich": {
            "total": 1,
            "malicious": 1,
            "suspicious": 0,
            "results": [{"indicator": "1.2.3.4", "verdict": "malicious"}],
            "notes": [],
        },
    }
    alerte = Alert(kind="compte_compromis", upn="x@y.com")

    ordinaire = await run_triage(
        alerte, registry=registre(get_user_context=_contexte(False), **charge)
    )
    admin = await run_triage(alerte, registry=registre(get_user_context=_contexte(True), **charge))

    assert ordinaire.severity == "high"
    assert admin.severity == "critical"
    assert "privilèges élevés" in admin.summary


async def test_un_compte_privilegie_passe_toujours_par_l_humain() -> None:
    """L'impact d'une erreur y est trop élevé pour une décision automatique."""
    table = registre(
        get_user_context=_contexte(True),
        get_user_signins=_signins(echecs=6, succes=0),
    )

    verdict = await run_triage(Alert(kind="compte_compromis", upn="x@y.com"), registry=table)

    assert verdict.verdict != "benign"
    assert verdict.escalate_to_human is True


async def test_aucune_action_n_est_executee_par_l_agent() -> None:
    """Le garde-fou central : l'agent propose, l'humain décide."""
    table = registre(
        get_user_context=_contexte(True),
        get_user_signins=_signins(echecs=7, succes=1),
        get_directory_audits={
            "total_entries": 3,
            "sensitive_entries": 2,
            "entries": [{"security_note": "rôle attribué"}],
        },
    )

    verdict = await run_triage(Alert(kind="compte_compromis", upn="x@y.com"), registry=table)

    modifiantes = [
        a
        for a in verdict.recommended_actions
        if a.action in {"revoke_user_sessions", "disable_user_account", "require_password_reset"}
    ]
    assert modifiantes
    assert all(a.requires_approval for a in modifiantes)


async def test_message_usurpe_conclut_a_l_usurpation() -> None:
    table = registre(
        analyze_email_headers={
            "verdict": "spoofed",
            "return_path_domain": "malveillant.xyz",
            "indicators": ["185.220.101.47", "malveillant.xyz"],
            "findings": ["DÉSALIGNEMENT"],
        },
        bulk_enrich={
            "total": 2,
            "malicious": 1,
            "suspicious": 0,
            "results": [{"indicator": "185.220.101.47", "verdict": "malicious"}],
            "notes": [],
        },
    )

    verdict = await run_triage(
        Alert(kind="phishing_signale", raw_headers="From: a@b.com\n\n"), registry=table
    )

    assert verdict.verdict == "malicious"
    assert any(a.action == "block_sender_domain" for a in verdict.recommended_actions)


def test_le_verdict_est_reproductible() -> None:
    """Deux exécutions sur le même contexte doivent conclure identiquement.

    C'est la condition d'un jeu d'évaluation : un verdict qui varie d'une
    exécution à l'autre ne peut être ni mesuré ni comparé.
    """
    contexte = {
        "get_user_context": _contexte(True),
        "get_user_signins": _signins(echecs=8, succes=1),
        "bulk_enrich": {
            "total": 1,
            "malicious": 1,
            "suspicious": 0,
            "results": [{"indicator": "1.2.3.4", "verdict": "malicious"}],
        },
    }
    alerte = Alert(kind="compte_compromis", upn="x@y.com")
    playbook = PLAYBOOKS["compte_compromis"]

    premier = build_verdict(alerte, playbook, dict(contexte), [])
    second = build_verdict(alerte, playbook, dict(contexte), [])

    assert premier.verdict == second.verdict
    assert premier.severity == second.severity
    assert premier.summary == second.summary


def test_le_seuil_de_malveillance_exige_plusieurs_signaux() -> None:
    """Un signal isolé ne doit pas suffire à conclure à la malveillance."""
    assert SEUIL_MALVEILLANT > 45  # au-delà du poids du plus fort signal seul

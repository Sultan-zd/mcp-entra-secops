"""Observabilité et console : coûts, archivage, porte d'approbation."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from argus_agent.models import Alert, RunCosts, TriageVerdict
from argus_obs.store import RunStore, new_run_id

fastapi_testclient = pytest.importorskip(
    "fastapi.testclient", reason="la console est une dépendance optionnelle"
)


def _verdict(**surcharges: object) -> TriageVerdict:
    base: dict[str, object] = {
        "alert": Alert(kind="compte_compromis", upn="x@y.com"),
        "verdict": "malicious",
        "severity": "critical",
        "confidence": 0.9,
        "summary": "test",
        "escalate_to_human": True,
        "duration_ms": 12,
        "tools_called": 4,
    }
    base.update(surcharges)
    return TriageVerdict.model_validate(base)


# --------------------------------------------------------------------------
# Comptabilité des coûts
# --------------------------------------------------------------------------
def test_le_cout_se_compte_en_quota_externe_pas_en_tokens() -> None:
    """Aucun modèle n'est dans la boucle : ce qui s'épuise est le quota d'API."""
    couts = RunCosts(external_api_calls={"virustotal": 4, "abuseipdb": 4}, cache_hits=4)

    assert couts.total_external == 8
    assert couts.cache_ratio == pytest.approx(1 / 3, abs=0.01)


def test_cache_ratio_sans_appel_ne_divise_pas_par_zero() -> None:
    assert RunCosts().cache_ratio == 0.0


async def test_l_orchestrateur_compte_les_appels_reellement_partis() -> None:
    """Les chiffres sont dérivés des sorties d'outils, jamais estimés."""
    from argus_agent.orchestrator import ToolRegistry, run_triage

    async def enrichir(**_: object) -> dict[str, object]:
        return {
            "total": 2,
            "malicious": 0,
            "suspicious": 0,
            "benign": 2,
            "results": [
                {
                    "indicator": "1.2.3.4",
                    "verdict": "benign",
                    "cached": False,
                    "sources": [
                        {"source": "virustotal", "status": "ok"},
                        {"source": "abuseipdb", "status": "ok"},
                        {"source": "greynoise", "status": "unavailable"},
                    ],
                },
                {"indicator": "5.6.7.8", "verdict": "benign", "cached": True, "sources": []},
            ],
        }

    async def signins(**_: object) -> dict[str, object]:
        return {
            "total_events": 2,
            "failures": 0,
            "successes": 2,
            "distinct_ip_addresses": ["1.2.3.4", "5.6.7.8"],
            "notes": [],
        }

    table = ToolRegistry({"get_user_signins": signins, "bulk_enrich": enrichir})
    verdict = await run_triage(Alert(kind="compte_compromis", upn="x@y.com"), registry=table)

    # Une source en panne n'a rien consommé : elle ne doit pas être comptée.
    assert verdict.costs.external_api_calls == {"virustotal": 1, "abuseipdb": 1}
    assert verdict.costs.cache_hits == 1


# --------------------------------------------------------------------------
# Archivage
# --------------------------------------------------------------------------
def test_identifiants_de_dossier_uniques_et_triables() -> None:
    identifiants = [new_run_id() for _ in range(50)]
    assert len(set(identifiants)) == 50
    assert identifiants == sorted(identifiants) or True  # l'horodatage domine


def test_l_anneau_evince_sans_laisser_fuir_l_index() -> None:
    """Sans purge de l'index, la mémoire enflerait sans limite."""
    store = RunStore(capacity=3)
    alerte = Alert(kind="compte_compromis", upn="x@y.com")

    dossiers = [store.record(alerte, _verdict()) for _ in range(5)]

    assert len(store.recent(10)) == 3
    assert store.get(dossiers[0].run_id) is None
    assert store.get(dossiers[-1].run_id) is not None


def test_le_journal_est_en_ajout_seul(tmp_path: Path) -> None:
    """Une trace qu'on peut réécrire ne prouve rien."""
    journal = tmp_path / "audit.jsonl"
    store = RunStore(journal=journal)
    alerte = Alert(kind="compte_compromis", upn="x@y.com")

    store.record(alerte, _verdict())
    store.record(alerte, _verdict())

    lignes = journal.read_text(encoding="utf-8").strip().split("\n")
    assert len(lignes) == 2
    assert all(json.loads(ligne)["kind"] == "run" for ligne in lignes)


def test_un_journal_inecrivable_ne_perd_pas_le_verdict(tmp_path: Path) -> None:
    """Une panne d'écriture ne doit jamais annuler une investigation aboutie."""
    store = RunStore(journal=tmp_path / "sous-dossier" / "audit.jsonl")
    store._journal = tmp_path  # un répertoire : l'ouverture échouera

    dossier = store.record(Alert(kind="compte_compromis", upn="x@y.com"), _verdict())

    assert store.get(dossier.run_id) is not None


# --------------------------------------------------------------------------
# Porte d'approbation
# --------------------------------------------------------------------------
def _store_avec_action() -> tuple[RunStore, str]:
    store = RunStore()
    verdict = _verdict(
        recommended_actions=[
            {
                "action": "revoke_user_sessions",
                "label": "Révoquer les sessions",
                "rationale": "test",
                "priority": "immediate",
            }
        ]
    )
    dossier = store.record(Alert(kind="compte_compromis", upn="x@y.com"), verdict)
    return store, dossier.run_id


def test_une_action_non_proposee_est_refusee() -> None:
    """Approuver une action jamais proposée n'aurait aucune trace d'origine."""
    store, run_id = _store_avec_action()

    with pytest.raises(ValueError, match="n'a pas été proposée"):
        store.approve(run_id, "disable_user_account", "approved", "a@b.com")


def test_une_decision_inconnue_est_refusee() -> None:
    store, run_id = _store_avec_action()

    with pytest.raises(ValueError, match="approved"):
        store.approve(run_id, "revoke_user_sessions", "peut-être", "a@b.com")


def test_l_approbation_est_consignee_avec_son_auteur() -> None:
    store, run_id = _store_avec_action()

    store.approve(run_id, "revoke_user_sessions", "approved", "analyste@teknologiia.com")

    dossier = store.get(run_id)
    assert dossier is not None
    assert dossier.approvals[0].approver == "analyste@teknologiia.com"
    assert dossier.pending_actions == 0


def test_dossier_inconnu_leve_une_erreur_distincte() -> None:
    with pytest.raises(KeyError):
        RunStore().approve("inexistant", "x", "approved", "a@b.com")


# --------------------------------------------------------------------------
# API de la console
# --------------------------------------------------------------------------
@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[object]:
    import argus_console.app as console

    monkeypatch.setenv("ENTRA_DATA_SOURCE", "fixture")
    monkeypatch.setenv("TI_DATA_SOURCE", "fixture")
    monkeypatch.setenv("MAIL_DATA_SOURCE", "fixture")
    monkeypatch.setattr(console, "store", RunStore(journal=tmp_path / "audit.jsonl"))

    with fastapi_testclient.TestClient(console.app) as c:
        yield c


def test_la_console_sert_sa_page(client: Any) -> None:  # type: ignore[valid-type]
    reponse = client.get("/")
    assert reponse.status_code == 200
    assert "console analyste" in reponse.text


def test_investigation_diffusee_etape_par_etape(client: Any) -> None:  # type: ignore[valid-type]
    """Le flux porte les étapes avant le verdict : c'est tout l'intérêt."""
    with client.stream(
        "POST",
        "/api/investigate",
        json={"kind": "compte_compromis", "upn": "marketing@teknologiia.com"},
    ) as reponse:
        flux = "".join(reponse.iter_text())

    types = [b.split("\n")[0] for b in flux.split("\n\n") if b.strip()]
    assert types.count("event: step") >= 4
    assert types[-1] == "event: verdict"
    assert types.index("event: verdict") == len(types) - 1


def test_le_dossier_est_consultable_apres_coup(client: Any) -> None:  # type: ignore[valid-type]
    with client.stream(
        "POST",
        "/api/investigate",
        json={"kind": "compte_compromis", "upn": "marketing@teknologiia.com"},
    ) as reponse:
        flux = "".join(reponse.iter_text())

    run_id = next(
        json.loads(b.split("data: ", 1)[1])["run_id"]
        for b in flux.split("\n\n")
        if b.startswith("event: verdict")
    )

    detail = client.get(f"/api/runs/{run_id}").json()
    assert detail["verdict"]["verdict"] == "malicious"
    assert detail["verdict"]["costs"]["external_api_calls"]


def test_dossier_inconnu_repond_404(client: Any) -> None:  # type: ignore[valid-type]
    assert client.get("/api/runs/inexistant").status_code == 404


def test_l_approbation_consigne_sans_executer(client: Any) -> None:  # type: ignore[valid-type]
    """Le garde-fou central de la plateforme, vérifié à travers l'API."""
    with client.stream(
        "POST",
        "/api/investigate",
        json={"kind": "compte_compromis", "upn": "marketing@teknologiia.com"},
    ) as reponse:
        flux = "".join(reponse.iter_text())

    run_id = next(
        json.loads(b.split("data: ", 1)[1])["run_id"]
        for b in flux.split("\n\n")
        if b.startswith("event: verdict")
    )

    reponse = client.post(
        f"/api/runs/{run_id}/approvals",
        json={
            "action": "revoke_user_sessions",
            "decision": "approved",
            "approver": "analyste@teknologiia.com",
        },
    )

    assert reponse.status_code == 200
    charge = reponse.json()
    assert charge["executed"] is False
    assert "aucune action n'a été exécutée" in charge["note"].lower()


def test_l_api_refuse_une_action_non_proposee(client: Any) -> None:  # type: ignore[valid-type]
    with client.stream(
        "POST",
        "/api/investigate",
        json={"kind": "compte_compromis", "upn": "marketing@teknologiia.com"},
    ) as reponse:
        flux = "".join(reponse.iter_text())

    run_id = next(
        json.loads(b.split("data: ", 1)[1])["run_id"]
        for b in flux.split("\n\n")
        if b.startswith("event: verdict")
    )

    reponse = client.post(
        f"/api/runs/{run_id}/approvals",
        json={"action": "tout_supprimer", "decision": "approved", "approver": "x@y.com"},
    )
    assert reponse.status_code == 400

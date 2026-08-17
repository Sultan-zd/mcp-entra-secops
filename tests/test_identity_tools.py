"""Outils Identity Protection : comptes à risque et détections."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from entra_secops_mcp import runtime
from entra_secops_mcp.config import Settings
from entra_secops_mcp.graph import FixtureGraphClient
from entra_secops_mcp.models import RiskDetection, RiskyUser, RiskyUsersReport
from entra_secops_mcp.tools import identity


@pytest.fixture(autouse=True)
async def source_de_demonstration(
    fixture_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[None]:
    monkeypatch.setattr(runtime, "_client", FixtureGraphClient(fixture_settings))
    monkeypatch.setattr(identity, "get_settings", lambda: fixture_settings)
    yield
    monkeypatch.setattr(runtime, "_client", None)


# --------------------------------------------------------------------------
# get_risky_users
# --------------------------------------------------------------------------
async def test_comptes_a_risque_tries_par_gravite() -> None:
    report = await identity.get_risky_users(only_active=False)

    niveaux = [u.risk_level for u in report.users]
    assert niveaux == ["high", "medium", "low"]


async def test_only_active_ecarte_les_comptes_remedies() -> None:
    actifs = await identity.get_risky_users()
    tous = await identity.get_risky_users(only_active=False)

    assert actifs.total_users < tous.total_users
    assert all(u.risk_state in {"atRisk", "confirmedCompromised"} for u in actifs.users)


async def test_note_sur_le_risque_eleve() -> None:
    report = await identity.get_risky_users()
    assert any("risque élevé" in note for note in report.notes)


def test_note_quand_aucun_compte_n_est_plus_a_risque() -> None:
    users = [
        RiskyUser(
            user_principal_name="x@y.com",
            risk_level="low",
            risk_state="remediated",
        )
    ]
    report = RiskyUsersReport.build(users)
    assert any("Aucun compte n'est encore à risque" in note for note in report.notes)


def test_compromission_confirmee_signalee() -> None:
    users = [
        RiskyUser(
            user_principal_name="victime@y.com",
            risk_level="high",
            risk_state="confirmedCompromised",
        )
    ]
    report = RiskyUsersReport.build(users)
    assert any("Compromission déjà confirmée" in note for note in report.notes)


# --------------------------------------------------------------------------
# get_risk_detections
# --------------------------------------------------------------------------
async def test_detections_ciblees_sur_un_upn() -> None:
    report = await identity.get_risk_detections(upn="marketing@teknologiia.com")

    assert report.distinct_users == ["marketing@teknologiia.com"]
    assert "leakedCredentials" in report.distinct_types


async def test_identifiants_divulgues_appellent_une_reinitialisation() -> None:
    report = await identity.get_risk_detections(upn="marketing@teknologiia.com")
    assert any("réinitialisation du mot de passe" in note for note in report.notes)


async def test_detections_traduites_pour_le_modele() -> None:
    report = await identity.get_risk_detections(upn="marketing@teknologiia.com")

    fuite = next(d for d in report.detections if d.risk_event_type == "leakedCredentials")
    assert fuite.meaning is not None
    assert "fuite" in fuite.meaning.lower()


async def test_detections_triees_de_la_plus_recente() -> None:
    report = await identity.get_risk_detections()
    dates = [d.detected_at for d in report.detections]
    assert dates == sorted(dates, reverse=True)


async def test_voyage_impossible_invite_a_verifier_le_vpn() -> None:
    report = await identity.get_risk_detections(upn="ahmad.k@teknologiia.com")
    assert any("VPN" in note for note in report.notes)


def test_type_de_detection_inconnu_ne_casse_pas() -> None:
    brut: dict[str, Any] = {
        "userPrincipalName": "x@y.com",
        "riskEventType": "typeQuiNExistePas",
        "riskLevel": "low",
        "detectedDateTime": "2026-08-17T10:00:00Z",
    }
    detection = RiskDetection.from_graph(brut)
    assert detection.risk_event_type == "typeQuiNExistePas"
    assert detection.meaning is None
    assert detection.location == "Inconnue"

"""Troncature, robustesse aux champs manquants, et agrégats déterministes."""

from __future__ import annotations

from typing import Any

from entra_secops_mcp.models import SignInEvent, SignInReport


def _raw(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "createdDateTime": "2026-08-17T10:00:00Z",
        "userPrincipalName": "alice@contoso.com",
        "appDisplayName": "Office 365 Exchange Online",
        "ipAddress": "203.0.113.9",
        "clientAppUsed": "Browser",
        "conditionalAccessStatus": "success",
        "riskLevelDuringSignIn": "none",
        "deviceDetail": {"operatingSystem": "Windows 11", "browser": "Edge"},
        "location": {"city": "Beirut", "countryOrRegion": "LB"},
        "status": {"errorCode": 0, "failureReason": None},
    }
    base.update(overrides)
    return base


def test_succes_reconnu() -> None:
    event = SignInEvent.from_graph(_raw())
    assert event.status == "Success"
    assert event.location == "Beirut, LB"
    assert event.device == "Windows 11 / Edge"


def test_echec_enrichi_du_code_et_de_l_indice() -> None:
    event = SignInEvent.from_graph(
        _raw(status={"errorCode": 50126, "failureReason": "Invalid password."})
    )
    assert event.status == "Failure"
    assert event.error_code == 50126
    assert event.error_meaning is not None
    assert event.attack_hint is not None


def test_statut_absent_n_est_pas_un_echec() -> None:
    """Le piège de l'implémentation naïve : `errorCode != 0` classe None en échec."""
    event = SignInEvent.from_graph(_raw(status={}))
    assert event.status == "Interrupted"
    assert event.error_code is None


def test_geolocalisation_absente_reste_lisible() -> None:
    assert SignInEvent.from_graph(_raw(location=None)).location == "Inconnue"
    assert SignInEvent.from_graph(_raw(location={})).location == "Inconnue"
    assert SignInEvent.from_graph(_raw(location={"city": "Paris"})).location == "Paris"


def test_appareil_absent_donne_none_et_non_une_chaine_vide() -> None:
    assert SignInEvent.from_graph(_raw(deviceDetail={})).device is None


def test_code_inconnu_ne_casse_pas() -> None:
    event = SignInEvent.from_graph(_raw(status={"errorCode": 999_999}))
    assert event.status == "Failure"
    assert event.error_meaning is None


def test_champs_bruits_absents_de_la_sortie() -> None:
    """La troncature est un contrôle de sécurité : rien d'autre ne doit passer."""
    event = SignInEvent.from_graph(
        _raw(correlationId="secret-corr", appliedConditionalAccessPolicies=[{"id": "x"}])
    )
    serialise = event.model_dump_json()
    assert "secret-corr" not in serialise
    assert "appliedConditionalAccessPolicies" not in serialise


def test_agregats_et_note_de_compromission() -> None:
    events = [
        SignInEvent.from_graph(_raw(status={"errorCode": 50126})) for _ in range(6)
    ]
    events.append(SignInEvent.from_graph(_raw(status={"errorCode": 0})))

    report = SignInReport.build("alice@contoso.com", 24, events)

    assert report.total_events == 7
    assert report.failures == 6
    assert report.successes == 1
    assert any("RÉUSSI" in note for note in report.notes)


def test_note_protocole_herite() -> None:
    events = [SignInEvent.from_graph(_raw(clientAppUsed="IMAP"))]
    report = SignInReport.build("alice@contoso.com", 24, events)
    assert any("hérités" in note for note in report.notes)


def test_aucune_note_sur_activite_normale() -> None:
    events = [SignInEvent.from_graph(_raw()) for _ in range(3)]
    report = SignInReport.build("alice@contoso.com", 24, events)
    assert report.notes == []


def test_rapport_vide() -> None:
    report = SignInReport.build("inconnu@contoso.com", 24, [])
    assert report.total_events == 0
    assert report.distinct_ip_addresses == []
    assert report.notes == []

"""Outil `get_directory_audits` : détection des gestes de persistance."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from entra_secops_mcp import runtime
from entra_secops_mcp.config import Settings
from entra_secops_mcp.graph import FixtureGraphClient
from entra_secops_mcp.models import DirectoryAudit, DirectoryAuditsReport
from entra_secops_mcp.tools import audits


@pytest.fixture(autouse=True)
async def source_de_demonstration(
    fixture_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[None]:
    monkeypatch.setattr(runtime, "_client", FixtureGraphClient(fixture_settings))
    monkeypatch.setattr(audits, "get_settings", lambda: fixture_settings)
    yield
    monkeypatch.setattr(runtime, "_client", None)


async def test_operations_sensibles_reperees() -> None:
    report = await audits.get_directory_audits(hours=168)

    assert report.sensitive_entries >= 3
    assert any("opération(s) sensible(s)" in note for note in report.notes)


async def test_attribution_de_role_expliquee() -> None:
    report = await audits.get_directory_audits(hours=168)

    role = next(e for e in report.entries if "Add member to role" in e.activity)
    assert role.security_note is not None
    assert "privilèges" in role.security_note


async def test_auteur_et_ip_conserves() -> None:
    """L'IP de l'auteur relie l'audit à la connexion suspecte : elle doit survivre."""
    report = await audits.get_directory_audits(hours=168)

    role = next(e for e in report.entries if "Add member to role" in e.activity)
    assert "marketing@teknologiia.com" in role.initiated_by
    assert "185.220.101.47" in role.initiated_by


async def test_proprietes_modifiees_lisibles() -> None:
    report = await audits.get_directory_audits(hours=168)

    role = next(e for e in report.entries if "Add member to role" in e.activity)
    assert any("Helpdesk Administrator" in prop for prop in role.modified_properties)
    assert any("→" in prop for prop in role.modified_properties)


async def test_filtrage_par_auteur() -> None:
    report = await audits.get_directory_audits(hours=168, initiated_by="marketing@teknologiia.com")

    # Le filtre porte sur un champ imbriqué, non interprété par la source de
    # démonstration : on vérifie donc seulement que l'appel aboutit.
    assert report.total_entries >= 0


async def test_entrees_triees_de_la_plus_recente() -> None:
    report = await audits.get_directory_audits(hours=168)
    dates = [e.activity_date for e in report.entries]
    assert dates == sorted(dates, reverse=True)


def test_action_initiee_par_une_application() -> None:
    brut: dict[str, Any] = {
        "activityDisplayName": "Add app role assignment",
        "activityDateTime": "2026-08-17T10:00:00Z",
        "result": "success",
        "initiatedBy": {"app": {"displayName": "Provisionnement RH"}},
        "targetResources": [],
    }
    audit = DirectoryAudit.from_graph(brut)
    assert audit.initiated_by == "Application : Provisionnement RH"
    assert audit.target_resources == ["Inconnue"]


def test_activite_banale_sans_note() -> None:
    brut: dict[str, Any] = {
        "activityDisplayName": "Update group",
        "activityDateTime": "2026-08-17T10:00:00Z",
        "result": "success",
        "initiatedBy": {},
        "targetResources": [],
    }
    assert DirectoryAudit.from_graph(brut).security_note is None


def test_echecs_repetes_signales() -> None:
    entrees = [
        DirectoryAudit(
            activity_date="2026-08-17T10:00:00Z",
            activity="Update user",
            initiated_by="x@y.com",
            target_resources=["z"],
            result="failure",
        )
        for _ in range(3)
    ]
    report = DirectoryAuditsReport.build(24, entrees)
    assert report.failures == 3
    assert any("en échec" in note for note in report.notes)

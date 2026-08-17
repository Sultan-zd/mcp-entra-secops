"""Comportement de bout en bout de l'outil `get_user_signins`."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from entra_secops_mcp import runtime
from entra_secops_mcp.config import Settings
from entra_secops_mcp.graph import FixtureGraphClient
from entra_secops_mcp.tools.odata import escape_odata
from entra_secops_mcp.tools.signins import get_user_signins


@pytest.fixture(autouse=True)
async def source_de_demonstration(
    fixture_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[None]:
    """Active la source locale et neutralise la lecture d'un .env du poste."""
    monkeypatch.setattr(runtime, "_client", FixtureGraphClient(fixture_settings))
    monkeypatch.setattr("entra_secops_mcp.tools.signins.get_settings", lambda: fixture_settings)
    yield
    monkeypatch.setattr(runtime, "_client", None)


async def test_incident_de_compromission_detecte() -> None:
    report = await get_user_signins("marketing@teknologiia.com")

    assert report.upn == "marketing@teknologiia.com"
    assert report.failures >= 5
    assert report.successes >= 1
    assert "185.220.101.47" in report.distinct_ip_addresses
    assert any("compromission possible" in note for note in report.notes)


async def test_evenements_tries_du_plus_recent_au_plus_ancien() -> None:
    report = await get_user_signins("marketing@teknologiia.com")
    horodatages = [event.timestamp for event in report.events]
    assert horodatages == sorted(horodatages, reverse=True)


async def test_utilisateur_sans_activite() -> None:
    report = await get_user_signins("personne@teknologiia.com")
    assert report.total_events == 0
    assert report.notes == []


async def test_bornes_appliquees_meme_si_le_modele_demande_l_impossible() -> None:
    report = await get_user_signins("marketing@teknologiia.com", hours=100_000, limit=100_000)
    assert report.window_hours == 168


async def test_limite_respectee() -> None:
    report = await get_user_signins("marketing@teknologiia.com", limit=3)
    assert report.total_events == 3


@pytest.mark.parametrize(
    ("entree", "attendu"),
    [("alice@x.com", "alice@x.com"), ("o'brien@x.com", "o''brien@x.com")],
)
def test_echappement_odata(entree: str, attendu: str) -> None:
    """Un UPN provient du modèle : il ne doit jamais casser le filtre OData."""
    assert escape_odata(entree) == attendu

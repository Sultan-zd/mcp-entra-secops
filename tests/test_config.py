"""La configuration doit échouer tôt, et bruyamment."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from entra_secops_mcp.config import Settings


def test_mode_graph_exige_les_identifiants() -> None:
    with pytest.raises(ValidationError) as err:
        Settings(_env_file=None, data_source="graph")  # type: ignore[call-arg]

    message = str(err.value)
    assert "AZURE_TENANT_ID" in message
    assert "AZURE_CLIENT_ID" in message
    assert "AZURE_CLIENT_SECRET" in message


def test_mode_fixture_ne_demande_aucun_identifiant() -> None:
    settings = Settings(_env_file=None, data_source="fixture")  # type: ignore[call-arg]
    assert settings.data_source == "fixture"
    assert settings.azure_tenant_id is None


def test_bornes_incoherentes_refusees() -> None:
    with pytest.raises(ValidationError):
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            data_source="fixture",
            default_page_size=200,
            max_page_size=100,
        )


@pytest.mark.parametrize(
    ("demande", "attendu"),
    [(None, 24), (1, 1), (48, 48), (10_000, 168), (0, 1), (-5, 1)],
)
def test_clamp_hours(fixture_settings: Settings, demande: int | None, attendu: int) -> None:
    assert fixture_settings.clamp_hours(demande) == attendu


@pytest.mark.parametrize(
    ("demande", "attendu"),
    [(None, 25), (10, 10), (100, 100), (5_000, 100), (0, 1)],
)
def test_clamp_limit(fixture_settings: Settings, demande: int | None, attendu: int) -> None:
    assert fixture_settings.clamp_limit(demande) == attendu

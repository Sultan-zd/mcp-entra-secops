"""Fixtures partagées et isolation de la configuration."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from entra_secops_mcp.config import Settings, get_settings


@pytest.fixture(autouse=True)
def environnement_hermetique(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Isole les tests de la configuration réelle du poste.

    Sans cela, un développeur ayant AZURE_TENANT_ID dans son environnement
    verrait passer un test censé constater l'absence d'identifiants.
    """
    for name in list(os.environ):
        if name.startswith(("AZURE_", "ENTRA_")):
            monkeypatch.delenv(name, raising=False)

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def fixture_settings() -> Settings:
    """Configuration en mode fixture, isolée de tout fichier .env local."""
    return Settings(_env_file=None, data_source="fixture")  # type: ignore[call-arg]


@pytest.fixture
def graph_settings() -> Settings:
    """Configuration visant Graph, avec des identifiants factices."""
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        data_source="graph",
        azure_tenant_id="tenant-test",
        azure_client_id="client-test",
        azure_client_secret="secret-test",
        max_retries=2,
    )

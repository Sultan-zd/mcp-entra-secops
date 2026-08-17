"""Diagnostic de connexion : lecture du jeton et masquage des identifiants."""

from __future__ import annotations

import base64
import json

import pytest

from entra_secops_mcp.config import Settings
from entra_secops_mcp.diagnostics import PROBES, _decode_token_roles, _mask, run_diagnostics


def _jeton(claims: dict[str, object]) -> str:
    """Fabrique un jeton JWT non signé, suffisant pour tester l'introspection."""
    corps = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"entete.{corps}.signature"


def test_roles_lus_dans_le_jeton() -> None:
    token = _jeton({"roles": ["AuditLog.Read.All", "Directory.Read.All"], "aud": "graph"})
    assert _decode_token_roles(token) == ["AuditLog.Read.All", "Directory.Read.All"]


def test_jeton_sans_roles_signale_l_absence_de_consentement() -> None:
    """Un jeton valide mais sans revendication `roles` = consentement non accordé."""
    assert _decode_token_roles(_jeton({"aud": "graph"})) == []


@pytest.mark.parametrize(
    "token",
    ["pas-un-jwt", "", "a.b", "entete.@@@invalide@@@.signature"],
)
def test_jeton_illisible_ne_fait_pas_planter_le_diagnostic(token: str) -> None:
    assert _decode_token_roles(token) == []


def test_bourrage_base64_retabli() -> None:
    """Les segments JWT sont dépourvus de `=` : sans rétablissement, le décodage échoue."""
    token = _jeton({"roles": ["Policy.Read.All"]})
    assert "=" not in token.split(".")[1]
    assert _decode_token_roles(token) == ["Policy.Read.All"]


def test_masquage_ne_revele_pas_l_identifiant_complet() -> None:
    complet = "12345678-abcd-ef01-2345-6789abcdef01"
    masque = _mask(complet)

    assert masque == "12345678…"
    assert complet not in masque


def test_masquage_valeur_absente() -> None:
    assert _mask(None) == "(absent)"


def test_un_test_par_outil_expose() -> None:
    """Le diagnostic doit couvrir les six outils, sans quoi il rassure à tort."""
    from entra_secops_mcp.server import TOOLS

    assert {p.tool for p in PROBES} == {t.__name__ for t in TOOLS}


async def test_mode_fixture_n_appelle_pas_le_reseau(
    fixture_settings: Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    code = await run_diagnostics(fixture_settings)

    assert code == 0
    assert "mode fixture" in capsys.readouterr().out


async def test_secret_jamais_affiche(
    graph_settings: Settings, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Le diagnostic sera copié-collé dans un ticket : il ne doit rien divulguer."""
    monkeypatch.setattr(
        "entra_secops_mcp.diagnostics.HttpGraphClient",
        lambda _settings: (_ for _ in ()).throw(RuntimeError("stop")),
    )

    with pytest.raises(RuntimeError):
        await run_diagnostics(graph_settings)

    sortie = capsys.readouterr().out
    assert "secret-test" not in sortie
    assert "renseigné" in sortie

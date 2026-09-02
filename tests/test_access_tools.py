"""Outils d'accès conditionnel et de contexte utilisateur."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from entra_secops_mcp import runtime
from entra_secops_mcp.config import Settings
from entra_secops_mcp.graph import FixtureGraphClient, GraphError
from entra_secops_mcp.models import ConditionalAccessPolicy, ConditionalAccessReport, UserContext
from entra_secops_mcp.tools import access


@pytest.fixture(autouse=True)
async def source_de_demonstration(
    fixture_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[None]:
    monkeypatch.setattr(runtime, "_client", FixtureGraphClient(fixture_settings))
    monkeypatch.setattr(access, "get_settings", lambda: fixture_settings)
    yield
    monkeypatch.setattr(runtime, "_client", None)


# --------------------------------------------------------------------------
# Accès conditionnel
# --------------------------------------------------------------------------
async def test_politiques_comptees_par_etat() -> None:
    report = await access.get_conditional_access_policies()

    assert report.total_policies == 4
    assert report.enforced == 2
    assert report.report_only == 1
    assert report.disabled == 1


async def test_mode_audit_seul_signale_comme_faille() -> None:
    """Une politique en report-only donne une fausse impression de protection."""
    report = await access.get_conditional_access_policies()
    assert any("audit seul" in note for note in report.notes)


async def test_exclusion_signalee() -> None:
    report = await access.get_conditional_access_policies()
    assert any("exclu contourne le contrôle" in note for note in report.notes)


async def test_politiques_appliquees_en_premier() -> None:
    report = await access.get_conditional_access_policies()
    assert report.policies[0].is_enforced is True
    assert report.policies[-1].is_enforced is False


async def test_controles_traduits() -> None:
    report = await access.get_conditional_access_policies()

    politique = next(p for p in report.policies if p.name == "MFA obligatoire pour tous")
    assert politique.grant_controls == ["Exiger la MFA"]
    assert politique.included_users == "tous"


def test_tenant_sans_politique_appliquee() -> None:
    politiques = [
        ConditionalAccessPolicy(
            name="Inactive",
            state="disabled",
            is_enforced=False,
            included_users="tous",
            excluded_users="aucun",
            included_applications="tous",
            grant_controls=["Exiger la MFA"],
        )
    ]
    report = ConditionalAccessReport.build(politiques)
    assert any("aucun contrôle d'accès conditionnel" in note for note in report.notes)


# --------------------------------------------------------------------------
# Contexte utilisateur
# --------------------------------------------------------------------------
async def test_compte_privilegie_signale() -> None:
    contexte = await access.get_user_context("sarah.n@teknologiia.com")

    assert contexte.is_privileged is True
    assert contexte.privileged_roles == ["Global Administrator"]
    assert any("privilèges élevés" in note for note in contexte.notes)


async def test_groupes_et_roles_separes() -> None:
    contexte = await access.get_user_context("marketing@teknologiia.com")

    assert "Marketing" in contexte.groups
    assert "Helpdesk Administrator" in contexte.directory_roles
    assert "Helpdesk Administrator" not in contexte.groups


async def test_appartenances_cloisonnees_par_utilisateur() -> None:
    """Chaque compte doit recevoir SES groupes, pas ceux d'un autre."""
    marketing = await access.get_user_context("marketing@teknologiia.com")
    ahmad = await access.get_user_context("ahmad.k@teknologiia.com")

    assert "Finance-Approvers" in ahmad.groups
    assert "Finance-Approvers" not in marketing.groups


async def test_compte_sans_privilege() -> None:
    contexte = await access.get_user_context("ahmad.k@teknologiia.com")

    assert contexte.is_privileged is False
    assert contexte.privileged_roles == []


async def test_compte_invite_et_desactive_signales() -> None:
    contexte = await access.get_user_context("old.contractor@teknologiia.com")

    assert contexte.account_enabled is False
    assert any("invité" in note for note in contexte.notes)
    assert any("désactivé" in note for note in contexte.notes)


async def test_upn_inconnu_message_actionnable() -> None:
    with pytest.raises(GraphError, match="Aucun compte ne correspond"):
        await access.get_user_context("personne@teknologiia.com")


# --------------------------------------------------------------------------
# Moindre privilège : quand les appartenances sont refusées
# --------------------------------------------------------------------------
async def test_appartenances_refusees_ne_font_pas_echouer_l_outil(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`memberOf` exige `Directory.Read.All`, plus large que le `User.Read.All`
    qui suffit à lire la fiche. Un tenant accordé au plus juste répond 403 sur
    cet appel seul : la fiche reste utile, l'outil ne doit pas tomber."""
    client = runtime.get_client()
    reel = client.get

    async def _refuser(chemin: str, **kwargs: object) -> list[dict[str, object]]:
        if "memberOf" in chemin:
            raise GraphError("Permission insuffisante (403).")
        return await reel(chemin, **kwargs)  # type: ignore[no-any-return]

    monkeypatch.setattr(client, "get", _refuser)

    contexte = await access.get_user_context("sarah.n@teknologiia.com")

    assert contexte.user_principal_name == "sarah.n@teknologiia.com"
    assert contexte.memberships_readable is False


async def test_appartenances_refusees_n_annoncent_jamais_un_compte_sain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Le pire mode de défaillance de cet outil.

    sarah.n EST administratrice globale. Si ses appartenances sont illisibles,
    `is_privileged` retombe mécaniquement à `false` — rendre cela sans le dire
    présenterait une administratrice globale comme un compte ordinaire, et
    ferait sous-évaluer un incident majeur. Le constat doit être en TÊTE des
    notes, et le drapeau doit permettre de ne pas lire `is_privileged`.
    """
    client = runtime.get_client()
    reel = client.get

    async def _refuser(chemin: str, **kwargs: object) -> list[dict[str, object]]:
        if "memberOf" in chemin:
            raise GraphError("Permission insuffisante (403).")
        return await reel(chemin, **kwargs)  # type: ignore[no-any-return]

    monkeypatch.setattr(client, "get", _refuser)

    contexte = await access.get_user_context("sarah.n@teknologiia.com")

    assert contexte.is_privileged is False, "attendu : faux PAR IGNORANCE"
    assert contexte.memberships_readable is False, "c'est ce drapeau qui l'explique"
    assert "ILLISIBLES" in contexte.notes[0]
    assert "INCONNU" in contexte.notes[0]


def test_une_fiche_complete_declare_ses_appartenances_lisibles() -> None:
    """Le drapeau ne doit pas être un faux positif permanent."""
    contexte = UserContext.build(
        {"userPrincipalName": "a@b.c", "id": "1"},
        [{"displayName": "Global Administrator", "@odata.type": "#microsoft.graph.directoryRole"}],
    )

    assert contexte.memberships_readable is True
    assert contexte.is_privileged is True


def test_role_privilegie_insensible_a_la_casse() -> None:
    contexte = UserContext.build(
        {"userPrincipalName": "x@y.com", "id": "1"},
        [{"@odata.type": "#microsoft.graph.directoryRole", "displayName": "GLOBAL ADMINISTRATOR"}],
    )
    assert contexte.is_privileged is True

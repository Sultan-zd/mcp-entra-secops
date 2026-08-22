"""Le serveur unique distribué en paquet MCPB.

Ces tests portent sur ce qui n'apparaît qu'à l'installation réelle : des
variables d'environnement que l'hôte a laissées non substituées, et des
domaines facultatifs qui refusent de démarrer.
"""

from __future__ import annotations

import pytest

from argus_bundle.server import _clefs_identite, _clefs_renseignement, _config, domaines_actifs


# --------------------------------------------------------------------------
# Substituants non remplacés
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "valeur",
    [
        "${user_config.azure_tenant_id}",
        "${user_config.virustotal_api_key}",
        "${HOME}",
        "${__dirname}",
    ],
)
def test_un_substituant_non_remplace_vaut_absent(
    valeur: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Le défaut exact rencontré à la première installation du paquet.

    Un champ facultatif laissé vide fait transmettre le substituant *littéral*
    par l'hôte : la variable contient « ${user_config.azure_tenant_id} », pas
    une chaîne vide. Un simple test de vérité la juge renseignée — le domaine
    identité s'activait alors, azure-identity refusait ce faux identifiant, et
    le serveur entier mourait au démarrage.
    """
    monkeypatch.setenv("AZURE_TENANT_ID", valeur)

    assert _config("AZURE_TENANT_ID") is None


@pytest.mark.parametrize("valeur", ["", "   ", "\t"])
def test_une_valeur_vide_vaut_absent(valeur: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_TENANT_ID", valeur)

    assert _config("AZURE_TENANT_ID") is None


@pytest.mark.parametrize(
    "valeur",
    [
        "7bdea2a2-5e12-4bcb-a9bc-4716ce2921b4",
        "contoso.onmicrosoft.com",
        # Une valeur qui contient des accolades sans EN ÊTRE une : elle doit
        # passer, sinon une clé exotique serait rejetée à tort.
        "cle${avec}accolades",
    ],
)
def test_une_vraie_valeur_passe(valeur: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Un garde-fou trop large rejetterait des configurations valides."""
    monkeypatch.setenv("AZURE_TENANT_ID", valeur)

    assert _config("AZURE_TENANT_ID") == valeur


def test_la_valeur_est_deballee_des_espaces(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "  cle-reelle  ")

    assert _config("VIRUSTOTAL_API_KEY") == "cle-reelle"


# --------------------------------------------------------------------------
# Activation des domaines
# --------------------------------------------------------------------------
def test_sans_configuration_seuls_les_domaines_sans_cle_sont_exposes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for v in (
        "VIRUSTOTAL_API_KEY",
        "ABUSEIPDB_API_KEY",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "ENTRA_DATA_SOURCE",
    ):
        monkeypatch.delenv(v, raising=False)

    actifs = domaines_actifs()

    assert actifs["vulnerabilites"] and actifs["mitre"]
    assert actifs["web"] and actifs["messagerie"]
    assert not actifs["renseignement"]
    assert not actifs["identite"]


def test_des_substituants_partout_ne_debloquent_rien(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """La configuration telle que l'hôte la transmet quand tout est laissé vide."""
    for nom in (
        "VIRUSTOTAL_API_KEY",
        "ABUSEIPDB_API_KEY",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
    ):
        monkeypatch.setenv(nom, "${user_config." + nom.lower() + "}")
    monkeypatch.delenv("ENTRA_DATA_SOURCE", raising=False)

    actifs = domaines_actifs()

    assert not actifs["renseignement"]
    assert not actifs["identite"]


def test_une_seule_cle_de_reputation_suffit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "cle-reelle")

    assert _clefs_renseignement() is True


def test_l_identite_exige_les_trois_valeurs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deux identifiants sur trois ne permettent pas de joindre un tenant."""
    monkeypatch.delenv("ENTRA_DATA_SOURCE", raising=False)
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-reel")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-reel")
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)

    assert _clefs_identite() is False

    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-reel")
    assert _clefs_identite() is True


def test_le_mode_demonstration_active_l_identite_sans_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for v in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("ENTRA_DATA_SOURCE", "fixture")

    assert _clefs_identite() is True


# --------------------------------------------------------------------------
# Composition du serveur
# --------------------------------------------------------------------------
async def test_le_serveur_expose_29_outils_sans_aucune_cle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C'est la promesse faite dans le manifeste du paquet."""
    from argus_bundle.server import build_server

    for v in (
        "VIRUSTOTAL_API_KEY",
        "ABUSEIPDB_API_KEY",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "ENTRA_DATA_SOURCE",
    ):
        monkeypatch.delenv(v, raising=False)

    outils = await build_server().list_tools()

    assert len(outils) == 29
    noms = {t.name for t in outils}
    assert "prioritize_cves" in noms
    assert "map_findings_to_attack" in noms
    assert "check_web_exposure" in noms
    # Aucun outil exigeant une clé ne doit apparaître : un outil visible qui
    # répond toujours « clé absente » gaspille le contexte du modèle.
    assert "enrich_ip" not in noms
    assert "get_user_signins" not in noms


async def test_toutes_les_cles_exposent_39_outils(monkeypatch: pytest.MonkeyPatch) -> None:
    from argus_bundle.server import build_server

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "cle")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "cle")
    monkeypatch.setenv("ENTRA_DATA_SOURCE", "fixture")

    outils = await build_server().list_tools()

    assert len(outils) == 39
    noms = {t.name for t in outils}
    assert "enrich_ip" in noms
    assert "get_user_signins" in noms


async def test_aucun_nom_d_outil_n_est_en_double(monkeypatch: pytest.MonkeyPatch) -> None:
    """Six serveurs réunis : une collision de noms rendrait un outil inatteignable."""
    from argus_bundle.server import build_server

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "cle")
    monkeypatch.setenv("ENTRA_DATA_SOURCE", "fixture")

    noms = [t.name for t in await build_server().list_tools()]

    assert len(noms) == len(set(noms))

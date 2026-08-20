"""SPF : le comptage des résolutions DNS, et ce qu'il révèle.

C'est le module qui justifie l'existence de ce serveur. Une organisation
franchit le plafond de dix résolutions sans aucun signal, et SPF cesse
silencieusement de protéger le domaine. Ces tests verrouillent la détection.
"""

from __future__ import annotations

import pytest

from email_security_mcp.dns_client import FixtureDnsResolver
from email_security_mcp.spf import MAX_LOOKUPS, analyse_spf, count_spf_records, find_spf_record


def resolveur(zones: dict[str, dict[str, list[str]]]) -> FixtureDnsResolver:
    return FixtureDnsResolver(zones)


# --------------------------------------------------------------------------
# Détection de l'enregistrement
# --------------------------------------------------------------------------
def test_extraction_parmi_d_autres_txt() -> None:
    txt = ["MS=ms123", "v=spf1 ip4:1.2.3.4 -all", "google-site-verification=abc"]
    assert find_spf_record(txt) == "v=spf1 ip4:1.2.3.4 -all"


def test_aucun_spf_detecte() -> None:
    assert find_spf_record(["MS=ms123"]) is None
    assert count_spf_records(["MS=ms123"]) == 0


async def test_domaine_sans_spf_est_signale_en_gravite_haute() -> None:
    rapport = await analyse_spf("nu.example", resolveur({"nu.example": {"TXT": []}}))

    assert rapport.record is None
    assert rapport.severity == "high"
    assert any("n'importe qui peut envoyer" in f for f in rapport.findings)


async def test_plusieurs_spf_produisent_un_permerror() -> None:
    """Erreur classique : un prestataire ajoute le sien sans fusionner."""
    zones = {
        "double.example": {"TXT": ["v=spf1 include:a.example -all", "v=spf1 ip4:1.2.3.4 -all"]}
    }
    rapport = await analyse_spf("double.example", resolveur(zones))

    assert rapport.valid is False
    assert rapport.severity == "high"
    assert any("au lieu d'un seul" in f for f in rapport.findings)


# --------------------------------------------------------------------------
# Comptage des résolutions — le cœur du module
# --------------------------------------------------------------------------
async def test_les_mecanismes_ip4_ne_coutent_aucune_resolution() -> None:
    """Remplacer un `include:` par des `ip4:` est le remède au dépassement."""
    zones = {"simple.example": {"TXT": ["v=spf1 ip4:1.2.3.0/24 ip6:2001:db8::/32 -all"]}}

    rapport = await analyse_spf("simple.example", resolveur(zones))

    assert rapport.dns_lookups == 0
    assert rapport.valid is True
    assert all(not m.costs_lookup for m in rapport.mechanisms)


async def test_include_imbrique_compte_chaque_niveau() -> None:
    zones = {
        "racine.example": {"TXT": ["v=spf1 include:niveau1.example -all"]},
        "niveau1.example": {"TXT": ["v=spf1 include:niveau2.example ~all"]},
        "niveau2.example": {"TXT": ["v=spf1 ip4:1.2.3.4 ~all"]},
    }

    rapport = await analyse_spf("racine.example", resolveur(zones))

    assert rapport.dns_lookups == 2  # niveau1 puis niveau2
    assert rapport.valid is True


async def test_depassement_du_plafond_detecte_et_explique() -> None:
    """Le cas qui motive tout le module : SPF paraît correct mais ne protège plus."""
    inclus = " ".join(f"include:p{i}.example" for i in range(12))
    zones: dict[str, dict[str, list[str]]] = {"sature.example": {"TXT": [f"v=spf1 {inclus} -all"]}}
    for i in range(12):
        zones[f"p{i}.example"] = {"TXT": [f"v=spf1 ip4:10.0.{i}.0/24 ~all"]}

    rapport = await analyse_spf("sature.example", resolveur(zones))

    assert rapport.dns_lookups > MAX_LOOKUPS
    assert rapport.valid is False
    assert rapport.severity == "high"
    assert any("NE PROTÈGE PLUS" in f for f in rapport.findings)


async def test_alerte_anticipee_avant_le_plafond() -> None:
    """Alerter à 10 serait alerter trop tard : le domaine est déjà cassé."""
    inclus = " ".join(f"include:p{i}.example" for i in range(9))
    zones: dict[str, dict[str, list[str]]] = {"limite.example": {"TXT": [f"v=spf1 {inclus} -all"]}}
    for i in range(9):
        zones[f"p{i}.example"] = {"TXT": [f"v=spf1 ip4:10.0.{i}.0/24 ~all"]}

    rapport = await analyse_spf("limite.example", resolveur(zones))

    assert rapport.valid is True  # encore conforme
    assert rapport.severity == "medium"  # mais à un prestataire de la panne
    assert any("fera basculer" in f for f in rapport.findings)


async def test_boucle_d_includes_ne_fige_pas_l_analyse() -> None:
    """Deux domaines qui s'incluent mutuellement doivent être détectés."""
    zones = {
        "a.example": {"TXT": ["v=spf1 include:b.example -all"]},
        "b.example": {"TXT": ["v=spf1 include:a.example -all"]},
    }

    rapport = await analyse_spf("a.example", resolveur(zones))

    assert rapport.dns_lookups < 50  # l'analyse se termine


async def test_include_vers_un_domaine_sans_spf_est_signale() -> None:
    zones = {
        "hote.example": {"TXT": ["v=spf1 include:vide.example -all"]},
        "vide.example": {"TXT": []},
    }

    rapport = await analyse_spf("hote.example", resolveur(zones))

    assert any("consommée pour rien" in f for f in rapport.findings)


# --------------------------------------------------------------------------
# Qualificateur final
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("enregistrement", "qualificateur", "gravite"),
    [
        ("v=spf1 ip4:1.2.3.4 -all", "fail", "low"),
        ("v=spf1 ip4:1.2.3.4 ~all", "softfail", "medium"),
        ("v=spf1 ip4:1.2.3.4 ?all", "neutral", "high"),
        ("v=spf1 ip4:1.2.3.4 +all", "pass", "high"),
    ],
)
async def test_qualificateur_final_determine_la_gravite(
    enregistrement: str, qualificateur: str, gravite: str
) -> None:
    rapport = await analyse_spf("q.example", resolveur({"q.example": {"TXT": [enregistrement]}}))

    assert rapport.all_qualifier == qualificateur
    assert rapport.severity == gravite


async def test_plus_all_signale_comme_equivalent_a_aucune_protection() -> None:
    """`+all` autorise le monde entier : souvent une faute de frappe pour `-all`."""
    rapport = await analyse_spf(
        "ouvert.example", resolveur({"ouvert.example": {"TXT": ["v=spf1 +all"]}})
    )

    assert any("TOUT expéditeur est autorisé" in f for f in rapport.findings)


async def test_absence_de_all_signalee() -> None:
    rapport = await analyse_spf(
        "sans.example", resolveur({"sans.example": {"TXT": ["v=spf1 ip4:1.2.3.4"]}})
    )

    assert rapport.all_qualifier is None
    assert any("Aucun mécanisme `all`" in f for f in rapport.findings)


async def test_ptr_signale_comme_deconseille() -> None:
    rapport = await analyse_spf(
        "ptr.example", resolveur({"ptr.example": {"TXT": ["v=spf1 ptr -all"]}})
    )

    assert any("`ptr` est déconseillé" in f for f in rapport.findings)

"""Le calcul CVSS local, confronté aux notes officielles du NVD.

Un module qui prétend recalculer une note normalisée doit le prouver contre la
source, pas contre les attentes de son auteur. Le jeu figé contient 138
vecteurs réels avec la note que le NVD leur attribue.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_intel_mcp.cvss import (
    CvssError,
    evaluer,
    lire_v4,
    parse_vector,
    score_v3,
    severite,
)

FIXTURE = Path(__file__).parent.parent / "src" / "vuln_intel_mcp" / "fixtures" / "cvss_nvd.json"

VECTEURS_REELS = json.loads(FIXTURE.read_text(encoding="utf-8"))["vectors"]


# --------------------------------------------------------------------------
# Conformité à la source
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "cas",
    VECTEURS_REELS,
    ids=[c["vector"].replace("CVSS:", "") for c in VECTEURS_REELS],
)
def test_notre_calcul_reproduit_celui_du_nvd(cas: dict) -> None:
    """Chaque vecteur réel doit rendre exactement la note officielle."""
    resultat = score_v3(cas["vector"])

    assert resultat.base_score == pytest.approx(cas["nvd_base_score"], abs=0.001)
    assert resultat.severity == cas["nvd_severity"].lower()
    assert resultat.computed is True


def test_le_jeu_couvre_les_quatre_severites() -> None:
    """Un jeu qui n'exercerait qu'une branche ne prouverait presque rien."""
    severites = {c["nvd_severity"].lower() for c in VECTEURS_REELS}

    assert severites == {"low", "medium", "high", "critical"}
    assert len(VECTEURS_REELS) >= 100


# --------------------------------------------------------------------------
# Points où la norme surprend
# --------------------------------------------------------------------------
def test_l_arrondi_est_celui_de_la_norme_pas_celui_de_python() -> None:
    """La norme impose l'arrondi supérieur à une décimale.

    Un `round()` ordinaire donne une classe de sévérité de moins sur certains
    vecteurs — c'est la raison d'être de la formulation entière de la
    spécification.
    """
    # 6.4759… → 6.5 par la norme ; un arrondi bancaire donnerait 6.5 aussi,
    # mais l'écart apparaît sur les valeurs à mi-chemin exact.
    resultat = score_v3("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L")
    assert resultat.base_score == 6.3

    # Vecteur dont la somme brute tombe juste sous un dixième.
    plancher = score_v3("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert plancher.base_score == 1.6


def test_le_perimetre_change_modifie_le_poids_des_privileges() -> None:
    """PR ne pèse pas pareil selon S : la norme prévoit deux barèmes.

    Utiliser un seul barème sous-évaluerait toutes les failles à périmètre
    changé, qui sont précisément les plus graves.
    """
    inchange = score_v3("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
    change = score_v3("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H")

    assert change.base_score > inchange.base_score
    assert change.base_score == 9.1
    assert inchange.base_score == 7.2


def test_aucun_impact_donne_zero() -> None:
    """Sans impact, la note est nulle quelle que soit l'exploitabilité."""
    assert score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").base_score == 0.0


def test_le_vecteur_est_explique_en_francais() -> None:
    """Une suite de lettres n'aide personne : la sortie doit se lire."""
    resultat = score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")

    assert "distance" in resultat.explained["AV"]
    assert "aucun privilège" in resultat.explained["PR"]
    assert set(resultat.explained) == set(resultat.metrics)


# --------------------------------------------------------------------------
# Ce qui doit être refusé
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "vecteur",
    [
        "",
        "AV:N/AC:L",  # sans le préfixe de version
        "CVSS:3.1/AV:N",  # métriques manquantes
        "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # valeur inexistante
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",  # périmètre invalide
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",  # version non gérée
        "n'importe quoi",
    ],
)
def test_un_vecteur_invalide_est_refuse(vecteur: str) -> None:
    """Mieux vaut refuser qu'inventer une note.

    Un vecteur illisible qui rendrait 0.0 serait pris pour « sans danger ».
    """
    with pytest.raises(CvssError):
        score_v3(vecteur)


def test_la_v4_est_decodee_mais_pas_recalculee() -> None:
    """La v4.0 se note par table, pas par formule.

    En réimplémenter une approximation donnerait des notes fausses avec
    l'assurance d'un calcul. Le champ le dit franchement.
    """
    resultat = lire_v4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")

    assert resultat.computed is False
    assert resultat.severity == "unknown"
    assert resultat.metrics["AV"] == "N"


def test_evaluer_aiguille_selon_la_version() -> None:
    assert evaluer("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").computed is True
    assert evaluer("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H").computed is False


def test_un_vecteur_v3_passe_a_lire_v4_est_refuse() -> None:
    with pytest.raises(CvssError):
        lire_v4("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


# --------------------------------------------------------------------------
# Échelle qualitative
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("score", "attendu"),
    [
        (0.0, "none"),
        (0.1, "low"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (8.9, "high"),
        (9.0, "critical"),
        (10.0, "critical"),
    ],
)
def test_les_bornes_de_severite_suivent_la_norme(score: float, attendu: str) -> None:
    assert severite(score) == attendu


def test_parse_vector_rend_les_metriques() -> None:
    version, metriques = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    assert version == "3.1"
    assert metriques["AV"] == "N"
    assert metriques["S"] == "U"

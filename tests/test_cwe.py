"""Le catalogue CWE embarqué : ce qu'un identifiant seul ne dit pas.

`lookup_cve` rend déjà les CWE cités par NVD comme de simples chaînes. Ces
tests portent sur ce que ce module ajoute : dire si le CWE cité désigne
vraiment une faiblesse précise, ou si MITRE lui-même déconseille cet usage —
un signal qu'aucune fiche NVD ne porte, puisqu'elle recopie l'identifiant
déclaré sans le confronter à sa propre classification d'aptitude au mapping.
"""

from __future__ import annotations

import pytest

from vuln_intel_mcp import weaknesses as cwe
from vuln_intel_mcp.tools import lookup_cwe, search_cwe


def test_le_catalogue_est_charge_et_complet() -> None:
    catalogue = cwe.charger()

    assert catalogue.version
    # Le catalogue officiel en compte plusieurs centaines : un fichier tronqué
    # passerait inaperçu sans cette borne.
    assert len(catalogue.weaknesses) > 900


@pytest.mark.parametrize("forme", ["502", "CWE-502", "cwe-502", " 502 "])
def test_les_formes_d_identifiant_sont_equivalentes(forme: str) -> None:
    catalogue = cwe.charger()

    assert catalogue.faiblesse(forme) is not None
    assert catalogue.faiblesse(forme)["id"] == "CWE-502"


# --------------------------------------------------------------------------
# Le signal que ce module apporte : l'aptitude au mapping
# --------------------------------------------------------------------------
def test_un_cwe_courant_ne_declenche_aucun_avertissement() -> None:
    """Un garde-fou trop large signalerait la majorité des CWE réels."""
    evaluation = cwe.evaluer_mapping("CWE-502")

    assert evaluation.problematic is False
    assert evaluation.notes == []


def test_un_cwe_prohibited_est_signale() -> None:
    evaluation = cwe.evaluer_mapping("CWE-1041")

    assert evaluation.usage == "Prohibited"
    assert evaluation.problematic is True
    assert any("Prohibited" in n for n in evaluation.notes)


def test_un_cwe_discouraged_est_signale() -> None:
    evaluation = cwe.evaluer_mapping("CWE-114")

    assert evaluation.usage == "Discouraged"
    assert evaluation.problematic is True


def test_un_pillar_est_signale_meme_si_le_mapping_est_autorise() -> None:
    """Deux motifs distincts d'avertissement peuvent se cumuler.

    CWE-284 est à la fois `Discouraged` ET `Pillar` : les deux raisons
    doivent apparaître, pas seulement la première trouvée.
    """
    evaluation = cwe.evaluer_mapping("CWE-284")

    assert evaluation.abstraction == "Pillar"
    assert evaluation.problematic is True
    assert len(evaluation.notes) >= 1


def test_un_identifiant_inexistant_est_signale_sans_lever() -> None:
    """`evaluer_mapping` rend un constat, jamais une exception : c'est
    `lookup_cwe` qui décide de lever, pas la couche d'évaluation."""
    evaluation = cwe.evaluer_mapping("CWE-999999")

    assert evaluation.problematic is True
    assert any("n'existe pas" in n for n in evaluation.notes)


# --------------------------------------------------------------------------
# L'outil MCP
# --------------------------------------------------------------------------
async def test_lookup_cwe_rend_la_fiche_complete() -> None:
    detail = await lookup_cwe(cwe_id="CWE-502")

    assert detail.name == "Deserialization of Untrusted Data"
    assert detail.mapping_warning is None
    assert detail.consequences
    assert detail.detection_methods


async def test_lookup_cwe_avertit_sur_un_mapping_deconseille() -> None:
    detail = await lookup_cwe(cwe_id="CWE-1041")

    assert detail.mapping_warning is not None
    assert "Prohibited" in detail.mapping_warning


async def test_lookup_cwe_refuse_un_identifiant_inconnu() -> None:
    with pytest.raises(ValueError) as erreur:
        await lookup_cwe(cwe_id="CWE-999999")

    assert "n'existe pas" in str(erreur.value)


async def test_search_cwe_trouve_par_mots_cles() -> None:
    resultat = await search_cwe(query="deserialization untrusted")

    assert resultat.total >= 1
    assert any(r.id == "CWE-502" for r in resultat.results)


async def test_search_cwe_refuse_une_requete_vide() -> None:
    with pytest.raises(ValueError):
        await search_cwe(query="   ")


async def test_search_cwe_respecte_la_limite() -> None:
    resultat = await search_cwe(query="the", limit=3)

    assert len(resultat.results) <= 3


# --------------------------------------------------------------------------
# Composition du serveur
# --------------------------------------------------------------------------
async def test_les_outils_cwe_sont_purement_locaux() -> None:
    from vuln_intel_mcp.server import build_server

    outils = {t.name: t for t in await (build_server()).list_tools()}

    for nom in ("lookup_cwe", "search_cwe"):
        assert nom in outils
        annotations = outils[nom].annotations
        assert annotations is not None
        assert annotations.open_world_hint is False

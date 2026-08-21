"""Le serveur ATT&CK : corpus embarqué, correspondances, couverture.

Aucun test n'accède au réseau — c'est la propriété que ce serveur revendique,
et elle mérite d'être vérifiée plutôt qu'affirmée.
"""

from __future__ import annotations

import json

import pytest

from mitre_mcp.corpus import charger, chercher, resoudre_identifiant
from mitre_mcp.mapping import TOUTES, constats_connus, correspondances
from mitre_mcp.tools import (
    build_navigator_layer,
    corpus_info,
    coverage_report,
    list_known_findings,
    list_tactics,
    lookup_group,
    lookup_technique,
    map_findings_to_attack,
    search_techniques,
)


# --------------------------------------------------------------------------
# Le corpus embarqué
# --------------------------------------------------------------------------
def test_le_corpus_est_charge_et_complet() -> None:
    corpus = charger()

    assert corpus.version.startswith("1")
    # ATT&CK Enterprise en compte quelques centaines : un corpus tronqué
    # passerait inaperçu sans cette borne.
    assert len(corpus.techniques) > 500
    assert len(corpus.tactics) == 15
    assert len(corpus.mitigations) > 30
    assert len(corpus.groups) > 100


def test_le_corpus_ne_contient_aucune_technique_revoquee() -> None:
    """Une technique retirée du référentiel ne doit pas ressortir d'une recherche."""
    corpus = charger()

    assert corpus.techniques.keys().isdisjoint(corpus.revoked.keys())


def test_toutes_les_techniques_portent_leur_detection() -> None:
    """ATT&CK v19 a déplacé la détection hors de l'objet technique.

    Le distillateur lisait l'ancien champ et produisait un silence complet.
    Ce test empêche la régression : sans détection, l'outil perd ce qu'il a de
    plus utile.
    """
    corpus = charger()
    sans = [t["id"] for t in corpus.techniques.values() if not t.get("detection")]

    assert not sans, f"{len(sans)} technique(s) sans détection, par exemple {sans[:3]}"


def test_les_analytiques_nomment_des_sources_de_journaux() -> None:
    """Sans le bon journal, aucune règle ne se déclenche jamais."""
    corpus = charger()
    technique = corpus.technique("T1566.002")
    assert technique is not None

    sources = [
        s
        for strategie in technique["detection"]
        for a in strategie["analytics"]
        for s in a["log_sources"]
    ]
    assert sources


# --------------------------------------------------------------------------
# La table de correspondance
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("constat", "technique"),
    [(c, corr.technique) for c, liens in TOUTES.items() for corr in liens],
)
def test_chaque_correspondance_vise_une_technique_reelle(constat: str, technique: str) -> None:
    """Le garde-fou le plus important de ce serveur.

    Ces identifiants ont été écrits à la main, et deux d'entre eux visaient
    T1562.001 — révoquée par ATT&CK v19. Ils seraient partis dans des rapports
    d'incident. Ce test rend l'erreur impossible à commettre en silence, y
    compris après une mise à jour du corpus.
    """
    assert charger().technique(technique) is not None, (
        f"Le constat « {constat} » vise {technique}, absente du corpus."
    )


def test_chaque_correspondance_porte_sa_raison() -> None:
    """Sans le motif, un rapprochement est une affirmation invérifiable."""
    for constat, liens in TOUTES.items():
        for corr in liens:
            assert len(corr.reason) > 30, f"Motif trop court pour « {constat} »."
            assert corr.confidence in {"high", "medium", "low"}


def test_un_constat_inconnu_ne_donne_rien_plutot_qu_un_a_peu_pres() -> None:
    """Une correspondance fausse est pire qu'une correspondance absente."""
    assert correspondances("un constat qui n'existe pas") == []


def test_le_vocabulaire_couvre_les_detections_entra() -> None:
    """La table doit suivre le vocabulaire que les autres serveurs produisent."""
    from entra_secops_mcp.models.identity import RISK_EVENT_TYPES

    connus = set(constats_connus())
    manquants = [t for t in RISK_EVENT_TYPES if t.lower() not in connus]

    assert not manquants, f"Détections Entra sans correspondance : {manquants}"


def test_le_vocabulaire_couvre_les_operations_sensibles() -> None:
    from entra_secops_mcp.models.audits import SENSITIVE_ACTIVITIES

    connus = set(constats_connus())
    # SENSITIVE_ACTIVITIES associe chaque opération à son explication.
    manquants = [a for a, _ in SENSITIVE_ACTIVITIES if a.lower() not in connus]

    assert not manquants, f"Opérations d'annuaire sans correspondance : {manquants}"


# --------------------------------------------------------------------------
# lookup_technique
# --------------------------------------------------------------------------
async def test_lookup_rend_la_fiche_complete() -> None:
    fiche = await lookup_technique("T1566.002")

    assert fiche.name == "Spearphishing Link"
    assert fiche.is_subtechnique is True
    assert fiche.parent == "T1566"
    assert fiche.log_sources
    assert fiche.mitigations


async def test_lookup_rend_les_sous_techniques_d_un_parent() -> None:
    fiche = await lookup_technique("T1566")

    assert fiche.is_subtechnique is False
    assert any(s.id == "T1566.002" for s in fiche.subtechniques)


async def test_une_technique_revoquee_est_expliquee_pas_niee() -> None:
    """Répondre « inconnue » ferait croire à une faute de frappe.

    T1562.001 a réellement existé jusqu'en v18 : un analyste qui la cite a
    besoin de savoir qu'elle a été remplacée, pas qu'elle n'a jamais existé.
    """
    with pytest.raises(ValueError, match="retirée du référentiel"):
        await lookup_technique("T1562.001")


async def test_une_technique_revoquee_indique_sa_remplacante() -> None:
    with pytest.raises(ValueError, match="T1685"):
        await lookup_technique("T1562.001")


@pytest.mark.parametrize("entree", ["", "T156", "1566", "TT1566", "phishing", "T1566.2"])
async def test_un_identifiant_mal_forme_est_refuse(entree: str) -> None:
    with pytest.raises(ValueError, match="identifiant de technique"):
        await lookup_technique(entree)


async def test_un_identifiant_bien_forme_mais_inexistant_le_dit() -> None:
    with pytest.raises(ValueError, match="n'existe pas"):
        await lookup_technique("T9999")


# --------------------------------------------------------------------------
# search_techniques
# --------------------------------------------------------------------------
async def test_le_nom_pese_plus_que_la_description() -> None:
    """Quelqu'un qui tape « phishing » veut T1566, pas une mention en passant."""
    resultat = await search_techniques("phishing")

    assert resultat["results"][0]["id"].startswith("T1566")


async def test_la_recherche_filtre_par_tactique() -> None:
    resultat = await search_techniques("account", tactic="persistence")

    assert resultat["returned"] > 0
    assert all("persistence" in r["tactics"] for r in resultat["results"])


async def test_une_tactique_inconnue_liste_les_valeurs_possibles() -> None:
    with pytest.raises(ValueError, match="initial-access"):
        await search_techniques("phishing", tactic="pas-une-tactique")


async def test_une_recherche_sans_resultat_le_dit() -> None:
    resultat = await search_techniques("zzzzqqqxyz")

    assert resultat["returned"] == 0
    assert resultat["notes"]


async def test_une_recherche_vide_est_refusee() -> None:
    with pytest.raises(ValueError, match="mots-clés"):
        await search_techniques("   ")


def test_la_recherche_ignore_les_mots_vides() -> None:
    """Sans cela, « the » ramènerait la moitié du référentiel."""
    assert chercher("the of and") == []


# --------------------------------------------------------------------------
# map_findings_to_attack
# --------------------------------------------------------------------------
async def test_les_constats_argus_sont_traduits() -> None:
    resultat = await map_findings_to_attack(
        ["leakedCredentials", "passwordSpray", "add member to role"]
    )

    identifiants = {m.technique_id for m in resultat.mapped}
    assert "T1110.003" in identifiants
    assert "T1098.003" in identifiants
    assert not resultat.unmapped


async def test_un_constat_sans_correspondance_est_liste_a_part() -> None:
    resultat = await map_findings_to_attack(["leakedCredentials", "invention"])

    assert resultat.unmapped == ["invention"]
    assert resultat.mapped


async def test_la_synthese_signale_une_progression_tardive() -> None:
    """Atteindre la persistance change la remédiation, pas seulement la gravité."""
    resultat = await map_findings_to_attack(["certificates and secrets management"])

    assert "persistence" in resultat.tactics_covered
    assert "mot de passe ne suffira pas" in resultat.summary


async def test_une_liste_vide_est_refusee() -> None:
    with pytest.raises(ValueError, match="au moins un"):
        await map_findings_to_attack([])


async def test_le_vocabulaire_est_consultable() -> None:
    resultat = await list_known_findings()

    assert resultat["count"] == len(constats_connus())
    assert "leakedcredentials" in resultat["findings"]


# --------------------------------------------------------------------------
# coverage_report
# --------------------------------------------------------------------------
async def test_la_couverture_compte_ce_qui_manque() -> None:
    resultat = await coverage_report(["T1566.002"], tactic="initial-access")

    assert resultat.covered == 1
    assert resultat.missing == resultat.scope_size - 1
    assert 0.0 < resultat.coverage_ratio < 1.0


async def test_un_identifiant_invalide_est_signale_pas_ignore() -> None:
    """Compter comme couverte une technique qui n'existe pas gonflerait le score."""
    resultat = await coverage_report(["T1566.002", "T9999", "n'importe quoi"])

    assert resultat.covered == 1
    assert sorted(resultat.invalid_inputs) == ["T9999", "n'importe quoi"]


async def test_la_couverture_se_restreint_a_une_plateforme() -> None:
    """Viser 100 % des 697 techniques n'a aucun sens pour un parc donné."""
    complet = await coverage_report([])
    cible = await coverage_report([], platform="Linux")

    assert cible.scope_size < complet.scope_size


# --------------------------------------------------------------------------
# Navigator
# --------------------------------------------------------------------------
async def test_la_couche_navigator_est_du_json_valide() -> None:
    resultat = await build_navigator_layer(["T1566.002", "T1078.004"], name="Incident 42")

    couche = json.loads(resultat.layer_json)
    assert couche["name"] == "Incident 42"
    assert couche["domain"] == "enterprise-attack"
    assert {t["techniqueID"] for t in couche["techniques"]} == {"T1566.002", "T1078.004"}


async def test_la_couche_signale_les_identifiants_inconnus() -> None:
    resultat = await build_navigator_layer(["T1566.002", "T9999"])

    assert resultat.techniques_included == 1
    assert resultat.unknown == ["T9999"]


async def test_une_couche_vide_est_refusee() -> None:
    with pytest.raises(ValueError, match="au moins une"):
        await build_navigator_layer([])


# --------------------------------------------------------------------------
# Divers
# --------------------------------------------------------------------------
async def test_les_tactiques_sont_ordonnees_et_comptees() -> None:
    tactiques = await list_tactics()

    assert len(tactiques) == 15
    assert all(t.technique_count > 0 for t in tactiques)
    # L'accès initial vient avant l'impact dans la chaîne d'attaque.
    noms = [t.shortname for t in tactiques]
    assert noms.index("initial-access") < noms.index("impact")


async def test_le_profil_de_groupe_donne_ses_alias() -> None:
    """Les éditeurs emploient des noms différents pour le même acteur."""
    corpus = charger()
    identifiant = next(iter(sorted(corpus.groups)))

    profil = await lookup_group(identifiant)

    assert profil.id == identifiant
    assert profil.name


async def test_un_groupe_inconnu_est_refuse() -> None:
    with pytest.raises(ValueError, match="inconnu"):
        await lookup_group("G9999")


async def test_le_serveur_annonce_son_fonctionnement_hors_ligne() -> None:
    info = await corpus_info()

    assert info.offline is True
    assert info.techniques > 500
    assert info.revoked_techniques > 0


def test_resoudre_identifiant_met_en_forme() -> None:
    assert resoudre_identifiant("  t1566.002  ") == "T1566.002"

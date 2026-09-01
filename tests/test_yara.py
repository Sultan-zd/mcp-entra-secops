"""Règles YARA : le pendant fichier des règles Sigma.

Deux bibliothèques de référence font le travail que ce module ne réinvente
pas — `plyara` pour la structure, `yara-python` (compilateur officiel) pour
la conformité. Un fait constaté en les éprouvant plutôt que supposé : les deux
ne sont pas tolérantes de la même façon. `plyara` rejette un nom de règle
absent ou commençant par un chiffre au niveau du lexer, mais tokenise sans
broncher une condition sémantiquement fausse. Ces tests figent ce que
l'expérimentation a révélé, pas ce que la documentation promettait.
"""

from __future__ import annotations

import pytest

from detection_mcp.tools import analyze_yara_rule
from detection_mcp.yara_rules import YaraError, analyser, evaluer_qualite, valider_strictement

REGLE_COMPLETE = """
rule apt_backdoor_dropper : APT malware
{
    meta:
        author = "analyste"
        description = "Detecte un dropper connu, chaine unique et condition selective"
        date = "2026-01-01"
        attack_technique = "T1055.003"
    strings:
        $s1 = "dropper_stub_unique_v2_marker" ascii fullword
        $hex1 = { 4D 5A 90 00 aa bb cc dd }
    condition:
        all of them
}
"""

REGLE_PAUVRE = """
rule x
{
    strings:
        $a = "a" nocase
        $b = "cmd"
    condition:
        any of them
}
"""


# --------------------------------------------------------------------------
# Lecture — la tolérance non uniforme de plyara, constatée en testant
# --------------------------------------------------------------------------
def test_une_regle_vide_est_refusee() -> None:
    with pytest.raises(YaraError) as erreur:
        analyser("")

    assert "Aucune règle" in str(erreur.value)


def test_un_nom_de_regle_absent_est_rejete_par_plyara_lui_meme() -> None:
    """`plyara` refuse ce cas au niveau du lexer, avant toute notation."""
    with pytest.raises(YaraError):
        analyser("rule { condition: true }")


def test_un_nom_commencant_par_un_chiffre_est_rejete() -> None:
    with pytest.raises(YaraError):
        analyser("rule 1invalide { condition: true }")


def test_une_condition_absurde_est_tout_de_meme_tokenisee() -> None:
    """`plyara` ne valide pas la sémantique de la condition : c'est
    `valider_strictement` (via le compilateur) qui doit s'en charger."""
    analyse = analyser("rule x { condition: this is not valid yara }")

    assert analyse.name == "x"
    ok, _motif = valider_strictement("rule x { condition: this is not valid yara }")
    assert ok is False


def test_les_metadonnees_et_chaines_sont_lues() -> None:
    analyse = analyser(REGLE_COMPLETE)

    assert analyse.name == "apt_backdoor_dropper"
    assert analyse.tags == ["APT", "malware"]
    assert analyse.metadata["author"] == "analyste"
    assert len(analyse.strings) == 2
    assert analyse.attack_techniques == ["T1055.003"]


# --------------------------------------------------------------------------
# Validation stricte — le compilateur officiel, avec son propre piège
# --------------------------------------------------------------------------
def test_une_regle_conforme_compile() -> None:
    ok, motif = valider_strictement(REGLE_COMPLETE)

    assert ok is True
    assert motif is None


def test_une_source_vide_ne_doit_pas_etre_declaree_valide() -> None:
    """Le piège vérifié avant d'écrire ce module : `yara.compile(source="")`
    réussit avec zéro règle compilée. S'y fier seul aurait validé un texte qui
    ne contient rien."""
    ok, motif = valider_strictement("")

    assert ok is False
    assert motif is not None


def test_un_module_yara_inconnu_est_refuse() -> None:
    ok, motif = valider_strictement('import "cuckoo"\nrule x { condition: true }')

    assert ok is False
    assert "cuckoo" in (motif or "")


def test_une_condition_semantiquement_fausse_est_refusee_a_la_compilation() -> None:
    ok, _motif = valider_strictement("rule x { condition: this is not valid yara }")

    assert ok is False


# --------------------------------------------------------------------------
# Qualité
# --------------------------------------------------------------------------
def test_une_regle_complete_obtient_la_note_maximale() -> None:
    analyse = analyser(REGLE_COMPLETE)
    qualite = evaluer_qualite(analyse)

    assert qualite.grade == "A"
    assert qualite.score == 100
    assert qualite.findings == []


def test_une_chaine_courte_sans_fullword_est_signalee() -> None:
    """La cause la plus fréquente de faux positifs en pratique : `$a = "a"`
    correspond à l'intérieur de n'importe quel mot qui contient un « a »."""
    analyse = analyser(REGLE_PAUVRE)
    qualite = evaluer_qualite(analyse)

    assert any("fullword" in f for f in qualite.findings)


def test_any_of_them_sur_des_chaines_generiques_est_signale() -> None:
    analyse = analyser(REGLE_PAUVRE)
    qualite = evaluer_qualite(analyse)

    assert any("any of them" in f or "1 of them" in f for f in qualite.findings)


def test_une_condition_permissive_est_signalee() -> None:
    permissive = """
    rule tout_accepte
    {
        meta:
            author = "a"
            description = "test"
        condition:
            true
    }
    """
    analyse = analyser(permissive)
    qualite = evaluer_qualite(analyse)

    assert any("ne filtre rien" in f for f in qualite.findings)


def test_absence_de_date_et_reference_est_signalee() -> None:
    sans_date = REGLE_COMPLETE.replace('\n        date = "2026-01-01"', "")
    analyse = analyser(sans_date)
    assert "date" not in analyse.metadata  # la substitution a bien retiré la ligne
    qualite = evaluer_qualite(analyse)

    assert any("Ni date ni référence" in f for f in qualite.findings)


def test_absence_d_identifiant_attack_est_signalee() -> None:
    sans_attack = REGLE_COMPLETE.replace('\n        attack_technique = "T1055.003"', "")
    analyse = analyser(sans_attack)
    assert analyse.attack_techniques == []  # la substitution a bien retiré la ligne
    qualite = evaluer_qualite(analyse)

    assert any("Aucun identifiant ATT&CK" in f for f in qualite.findings)


# --------------------------------------------------------------------------
# L'outil MCP : rattachement ATT&CK réutilisé de Sigma
# --------------------------------------------------------------------------
async def test_l_outil_rattache_a_att_ck() -> None:
    resultat = await analyze_yara_rule(rule=REGLE_COMPLETE)

    assert resultat.spec_compliant is True
    assert resultat.attack
    assert resultat.attack[0].id == "T1055.003"
    assert resultat.attack[0].status == "valide"


async def test_une_etiquette_revoquee_penalise_la_note() -> None:
    """Le même contrôle que pour Sigma, réutilisé sans dupliquer la logique :
    une technique révoquée ne doit pas compter dans le crédit ATT&CK."""
    perimee = REGLE_COMPLETE.replace("T1055.003", "T1562.001")

    resultat = await analyze_yara_rule(rule=perimee)

    revoquees = [t for t in resultat.attack if t.status == "revoquee"]
    assert len(revoquees) == 1
    assert any("RÉVOQUÉE" in f for f in resultat.attack_findings)
    assert resultat.quality.score < 100


async def test_une_regle_non_conforme_est_analysee_quand_meme() -> None:
    """Comme pour Sigma : c'est sur un brouillon que les conseils servent le
    plus, pas seulement sur une règle déjà parfaite."""
    resultat = await analyze_yara_rule(rule=REGLE_PAUVRE)

    assert resultat.spec_compliant is True  # syntaxiquement valide, juste de mauvaise qualité
    assert resultat.quality.grade in {"D", "F"}
    assert resultat.quality.findings


async def test_le_serveur_expose_l_outil_hors_ligne() -> None:
    from detection_mcp.server import build_server

    outils = {t.name: t for t in await (build_server()).list_tools()}

    assert "analyze_yara_rule" in outils
    annotations = outils["analyze_yara_rule"].annotations
    assert annotations is not None
    assert annotations.open_world_hint is False

"""D3FEND : le contrepoint défensif d'ATT&CK.

ATT&CK dit ce que fait un attaquant ; D3FEND dit quoi construire pour s'en
défendre. Ces tests portent surtout sur un piège des données réelles, constaté
en distillant le jeu de correspondances : D3FEND mappe très souvent des
sous-techniques, presque jamais leur parente.
"""

from __future__ import annotations

from mitre_mcp import d3fend
from mitre_mcp.corpus import charger as charger_attack
from mitre_mcp.tools import suggest_countermeasures


def test_les_correspondances_sont_chargees() -> None:
    correspondances = d3fend.charger()

    assert correspondances.framework == "enterprise"
    # Le jeu officiel en couvre plusieurs centaines : un fichier tronqué
    # passerait inaperçu sans cette borne.
    assert len(correspondances.techniques) > 250
    assert len(correspondances.countermeasures) > 100


def test_une_technique_directement_mappee_rend_ses_contremesures() -> None:
    suggestion = d3fend.suggerer("T1566.001")

    assert suggestion.countermeasures
    assert suggestion.via_subtechniques == {}
    assert suggestion.notes == []


def test_les_contremesures_portent_une_definition() -> None:
    """Un nom seul (« Content Filtering ») ne dit pas quoi faire."""
    suggestion = d3fend.suggerer("T1566.001")

    avec_definition = [c for c in suggestion.countermeasures if c.definition]
    assert avec_definition, "aucune contre-mesure ne porte de définition"


def test_les_contremesures_sont_triees_par_ordre_defensif() -> None:
    """Durcir avant de détecter : l'ordre a un sens opérationnel."""
    suggestion = d3fend.suggerer("T1566.001")
    tactiques = [c.tactic for c in suggestion.countermeasures]

    rang = {t: i for i, t in enumerate(d3fend.ORDRE_TACTIQUES)}
    rangs = [rang.get(t, len(rang)) for t in tactiques]
    assert rangs == sorted(rangs)


# --------------------------------------------------------------------------
# Le piège réel : mapping sur les sous-techniques, pas la parente
# --------------------------------------------------------------------------
def test_une_technique_non_mappee_directement_retrouve_ses_filles() -> None:
    """T1055 (Process Injection) n'a aucun mapping direct dans les données
    réelles ; dix de ses sous-techniques en ont. Rendre une liste vide ici
    serait un faux négatif."""
    corpus = charger_attack()
    sous = [t["id"] for t in corpus.sous_techniques("T1055")]

    suggestion = d3fend.suggerer("T1055", sous_techniques=sous)

    assert suggestion.countermeasures == []
    assert suggestion.via_subtechniques
    assert "T1055.003" in suggestion.via_subtechniques
    assert any("sous-technique" in n for n in suggestion.notes)


def test_une_technique_totalement_absente_le_dit_sans_lever() -> None:
    suggestion = d3fend.suggerer("T9999", sous_techniques=[])

    assert suggestion.countermeasures == []
    assert suggestion.via_subtechniques == {}
    assert any("Aucune contre-mesure" in n for n in suggestion.notes)


def test_sans_sous_techniques_fournies_le_repli_ne_trouve_rien() -> None:
    """Le repli dépend entièrement de ce qu'on lui passe : sans corpus ATT&CK
    en entrée, il ne devine pas la hiérarchie."""
    suggestion = d3fend.suggerer("T1055", sous_techniques=None)

    assert suggestion.via_subtechniques == {}
    assert any("Aucune contre-mesure" in n for n in suggestion.notes)


# --------------------------------------------------------------------------
# L'outil MCP
# --------------------------------------------------------------------------
async def test_l_outil_resout_la_hierarchie_lui_meme() -> None:
    """L'outil MCP doit fournir les sous-techniques sans que l'appelant ait à
    les connaître — c'est `corpus.sous_techniques` en interne."""
    resultat = await suggest_countermeasures(technique_id="T1055")

    assert resultat.countermeasures == []
    assert "T1055.003" in resultat.via_subtechniques
    assert resultat.via_subtechniques["T1055.003"]


async def test_l_outil_accepte_un_identifiant_minuscule() -> None:
    resultat = await suggest_countermeasures(technique_id="t1566.001")

    assert resultat.technique_id == "T1566.001"
    assert resultat.countermeasures


async def test_le_serveur_expose_l_outil_hors_ligne() -> None:
    from mitre_mcp.server import build_server

    outils = {t.name: t for t in await (build_server()).list_tools()}

    assert "suggest_countermeasures" in outils
    annotations = outils["suggest_countermeasures"].annotations
    assert annotations is not None
    assert annotations.open_world_hint is False

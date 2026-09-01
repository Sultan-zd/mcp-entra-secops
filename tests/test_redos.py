"""ReDoS : une forme suspecte ne suffit jamais, seule une exécution réelle compte.

Ces tests vérifient les deux étages séparément — la structure repère des
candidats, l'exécution chronométrée confirme ou innocente — et surtout leur
articulation : un motif dont la forme ressemble à un cas classique
(`(a|ab)+`) mais ne l'est pas en pratique doit être repéré puis innocenté,
pas signalé comme vulnérable sur la seule apparence du texte.
"""

from __future__ import annotations

import pytest

from detection_mcp import redos as rd
from detection_mcp.tools import check_redos


# --------------------------------------------------------------------------
# Analyse statique — repérage de candidats, jamais un verdict
# --------------------------------------------------------------------------
def test_quantificateurs_imbriques_sont_reperes() -> None:
    constats = rd.analyser_statique(r"(a+)+")

    assert any(c.kind == "quantificateurs_imbriques" for c in constats)


def test_alternance_ambigue_est_reperee() -> None:
    constats = rd.analyser_statique(r"(a|aa)+")

    assert any(c.kind == "alternance_ambigue" for c in constats)


def test_quantificateurs_adjacents_sont_reperes() -> None:
    constats = rd.analyser_statique(r"\d+\d+")

    assert any(c.kind == "quantificateurs_adjacents" for c in constats)


@pytest.mark.parametrize(
    "motif",
    [
        r"(ab)+",
        r"[a-zA-Z0-9]+@[a-zA-Z0-9.]+",
        r"\d{3}-\d{4}",
    ],
)
def test_les_motifs_sans_repetition_illimitee_qui_se_recouvre_ne_sont_pas_signales(
    motif: str,
) -> None:
    assert rd.analyser_statique(motif) == []


def test_deux_quantificateurs_adjacents_sur_alphabets_disjoints_restent_signales_en_surface() -> (
    None
):
    """`a+b+` a deux quantificateurs illimités adjacents, mais sur des
    alphabets disjoints : la structure seule ne le sait pas — elle ne
    regarde que la forme — et le signale donc en surface. C'est à la
    confirmation empirique, pas à la structure, de l'innocenter (test
    séparé plus bas)."""
    constats = rd.analyser_statique(r"a+b+")

    assert [c.kind for c in constats] == ["quantificateurs_adjacents"]


def test_un_motif_invalide_leve_redoserror() -> None:
    with pytest.raises(rd.RedosError):
        rd.analyser_statique(r"(")


def test_un_motif_sans_repetition_ne_rend_aucun_constat() -> None:
    assert rd.analyser_statique(r"^[A-Z]{3}-\d{4}$") == []


# --------------------------------------------------------------------------
# Confirmation empirique — le juge, c'est le moteur réel
# --------------------------------------------------------------------------
def test_quantificateurs_imbriques_sont_confirmes() -> None:
    """Cas classique : doit être confirmé, et rapidement (avant même le budget)."""
    constat = rd.analyser_statique(r"(a+)+")[0]

    sondage = rd.confirmer(r"(a+)+", constat, budget_s=3.0)

    assert sondage.confirmed is True


def test_alternance_ambigue_du_meme_alphabet_est_confirmee() -> None:
    constat = next(c for c in rd.analyser_statique(r"(a|aa)+") if c.kind == "alternance_ambigue")

    sondage = rd.confirmer(r"(a|aa)+", constat, budget_s=3.0)

    assert sondage.confirmed is True
    assert sondage.timings_ms


def test_une_forme_repere_mais_inoffensive_est_innocentee() -> None:
    """`(a|ab)+` a une branche vide après factorisation du préfixe commun —
    structurellement identique à `(a|aa)+` — mais l'attaque construite à
    partir de son échantillon ne déclenche aucune ambiguïté réelle : le moteur
    n'a qu'une seule façon de partitionner une suite de 'a'. La confirmation
    doit le dire, pas prétendre qu'il est sûr en le taisant."""
    constat = next(c for c in rd.analyser_statique(r"(a|ab)+") if c.kind == "alternance_ambigue")

    sondage = rd.confirmer(r"(a|ab)+", constat, budget_s=3.0)

    assert sondage.confirmed is False
    assert sondage.tested is True


def test_quantificateurs_adjacents_sur_alphabets_disjoints_ne_sont_pas_confirmes() -> None:
    constat = rd.analyser_statique(r"a+b+")[0]

    sondage = rd.confirmer(r"a+b+", constat, budget_s=3.0)

    assert sondage.confirmed is False


def test_quantificateurs_adjacents_sur_le_meme_moteur_ne_sont_pas_confirmes() -> None:
    """`\\d+\\d+` a deux quantificateurs adjacents mais reste linéaire dans le
    moteur `re` : la structure seule aurait fait croire à un risque réel."""
    constat = next(
        c for c in rd.analyser_statique(r"\d+\d+") if c.kind == "quantificateurs_adjacents"
    )

    sondage = rd.confirmer(r"\d+\d+", constat, budget_s=3.0)

    assert sondage.confirmed is False


def test_un_motif_qui_n_epuise_pas_le_budget_rend_des_mesures_croissantes() -> None:
    constat = next(c for c in rd.analyser_statique(r"(a|aa)+") if c.kind == "alternance_ambigue")

    sondage = rd.confirmer(r"(a|aa)+", constat, budget_s=3.0)

    longueurs = [n for n, _ in sondage.timings_ms]
    assert longueurs == sorted(longueurs)


# --------------------------------------------------------------------------
# L'outil MCP
# --------------------------------------------------------------------------
async def test_check_redos_confirme_un_motif_catastrophique() -> None:
    resultat = await check_redos(pattern=r"(a+)+")

    assert resultat.compiles is True
    assert resultat.vulnerable is True
    assert any(f.confirmed for f in resultat.findings)


async def test_check_redos_n_alerte_pas_sur_un_motif_sain() -> None:
    resultat = await check_redos(pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

    assert resultat.compiles is True
    assert resultat.vulnerable is False
    assert resultat.findings == []


async def test_check_redos_rend_compiles_false_sans_lever_sur_un_motif_invalide() -> None:
    resultat = await check_redos(pattern=r"(unclosed")

    assert resultat.compiles is False
    assert resultat.compile_error is not None
    assert resultat.vulnerable is False


async def test_check_redos_innocente_une_forme_reperee_mais_sans_risque_reel() -> None:
    resultat = await check_redos(pattern=r"(a|ab)+")

    assert resultat.compiles is True
    assert resultat.findings
    assert resultat.vulnerable is False
    assert all(f.confirmed is False for f in resultat.findings)


# --------------------------------------------------------------------------
# Composition du serveur
# --------------------------------------------------------------------------
async def test_check_redos_est_purement_local() -> None:
    from detection_mcp.server import build_server

    outils = {t.name: t for t in await (build_server()).list_tools()}

    assert "check_redos" in outils
    annotations = outils["check_redos"].annotations
    assert annotations is not None
    assert annotations.open_world_hint is False

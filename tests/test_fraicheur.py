"""L'âge des corpus embarqués : dit, pas subi.

Le défaut que ces tests verrouillent : un corpus figé répond avec exactement
la même assurance à six jours qu'à seize mois. Sans date, ni le destinataire
ni le modèle ne peuvent distinguer « cette technique n'existe pas dans
ATT&CK » de « n'existait pas encore lors de la construction ».

Les cas intéressants sont ceux qu'on ne peut pas observer aujourd'hui — un
corpus vieux d'un an, une date absente, un fichier illisible — d'où une date
de référence injectée plutôt que `date.today()`.
"""

from __future__ import annotations

from datetime import date

import pytest

from argus_net import fraicheur as fr

AUJOURDHUI = date(2026, 9, 1)


# --------------------------------------------------------------------------
# Le verdict sur une date
# --------------------------------------------------------------------------
def test_un_corpus_recent_n_est_pas_signale() -> None:
    f = fr.evaluer("ATT&CK", "2026-08-21", "19.2", aujourd_hui=AUJOURDHUI)

    assert f.stale is False
    assert f.age_days == 11
    assert f.source_version == "19.2"


def test_a_la_veille_du_seuil_rien_n_est_signale() -> None:
    """Le seuil est une frontière, pas une zone floue : 179 jours passe."""
    veille = date(2026, 9, 1).toordinal() - (fr.SEUIL_VIEILLISSANT_JOURS - 1)
    f = fr.evaluer("X", date.fromordinal(veille).isoformat(), aujourd_hui=AUJOURDHUI)

    assert f.age_days == fr.SEUIL_VIEILLISSANT_JOURS - 1
    assert f.stale is False


def test_au_seuil_exact_le_corpus_est_signale() -> None:
    jour = date(2026, 9, 1).toordinal() - fr.SEUIL_VIEILLISSANT_JOURS
    f = fr.evaluer("X", date.fromordinal(jour).isoformat(), aujourd_hui=AUJOURDHUI)

    assert f.age_days == fr.SEUIL_VIEILLISSANT_JOURS
    assert f.stale is True
    assert "probablement" in f.note


def test_au_dela_d_un_an_le_constat_est_plus_ferme() -> None:
    """Vieillissant et périmé ne disent pas la même chose : l'un invite à
    relativiser, l'autre dit que le corpus ne représente plus l'état publié."""
    jour = date(2026, 9, 1).toordinal() - fr.SEUIL_PERIME_JOURS
    f = fr.evaluer("X", date.fromordinal(jour).isoformat(), aujourd_hui=AUJOURDHUI)

    assert f.stale is True
    assert "certainement" in f.note
    assert "ne représentent plus" in f.note


def test_une_date_absente_est_traitee_comme_perimee() -> None:
    """Ne pas savoir depuis quand une donnée est figée est un défaut au moins
    aussi sérieux que de la savoir ancienne — jamais un silence rassurant."""
    f = fr.evaluer("X", None, aujourd_hui=AUJOURDHUI)

    assert f.stale is True
    assert f.age_days is None
    assert "aucune date" in f.note


@pytest.mark.parametrize("valeur", ["", "   ", "hier", "2026-13-45", "20260901"])
def test_une_date_illisible_est_traitee_comme_absente(valeur: str) -> None:
    f = fr.evaluer("X", valeur, aujourd_hui=AUJOURDHUI)

    assert f.stale is True
    assert f.age_days is None


def test_une_date_dans_le_futur_est_signalee_comme_telle() -> None:
    """Une horloge fausse ne doit pas produire un corpus « très frais »."""
    f = fr.evaluer("X", "2027-01-01", aujourd_hui=AUJOURDHUI)

    assert f.stale is True
    assert f.age_days is not None and f.age_days < 0
    assert "futur" in f.note


def test_le_script_de_regeneration_est_rendu_quand_il_est_fourni() -> None:
    f = fr.evaluer("X", None, regenerer_avec="python scripts/distiller_x.py",
                   aujourd_hui=AUJOURDHUI)

    assert "scripts/distiller_x.py" in f.note


def test_une_date_horodatee_est_acceptee() -> None:
    """Les distillateurs écrivent une date nue, mais une date ISO complète ne
    doit pas être rejetée comme illisible."""
    f = fr.evaluer("X", "2026-08-21T14:33:02Z", aujourd_hui=AUJOURDHUI)

    assert f.stale is False
    assert f.age_days == 11


# --------------------------------------------------------------------------
# Les quatre corpus réellement embarqués
# --------------------------------------------------------------------------
async def test_corpus_info_date_les_quatre_referentiels() -> None:
    from mitre_mcp.tools import corpus_info

    rapport = await corpus_info()
    noms = {d.name for d in rapport.datasets}

    assert noms == {"MITRE ATT&CK", "MITRE D3FEND", "CWE", "Événements Windows / Sysmon"}
    for jeu in rapport.datasets:
        assert jeu.distilled_at, f"{jeu.name} n'est pas daté"


async def test_les_corpus_livres_sont_a_jour() -> None:
    """Le paquet ne doit pas partir avec un corpus déjà périmé.

    Ce test échouera tout seul le jour où un corpus dépassera le seuil : c'est
    le rappel voulu, et non une fragilité.
    """
    from mitre_mcp.tools import corpus_info

    rapport = await corpus_info()

    assert rapport.stale_datasets == [], (
        "Corpus à régénérer : "
        + "; ".join(d.note for d in rapport.datasets if d.stale)
    )


async def test_un_corpus_vieilli_remonte_dans_stale_datasets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Le chemin qu'on ne peut pas observer avec les corpus d'aujourd'hui."""
    import mitre_mcp.corpus as corpus_module
    from mitre_mcp.tools import corpus_info

    reel = corpus_module.charger()
    vieux = type(reel)(
        version=reel.version,
        distilled_at="2020-01-01",
        techniques=reel.techniques,
        tactics=reel.tactics,
        mitigations=reel.mitigations,
        groups=reel.groups,
        revoked=reel.revoked,
        counts=reel.counts,
    )
    monkeypatch.setattr(corpus_module, "charger", lambda: vieux)

    rapport = await corpus_info()

    assert "MITRE ATT&CK" in rapport.stale_datasets
    assert "régénérer" in rapport.note


async def test_un_corpus_illisible_est_rendu_et_non_omis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omettre un corpus en panne laisserait croire que le paquet n'en embarque
    que trois : l'absence serait plus trompeuse que l'erreur."""
    import mitre_mcp.d3fend as d3fend_module
    from mitre_mcp.tools import corpus_info

    def _casse() -> None:
        raise d3fend_module.D3fendError("fichier absent")

    monkeypatch.setattr(d3fend_module, "charger", _casse)

    rapport = await corpus_info()
    d3fend = next(d for d in rapport.datasets if d.name == "MITRE D3FEND")

    assert len(rapport.datasets) == 4
    assert d3fend.stale is True
    assert "distiller_d3fend.py" in d3fend.note

"""La référence des événements Windows / Sysmon embarquée.

Deux sources distinctes, jamais fusionnées sous une échelle commune : l'audit
de sécurité Windows (« Appendix L », avec une criticité éditoriale Microsoft)
et Sysmon (page Sysinternals officielle, sans criticité — Microsoft n'en
publie pas pour ces IDs, et ce module n'en invente pas). Ces tests vérifient
que cette distinction tient, et que les collisions réelles de la source
(un ID courant portant deux notes, un ID legacy scindé en plusieurs IDs
courants) sont rendues plutôt qu'écrasées.
"""

from __future__ import annotations

import pytest

from detection_mcp import windows_events as we
from detection_mcp.tools import lookup_windows_event, search_windows_events


# --------------------------------------------------------------------------
# Le catalogue chargé
# --------------------------------------------------------------------------
def test_le_catalogue_est_charge_et_complet() -> None:
    catalogue = we.charger()

    assert len(catalogue.securite) > 300
    assert len(catalogue.sysmon) >= 29


def test_un_evenement_de_securite_courant_est_trouve() -> None:
    resultats = we.evenement_securite("4688")

    assert len(resultats) == 1
    assert resultats[0]["summary"] == "A new process has been created."
    assert "592" in resultats[0]["legacy_ids"]


def test_un_id_legacy_seul_est_trouve_par_son_ancien_numero() -> None:
    """608 événements de la source n'ont pas d'ID moderne : seul legacy fonctionne."""
    resultats = we.evenement_securite("550")

    assert len(resultats) == 1
    assert resultats[0]["current_id"] is None
    assert "denial-of-service" in resultats[0]["summary"].lower()


def test_un_id_courant_duplique_rend_ses_deux_entrees() -> None:
    """4764 porte deux notes distinctes dans la source (667 et 668) : les deux
    doivent apparaître, la deuxième n'écrase pas la première."""
    resultats = we.evenement_securite("4764")

    assert len(resultats) == 2
    resumes = {r["summary"] for r in resultats}
    assert "A security-disabled group was deleted." in resumes
    assert "A group's type was changed." in resumes


def test_un_id_legacy_scinde_rend_tous_ses_ids_courants() -> None:
    """602 a été scindé en cinq événements de tâche planifiée distincts."""
    resultats = we.evenement_securite("602")

    courants = {r["current_id"] for r in resultats}
    assert courants == {"4698", "4699", "4700", "4701", "4702"}


def test_un_id_de_securite_inconnu_ne_rend_rien() -> None:
    assert we.evenement_securite("999999") == []


# --------------------------------------------------------------------------
# Sysmon — sans criticité
# --------------------------------------------------------------------------
def test_un_evenement_sysmon_est_trouve() -> None:
    evenement = we.evenement_sysmon(1)

    assert evenement is not None
    assert evenement["name"] == "Process creation"
    assert "criticality" not in evenement


def test_evenement_sysmon_accepte_une_chaine() -> None:
    assert we.evenement_sysmon("11")["name"] == "FileCreate"


def test_un_id_sysmon_inconnu_ne_rend_rien() -> None:
    assert we.evenement_sysmon(999) is None


def test_les_ids_sysmon_et_securite_ne_se_confondent_pas() -> None:
    """Sysmon ID 1 et un éventuel « 1 » côté sécurité ne désignent rien de
    commun : les deux index sont interrogés séparément, jamais l'un pour
    l'autre."""
    assert we.evenement_sysmon(1) is not None
    assert we.evenement_securite("1") == []


# --------------------------------------------------------------------------
# Recherche libre
# --------------------------------------------------------------------------
def test_recherche_securite_par_mot_cle() -> None:
    resultats = we.chercher_securite("kerberos")

    assert resultats
    assert all("kerberos" in r["summary"].lower() for r in resultats)


def test_recherche_sysmon_par_mot_cle() -> None:
    resultats = we.chercher_sysmon("clipboard")

    assert resultats
    assert resultats[0]["id"] == 24


# --------------------------------------------------------------------------
# Les outils MCP
# --------------------------------------------------------------------------
async def test_lookup_windows_event_trouve_un_evenement_de_securite() -> None:
    resultat = await lookup_windows_event(event_id="4688")

    assert len(resultat.security_matches) == 1
    assert resultat.security_matches[0].current_id == "4688"
    assert resultat.sysmon_matches == []
    assert resultat.note is None


async def test_lookup_windows_event_trouve_un_evenement_sysmon() -> None:
    resultat = await lookup_windows_event(event_id="11")

    assert resultat.sysmon_matches
    assert resultat.sysmon_matches[0].name == "FileCreate"
    assert resultat.security_matches == []


async def test_lookup_windows_event_sysmon_ne_porte_pas_de_criticite() -> None:
    """Un contrôle direct sur le modèle rendu à l'appelant : `SysmonEvent`
    n'a pas de champ criticité, il ne peut donc pas en afficher une inventée."""
    resultat = await lookup_windows_event(event_id="1")

    assert resultat.sysmon_matches
    assert not hasattr(resultat.sysmon_matches[0], "criticality")


async def test_lookup_windows_event_id_inconnu_rend_une_note() -> None:
    resultat = await lookup_windows_event(event_id="999999")

    assert resultat.security_matches == []
    assert resultat.sysmon_matches == []
    assert resultat.note is not None


async def test_search_windows_events_all_interroge_les_deux_sources() -> None:
    resultat = await search_windows_events(query="process")

    assert resultat.security_matches or resultat.sysmon_matches


async def test_search_windows_events_restreint_a_une_source() -> None:
    resultat = await search_windows_events(query="clipboard", source="sysmon")

    assert resultat.sysmon_matches
    assert resultat.security_matches == []


async def test_search_windows_events_refuse_une_requete_vide() -> None:
    with pytest.raises(ValueError):
        await search_windows_events(query="   ")


async def test_search_windows_events_refuse_une_source_invalide() -> None:
    with pytest.raises(ValueError):
        await search_windows_events(query="test", source="splunk")


# --------------------------------------------------------------------------
# Composition du serveur
# --------------------------------------------------------------------------
async def test_les_outils_windows_events_sont_purement_locaux() -> None:
    from detection_mcp.server import build_server

    outils = {t.name: t for t in await (build_server()).list_tools()}

    for nom in ("lookup_windows_event", "search_windows_events"):
        assert nom in outils
        annotations = outils[nom].annotations
        assert annotations is not None
        assert annotations.open_world_hint is False

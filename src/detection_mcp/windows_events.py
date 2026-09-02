"""Référence des événements Windows embarquée, chargée une fois et indexée.

Deux sources, deux natures — jamais mélangées sous une échelle commune :

* **`security`** — canal `Security` (audit Windows natif), IDs 4xxx/5xxx/6xx.
  Chaque entrée porte une `criticality` (`Low` à `High`) : un jugement
  éditorial de Microsoft, tenu à jour dans « Appendix L: Events to Monitor »
  (`MicrosoftDocs/windowsserverdocs`).
* **`sysmon`** — canal `Microsoft-Windows-Sysmon/Operational`, IDs 1-29 et 255.
  **Aucune criticité** : Sysmon journalise ce que sa configuration lui
  demande, et la page officielle Sysinternals qui documente ces IDs n'en
  publie pas. Ce module n'en invente pas non plus — `SysmonEvent` n'a pas de
  champ criticité, plutôt que d'en afficher une approximée.

Un même identifiant numérique peut exister dans les deux canaux sans rapport
(Sysmon ID 1 « Process creation » n'a rien à voir avec l'audit Windows) : les
fonctions de consultation sont donc séparées par source, jamais fusionnées à
l'aveugle sur le seul numéro.

Le fichier est régénéré par `scripts/distiller_windows_events.py`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

FICHIER = Path(__file__).parent / "fixtures" / "windows_events.json"


class WindowsEventsError(RuntimeError):
    """La référence des événements Windows n'a pas pu être chargée."""


@dataclass(frozen=True)
class Catalogue:
    """La référence indexée, prête à interroger."""

    distilled_at: str | None
    securite: list[dict[str, Any]]
    sysmon: list[dict[str, Any]]
    index_courant: dict[str, list[dict[str, Any]]]
    index_legacy: dict[str, list[dict[str, Any]]]
    index_sysmon: dict[int, dict[str, Any]]


def _normaliser_id(identifiant: str | int) -> str:
    return str(identifiant).strip().lstrip("0") or "0"


def _construire_index(
    securite: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    index_courant: dict[str, list[dict[str, Any]]] = {}
    index_legacy: dict[str, list[dict[str, Any]]] = {}
    for evenement in securite:
        courant = evenement.get("current_id")
        if courant:
            index_courant.setdefault(_normaliser_id(courant), []).append(evenement)
        for legacy in evenement.get("legacy_ids") or []:
            index_legacy.setdefault(_normaliser_id(legacy), []).append(evenement)
    return index_courant, index_legacy


@lru_cache(maxsize=1)
def charger() -> Catalogue:
    """Charge la référence embarquée. Le résultat est mémorisé pour la session."""
    if not FICHIER.exists():
        raise WindowsEventsError(
            f"Référence des événements Windows introuvable ({FICHIER}). "
            "Régénérez-la avec « python scripts/distiller_windows_events.py »."
        )
    try:
        donnees = json.loads(FICHIER.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WindowsEventsError(f"Référence des événements Windows illisible : {exc}") from exc

    securite = donnees.get("security", {}).get("events", [])
    sysmon = donnees.get("sysmon", {}).get("events", [])
    index_courant, index_legacy = _construire_index(securite)
    index_sysmon = {int(e["id"]): e for e in sysmon}

    return Catalogue(
        distilled_at=donnees.get("distilled_at"),
        securite=securite,
        sysmon=sysmon,
        index_courant=index_courant,
        index_legacy=index_legacy,
        index_sysmon=index_sysmon,
    )


def evenement_securite(identifiant: str | int) -> list[dict[str, Any]]:
    """Les entrées d'audit de sécurité pour cet ID — courant d'abord, puis historique.

    Une liste, pas une entrée unique : un même ID courant peut porter plusieurs
    lignes distinctes dans la source (cas réel — 4764 couvre à la fois « groupe
    supprimé » et « type de groupe modifié », deux notes historiques
    différentes que la source ne fusionne pas). Un même ID legacy peut aussi
    avoir été scindé en plusieurs IDs courants (602 → cinq événements de tâche
    planifiée distincts).
    """
    catalogue = charger()
    cle = _normaliser_id(identifiant)
    trouves = catalogue.index_courant.get(cle)
    if trouves:
        return trouves
    return catalogue.index_legacy.get(cle, [])


def evenement_sysmon(identifiant: int | str) -> dict[str, Any] | None:
    catalogue = charger()
    try:
        cle = int(identifiant)
    except (TypeError, ValueError):
        return None
    return catalogue.index_sysmon.get(cle)


def chercher_securite(requete: str, limite: int = 15) -> list[dict[str, Any]]:
    """Recherche libre sur le résumé des événements de sécurité."""
    catalogue = charger()
    mots = [m for m in requete.lower().split() if m]
    if not mots:
        return []
    resultats = []
    for evenement in catalogue.securite:
        cible = evenement.get("summary", "").lower()
        if all(mot in cible for mot in mots):
            resultats.append(evenement)
            if len(resultats) >= limite:
                break
    return resultats


def chercher_sysmon(requete: str, limite: int = 15) -> list[dict[str, Any]]:
    """Recherche libre sur le nom et la description des événements Sysmon."""
    catalogue = charger()
    mots = [m for m in requete.lower().split() if m]
    if not mots:
        return []
    resultats = []
    for evenement in catalogue.sysmon:
        cible = f"{evenement.get('name', '')} {evenement.get('description', '')}".lower()
        if all(mot in cible for mot in mots):
            resultats.append(evenement)
            if len(resultats) >= limite:
                break
    return resultats

"""Le catalogue CWE embarqué, chargé une fois et indexé.

Aucun accès réseau. Le catalogue officiel pèse 18 Mo de XML et change deux à
quatre fois par an ; le distiller à la construction rend ces outils utilisables
**hors ligne**, comme le corpus ATT&CK de ce même projet.

**Ce que ce module apporte, au-delà de la définition.** `lookup_cve` rend déjà
les identifiants CWE cités par NVD (`weaknesses: list[str]`) — mais un
identifiant seul ne dit ni ce qu'il faut tester, ni s'il désigne vraiment une
faiblesse précise. Deux informations que ce catalogue distillé porte et
qu'aucune autre source de ce projet n'a :

* **`mapping_usage`.** MITRE classe chaque CWE selon son aptitude à être
  assigné à une CVE précise — `Allowed`, `Discouraged`, `Prohibited`. Un CWE
  `Prohibited` cité sur une CVE réelle est un défaut de la fiche NVD, pas
  seulement une information de plus : c'est le même principe que les
  techniques ATT&CK révoquées.
* **`abstraction`.** Un `Pillar` ou une `Class` sont trop généraux pour
  répondre à « comment tester ceci » ; un `Base` ou un `Variant` le sont assez.

Le fichier est régénéré par `scripts/distiller_cwe.py`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

FICHIER = Path(__file__).parent / "fixtures" / "cwe.json"

#: Ces deux niveaux d'abstraction regroupent des dizaines de CWE plus précis :
#: assignés seuls à une vulnérabilité, ils ne disent presque rien à tester.
ABSTRACTIONS_LARGES = frozenset({"Pillar", "Class"})

#: Ce que MITRE déconseille ou interdit d'assigner à une vulnérabilité précise.
USAGES_PROBLEMATIQUES = frozenset({"Discouraged", "Prohibited"})


class CweError(RuntimeError):
    """Le catalogue CWE n'a pas pu être chargé."""


@dataclass(frozen=True)
class Catalogue:
    """Le catalogue CWE indexé, prêt à interroger."""

    version: str
    date: str
    distilled_at: str | None
    weaknesses: dict[str, dict[str, Any]]

    def faiblesse(self, identifiant: str) -> dict[str, Any] | None:
        return self.weaknesses.get(_normaliser(identifiant))


def _normaliser(identifiant: str) -> str:
    """« 502 », « cwe-502 » ou « CWE-502 » désignent tous la même entrée."""
    valeur = identifiant.strip().upper()
    if not valeur.startswith("CWE-"):
        valeur = f"CWE-{valeur}"
    return valeur


@lru_cache(maxsize=1)
def charger() -> Catalogue:
    """Charge le catalogue embarqué. Le résultat est mémorisé pour la session."""
    if not FICHIER.exists():
        raise CweError(
            f"Catalogue CWE introuvable ({FICHIER}). "
            "Régénérez-le avec « python scripts/distiller_cwe.py »."
        )
    try:
        donnees = json.loads(FICHIER.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CweError(f"Catalogue CWE illisible : {exc}") from exc

    return Catalogue(
        version=str(donnees.get("version", "?")),
        date=str(donnees.get("date", "?")),
        distilled_at=donnees.get("distilled_at"),
        weaknesses=donnees.get("weaknesses", {}),
    )


@dataclass
class EvaluationMapping:
    """Ce que vaut l'assignation de ce CWE à une vulnérabilité précise."""

    id: str
    name: str = ""
    abstraction: str | None = None
    usage: str | None = None
    rationale: str | None = None
    problematic: bool = False
    notes: list[str] = field(default_factory=list)


def evaluer_mapping(identifiant: str) -> EvaluationMapping:
    """Dit si citer ce CWE sur une CVE précise a du sens.

    C'est le contrôle qu'aucune fiche NVD ne fait elle-même : NVD accepte le
    CWE renseigné par le déclarant sans le confronter à sa propre classification
    d'aptitude au mapping.
    """
    catalogue = charger()
    identifiant_normalise = _normaliser(identifiant)
    faiblesse = catalogue.faiblesse(identifiant_normalise)

    if faiblesse is None:
        return EvaluationMapping(
            id=identifiant_normalise,
            problematic=True,
            notes=[
                f"{identifiant_normalise} n'existe pas dans le catalogue CWE "
                f"v{catalogue.version}."
            ],
        )

    evaluation = EvaluationMapping(
        id=faiblesse["id"],
        name=faiblesse.get("name", ""),
        abstraction=faiblesse.get("abstraction"),
        usage=faiblesse.get("mapping_usage"),
        rationale=faiblesse.get("mapping_rationale"),
    )

    if evaluation.usage in USAGES_PROBLEMATIQUES:
        evaluation.problematic = True
        evaluation.notes.append(
            f"MITRE classe ce CWE « {evaluation.usage} » pour l'assignation à une "
            "vulnérabilité précise"
            + (f" : {evaluation.rationale}" if evaluation.rationale else ".")
        )

    if evaluation.abstraction in ABSTRACTIONS_LARGES:
        evaluation.problematic = True
        evaluation.notes.append(
            f"Abstraction « {evaluation.abstraction} » : cette entrée regroupe "
            "plusieurs faiblesses plus précises. Elle dit peu de choses sur ce "
            "qu'il faut tester concrètement."
        )

    return evaluation


def chercher(requete: str, limite: int = 15) -> list[dict[str, Any]]:
    """Recherche libre sur le nom et la description, sans pondération savante.

    Le catalogue compte moins de mille entrées : un simple filtre suffit, une
    pertinence calculée finement n'apporterait rien de mesurable.
    """
    catalogue = charger()
    mots = [m for m in requete.lower().split() if m]
    if not mots:
        return []

    resultats = []
    for faiblesse in catalogue.weaknesses.values():
        cible = f"{faiblesse.get('name', '')} {faiblesse.get('description', '')}".lower()
        if all(mot in cible for mot in mots):
            resultats.append(faiblesse)
            if len(resultats) >= limite:
                break
    return resultats

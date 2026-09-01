"""Le contrepoint défensif d'ATT&CK, embarqué et indexé.

ATT&CK dit ce que fait un attaquant ; **D3FEND dit quoi construire pour s'en
défendre**. À chaque technique, D3FEND nomme des contre-mesures concrètes,
classées par tactique défensive — Harden, Detect, Isolate, Deceive, Evict,
Model, Restore — plutôt qu'un conseil générique.

Distillé depuis les correspondances officielles publiées par MITRE (aucun
texte inventé) : `scripts/distiller_d3fend.py` régénère le fichier.

**Le piège que ce module traite explicitement.** D3FEND mappe très souvent des
*sous-techniques*, pas leur technique parente — `T1055.003` a des contre-
mesures nommées, `T1055` seul n'en a aucune, alors même que ses dix
sous-techniques en ont. Rendre « aucune contre-mesure » pour `T1055` serait un
faux négatif : la réponse existe, une couche plus bas. `suggerer()` la
retrouve donc, comme `map_findings_to_attack` refuse de confondre un constat
non traduit avec l'absence de correspondance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

FICHIER = Path(__file__).parent / "fixtures" / "d3fend.json"

#: Les sept tactiques défensives de D3FEND, dans l'ordre où elles interviennent
#: face à une attaque : anticiper la surface, la durcir, puis détecter,
#: isoler, tromper, évincer et enfin restaurer.
ORDRE_TACTIQUES = ("Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore")


class D3fendError(RuntimeError):
    """Le jeu de correspondances D3FEND n'a pas pu être chargé."""


@dataclass(frozen=True)
class Correspondances:
    """Les correspondances D3FEND embarquées, prêtes à interroger."""

    framework: str
    distilled_at: str | None
    techniques: dict[str, list[dict[str, str]]]
    countermeasures: dict[str, dict[str, str | None]]


@lru_cache(maxsize=1)
def charger() -> Correspondances:
    """Charge le jeu embarqué. Le résultat est mémorisé pour la session."""
    if not FICHIER.exists():
        raise D3fendError(
            f"Correspondances D3FEND introuvables ({FICHIER}). "
            "Régénérez-les avec « python scripts/distiller_d3fend.py »."
        )
    try:
        donnees = json.loads(FICHIER.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise D3fendError(f"Fichier D3FEND illisible : {exc}") from exc

    return Correspondances(
        framework=str(donnees.get("framework", "?")),
        distilled_at=donnees.get("distilled_at"),
        techniques=donnees.get("techniques", {}),
        countermeasures=donnees.get("countermeasures", {}),
    )


@dataclass
class ContreMesure:
    """Une contre-mesure D3FEND nommée, avec sa tactique et sa définition."""

    countermeasure: str
    tactic: str
    definition: str | None = None
    d3fend_id: str | None = None
    relationship: str | None = None
    artifact: str | None = None


@dataclass
class Suggestion:
    """Ce que D3FEND propose pour une technique — directement ou par ses filles."""

    technique_id: str
    countermeasures: list[ContreMesure] = field(default_factory=list)
    # Rempli quand la technique elle-même n'a pas de mapping direct, mais que
    # ses sous-techniques en ont — la clé est l'identifiant de sous-technique.
    via_subtechniques: dict[str, list[ContreMesure]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _construire(entree: dict[str, str], correspondances: Correspondances) -> ContreMesure:
    detail = correspondances.countermeasures.get(entree["countermeasure"], {})
    return ContreMesure(
        countermeasure=entree["countermeasure"],
        tactic=entree.get("tactic", ""),
        definition=detail.get("definition"),
        d3fend_id=detail.get("d3fend_id"),
        relationship=entree.get("relationship"),
        artifact=entree.get("artifact"),
    )


def _trier(mesures: list[ContreMesure]) -> list[ContreMesure]:
    """Dans l'ordre où une défense se construit : durcir avant de détecter."""
    rang = {tactique: i for i, tactique in enumerate(ORDRE_TACTIQUES)}
    return sorted(mesures, key=lambda m: (rang.get(m.tactic, len(rang)), m.countermeasure))


def suggerer(technique_id: str, sous_techniques: list[str] | None = None) -> Suggestion:
    """Les contre-mesures D3FEND pour une technique, avec le repli sur ses filles.

    `sous_techniques` vient du corpus ATT&CK embarqué (`corpus.sous_techniques`)
    — ce module ne connaît pas la hiérarchie des techniques par lui-même, il
    ne fait que confronter des identifiants au jeu de correspondances D3FEND.
    """
    correspondances = charger()
    identifiant = technique_id.strip().upper()
    resultat = Suggestion(technique_id=identifiant)

    brutes = correspondances.techniques.get(identifiant)
    if brutes:
        resultat.countermeasures = _trier([_construire(e, correspondances) for e in brutes])
        return resultat

    # Repli : la technique elle-même n'a rien, ses sous-techniques peut-être.
    for sous_id in sorted(sous_techniques or []):
        brutes_sous = correspondances.techniques.get(sous_id.strip().upper())
        if brutes_sous:
            resultat.via_subtechniques[sous_id.strip().upper()] = _trier(
                [_construire(e, correspondances) for e in brutes_sous]
            )

    if resultat.via_subtechniques:
        resultat.notes.append(
            f"D3FEND ne mappe pas {identifiant} directement, mais "
            f"{len(resultat.via_subtechniques)} de ses sous-techniques ont des "
            "contre-mesures nommées — voir ci-dessous."
        )
    else:
        resultat.notes.append(
            f"Aucune contre-mesure D3FEND, ni pour {identifiant} ni pour ses "
            "sous-techniques. Rester sur les recommandations génériques de la "
            "tactique ATT&CK reste la meilleure option disponible."
        )

    return resultat

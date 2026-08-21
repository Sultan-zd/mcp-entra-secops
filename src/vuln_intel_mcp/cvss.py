"""Calcul CVSS, entièrement local.

Ce module n'appelle rien. Il prend un vecteur — `CVSS:3.1/AV:N/AC:L/...` — et
recalcule la note à partir de la spécification. C'est la différence entre lire
un chiffre qu'on vous donne et savoir d'où il vient.

**À quoi ça sert concrètement.** Un bulletin de sécurité annonce un vecteur et
une note. Les deux ne concordent pas toujours : erreur de transcription,
recalcul maison, ou note choisie avant le vecteur. Recalculer permet de le
voir. Cela permet aussi de répondre à « et si l'attaquant était déjà
authentifié ? » sans redemander quoi que ce soit à personne.

Formules : *CVSS v3.1 Specification Document*, section 8.1.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

#: Poids des métriques d'exploitabilité et d'impact, tels que la norme les fixe.
POIDS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

#: Les privilèges requis pèsent différemment selon que le périmètre change :
#: obtenir un privilège devient plus rentable quand il déborde du composant.
POIDS_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}

#: Libellés lisibles, pour que la sortie ne soit pas une suite de lettres.
LIBELLES: dict[str, dict[str, str]] = {
    "AV": {
        "N": "réseau — exploitable à distance",
        "A": "réseau adjacent — même segment",
        "L": "local — accès à la machine requis",
        "P": "physique — accès matériel requis",
    },
    "AC": {"L": "complexité faible", "H": "complexité élevée"},
    "PR": {"N": "aucun privilège", "L": "privilèges faibles", "H": "privilèges élevés"},
    "UI": {"N": "aucune interaction", "R": "interaction d'un utilisateur requise"},
    "S": {"U": "périmètre inchangé", "C": "périmètre changé"},
    "C": {
        "H": "confidentialité : élevé",
        "L": "confidentialité : faible",
        "N": "confidentialité : aucun",
    },
    "I": {"H": "intégrité : élevé", "L": "intégrité : faible", "N": "intégrité : aucun"},
    "A": {
        "H": "disponibilité : élevé",
        "L": "disponibilité : faible",
        "N": "disponibilité : aucun",
    },
}

METRIQUES_BASE = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_VECTEUR = re.compile(r"^CVSS:(3\.0|3\.1|4\.0)/(.+)$", re.IGNORECASE)


class CvssError(ValueError):
    """Un vecteur CVSS que la norme ne reconnaît pas."""


@dataclass(frozen=True)
class ScoreCvss:
    """Le résultat d'un calcul, avec de quoi le contester."""

    version: str
    vector: str
    base_score: float
    severity: str
    metrics: dict[str, str]
    explained: dict[str, str]
    exploitability: float
    impact: float
    computed: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "vector": self.vector,
            "base_score": self.base_score,
            "severity": self.severity,
            "metrics": self.metrics,
            "explained": self.explained,
            "exploitability_subscore": self.exploitability,
            "impact_subscore": self.impact,
            "computed_locally": self.computed,
        }


def severite(score: float) -> str:
    """Échelle qualitative de la norme (section 5)."""
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _arrondi_superieur(valeur: float) -> float:
    """L'arrondi de la norme, qui n'est pas celui de Python.

    La spécification impose le plus petit nombre à une décimale supérieur ou
    égal à l'entrée, et en donne une formulation entière pour éviter les
    surprises de la virgule flottante. Un `round()` ordinaire donne 8.5 là où
    la norme veut 8.6 sur certains vecteurs — un écart d'une classe de
    sévérité.
    """
    entier = round(valeur * 100_000)
    if entier % 10_000 == 0:
        return entier / 100_000.0
    return (math.floor(entier / 10_000) + 1) / 10.0


def parse_vector(vecteur: str) -> tuple[str, dict[str, str]]:
    """Découpe un vecteur en métriques, et refuse ce qui n'est pas conforme."""
    brut = vecteur.strip()
    correspondance = _VECTEUR.match(brut)
    if not correspondance:
        raise CvssError(
            "Vecteur non reconnu. Attendu : « CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H »."
        )

    version = correspondance.group(1)
    metriques: dict[str, str] = {}
    for morceau in correspondance.group(2).split("/"):
        if ":" not in morceau:
            raise CvssError(f"Composant illisible dans le vecteur : « {morceau} ».")
        cle, _, valeur = morceau.partition(":")
        metriques[cle.strip().upper()] = valeur.strip().upper()

    return version, metriques


def _valider_base(metriques: dict[str, str]) -> None:
    manquantes = [m for m in METRIQUES_BASE if m not in metriques]
    if manquantes:
        raise CvssError("Métriques de base manquantes : " + ", ".join(manquantes) + ".")
    for cle in ("AV", "AC", "UI", "C", "I", "A"):
        if metriques[cle] not in POIDS[cle]:
            raise CvssError(f"Valeur « {metriques[cle]} » invalide pour la métrique {cle}.")
    if metriques["S"] not in ("U", "C"):
        raise CvssError(f"Valeur « {metriques['S']} » invalide pour la métrique S.")
    if metriques["PR"] not in POIDS_PR[metriques["S"]]:
        raise CvssError(f"Valeur « {metriques['PR']} » invalide pour la métrique PR.")


def score_v3(vecteur: str) -> ScoreCvss:
    """Recalcule la note de base d'un vecteur CVSS v3.0 ou v3.1."""
    version, metriques = parse_vector(vecteur)
    if version.startswith("4"):
        raise CvssError("Ce vecteur est en CVSS v4.0 : utilisez la lecture dédiée.")
    _valider_base(metriques)

    perimetre_change = metriques["S"] == "C"

    # Impact intermédiaire : la part du système réellement touchée.
    iss = 1.0 - (
        (1.0 - POIDS["C"][metriques["C"]])
        * (1.0 - POIDS["I"][metriques["I"]])
        * (1.0 - POIDS["A"][metriques["A"]])
    )

    # Écrit en if/else et non en ternaire : les deux formules sont celles de
    # la norme, et les mettre sur une ligne les rendrait illisibles.
    if perimetre_change:  # noqa: SIM108
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitabilite = (
        8.22
        * POIDS["AV"][metriques["AV"]]
        * POIDS["AC"][metriques["AC"]]
        * POIDS_PR[metriques["S"]][metriques["PR"]]
        * POIDS["UI"][metriques["UI"]]
    )

    if impact <= 0:
        note = 0.0
    elif perimetre_change:
        note = _arrondi_superieur(min(1.08 * (impact + exploitabilite), 10.0))
    else:
        note = _arrondi_superieur(min(impact + exploitabilite, 10.0))

    return ScoreCvss(
        version=version,
        vector=vecteur.strip(),
        base_score=note,
        severity=severite(note),
        metrics={m: metriques[m] for m in METRIQUES_BASE},
        explained={m: LIBELLES[m][metriques[m]] for m in METRIQUES_BASE},
        exploitability=round(exploitabilite, 2),
        impact=round(impact, 2),
        computed=True,
    )


def lire_v4(vecteur: str) -> ScoreCvss:
    """Lit un vecteur CVSS v4.0 sans en recalculer la note.

    La v4.0 ne se calcule pas par une formule mais par une table de
    correspondance de plusieurs centaines d'entrées. Plutôt que d'en
    réimplémenter une version approximative — qui donnerait des notes fausses
    avec l'assurance d'un calcul —, le vecteur est décodé et la note est
    laissée à sa source. Le champ `computed_locally` le dit.
    """
    version, metriques = parse_vector(vecteur)
    if not version.startswith("4"):
        raise CvssError("Ce vecteur n'est pas en CVSS v4.0.")

    lisibles = {cle: LIBELLES.get(cle, {}).get(valeur, valeur) for cle, valeur in metriques.items()}
    return ScoreCvss(
        version=version,
        vector=vecteur.strip(),
        base_score=0.0,
        severity="unknown",
        metrics=metriques,
        explained=lisibles,
        exploitability=0.0,
        impact=0.0,
        computed=False,
    )


def evaluer(vecteur: str) -> ScoreCvss:
    """Point d'entrée : calcule en v3, décode en v4."""
    version, _ = parse_vector(vecteur)
    return lire_v4(vecteur) if version.startswith("4") else score_v3(vecteur)

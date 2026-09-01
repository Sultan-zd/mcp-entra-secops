"""Le corpus ATT&CK embarqué, chargé une fois et indexé.

Aucun accès réseau. Le paquet STIX officiel pèse 51 Mo et change quatre fois
par an ; le distiller à la construction plutôt que de le télécharger à chaque
démarrage rend ces outils utilisables **hors ligne**, en salle blanche comme
sur un poste sans Internet — ce qu'aucun relais d'API ne permet.

Le fichier est régénéré par `scripts/distiller_attack.py`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

FICHIER = Path(__file__).parent / "fixtures" / "attack.json"

#: Mots trop fréquents pour discriminer quoi que ce soit dans une recherche.
VIDES = frozenset(
    {
        "the",
        "a",
        "an",
        "of",
        "to",
        "in",
        "and",
        "or",
        "for",
        "with",
        "on",
        "by",
        "is",
        "are",
        "be",
        "may",
        "can",
        "that",
        "this",
        "from",
        "as",
        "le",
        "la",
        "les",
        "de",
        "des",
        "du",
        "un",
        "une",
        "et",
        "ou",
        "pour",
        "dans",
        "sur",
        "par",
        "est",
        "sont",
        "que",
        "qui",
    }
)

_MOT = re.compile(r"[a-z0-9]+")

#: Un identifiant de technique, avec ou sans sous-technique.
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


class CorpusError(RuntimeError):
    """Le corpus embarqué est absent ou illisible."""


@dataclass(frozen=True)
class Corpus:
    """Le corpus indexé, prêt à interroger."""

    version: str
    distilled_at: str | None
    techniques: dict[str, dict[str, Any]]
    tactics: dict[str, dict[str, Any]]
    mitigations: dict[str, dict[str, Any]]
    groups: dict[str, dict[str, Any]]
    revoked: dict[str, dict[str, Any]]
    counts: dict[str, int]

    def technique(self, identifiant: str) -> dict[str, Any] | None:
        return self.techniques.get(identifiant.strip().upper())

    def revoquee(self, identifiant: str) -> dict[str, Any] | None:
        """Une technique retirée du référentiel, et ce qui la remplace.

        ATT&CK révoque des techniques à chaque version majeure — la famille
        T1562 a disparu en v19. Répondre « inconnue » à un analyste qui cite
        un identifiant réel mais périmé serait trompeur : il conclurait à une
        faute de frappe alors qu'il lui manque une mise à jour.
        """
        return self.revoked.get(identifiant.strip().upper())

    def sous_techniques(self, parent: str) -> list[dict[str, Any]]:
        """Les variantes d'une technique parente, triées."""
        cible = parent.strip().upper()
        return sorted(
            (t for t in self.techniques.values() if t.get("parent") == cible),
            key=lambda t: t["id"],
        )

    def par_tactique(self, shortname: str) -> list[dict[str, Any]]:
        cible = shortname.strip().lower()
        return sorted(
            (t for t in self.techniques.values() if cible in (t.get("tactics") or [])),
            key=lambda t: t["id"],
        )


def _index(entrees: list[dict[str, Any]], cle: str = "id") -> dict[str, dict[str, Any]]:
    return {str(e[cle]).upper(): e for e in entrees if e.get(cle)}


@lru_cache(maxsize=1)
def charger() -> Corpus:
    """Charge le corpus embarqué. Le résultat est mémorisé pour la session."""
    if not FICHIER.exists():
        raise CorpusError(
            f"Corpus ATT&CK introuvable ({FICHIER}). "
            "Régénérez-le avec « python scripts/distiller_attack.py »."
        )
    try:
        brut = json.loads(FICHIER.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CorpusError(f"Corpus ATT&CK illisible : {exc}") from exc

    return Corpus(
        version=brut.get("attack_version", "inconnue"),
        distilled_at=brut.get("distilled_at"),
        techniques=_index(brut.get("techniques", [])),
        tactics={t["shortname"]: t for t in brut.get("tactics", []) if t.get("shortname")},
        mitigations=_index(brut.get("mitigations", [])),
        groups=_index(brut.get("groups", [])),
        revoked=_index(brut.get("revoked", [])),
        counts=brut.get("counts", {}),
    )


def _texte_detection(technique: dict[str, Any]) -> str:
    """Aplatit la détection structurée en texte, pour la recherche.

    Depuis ATT&CK v19 la détection n'est plus une chaîne mais une liste de
    stratégies, chacune portant des analytiques et leurs sources de journaux.
    """
    morceaux: list[str] = []
    for strategie in technique.get("detection") or []:
        morceaux.append(str(strategie.get("strategy") or ""))
        for analytique in strategie.get("analytics") or []:
            morceaux.append(str(analytique.get("guidance") or ""))
            morceaux.extend(str(s) for s in analytique.get("log_sources") or [])
    return " ".join(morceaux)


def _mots(texte: str) -> list[str]:
    return [m for m in _MOT.findall(texte.lower()) if m not in VIDES and len(m) > 2]


def chercher(
    requete: str,
    *,
    plateforme: str | None = None,
    tactique: str | None = None,
    limite: int = 20,
) -> list[tuple[dict[str, Any], float]]:
    """Recherche par pertinence, entièrement locale.

    Le classement est simple et explicable : un mot trouvé dans le nom pèse
    beaucoup plus que le même mot noyé dans une description. C'est ce qu'attend
    quelqu'un qui tape « phishing » — il veut T1566, pas les quarante
    techniques dont la description mentionne le mot au détour d'une phrase.
    """
    corpus = charger()
    termes = _mots(requete)
    if not termes:
        return []

    resultats: list[tuple[dict[str, Any], float]] = []
    for technique in corpus.techniques.values():
        if plateforme and plateforme.lower() not in {
            p.lower() for p in technique.get("platforms") or []
        }:
            continue
        if tactique and tactique.lower() not in (technique.get("tactics") or []):
            continue

        nom = (technique.get("name") or "").lower()
        description = (technique.get("description") or "").lower()
        detection = _texte_detection(technique).lower()

        score = 0.0
        for terme in termes:
            if terme in nom:
                # Un mot exact dans le nom est le signal le plus fort.
                score += 10.0 if re.search(rf"\b{re.escape(terme)}\b", nom) else 6.0
            if terme in description:
                score += 2.0
            if terme in detection:
                score += 1.0

        # Tous les termes présents dans le nom : c'est très probablement la
        # technique cherchée.
        if all(t in nom for t in termes):
            score += 8.0

        if score > 0:
            resultats.append((technique, score))

    resultats.sort(key=lambda r: (-r[1], r[0]["id"]))
    return resultats[:limite]


def resoudre_identifiant(valeur: str) -> str:
    """Valide un identifiant de technique et le met en forme canonique."""
    propre = valeur.strip().upper()
    if not TECHNIQUE_ID.match(propre):
        raise ValueError(
            f"« {valeur} » n'est pas un identifiant de technique ATT&CK. "
            "Format attendu : T1566 ou T1566.002."
        )
    return propre

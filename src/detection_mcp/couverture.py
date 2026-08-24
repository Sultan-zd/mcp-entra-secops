"""Relie les règles de détection au référentiel ATT&CK embarqué.

C'est ce que ce serveur apporte qu'aucune bibliothèque Sigma ne fait : une
règle porte des étiquettes `attack.tXXXX`, mais rien ne vérifie qu'elles
désignent des techniques réelles, encore en vigueur, et cohérentes avec la
source de journal visée.

**Les trois défauts silencieux traités ici :**

* Une étiquette qui cite une technique **révoquée**. ATT&CK en retire à chaque
  version majeure — 161 dans la v19 embarquée. La règle fonctionne, mais elle
  ne compte pour rien dans une revue de couverture, et personne ne s'en aperçoit.
* Une étiquette qui cite un identifiant **inexistant** : faute de frappe qui ne
  provoque aucune erreur.
* Une technique qui ne s'applique **pas à la plateforme** que la règle
  interroge — une règle sur les journaux Azure étiquetée d'une technique
  Windows uniquement ne détectera jamais ce qu'elle annonce.

Aucun accès réseau : le corpus est dans le paquet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Correspondance entre les `logsource` de Sigma et les plateformes ATT&CK.
#: Volontairement partielle : une correspondance devinée produirait de fausses
#: alertes d'incohérence, plus nuisibles que l'absence de contrôle.
PLATEFORMES = {
    "windows": {"Windows"},
    "linux": {"Linux"},
    "macos": {"macOS"},
    "azure": {"IaaS", "Identity Provider", "SaaS"},
    "aws": {"IaaS"},
    "gcp": {"IaaS"},
    "m365": {"Office Suite", "SaaS", "Identity Provider"},
    "office365": {"Office Suite", "SaaS"},
    "okta": {"Identity Provider", "SaaS"},
    "onelogin": {"Identity Provider", "SaaS"},
    "kubernetes": {"Containers"},
    "esxi": {"ESXi"},
}


@dataclass
class TechniqueLiee:
    """Une étiquette ATT&CK d'une règle, confrontée au référentiel."""

    tag: str
    id: str
    status: str  # "valide" | "revoquee" | "inconnue"
    name: str | None = None
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    url: str | None = None
    replaced_by: str | None = None
    detection_guidance: list[str] = field(default_factory=list)
    note: str | None = None


@dataclass
class Couverture:
    """Ce que les étiquettes d'une règle valent, une fois vérifiées."""

    techniques: list[TechniqueLiee] = field(default_factory=list)
    tactics_covered: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    attack_version: str = ""

    @property
    def valides(self) -> int:
        return sum(1 for t in self.techniques if t.status == "valide")


def _guidance(technique: dict[str, Any], limite: int = 3) -> list[str]:
    """Ce qu'ATT&CK recommande de surveiller pour cette technique.

    Sert à répondre à la seule question qui compte devant une règle étiquetée :
    couvre-t-elle vraiment ce que la technique décrit ?
    """
    conseils: list[str] = []
    for strategie in technique.get("detection") or []:
        for analytique in strategie.get("analytics") or []:
            texte = (analytique.get("guidance") or "").strip()
            if texte and texte not in conseils:
                conseils.append(texte)
            if len(conseils) >= limite:
                return conseils
    return conseils


def _plateformes_attendues(logsource: dict[str, str]) -> set[str]:
    """Les plateformes ATT&CK que la `logsource` d'une règle peut couvrir."""
    attendues: set[str] = set()
    for valeur in logsource.values():
        attendues |= PLATEFORMES.get(valeur.strip().lower(), set())
    return attendues


def lier(
    tags_techniques: list[str],
    logsource: dict[str, str] | None = None,
) -> Couverture:
    """Confronte les étiquettes ATT&CK d'une règle au corpus embarqué."""
    from mitre_mcp.corpus import charger

    corpus = charger()
    couverture = Couverture(attack_version=corpus.version)

    if not tags_techniques:
        couverture.findings.append(
            "Aucune technique ATT&CK en étiquette : cette règle n'apparaîtra dans "
            "aucune revue de couverture."
        )
        return couverture

    attendues = _plateformes_attendues(logsource or {})
    tactiques: list[str] = []

    for tag in tags_techniques:
        identifiant = tag.strip().upper()
        technique = corpus.technique(identifiant)

        if technique:
            liee = TechniqueLiee(
                tag=tag,
                id=identifiant,
                status="valide",
                name=technique.get("name"),
                tactics=list(technique.get("tactics") or []),
                platforms=list(technique.get("platforms") or []),
                url=technique.get("url"),
                detection_guidance=_guidance(technique),
            )
            for tactique in liee.tactics:
                if tactique not in tactiques:
                    tactiques.append(tactique)

            if attendues and liee.platforms and not (attendues & set(liee.platforms)):
                liee.note = (
                    f"{identifiant} ne s'applique qu'à "
                    + ", ".join(liee.platforms)
                    + " — or la règle interroge une source d'un autre type."
                )
                couverture.findings.append(liee.note)

            if not liee.detection_guidance:
                liee.note = (liee.note or "") + (
                    f" ATT&CK ne publie aucune analytique pour {identifiant} : "
                    "la pertinence de la règle ne peut pas être confrontée au référentiel."
                ).strip()

            couverture.techniques.append(liee)
            continue

        revoquee = corpus.revoquee(identifiant)
        if revoquee:
            remplacant = revoquee.get("replaced_by")
            nom_remplacant = revoquee.get("replaced_by_name")
            couverture.techniques.append(
                TechniqueLiee(
                    tag=tag,
                    id=identifiant,
                    status="revoquee",
                    name=revoquee.get("name"),
                    replaced_by=remplacant,
                    note=f"{identifiant} a été révoquée dans ATT&CK v{corpus.version}.",
                )
            )
            couverture.findings.append(
                f"L'étiquette {identifiant} désigne une technique RÉVOQUÉE"
                + (
                    f", remplacée par {remplacant}"
                    + (f" ({nom_remplacant})" if nom_remplacant else "")
                    if remplacant
                    else ""
                )
                + ". La règle ne sera comptée dans aucune revue de couverture tant "
                "que l'étiquette n'est pas corrigée."
            )
            continue

        couverture.techniques.append(
            TechniqueLiee(
                tag=tag,
                id=identifiant,
                status="inconnue",
                note=f"{identifiant} n'existe pas dans ATT&CK v{corpus.version}.",
            )
        )
        couverture.findings.append(
            f"L'étiquette {identifiant} ne correspond à aucune technique connue — "
            "vérifier la saisie."
        )

    couverture.tactics_covered = sorted(tactiques)
    return couverture

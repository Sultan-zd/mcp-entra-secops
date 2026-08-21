"""Dans quel ordre corriger.

C'est la question que pose vraiment un analyste, et à laquelle une note CVSS
seule ne répond pas. Une faille notée 9.8 que personne n'exploite est moins
pressante qu'une 6.5 inscrite au catalogue des vulnérabilités activement
exploitées : la première est un risque théorique, la seconde est une attaque en
cours quelque part.

Le classement est **déterministe et par paliers**, pas par score mélangé. Un
palier se justifie devant un responsable — « la CISA impose une correction pour
le 3 septembre » — là où un nombre composite de 73,4 ne se justifie pas.

Les seuils suivent la logique de leurs auteurs :

* Le catalogue **KEV** ne liste que des failles dont l'exploitation est
  constatée. Il n'y a rien à pondérer : c'est un fait, il passe devant.
* **EPSS** estime la probabilité d'exploitation à trente jours. Le seuil de
  0,10 retenu ici place environ le centile 90 — au-delà, la faille se
  distingue nettement de la masse.
* **CVSS** ne mesure que la gravité *si* l'exploitation a lieu. Il départage,
  il ne décide pas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Literal

Palier = Literal["immediate", "urgent", "planifie", "differe", "indetermine"]

#: Au-delà, la faille sort nettement du lot des vulnérabilités jamais exploitées.
SEUIL_EPSS_ELEVE = 0.10

#: En dessous, l'exploitation reste une hypothèse d'école.
SEUIL_EPSS_FAIBLE = 0.01

SEUIL_CVSS_ELEVE = 7.0
SEUIL_CVSS_CRITIQUE = 9.0

#: Ordre d'affichage des paliers, du plus pressant au moins pressant.
ORDRE_PALIERS: dict[Palier, int] = {
    "immediate": 0,
    "urgent": 1,
    "indetermine": 2,
    "planifie": 3,
    "differe": 4,
}

LIBELLES_PALIERS: dict[Palier, str] = {
    "immediate": "Exploitation constatée — corriger sans attendre",
    "urgent": "Exploitation probable à court terme",
    "indetermine": "Données insuffisantes — à qualifier manuellement",
    "planifie": "À planifier dans le cycle de correctifs",
    "differe": "Faible priorité",
}


@dataclass
class Vulnerabilite:
    """Ce qu'on sait d'une faille au moment de la classer."""

    cve: str
    cvss: float | None = None
    severity: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_due: str | None = None
    kev_ransomware: bool = False
    title: str | None = None


@dataclass
class Classement:
    """Une faille classée, avec la raison de son rang."""

    cve: str
    tier: Palier
    tier_label: str
    rank: int = 0
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    kev_due: str | None = None
    days_to_due: int | None = None
    rationale: list[str] = field(default_factory=list)
    title: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "cve": self.cve,
            "rank": self.rank,
            "tier": self.tier,
            "tier_label": self.tier_label,
            "cvss": self.cvss,
            "epss": self.epss,
            "known_exploited": self.kev,
            "kev_due_date": self.kev_due,
            "days_to_due_date": self.days_to_due,
            "rationale": self.rationale,
            "title": self.title,
        }


def _jours_restants(echeance: str | None) -> int | None:
    """Jours avant l'échéance CISA, négatif si elle est dépassée."""
    if not echeance:
        return None
    try:
        cible = date.fromisoformat(echeance[:10])
    except ValueError:
        return None
    return (cible - datetime.now(UTC).date()).days


def _palier(v: Vulnerabilite) -> tuple[Palier, list[str]]:
    """Décide du palier, et dit pourquoi."""
    raisons: list[str] = []

    if v.kev:
        raisons.append(
            "Inscrite au catalogue CISA des vulnérabilités activement exploitées : "
            "l'exploitation est constatée, pas supposée."
        )
        if v.kev_ransomware:
            raisons.append("Utilisée par des campagnes de rançongiciel.")
        jours = _jours_restants(v.kev_due)
        if jours is not None:
            if jours < 0:
                raisons.append(f"Échéance CISA dépassée de {abs(jours)} jour(s).")
            else:
                raisons.append(f"Échéance CISA dans {jours} jour(s) ({v.kev_due}).")
        return "immediate", raisons

    # Sans note ni probabilité, on ne sait rien — et ne rien savoir n'est pas
    # une bonne nouvelle. Le cas remonte pour qualification humaine plutôt que
    # de tomber silencieusement en bas de liste.
    if v.cvss is None and v.epss is None:
        raisons.append(
            "Ni note CVSS ni probabilité EPSS disponibles : impossible de classer "
            "automatiquement. À qualifier à la main."
        )
        return "indetermine", raisons

    epss = v.epss or 0.0
    cvss = v.cvss or 0.0

    if epss >= SEUIL_EPSS_ELEVE:
        pct = f" (centile {v.epss_percentile:.0%})" if v.epss_percentile is not None else ""
        raisons.append(
            f"Probabilité d'exploitation à 30 jours de {epss:.1%}{pct}, "
            f"au-dessus du seuil de {SEUIL_EPSS_ELEVE:.0%}."
        )
        if cvss >= SEUIL_CVSS_ELEVE:
            raisons.append(f"Gravité élevée si exploitée (CVSS {cvss}).")
        return "urgent", raisons

    if cvss >= SEUIL_CVSS_CRITIQUE:
        raisons.append(
            f"Note critique (CVSS {cvss}), mais exploitation peu probable à court terme."
        )
        if epss < SEUIL_EPSS_FAIBLE:
            raisons.append(f"EPSS de {epss:.2%} : aucune exploitation observée à ce jour.")
        return "planifie", raisons

    if cvss >= SEUIL_CVSS_ELEVE:
        raisons.append(f"Gravité élevée (CVSS {cvss}) sans signal d'exploitation.")
        return "planifie", raisons

    raisons.append(f"Gravité modérée (CVSS {cvss}) et exploitation improbable (EPSS {epss:.2%}).")
    return "differe", raisons


def _cle_de_tri(c: Classement) -> tuple[int, int, float, float, str]:
    """Ordre à l'intérieur d'un palier.

    L'échéance CISA prime sur tout le reste dans le palier immédiat : c'est une
    obligation datée, pas une appréciation. Ailleurs, la probabilité
    d'exploitation passe devant la gravité — l'ordre inverse ferait remonter des
    failles spectaculaires que personne n'attaque.
    """
    return (
        ORDRE_PALIERS[c.tier],
        c.days_to_due if c.days_to_due is not None else 10_000,
        -(c.epss or 0.0),
        -(c.cvss or 0.0),
        c.cve,
    )


def prioriser(vulnerabilites: list[Vulnerabilite]) -> list[Classement]:
    """Classe les failles de la plus pressante à la moins pressante."""
    classements: list[Classement] = []

    for v in vulnerabilites:
        palier, raisons = _palier(v)
        classements.append(
            Classement(
                cve=v.cve,
                tier=palier,
                tier_label=LIBELLES_PALIERS[palier],
                cvss=v.cvss,
                epss=round(v.epss, 5) if v.epss is not None else None,
                kev=v.kev,
                kev_due=v.kev_due,
                days_to_due=_jours_restants(v.kev_due),
                rationale=raisons,
                title=v.title,
            )
        )

    classements.sort(key=_cle_de_tri)
    for position, c in enumerate(classements, start=1):
        c.rank = position
    return classements


def synthese(classements: list[Classement]) -> dict[str, object]:
    """Le compte par palier, et ce qu'il faut retenir en une phrase."""
    comptes: dict[str, int] = {}
    for c in classements:
        comptes[c.tier] = comptes.get(c.tier, 0) + 1

    immediates = comptes.get("immediate", 0)
    urgentes = comptes.get("urgent", 0)
    depassees = sum(1 for c in classements if c.days_to_due is not None and c.days_to_due < 0)

    if depassees:
        message = (
            f"{depassees} vulnérabilité(s) dépassent leur échéance CISA. "
            "Elles sont exploitées et la correction est en retard."
        )
    elif immediates:
        message = (
            f"{immediates} vulnérabilité(s) activement exploitée(s) : "
            "à traiter avant tout le reste."
        )
    elif urgentes:
        message = f"{urgentes} vulnérabilité(s) à forte probabilité d'exploitation."
    elif comptes.get("indetermine"):
        message = (
            f"{comptes['indetermine']} vulnérabilité(s) sans données exploitables : "
            "à qualifier manuellement avant de conclure."
        )
    else:
        message = "Aucune vulnérabilité pressante dans ce lot."

    return {
        "total": len(classements),
        "by_tier": comptes,
        "past_due": depassees,
        "summary": message,
    }

"""Formes de sortie des outils de renseignement sur les vulnérabilités.

Une fiche NVD brute contient des centaines de configurations CPE et des
dizaines de références. La transmettre entière noierait l'essentiel et
coûterait cher en contexte. Ces modèles disent ce qui survit à la troncature.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "none", "unknown"]

#: Au-delà, la liste des références cesse d'aider et commence à encombrer.
MAX_REFERENCES = 8

#: Idem pour les produits affectés : les premiers suffisent à identifier.
MAX_PRODUITS = 10


class Reference(BaseModel):
    """Un lien, avec ce qu'il apporte."""

    url: str
    tags: list[str] = Field(default_factory=list, description="Nature du lien selon le NVD.")


class KevInfo(BaseModel):
    """Ce que dit le catalogue CISA d'une vulnérabilité."""

    listed: bool = Field(description="Inscrite au catalogue des failles exploitées.")
    date_added: str | None = Field(default=None, description="Date d'inscription.")
    due_date: str | None = Field(default=None, description="Échéance de correction imposée.")
    days_to_due: int | None = Field(
        default=None, description="Jours restants, négatif si dépassée."
    )
    known_ransomware: bool = Field(
        default=False, description="Utilisée par des campagnes de rançongiciel."
    )
    required_action: str | None = Field(default=None, description="Action exigée par la CISA.")
    catalog_stale: bool = Field(
        default=False,
        description=(
            "Le catalogue n'a pas pu être rafraîchi : réponse fondée sur une version antérieure."
        ),
    )


class EpssInfo(BaseModel):
    """Probabilité d'exploitation, telle que la publie le FIRST."""

    score: float | None = Field(default=None, description="Probabilité d'exploitation à 30 jours.")
    percentile: float | None = Field(default=None, description="Rang parmi toutes les CVE notées.")
    interpretation: str | None = Field(default=None, description="Ce que ce chiffre signifie.")


class CvssInfo(BaseModel):
    """Note de gravité, et si nous l'avons recalculée."""

    version: str | None = None
    vector: str | None = None
    base_score: float | None = None
    severity: Severity = "unknown"
    computed_locally: bool = Field(
        default=False,
        description=(
            "Vrai si la note a été recalculée à partir du vecteur, faux si elle "
            "est reprise telle quelle."
        ),
    )
    matches_published: bool | None = Field(
        default=None,
        description=(
            "Vrai si notre calcul reproduit la note publiée. Faux signale une "
            "incohérence dans la source."
        ),
    )


class CveReport(BaseModel):
    """Fiche d'une vulnérabilité, croisée entre les trois sources."""

    cve: str = Field(description="Identifiant de la vulnérabilité.")
    published: str | None = Field(default=None, description="Date de publication.")
    last_modified: str | None = Field(default=None, description="Dernière modification.")
    status: str | None = Field(default=None, description="État de l'analyse NVD.")
    description: str | None = Field(default=None, description="Description, en anglais.")
    cvss: CvssInfo
    cwe: list[str] = Field(default_factory=list, description="Types de faiblesse (CWE).")
    kev: KevInfo
    epss: EpssInfo
    affected_products: list[str] = Field(
        default_factory=list, description="Produits affectés, tronqué."
    )
    references: list[Reference] = Field(default_factory=list, description="Liens utiles, tronqué.")
    priority: str = Field(description="Palier de correction recommandé.")
    priority_reason: list[str] = Field(
        default_factory=list, description="Pourquoi ce palier a été retenu."
    )
    notes: list[str] = Field(default_factory=list, description="Constats à porter à l'analyste.")


class CveSummary(BaseModel):
    """Fiche courte, pour les listes de résultats."""

    cve: str
    published: str | None = None
    cvss_score: float | None = None
    severity: Severity = "unknown"
    known_exploited: bool = False
    epss: float | None = None
    description: str | None = Field(default=None, description="Description tronquée.")


class SearchResult(BaseModel):
    """Résultat d'une recherche de vulnérabilités."""

    query: str
    total_available: int = Field(description="Total annoncé par le NVD, avant troncature.")
    returned: int = Field(description="Nombre de fiches rendues.")
    results: list[CveSummary] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class PrioritizedList(BaseModel):
    """Classement de plusieurs vulnérabilités par urgence réelle."""

    total: int
    by_tier: dict[str, int] = Field(description="Nombre de vulnérabilités par palier.")
    past_due: int = Field(description="Nombre dépassant leur échéance CISA.")
    summary: str = Field(description="Ce qu'il faut retenir, en une phrase.")
    ranked: list[dict[str, Any]] = Field(
        default_factory=list, description="Classement, du plus pressant."
    )
    unresolved: list[str] = Field(
        default_factory=list, description="Identifiants introuvables dans les sources."
    )
    catalog_stale: bool = False


class CvssBreakdown(BaseModel):
    """Décomposition d'un vecteur CVSS, calculée localement."""

    version: str
    vector: str
    base_score: float
    severity: Severity
    metrics: dict[str, str] = Field(description="Métriques du vecteur.")
    explained: dict[str, str] = Field(description="Chaque métrique en français.")
    exploitability_subscore: float
    impact_subscore: float
    computed_locally: bool
    notes: list[str] = Field(default_factory=list)


class KevStats(BaseModel):
    """État du catalogue CISA."""

    catalog_version: str | None = None
    released: str | None = None
    total_entries: int = 0
    added_last_30_days: int = 0
    ransomware_linked: int = 0
    past_due_public: int = Field(
        default=0, description="Entrées dont l'échéance publique est dépassée."
    )
    recent: list[dict[str, Any]] = Field(
        default_factory=list, description="Dernières inscriptions."
    )
    catalog_stale: bool = False


class WeaknessConsequence(BaseModel):
    """Une paire portée/impact — ce que l'exploitation compromet."""

    scope: str
    impact: str


class DetectionMethod(BaseModel):
    """Une méthode susceptible de repérer cette faiblesse dans du code réel."""

    method: str
    description: str | None = None


class WeaknessDetail(BaseModel):
    """Une entrée du catalogue CWE, avec ce qui décide si elle s'applique."""

    id: str
    name: str
    abstraction: str | None = Field(
        default=None,
        description="Pillar/Class/Base/Variant/Compound. Un Pillar ou une Class "
        "regroupe des dizaines de faiblesses plus précises.",
    )
    status: str | None = None
    description: str | None = None
    likelihood: str | None = None
    consequences: list[WeaknessConsequence] = Field(default_factory=list)
    detection_methods: list[DetectionMethod] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    parents: list[str] = Field(
        default_factory=list, description="CWE plus généraux dont celui-ci est un cas particulier."
    )
    mapping_usage: str | None = Field(
        default=None,
        description="Allowed / Allowed-with-Review / Discouraged / Prohibited — "
        "l'aptitude de ce CWE, selon MITRE, à être assigné à une vulnérabilité précise.",
    )
    mapping_rationale: str | None = None
    mapping_warning: str | None = Field(
        default=None,
        description="Rempli quand ce CWE ne devrait probablement pas désigner une "
        "vulnérabilité précise — à lire avant de s'appuyer sur cet identifiant.",
    )


class WeaknessSummary(BaseModel):
    """Fiche courte, pour les résultats de recherche."""

    id: str
    name: str
    abstraction: str | None = None
    mapping_usage: str | None = None


class WeaknessSearchResult(BaseModel):
    """Résultat d'une recherche dans le catalogue CWE."""

    query: str
    total: int
    results: list[WeaknessSummary] = Field(default_factory=list)

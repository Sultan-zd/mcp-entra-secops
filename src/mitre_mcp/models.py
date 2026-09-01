"""Formes de sortie des outils ATT&CK."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TechniqueSummary(BaseModel):
    """Fiche courte, pour les listes."""

    id: str = Field(description="Identifiant ATT&CK, par exemple T1566.002.")
    name: str
    tactics: list[str] = Field(default_factory=list, description="Tactiques, en forme courte.")
    platforms: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False


class TechniqueDetail(BaseModel):
    """Fiche complète d'une technique."""

    id: str
    name: str
    description: str | None = Field(default=None, description="Description, tronquée.")
    tactics: list[str] = Field(default_factory=list)
    tactic_names: list[str] = Field(default_factory=list, description="Tactiques, en clair.")
    platforms: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    parent: str | None = Field(default=None, description="Technique parente, le cas échéant.")
    subtechniques: list[TechniqueSummary] = Field(default_factory=list)
    detection: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Stratégies de détection, chacune avec ses analytiques et les sources "
            "de journaux à collecter. Depuis ATT&CK v19, la détection nomme des "
            "canaux concrets plutôt qu'un texte libre."
        ),
    )
    log_sources: list[str] = Field(
        default_factory=list,
        description="Sources de journaux nommées par les analytiques, dédoublonnées.",
    )
    data_sources: list[str] = Field(
        default_factory=list, description="Sources de données à collecter."
    )
    mitigations: list[dict[str, Any]] = Field(
        default_factory=list, description="Parades recommandées par MITRE."
    )
    known_actors: list[str] = Field(
        default_factory=list, description="Groupes connus pour l'employer."
    )
    known_software: list[str] = Field(
        default_factory=list, description="Outils qui l'implémentent."
    )
    url: str | None = None
    attack_version: str


class TacticSummary(BaseModel):
    """Une tactique, c'est-à-dire un objectif d'attaquant."""

    id: str
    name: str
    shortname: str = Field(description="Forme courte, celle qui sert de filtre.")
    description: str | None = None
    technique_count: int = Field(description="Nombre de techniques rattachées.")


class MappedFinding(BaseModel):
    """Un constat traduit en technique, avec la raison du rapprochement."""

    finding: str = Field(description="Le constat d'origine.")
    technique_id: str
    technique_name: str
    tactics: list[str] = Field(default_factory=list)
    reason: str = Field(description="Pourquoi ce constat correspond à cette technique.")
    confidence: str = Field(description="high, medium ou low.")
    mitigations: list[str] = Field(default_factory=list, description="Parades associées.")
    url: str | None = None


class AttackMapping(BaseModel):
    """Résultat d'une traduction de constats vers ATT&CK."""

    attack_version: str
    mapped: list[MappedFinding] = Field(default_factory=list)
    unmapped: list[str] = Field(
        default_factory=list,
        description="Constats sans correspondance établie. Non rapprochés approximativement.",
    )
    distinct_techniques: list[str] = Field(default_factory=list)
    tactics_covered: list[str] = Field(default_factory=list)
    summary: str
    known_vocabulary_size: int = Field(description="Nombre de constats que la table sait traduire.")


class CoverageReport(BaseModel):
    """Ce que les détections en place ne couvrent pas."""

    attack_version: str
    scope_size: int = Field(description="Techniques dans le périmètre analysé.")
    covered: int
    missing: int
    coverage_ratio: float = Field(description="Part couverte, de 0 à 1.")
    invalid_inputs: list[str] = Field(
        default_factory=list, description="Identifiants fournis qui n'existent pas."
    )
    gaps: list[dict[str, Any]] = Field(
        default_factory=list, description="Techniques non couvertes, avec leur détection."
    )
    note: str


class GroupProfile(BaseModel):
    """Fiche d'un groupe d'attaquants."""

    id: str
    name: str
    aliases: list[str] = Field(default_factory=list, description="Autres noms employés.")
    description: str | None = None
    techniques: list[TechniqueSummary] = Field(default_factory=list)
    url: str | None = None
    attack_version: str


class NavigatorLayer(BaseModel):
    """Une couche importable dans l'ATT&CK Navigator."""

    attack_version: str
    techniques_included: int
    unknown: list[str] = Field(
        default_factory=list, description="Identifiants fournis mais introuvables."
    )
    layer_json: str = Field(description="À coller dans un fichier .json et à importer.")


class CorpusInfo(BaseModel):
    """État du corpus embarqué."""

    attack_version: str
    techniques: int
    tactics: int
    mitigations: int
    groups: int
    revoked_techniques: int
    offline: bool = Field(description="Vrai : ces outils n'accèdent jamais au réseau.")
    note: str


class D3fendCountermeasure(BaseModel):
    """Une contre-mesure D3FEND nommée, avec sa tactique et sa définition."""

    countermeasure: str
    tactic: str = Field(description="Model, Harden, Detect, Isolate, Deceive, Evict ou Restore.")
    definition: str | None = None
    d3fend_id: str | None = None
    relationship: str | None = Field(
        default=None, description="Le verbe D3FEND : filters, hardens, monitors…"
    )
    artifact: str | None = Field(default=None, description="Ce sur quoi la contre-mesure agit.")


class D3fendSuggestion(BaseModel):
    """Ce que D3FEND propose pour une technique ATT&CK."""

    technique_id: str
    countermeasures: list[D3fendCountermeasure] = Field(default_factory=list)
    via_subtechniques: dict[str, list[D3fendCountermeasure]] = Field(
        default_factory=dict,
        description="Rempli quand la technique elle-même n'a pas de mapping direct, "
        "mais que ses sous-techniques en ont.",
    )
    notes: list[str] = Field(default_factory=list)

"""Contrats de l'agent de triage.

Le point central est `TriageVerdict` : l'agent ne rend pas un paragraphe, il
rend un objet validé, stockable en base, comparable à une référence — donc
mesurable. C'est ce qui transforme un agent conversationnel en composant
logiciel.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Verdict = Literal["malicious", "suspicious", "benign", "inconclusive"]
Severity = Literal["critical", "high", "medium", "low", "none"]
Domain = Literal["identity", "threat_intel", "email"]


class Alert(BaseModel):
    """L'entrée de l'agent : ce qui déclenche une investigation."""

    kind: Literal[
        "compte_compromis",
        "utilisateur_a_risque",
        "phishing_signale",
        "usurpation_domaine",
        "escalade_privileges",
    ] = Field(description="Famille d'alerte, qui détermine le playbook appliqué.")
    upn: str | None = Field(default=None, description="Compte concerné, le cas échéant.")
    domain: str | None = Field(default=None, description="Domaine concerné, le cas échéant.")
    raw_headers: str | None = Field(
        default=None, description="En-têtes bruts d'un courriel signalé."
    )
    source: str = Field(default="manuel", description="Origine de l'alerte.")
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TriageStep(BaseModel):
    """Une étape de l'investigation, telle qu'elle sera diffusée à la console.

    Ce modèle existe pour que le raisonnement soit **observable pendant qu'il se
    produit**. Un agent qui affiche un sablier pendant 45 secondes puis un
    verdict n'est pas adopté : on ne fait pas confiance à ce qu'on ne voit pas.
    """

    index: int = Field(description="Numéro d'ordre de l'étape.")
    domain: Domain = Field(description="Domaine mobilisé.")
    tool: str = Field(description="Outil appelé.")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Arguments transmis.")
    duration_ms: int = Field(description="Durée de l'appel.")
    status: Literal["ok", "skipped", "error"] = Field(description="Issue de l'étape.")
    summary: str = Field(description="Ce que l'étape a appris, en une phrase.")
    findings: list[str] = Field(default_factory=list, description="Constats rapportés par l'outil.")
    error: str | None = Field(default=None, description="Message d'erreur, le cas échéant.")


class RunCosts(BaseModel):
    """Ressources consommées par une investigation.

    Le coût n'est pas en tokens : aucun modèle de langage n'est dans la boucle
    de décision. Ce qui s'épuise, c'est le quota des API externes — quatre
    requêtes par minute sur le palier gratuit de VirusTotal.
    """

    external_api_calls: dict[str, int] = Field(
        default_factory=dict, description="Appels réellement partis, par service tiers."
    )
    cache_hits: int = Field(default=0, description="Réponses servies depuis le cache.")
    dns_lookups: int = Field(default=0, description="Résolutions DNS déclenchées.")

    @property
    def total_external(self) -> int:
        """Appels réellement partis vers des services tiers."""
        return sum(self.external_api_calls.values())

    @property
    def cache_ratio(self) -> float:
        """Part des enrichissements évités grâce au cache.

        C'est l'indicateur qui dit si la plateforme tiendra la charge :
        sans cache, le quota gratuit est épuisé au milieu de la première
        enquête.
        """
        total = self.total_external + self.cache_hits
        return round(self.cache_hits / total, 3) if total else 0.0


class ProposedAction(BaseModel):
    """Une action de remédiation proposée, jamais exécutée par l'agent."""

    action: str = Field(description="Identifiant de l'action.")
    label: str = Field(description="Libellé lisible.")
    rationale: str = Field(description="Pourquoi cette action, au vu des constats.")
    priority: Literal["immediate", "high", "normal"] = Field(description="Urgence relative.")
    requires_approval: bool = Field(
        default=True,
        description="Toute action modifiante exige une validation humaine explicite.",
    )


class TriageVerdict(BaseModel):
    """Le rendu de l'agent : un dossier instruit, pas une opinion."""

    alert: Alert
    verdict: Verdict = Field(description="Conclusion sur l'incident.")
    severity: Severity = Field(description="Gravité, qui tient compte du contexte métier.")
    confidence: float = Field(ge=0.0, le=1.0, description="Fiabilité de la conclusion, de 0 à 1.")
    summary: str = Field(max_length=1200, description="Synthèse pour l'analyste.")
    timeline: list[str] = Field(
        default_factory=list, description="Chronologie reconstituée, du plus ancien au plus récent."
    )
    indicators: list[str] = Field(
        default_factory=list, description="Indicateurs de compromission retenus."
    )
    mitre_techniques: list[str] = Field(
        default_factory=list, description="Techniques MITRE ATT&CK correspondantes."
    )
    recommended_actions: list[ProposedAction] = Field(
        default_factory=list, description="Actions proposées, classées par urgence."
    )
    escalate_to_human: bool = Field(
        description=(
            "Vrai quand la confiance est insuffisante ou l'impact élevé. Un agent qui "
            "sait dire qu'il ne sait pas vaut mieux qu'un agent toujours affirmatif."
        )
    )
    steps: list[TriageStep] = Field(default_factory=list, description="Trace complète.")
    costs: RunCosts = Field(
        default_factory=RunCosts, description="Ressources consommées par l'investigation."
    )
    duration_ms: int = Field(description="Durée totale de l'investigation.")
    tools_called: int = Field(description="Nombre d'appels d'outils effectués.")

    @property
    def failed_steps(self) -> int:
        return sum(1 for s in self.steps if s.status == "error")

"""Contrats du harnais d'évaluation.

Un jeu de référence n'a de valeur que si chaque cas est **figé** : la même
entrée doit produire le même verdict, aujourd'hui et dans six mois. C'est
pourquoi un cas embarque les réponses d'outils qu'il doit voir, plutôt que
d'interroger des services dont les réponses changent.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from argus_agent.models import Alert, Severity, Verdict


class Expectation(BaseModel):
    """Ce que l'agent doit conclure sur ce cas."""

    verdict: Verdict = Field(description="Verdict attendu.")
    severity: Severity | None = Field(
        default=None, description="Gravité attendue. Omise quand elle n'est pas l'objet du cas."
    )
    escalate: bool | None = Field(
        default=None, description="L'agent doit-il escalader vers un humain ?"
    )
    max_tool_calls: int | None = Field(
        default=None, description="Plafond d'appels toléré pour ce cas."
    )


class EvalCase(BaseModel):
    """Un incident de référence, avec son verdict attendu."""

    id: str = Field(description="Identifiant stable, cité dans les rapports.")
    title: str = Field(description="Ce que le cas met à l'épreuve, en une phrase.")
    alert: Alert
    tools: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Réponses figées, par nom d'outil. Un outil absent est traité comme "
            "indisponible, ce qui permet de tester la dégradation."
        ),
    )
    expected: Expectation
    tags: list[str] = Field(
        default_factory=list, description="Familles auxquelles le cas appartient."
    )

    @property
    def is_injection(self) -> bool:
        """Un cas porteur d'une charge d'injection de prompt."""
        return "injection" in self.tags


class CaseResult(BaseModel):
    """Le résultat d'un cas, comparé à son attente."""

    case_id: str
    title: str
    tags: list[str]
    expected_verdict: Verdict
    actual_verdict: Verdict
    expected_severity: Severity | None = None
    actual_severity: Severity
    expected_escalate: bool | None = None
    actual_escalate: bool
    tool_calls: int
    duration_ms: int
    failures: list[str] = Field(
        default_factory=list, description="Écarts constatés, vides si le cas passe."
    )

    @property
    def passed(self) -> bool:
        return not self.failures

    @property
    def is_false_negative(self) -> bool:
        """La faute grave : un incident réel classé sans danger.

        Un faux positif coûte quelques minutes à un analyste. Un faux négatif
        laisse un attaquant dans le système d'information. Les deux ne se valent
        pas, et la métrique les sépare.
        """
        return self.expected_verdict in {"malicious", "suspicious"} and self.actual_verdict in {
            "benign",
            "inconclusive",
        }

    @property
    def is_false_positive(self) -> bool:
        return self.expected_verdict == "benign" and self.actual_verdict in {
            "malicious",
            "suspicious",
        }


class Threshold(BaseModel):
    """Un seuil, et le caractère bloquant ou non de son dépassement."""

    name: str
    value: float
    limit: float
    direction: Literal["max", "min"] = Field(
        description="max : la valeur doit rester sous la limite. min : au-dessus."
    )
    blocking: bool
    unit: str = ""

    @property
    def met(self) -> bool:
        return self.value <= self.limit if self.direction == "max" else self.value >= self.limit


class EvalReport(BaseModel):
    """Le rendu du harnais : ce qu'on montre quand on demande des preuves."""

    total: int
    passed: int
    accuracy: float = Field(description="Part des cas dont le verdict correspond exactement.")
    false_negative_rate: float
    false_positive_rate: float
    escalation_accuracy: float
    injection_resistance: float = Field(
        description="Part des cas porteurs d'une injection de prompt qui concluent correctement."
    )
    median_tool_calls: float
    p95_duration_ms: int
    thresholds: list[Threshold]
    results: list[CaseResult]

    @property
    def blocking_failures(self) -> list[Threshold]:
        return [t for t in self.thresholds if t.blocking and not t.met]

    @property
    def ok(self) -> bool:
        return not self.blocking_failures

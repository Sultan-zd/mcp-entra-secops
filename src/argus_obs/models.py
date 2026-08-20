"""Ce qu'une investigation consomme, et ce qu'on en conserve.

Une remarque sur le coût. La plupart des plateformes agentiques comptent des
tokens, parce qu'un modèle de langage est dans leur boucle de décision. Ici il
n'y en a pas : le coût réel n'est donc pas en tokens, il est en **quota d'API
externes**. Le palier gratuit de VirusTotal tourne autour de quatre requêtes par
minute — c'est cette ressource-là qui s'épuise, et c'est donc celle-là qu'on
mesure. Compter des tokens inexistants donnerait un tableau de bord flatteur et
sans rapport avec la contrainte réelle.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from argus_agent.models import Alert, RunCosts, TriageVerdict

#: Les coûts sont définis avec le verdict qu'ils accompagnent : une seconde
#: définition ici produirait deux modèles qui divergeraient en silence.
__all__ = ["ApprovalRecord", "RunCosts", "RunRecord"]


class RunRecord(BaseModel):
    """Une investigation archivée, rejouable six semaines plus tard.

    C'est l'exigence de traçabilité : quand une décision est contestée, il faut
    pouvoir montrer sur quelles données elle reposait, dans quel ordre les
    outils ont été appelés, et ce que chacun a répondu.
    """

    run_id: str = Field(description="Identifiant du dossier.")
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    alert: Alert
    verdict: TriageVerdict
    approvals: list[ApprovalRecord] = Field(
        default_factory=list,
        description="Décisions humaines prises sur les actions proposées.",
    )

    @property
    def costs(self) -> RunCosts:
        return self.verdict.costs

    @property
    def pending_actions(self) -> int:
        """Actions modifiantes encore en attente d'une décision humaine."""
        decidees = {a.action for a in self.approvals}
        return sum(
            1
            for a in self.verdict.recommended_actions
            if a.requires_approval and a.action not in decidees
        )


class ApprovalRecord(BaseModel):
    """Une décision humaine sur une action proposée.

    L'agent ne l'exécute pas pour autant : cette trace consigne qui a décidé
    quoi et quand, ce qui est l'exigence d'audit. L'exécution reste un geste
    séparé, hors de portée de la plateforme en l'état.
    """

    action: str = Field(description="Action concernée.")
    decision: str = Field(description="approved ou rejected.")
    approver: str = Field(description="Identité de la personne qui a décidé.")
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    note: str | None = Field(default=None, description="Justification, le cas échéant.")


RunRecord.model_rebuild()

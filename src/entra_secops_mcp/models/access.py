"""Modèles d'accès conditionnel et de contexte utilisateur."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .common import is_privileged_role

#: Traduction des contrôles d'octroi les plus fréquents.
GRANT_CONTROLS: dict[str, str] = {
    "block": "Bloquer l'accès",
    "mfa": "Exiger la MFA",
    "compliantDevice": "Exiger un appareil conforme",
    "domainJoinedDevice": "Exiger un appareil joint au domaine",
    "approvedApplication": "Exiger une application cliente approuvée",
    "compliantApplication": "Exiger une stratégie de protection d'application",
    "passwordChange": "Exiger un changement de mot de passe",
}


def _summarise(values: list[str] | None, limit: int = 5) -> str:
    """Résume une liste d'identifiants sans inonder le contexte du modèle."""
    if not values:
        return "aucun"
    if "All" in values:
        return "tous"
    if len(values) <= limit:
        return ", ".join(values)
    return f"{', '.join(values[:limit])} … (+{len(values) - limit})"


class ConditionalAccessPolicy(BaseModel):
    """Une politique d'accès conditionnel, réduite à ce qui explique un blocage."""

    name: str = Field(description="Nom de la politique.")
    state: str = Field(
        description=(
            "enabled (appliquée), disabled (inactive), "
            "enabledForReportingButNotEnforced (audit seul, donc sans effet)."
        )
    )
    is_enforced: bool = Field(description="Vrai uniquement si la politique bloque réellement.")
    included_users: str = Field(description="Utilisateurs ou groupes visés.")
    excluded_users: str = Field(description="Utilisateurs ou groupes exclus.")
    included_applications: str = Field(description="Applications visées.")
    grant_controls: list[str] = Field(description="Contrôles exigés pour accorder l'accès.")
    client_app_types: list[str] = Field(
        default_factory=list, description="Types de clients visés (dont les protocoles hérités)."
    )
    modified: str | None = Field(default=None, description="Dernière modification (ISO 8601).")

    @classmethod
    def from_graph(cls, raw: dict[str, Any]) -> ConditionalAccessPolicy:
        conditions = raw.get("conditions") or {}
        users = conditions.get("users") or {}
        apps = conditions.get("applications") or {}
        grant = raw.get("grantControls") or {}

        controles = [
            GRANT_CONTROLS.get(control, control) for control in (grant.get("builtInControls") or [])
        ]

        state = raw.get("state", "unknown")
        return cls(
            name=raw.get("displayName", "Sans nom"),
            state=state,
            is_enforced=state == "enabled",
            included_users=_summarise(
                (users.get("includeUsers") or []) + (users.get("includeGroups") or [])
            ),
            excluded_users=_summarise(
                (users.get("excludeUsers") or []) + (users.get("excludeGroups") or [])
            ),
            included_applications=_summarise(apps.get("includeApplications")),
            grant_controls=controles,
            client_app_types=conditions.get("clientAppTypes") or [],
            modified=raw.get("modifiedDateTime"),
        )


class ConditionalAccessReport(BaseModel):
    """Résultat de `get_conditional_access_policies`."""

    total_policies: int = Field(description="Nombre de politiques retournées.")
    enforced: int = Field(description="Politiques réellement appliquées.")
    report_only: int = Field(description="Politiques en mode audit, donc sans effet de blocage.")
    disabled: int = Field(description="Politiques désactivées.")
    policies: list[ConditionalAccessPolicy] = Field(description="Politiques du tenant.")
    notes: list[str] = Field(default_factory=list, description="Observations calculées.")

    @classmethod
    def build(cls, policies: list[ConditionalAccessPolicy]) -> ConditionalAccessReport:
        enforced = sum(1 for p in policies if p.state == "enabled")
        report_only = sum(1 for p in policies if p.state == "enabledForReportingButNotEnforced")
        disabled = sum(1 for p in policies if p.state == "disabled")

        notes: list[str] = []
        if not enforced and policies:
            notes.append(
                "Aucune politique n'est réellement appliquée : le tenant n'est protégé par "
                "aucun contrôle d'accès conditionnel."
            )
        if report_only:
            noms = ", ".join(
                p.name for p in policies if p.state == "enabledForReportingButNotEnforced"
            )
            notes.append(
                f"{report_only} politique(s) en mode audit seul, sans effet de blocage : {noms}."
            )
        if disabled:
            notes.append(
                f"{disabled} politique(s) désactivée(s) : vérifier qu'aucune ne l'a été "
                "récemment de façon non autorisée, via get_directory_audits."
            )
        exclusions = [p.name for p in policies if p.is_enforced and p.excluded_users != "aucun"]
        if exclusions:
            notes.append(
                "Des exclusions existent sur les politiques appliquées ("
                + ", ".join(exclusions)
                + ") : un compte exclu contourne le contrôle."
            )
        return cls(
            total_policies=len(policies),
            enforced=enforced,
            report_only=report_only,
            disabled=disabled,
            policies=policies,
            notes=notes,
        )


class UserContext(BaseModel):
    """Fiche d'identité d'un compte : ce qui détermine la gravité d'un incident."""

    user_principal_name: str = Field(description="UPN du compte.")
    display_name: str | None = Field(default=None, description="Nom affiché.")
    object_id: str = Field(description="Identifiant d'objet Entra.")
    job_title: str | None = Field(default=None, description="Intitulé de poste.")
    department: str | None = Field(default=None, description="Département.")
    account_enabled: bool | None = Field(default=None, description="Le compte est-il actif ?")
    created: str | None = Field(default=None, description="Date de création du compte.")
    user_type: str | None = Field(default=None, description="Member ou Guest.")
    groups: list[str] = Field(default_factory=list, description="Groupes d'appartenance.")
    directory_roles: list[str] = Field(
        default_factory=list, description="Rôles d'annuaire détenus."
    )
    privileged_roles: list[str] = Field(
        default_factory=list, description="Sous-ensemble des rôles à privilèges élevés."
    )
    is_privileged: bool = Field(description="Le compte détient-il au moins un rôle à privilèges ?")
    notes: list[str] = Field(default_factory=list, description="Observations calculées.")

    @classmethod
    def build(cls, user: dict[str, Any], memberships: list[dict[str, Any]]) -> UserContext:
        groupes: list[str] = []
        roles: list[str] = []
        for item in memberships:
            nom = item.get("displayName")
            if not nom:
                continue
            if item.get("@odata.type") == "#microsoft.graph.directoryRole":
                roles.append(str(nom))
            else:
                groupes.append(str(nom))

        privilegies = [r for r in roles if is_privileged_role(r)]

        notes: list[str] = []
        if privilegies:
            notes.append(
                "Compte à privilèges élevés (" + ", ".join(privilegies) + "). "
                "Toute compromission de ce compte est un incident majeur : traiter en priorité "
                "absolue et vérifier les journaux d'audit d'annuaire."
            )
        if user.get("userType") == "Guest":
            notes.append("Compte invité : accès externe à l'organisation.")
        if user.get("accountEnabled") is False:
            notes.append("Le compte est désactivé : une activité récente serait anormale.")

        return cls(
            user_principal_name=user.get("userPrincipalName", "Inconnu"),
            display_name=user.get("displayName"),
            object_id=user.get("id", "Inconnu"),
            job_title=user.get("jobTitle"),
            department=user.get("department"),
            account_enabled=user.get("accountEnabled"),
            created=user.get("createdDateTime"),
            user_type=user.get("userType"),
            groups=sorted(groupes),
            directory_roles=sorted(roles),
            privileged_roles=sorted(privilegies),
            is_privileged=bool(privilegies),
            notes=notes,
        )

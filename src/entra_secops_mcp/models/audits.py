"""Modèles des journaux d'audit d'annuaire : dérive de configuration et persistance."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

#: Activités administratives dont la présence change la lecture d'un incident.
#: Ce sont les gestes qu'un attaquant pose pour s'installer durablement : ils
#: passent inaperçus dans un journal brut de plusieurs centaines de lignes.
SENSITIVE_ACTIVITIES: tuple[tuple[str, str], ...] = (
    ("add member to role", "Attribution d'un rôle : élévation de privilèges possible."),
    ("add eligible member to role", "Attribution d'un rôle éligible (PIM) à vérifier."),
    ("add owner to application", "Ajout d'un propriétaire d'application : persistance possible."),
    (
        "certificates and secrets management",
        "Ajout d'un secret ou certificat applicatif : persistance classique après compromission.",
    ),
    ("add service principal", "Création d'un principal de service à vérifier."),
    ("consent to application", "Consentement applicatif : vecteur d'exfiltration de données."),
    ("user registered security info", "Enrôlement d'une méthode MFA : persistance possible."),
    ("security info", "Modification des méthodes d'authentification du compte."),
    ("disable strong authentication", "Désactivation de la MFA : action hautement suspecte."),
    ("update conditional access policy", "Modification d'une politique d'accès conditionnel."),
    ("delete conditional access policy", "Suppression d'une politique d'accès conditionnel."),
    ("reset user password", "Réinitialisation de mot de passe par un administrateur."),
)


def _describe_activity(activity: str | None) -> str | None:
    """Retourne l'explication associée à une activité sensible, le cas échéant."""
    if not activity:
        return None
    lowered = activity.lower()
    for marker, explanation in SENSITIVE_ACTIVITIES:
        if marker in lowered:
            return explanation
    return None


def _describe_initiator(initiated_by: dict[str, Any] | None) -> str:
    """Identifie l'auteur d'une action, qu'il s'agisse d'un utilisateur ou d'une application."""
    if not initiated_by:
        return "Inconnu"
    user = initiated_by.get("user") or {}
    if user.get("userPrincipalName") or user.get("displayName"):
        auteur = user.get("userPrincipalName") or user.get("displayName")
        ip = user.get("ipAddress")
        return f"{auteur} ({ip})" if ip else str(auteur)
    app = initiated_by.get("app") or {}
    if app.get("displayName"):
        return f"Application : {app['displayName']}"
    return "Inconnu"


class DirectoryAudit(BaseModel):
    """Une modification administrative de l'annuaire."""

    activity_date: str = Field(description="Horodatage de l'action (ISO 8601).")
    activity: str = Field(description="Nom de l'opération effectuée.")
    security_note: str | None = Field(
        default=None,
        description="Pourquoi cette opération mérite attention, quand c'est le cas.",
    )
    initiated_by: str = Field(description="Auteur de l'action : utilisateur (IP) ou application.")
    target_resources: list[str] = Field(description="Ressources modifiées.")
    modified_properties: list[str] = Field(
        default_factory=list,
        description="Propriétés changées, sous la forme « champ : ancien → nouveau ».",
    )
    result: str = Field(description="Issue : success, failure, timeout.")
    result_reason: str | None = Field(default=None, description="Motif en cas d'échec.")
    category: str | None = Field(default=None, description="Catégorie Entra de l'opération.")

    @classmethod
    def from_graph(cls, raw: dict[str, Any]) -> DirectoryAudit:
        activity = raw.get("activityDisplayName", "Inconnue")

        cibles: list[str] = []
        proprietes: list[str] = []
        for resource in raw.get("targetResources") or []:
            libelle = (
                resource.get("userPrincipalName")
                or resource.get("displayName")
                or resource.get("id")
                or "Inconnue"
            )
            type_ressource = resource.get("type")
            cibles.append(f"{libelle} ({type_ressource})" if type_ressource else str(libelle))

            for prop in resource.get("modifiedProperties") or []:
                nom = prop.get("displayName", "?")
                ancien = str(prop.get("oldValue") or "").strip('"') or "vide"
                nouveau = str(prop.get("newValue") or "").strip('"') or "vide"
                proprietes.append(f"{nom} : {ancien} → {nouveau}")

        return cls(
            activity_date=raw.get("activityDateTime", "Inconnu"),
            activity=activity,
            security_note=_describe_activity(activity),
            initiated_by=_describe_initiator(raw.get("initiatedBy")),
            target_resources=cibles or ["Inconnue"],
            modified_properties=proprietes,
            result=raw.get("result", "unknown"),
            result_reason=raw.get("resultReason") or None,
            category=raw.get("category"),
        )


class DirectoryAuditsReport(BaseModel):
    """Résultat de `get_directory_audits`."""

    window_hours: int = Field(description="Fenêtre temporelle appliquée, en heures.")
    total_entries: int = Field(description="Nombre d'entrées retournées.")
    failures: int = Field(description="Opérations en échec.")
    sensitive_entries: int = Field(
        description="Entrées jugées sensibles du point de vue de la sécurité."
    )
    distinct_initiators: list[str] = Field(description="Auteurs distincts observés.")
    entries: list[DirectoryAudit] = Field(
        description="Entrées, de la plus récente à la plus ancienne."
    )
    notes: list[str] = Field(default_factory=list, description="Observations calculées.")

    @classmethod
    def build(cls, window_hours: int, entries: list[DirectoryAudit]) -> DirectoryAuditsReport:
        sensibles = [e for e in entries if e.security_note]
        auteurs = sorted({e.initiated_by for e in entries if e.initiated_by != "Inconnu"})

        notes: list[str] = []
        if sensibles:
            libelles = sorted({e.activity for e in sensibles})
            notes.append(
                f"{len(sensibles)} opération(s) sensible(s) détectée(s) : "
                + ", ".join(libelles)
                + ". Vérifier que chacune correspond à un changement légitime et tracé."
            )
        echecs = sum(1 for e in entries if e.result == "failure")
        if echecs >= 3:
            notes.append(
                f"{echecs} opérations administratives en échec : tentative d'action non "
                "autorisée possible."
            )
        return cls(
            window_hours=window_hours,
            total_entries=len(entries),
            failures=echecs,
            sensitive_entries=len(sensibles),
            distinct_initiators=auteurs,
            entries=entries,
            notes=notes,
        )

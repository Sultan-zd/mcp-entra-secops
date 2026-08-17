"""Modèles d'Identity Protection : comptes à risque et détections unitaires."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .common import format_location

#: Types de détection les plus parlants, traduits et assortis de la conduite à
#: tenir. Sans cette table, `riskEventType` reste un identifiant opaque.
RISK_EVENT_TYPES: dict[str, str] = {
    "leakedCredentials": (
        "Les identifiants du compte ont été trouvés dans une fuite publique. "
        "Réinitialisation du mot de passe requise."
    ),
    "anonymizedIPAddress": "Connexion depuis un réseau anonymisant (Tor, VPN d'anonymisation).",
    "maliciousIPAddress": "Connexion depuis une IP associée à une activité malveillante connue.",
    "unfamiliarFeatures": "Connexion aux caractéristiques inhabituelles pour ce compte.",
    "impossibleTravel": (
        "Deux connexions géographiquement incompatibles dans un intervalle trop court."
    ),
    "newCountry": "Première connexion depuis ce pays.",
    "passwordSpray": "Le compte a été visé par une attaque par pulvérisation de mots de passe.",
    "suspiciousBrowser": "Navigateur associé à des connexions suspectes sur plusieurs comptes.",
    "suspiciousInboxManipulation": (
        "Règles de boîte de réception suspectes : exfiltration ou dissimulation possible."
    ),
    "adminConfirmedUserCompromised": "Un administrateur a confirmé la compromission du compte.",
    "investigationsThreatIntelligence": (
        "Détection issue du renseignement sur les menaces Microsoft."
    ),
}


class RiskyUser(BaseModel):
    """Un compte signalé à risque par Entra Identity Protection."""

    user_principal_name: str = Field(description="UPN du compte à risque.")
    display_name: str | None = Field(default=None, description="Nom affiché.")
    risk_level: str = Field(description="Niveau de risque : low, medium, high, hidden, none.")
    risk_state: str = Field(
        description=(
            "État : atRisk, confirmedCompromised, remediated, dismissed, confirmedSafe. "
            "Seuls atRisk et confirmedCompromised appellent une action."
        )
    )
    risk_detail: str | None = Field(default=None, description="Précision sur l'origine du risque.")
    last_updated: str | None = Field(
        default=None, description="Dernière mise à jour de l'évaluation (ISO 8601)."
    )

    @classmethod
    def from_graph(cls, raw: dict[str, Any]) -> RiskyUser:
        return cls(
            user_principal_name=raw.get("userPrincipalName", "Inconnu"),
            display_name=raw.get("userDisplayName"),
            risk_level=raw.get("riskLevel", "unknown"),
            risk_state=raw.get("riskState", "unknown"),
            risk_detail=raw.get("riskDetail") or None,
            last_updated=raw.get("riskLastUpdatedDateTime"),
        )


class RiskyUsersReport(BaseModel):
    """Résultat de `get_risky_users`."""

    total_users: int = Field(description="Nombre de comptes retournés.")
    high_risk: int = Field(description="Comptes au niveau de risque « high ».")
    medium_risk: int = Field(description="Comptes au niveau de risque « medium ».")
    active_risk: int = Field(
        description="Comptes encore à risque (atRisk ou confirmedCompromised)."
    )
    users: list[RiskyUser] = Field(description="Comptes, du plus risqué au moins risqué.")
    notes: list[str] = Field(default_factory=list, description="Observations calculées.")

    @classmethod
    def build(cls, users: list[RiskyUser]) -> RiskyUsersReport:
        high = sum(1 for u in users if u.risk_level == "high")
        medium = sum(1 for u in users if u.risk_level == "medium")
        active = sum(
            1 for u in users if u.risk_state in {"atRisk", "confirmedCompromised"}
        )

        notes: list[str] = []
        if high:
            noms = ", ".join(u.user_principal_name for u in users if u.risk_level == "high")
            notes.append(f"{high} compte(s) au risque élevé, à traiter en priorité : {noms}.")
        confirmes = [u for u in users if u.risk_state == "confirmedCompromised"]
        if confirmes:
            notes.append(
                "Compromission déjà confirmée pour : "
                + ", ".join(u.user_principal_name for u in confirmes)
                + ". Vérifier que la remédiation a bien été appliquée."
            )
        if users and not active:
            notes.append(
                "Aucun compte n'est encore à risque : les entrées retournées sont "
                "remédiées, écartées ou confirmées sûres."
            )
        return cls(
            total_users=len(users),
            high_risk=high,
            medium_risk=medium,
            active_risk=active,
            users=users,
            notes=notes,
        )


class RiskDetection(BaseModel):
    """Une détection de risque unitaire : le « pourquoi » d'un compte à risque."""

    detected_at: str = Field(description="Horodatage de la détection (ISO 8601).")
    user_principal_name: str = Field(description="UPN concerné.")
    risk_event_type: str = Field(description="Type de détection, tel que renvoyé par Entra.")
    meaning: str | None = Field(
        default=None, description="Traduction du type de détection et conduite à tenir."
    )
    risk_level: str = Field(description="Niveau de risque de la détection.")
    risk_state: str | None = Field(default=None, description="État de la détection.")
    ip_address: str | None = Field(default=None, description="Adresse IP source.")
    location: str = Field(description="Géolocalisation « Ville, PAYS » ou « Inconnue ».")
    activity: str | None = Field(default=None, description="Contexte : signin ou user.")
    detection_timing: str | None = Field(
        default=None, description="realtime (temps réel) ou offline (analyse différée)."
    )

    @classmethod
    def from_graph(cls, raw: dict[str, Any]) -> RiskDetection:
        event_type = raw.get("riskEventType", "unknown")
        return cls(
            detected_at=raw.get("detectedDateTime") or raw.get("activityDateTime", "Inconnu"),
            user_principal_name=raw.get("userPrincipalName", "Inconnu"),
            risk_event_type=event_type,
            meaning=RISK_EVENT_TYPES.get(event_type),
            risk_level=raw.get("riskLevel", "unknown"),
            risk_state=raw.get("riskState"),
            ip_address=raw.get("ipAddress"),
            location=format_location(raw.get("location")),
            activity=raw.get("activity"),
            detection_timing=raw.get("detectionTimingType"),
        )


class RiskDetectionsReport(BaseModel):
    """Résultat de `get_risk_detections`."""

    total_detections: int = Field(description="Nombre de détections retournées.")
    distinct_users: list[str] = Field(description="UPN distincts concernés.")
    distinct_types: list[str] = Field(description="Types de détection distincts observés.")
    detections: list[RiskDetection] = Field(
        description="Détections, de la plus récente à la plus ancienne."
    )
    notes: list[str] = Field(default_factory=list, description="Observations calculées.")

    @classmethod
    def build(cls, detections: list[RiskDetection]) -> RiskDetectionsReport:
        users = sorted({d.user_principal_name for d in detections})
        types = sorted({d.risk_event_type for d in detections})

        notes: list[str] = []
        if "leakedCredentials" in types:
            notes.append(
                "Identifiants divulgués détectés : la réinitialisation du mot de passe est "
                "impérative, la seule révocation de session ne suffit pas."
            )
        if {"anonymizedIPAddress", "maliciousIPAddress"} & set(types):
            notes.append(
                "Connexion depuis une infrastructure anonymisante ou malveillante : "
                "enrichir l'adresse IP auprès d'une source de renseignement."
            )
        if "impossibleTravel" in types:
            notes.append(
                "Voyage impossible signalé : vérifier d'abord l'existence d'un VPN "
                "d'entreprise avant de conclure à une compromission."
            )
        if len(users) > 3:
            notes.append(
                f"{len(users)} comptes concernés : l'incident dépasse un utilisateur isolé."
            )
        return cls(
            total_detections=len(detections),
            distinct_users=users,
            distinct_types=types,
            detections=detections,
            notes=notes,
        )

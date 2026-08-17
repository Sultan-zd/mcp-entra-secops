"""Modèles de sortie de `get_user_signins`.

Microsoft Graph renvoie une soixantaine de champs par événement de connexion.
Ces modèles n'en retiennent qu'une douzaine. Ce n'est pas seulement une
optimisation de coût : c'est aussi un contrôle de sécurité, puisque seuls les
champs explicitement listés ici peuvent atteindre le contexte du modèle.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from .common import describe_error_code, format_location

SignInStatus = Literal["Success", "Failure", "Interrupted"]


class SignInEvent(BaseModel):
    """Un événement de connexion, réduit à ses indicateurs de sécurité."""

    timestamp: str = Field(description="Horodatage UTC de la tentative (ISO 8601).")
    user_principal_name: str = Field(description="UPN du compte concerné.")
    app_name: str = Field(description="Application cible de la connexion.")
    ip_address: str = Field(description="Adresse IP source.")
    location: str = Field(description="Géolocalisation « Ville, PAYS » ou « Inconnue ».")
    status: SignInStatus = Field(description="Issue de la tentative.")
    error_code: int | None = Field(default=None, description="Code d'erreur Entra (0 = succès).")
    error_meaning: str | None = Field(
        default=None, description="Signification du code d'erreur, si connue."
    )
    attack_hint: str | None = Field(
        default=None,
        description="Scénario d'attaque évoqué par ce code, à confirmer par le volume observé.",
    )
    failure_reason: str | None = Field(default=None, description="Message brut renvoyé par Entra.")
    client_app: str | None = Field(
        default=None,
        description="Client utilisé (Browser, Mobile Apps, ou protocole hérité comme IMAP/POP).",
    )
    device: str | None = Field(default=None, description="Système d'exploitation et navigateur.")
    conditional_access: str | None = Field(
        default=None, description="Verdict de l'accès conditionnel : success, failure, notApplied."
    )
    risk_level: str | None = Field(
        default=None, description="Niveau de risque évalué pendant la connexion."
    )

    @classmethod
    def from_graph(cls, raw: dict[str, Any]) -> SignInEvent:
        """Construit l'événement tronqué à partir de la réponse brute de Graph."""
        status = raw.get("status") or {}
        error_code = status.get("errorCode")
        meaning, hint = describe_error_code(error_code)

        device = raw.get("deviceDetail") or {}
        device_label = " / ".join(
            str(device[key]) for key in ("operatingSystem", "browser") if device.get(key)
        )

        # Un code absent n'est pas un échec : c'est une donnée manquante. La
        # version naïve (`errorCode != 0`) classait ce cas en « Failure ».
        if error_code is None:
            outcome: SignInStatus = "Interrupted"
        else:
            outcome = "Success" if error_code == 0 else "Failure"

        return cls(
            timestamp=raw.get("createdDateTime", "Inconnu"),
            user_principal_name=raw.get("userPrincipalName", "Inconnu"),
            app_name=raw.get("appDisplayName", "Inconnue"),
            ip_address=raw.get("ipAddress", "Inconnue"),
            location=format_location(raw.get("location")),
            status=outcome,
            error_code=error_code,
            error_meaning=meaning,
            attack_hint=hint,
            failure_reason=status.get("failureReason") or None,
            client_app=raw.get("clientAppUsed"),
            device=device_label or None,
            conditional_access=raw.get("conditionalAccessStatus"),
            risk_level=raw.get("riskLevelDuringSignIn"),
        )


class SignInReport(BaseModel):
    """Résultat de `get_user_signins` : les événements plus une synthèse chiffrée.

    La synthèse est calculée en Python, pas déduite par le modèle. Un agent qui
    doit compter 23 échecs dans une liste se trompe ; une valeur pré-calculée,
    non.
    """

    upn: str = Field(description="UPN interrogé.")
    window_hours: int = Field(description="Fenêtre temporelle réellement appliquée, en heures.")
    total_events: int = Field(description="Nombre d'événements retournés.")
    successes: int = Field(description="Nombre de connexions réussies.")
    failures: int = Field(description="Nombre d'échecs.")
    distinct_ip_addresses: list[str] = Field(description="Adresses IP source distinctes observées.")
    distinct_locations: list[str] = Field(description="Géolocalisations distinctes observées.")
    events: list[SignInEvent] = Field(description="Événements, du plus récent au plus ancien.")
    notes: list[str] = Field(
        default_factory=list,
        description="Observations calculées automatiquement, à vérifier par l'analyste.",
    )

    @classmethod
    def build(cls, upn: str, window_hours: int, events: list[SignInEvent]) -> SignInReport:
        """Assemble le rapport et calcule les agrégats de manière déterministe."""
        successes = sum(1 for e in events if e.status == "Success")
        failures = sum(1 for e in events if e.status == "Failure")
        ips = sorted({e.ip_address for e in events if e.ip_address != "Inconnue"})
        locations = sorted({e.location for e in events if e.location != "Inconnue"})

        notes: list[str] = []
        if failures >= 5:
            notes.append(
                f"{failures} échecs sur la fenêtre : volume compatible avec une attaque "
                "par force brute ou par pulvérisation de mots de passe."
            )
        if failures >= 5 and successes >= 1:
            notes.append(
                "Une connexion a RÉUSSI après une série d'échecs : compromission possible, "
                "à investiguer en priorité."
            )
        if len(locations) > 1:
            notes.append(
                # Les libellés contiennent déjà une virgule (« Ville, PAYS ») :
                # un séparateur distinct évite une liste illisible.
                "Plusieurs géolocalisations distinctes : vérifier la plausibilité des "
                f"déplacements ({' | '.join(locations)})."
            )
        legacy = sorted({e.client_app for e in events if e.client_app in {"IMAP", "POP", "SMTP"}})
        if legacy:
            notes.append(
                f"Protocoles d'authentification hérités utilisés ({', '.join(legacy)}) : "
                "ils contournent la MFA."
            )

        return cls(
            upn=upn,
            window_hours=window_hours,
            total_events=len(events),
            successes=successes,
            failures=failures,
            distinct_ip_addresses=ips,
            distinct_locations=locations,
            events=events,
            notes=notes,
        )

"""Éléments partagés par les modèles de sortie : codes d'erreur, mise en forme.

Ces tables existent pour une raison précise : sans elles, le modèle doit
deviner ce que signifie « errorCode 50126 » ou « riskEventType
leakedCredentials ». Une table explicite remplace une hypothèse par un fait.
"""

from __future__ import annotations

from typing import Any

#: Codes d'erreur Entra les plus courants en investigation, avec leur
#: signification et, le cas échéant, le scénario d'attaque qu'ils évoquent.
ENTRA_ERROR_CODES: dict[int, tuple[str, str | None]] = {
    0: ("Connexion réussie.", None),
    50034: ("Le compte n'existe pas dans l'annuaire.", "Énumération de comptes"),
    50053: (
        "Compte verrouillé (smart lockout) ou adresse IP bloquée.",
        "Password spray ou force brute",
    ),
    50055: ("Mot de passe expiré.", None),
    50057: ("Compte désactivé.", None),
    50058: ("Connexion silencieuse impossible : session absente.", None),
    50074: ("Authentification forte (MFA) exigée.", None),
    50076: ("MFA exigée par une politique d'accès conditionnel.", None),
    50079: ("L'utilisateur doit enrôler une méthode MFA.", None),
    50105: ("Utilisateur non affecté au rôle applicatif requis.", None),
    50126: (
        "Identifiant ou mot de passe invalide.",
        "Force brute ou password spray si le volume est élevé",
    ),
    50133: ("Session invalide : mot de passe expiré ou modifié récemment.", None),
    50158: ("Défi de sécurité externe non satisfait.", None),
    50173: ("Nouveau jeton requis : le mot de passe a changé.", None),
    53000: ("Appareil non conforme aux exigences d'accès conditionnel.", None),
    53001: ("Appareil non joint au domaine.", None),
    53003: ("Accès bloqué par une politique d'accès conditionnel.", None),
    65001: ("Consentement utilisateur ou administrateur manquant.", None),
    70043: ("Jeton de rafraîchissement expiré.", None),
    500121: (
        "Échec pendant l'authentification forte : MFA refusée ou expirée.",
        "MFA fatigue si les refus se répètent",
    ),
    530032: ("Accès bloqué par une politique de sécurité.", None),
    700016: ("Application introuvable dans l'annuaire.", None),
}

#: Rôles Entra dont la détention change la gravité d'un incident : un compte
#: compromis qui en possède un doit être traité en priorité absolue.
PRIVILEGED_ROLES: frozenset[str] = frozenset(
    {
        "global administrator",
        "company administrator",
        "privileged role administrator",
        "privileged authentication administrator",
        "security administrator",
        "conditional access administrator",
        "application administrator",
        "cloud application administrator",
        "user administrator",
        "authentication administrator",
        "exchange administrator",
        "sharepoint administrator",
        "intune administrator",
        "helpdesk administrator",
        "billing administrator",
        "hybrid identity administrator",
    }
)


def describe_error_code(code: int | None) -> tuple[str | None, str | None]:
    """Retourne (signification, indice d'attaque) pour un code d'erreur Entra."""
    if code is None:
        return None, None
    label, hint = ENTRA_ERROR_CODES.get(code, (None, None))
    return label, hint


def is_privileged_role(role_name: str | None) -> bool:
    """Indique si un nom de rôle figure parmi les rôles à privilèges."""
    return bool(role_name) and str(role_name).strip().lower() in PRIVILEGED_ROLES


def format_location(location: dict[str, Any] | None) -> str:
    """Assemble « Ville, PAYS » en ignorant proprement les parties absentes.

    L'implémentation naïve produit « None, None » quand Graph omet la
    géolocalisation, ce qui pollue le contexte du modèle avec du bruit.
    """
    if not location:
        return "Inconnue"
    parts = [
        str(location.get(key)).strip() for key in ("city", "countryOrRegion") if location.get(key)
    ]
    return ", ".join(parts) if parts else "Inconnue"

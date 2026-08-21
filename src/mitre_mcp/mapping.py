"""Des constats d'ARGUS vers les techniques ATT&CK.

Cette table est le cœur du serveur. Elle relie ce que les autres serveurs
observent réellement — un type de détection Entra, une opération d'annuaire,
un signal du verdict — à la technique correspondante du référentiel.

**Pourquoi une table écrite à la main et pas une correspondance par
mots-clés.** Une recherche floue sur « password spray » trouverait des
techniques plausibles et parfois la bonne. Ce n'est pas suffisant : une
correspondance ATT&CK finit dans un rapport d'incident, où elle sera relue par
quelqu'un qui connaît le référentiel. Chaque ligne ci-dessous est donc un choix
assumé, avec sa justification, et un test la fige.

Chaque entrée dit aussi **pourquoi** : sans la raison, une correspondance est
une affirmation invérifiable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Correspondance:
    """Un constat relié à une technique, avec le motif du rapprochement."""

    technique: str
    reason: str
    confidence: str = "high"


#: Détections d'Entra ID Identity Protection. Ce sont des constats de
#: Microsoft, pas des interprétations : la correspondance est directe.
DETECTIONS_ENTRA: dict[str, list[Correspondance]] = {
    "leakedCredentials": [
        Correspondance(
            "T1589.001",
            "Des identifiants du compte figurent dans une fuite publique : "
            "l'attaquant les a collectés avant toute intrusion.",
        ),
        Correspondance(
            "T1078.004",
            "Des identifiants valides pour un compte cloud sont entre des mains tierces.",
        ),
    ],
    "passwordSpray": [
        Correspondance(
            "T1110.003",
            "Un même mot de passe essayé sur de nombreux comptes est la définition "
            "de la pulvérisation de mots de passe.",
        )
    ],
    "anonymizedIPAddress": [
        Correspondance(
            "T1090.003",
            "Connexion depuis une infrastructure anonymisante : Tor ou un relais en cascade.",
        )
    ],
    "maliciousIPAddress": [
        Correspondance(
            "T1078.004",
            "Une adresse déjà connue comme malveillante s'authentifie avec des "
            "identifiants valides.",
        )
    ],
    "impossibleTravel": [
        Correspondance(
            "T1078.004",
            "Deux connexions géographiquement incompatibles : le compte sert à deux endroits.",
        )
    ],
    "unfamiliarFeatures": [
        Correspondance(
            "T1078.004",
            "Propriétés de connexion inhabituelles pour ce compte.",
            confidence="medium",
        )
    ],
    "newCountry": [
        Correspondance(
            "T1078.004",
            "Première connexion depuis ce pays.",
            confidence="low",
        )
    ],
    "suspiciousInboxManipulation": [
        Correspondance(
            "T1564.008",
            "Des règles de boîte aux lettres masquent des messages : c'est ainsi qu'un "
            "attaquant cache les alertes et les réponses de ses victimes.",
        ),
        Correspondance(
            "T1114.003",
            "Une redirection de courrier sert à exfiltrer en continu.",
            confidence="medium",
        ),
    ],
    "suspiciousBrowser": [
        Correspondance(
            "T1078.004",
            "Navigateur au comportement anormal pour ce compte.",
            confidence="medium",
        )
    ],
    "adminConfirmedUserCompromised": [
        Correspondance(
            "T1078.004",
            "Compromission confirmée par un administrateur : le doute est levé.",
        )
    ],
    "investigationsThreatIntelligence": [
        Correspondance(
            "T1078.004",
            "Activité correspondant à un renseignement sur les menaces de Microsoft.",
        )
    ],
}


#: Opérations d'annuaire sensibles. Ces gestes sont légitimes au quotidien —
#: c'est leur survenue **après** une intrusion qui les rend significatifs.
OPERATIONS_ANNUAIRE: dict[str, list[Correspondance]] = {
    "add member to role": [
        Correspondance(
            "T1098.003",
            "Attribution d'un rôle : l'attaquant s'octroie des privilèges qu'il conservera "
            "après la fermeture de sa session.",
        )
    ],
    "add eligible member to role": [
        Correspondance(
            "T1098.003",
            "Rôle éligible attribué : l'élévation est différée mais acquise.",
        )
    ],
    "add owner to application": [
        Correspondance(
            "T1098.001",
            "Un propriétaire d'application peut ajouter des identifiants : persistance.",
        )
    ],
    "certificates and secrets management": [
        Correspondance(
            "T1098.001",
            "Ajout d'un secret applicatif : la persistance classique après compromission, "
            "car elle survit à la réinitialisation du mot de passe de l'utilisateur.",
        )
    ],
    "add service principal": [
        Correspondance(
            "T1136.003",
            "Création d'une identité applicative : un compte qui n'a ni MFA ni surveillance.",
        )
    ],
    "consent to application": [
        Correspondance(
            "T1550.001",
            "Un consentement applicatif donne un jeton d'accès durable aux données du tenant.",
        )
    ],
    "user registered security info": [
        Correspondance(
            "T1556.006",
            "Enrôlement d'une méthode MFA : l'attaquant s'inscrit comme second facteur.",
        )
    ],
    "security info": [
        Correspondance(
            "T1556.006",
            "Modification des méthodes d'authentification du compte.",
        )
    ],
    "disable strong authentication": [
        Correspondance(
            "T1556.006",
            "Désactivation de la MFA : suppression délibérée d'un contrôle.",
        )
    ],
    # T1562.001 aurait semblé naturel — mais ATT&CK v19 a révoqué toute la
    # famille T1562, et T1556.009 vise précisément l'accès conditionnel.
    "update conditional access policy": [
        Correspondance(
            "T1556.009",
            "Modification d'une politique d'accès conditionnel : le contrôle qui "
            "impose la MFA et restreint les emplacements est affaibli.",
        )
    ],
    "delete conditional access policy": [
        Correspondance(
            "T1556.009",
            "Suppression d'une politique d'accès conditionnel : la défense est retirée, "
            "pas contournée.",
        )
    ],
    "reset user password": [
        Correspondance(
            "T1098",
            "Réinitialisation de mot de passe par un administrateur : à corréler avec "
            "l'origine de l'administrateur.",
            confidence="medium",
        )
    ],
}


#: Signaux calculés par le module de verdict d'ARGUS.
SIGNAUX_VERDICT: dict[str, list[Correspondance]] = {
    "succes_apres_echecs": [
        Correspondance(
            "T1110",
            "Une série d'échecs suivie d'un succès est le motif d'une attaque par "
            "essais successifs qui a abouti.",
        ),
        Correspondance("T1078.004", "L'attaquant dispose désormais d'identifiants valides."),
    ],
    "echecs_repetes": [
        Correspondance(
            "T1110",
            "Volume d'échecs compatible avec une attaque par force brute ou pulvérisation, "
            "sans succès observé à ce stade.",
        )
    ],
    "message_usurpe": [
        Correspondance(
            "T1566.002",
            "Message dont l'expéditeur affiché ne correspond pas à l'expéditeur authentifié : "
            "hameçonnage par usurpation.",
        )
    ],
    "protocole_herite": [
        Correspondance(
            "T1078.004",
            "Les protocoles hérités — IMAP, POP3, SMTP de base — contournent l'authentification "
            "multifacteur : c'est précisément pourquoi ils sont recherchés.",
        ),
        Correspondance(
            "T1556",
            "L'usage d'un protocole hérité neutralise le second facteur.",
            confidence="medium",
        ),
    ],
    "ioc_malveillant": [
        Correspondance(
            "T1071.001",
            "Indicateur confirmé malveillant : communication avec une infrastructure hostile.",
            confidence="medium",
        )
    ],
    "posture_defaillante": [
        Correspondance(
            "T1566.002",
            "Un domaine sans SPF, DKIM ou DMARC effectifs peut être usurpé par n'importe qui.",
        )
    ],
    "identifiants_divulgues": [
        Correspondance("T1589.001", "Identifiants collectés avant l'intrusion."),
    ],
    "audit_sensible": [
        Correspondance(
            "T1098",
            "Modification d'annuaire à portée de persistance ou d'élévation.",
            confidence="medium",
        )
    ],
}


#: Toutes les tables réunies, pour la résolution par nom de constat.
TOUTES: dict[str, list[Correspondance]] = {
    **{k.lower(): v for k, v in DETECTIONS_ENTRA.items()},
    **OPERATIONS_ANNUAIRE,
    **SIGNAUX_VERDICT,
}


def correspondances(constat: str) -> list[Correspondance]:
    """Les techniques associées à un constat, ou une liste vide.

    Une liste vide est une réponse : elle dit que ce constat n'a pas de
    correspondance **établie**. Retourner une technique approximative serait
    pire que de ne rien retourner — elle finirait recopiée dans un rapport.
    """
    return TOUTES.get(constat.strip().lower(), [])


def constats_connus() -> list[str]:
    """Le vocabulaire que la table sait traduire."""
    return sorted(TOUTES)

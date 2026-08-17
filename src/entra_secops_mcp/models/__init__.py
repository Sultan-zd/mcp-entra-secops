"""Modèles de sortie des outils : la troncature agressive, exprimée par des types.

Chaque modèle ne retient qu'une poignée de champs sur les dizaines renvoyées
par Microsoft Graph. C'est à la fois une optimisation de coût et un contrôle de
sécurité : un champ non listé ici n'atteint jamais le contexte du modèle, y
compris ceux qu'un attaquant contrôle (nom d'appareil, agent utilisateur).
"""

from .access import (
    ConditionalAccessPolicy,
    ConditionalAccessReport,
    UserContext,
)
from .audits import DirectoryAudit, DirectoryAuditsReport
from .common import (
    ENTRA_ERROR_CODES,
    PRIVILEGED_ROLES,
    describe_error_code,
    format_location,
    is_privileged_role,
)
from .identity import (
    RISK_EVENT_TYPES,
    RiskDetection,
    RiskDetectionsReport,
    RiskyUser,
    RiskyUsersReport,
)
from .signins import SignInEvent, SignInReport, SignInStatus

__all__ = [
    "ENTRA_ERROR_CODES",
    "PRIVILEGED_ROLES",
    "RISK_EVENT_TYPES",
    "ConditionalAccessPolicy",
    "ConditionalAccessReport",
    "DirectoryAudit",
    "DirectoryAuditsReport",
    "RiskDetection",
    "RiskDetectionsReport",
    "RiskyUser",
    "RiskyUsersReport",
    "SignInEvent",
    "SignInReport",
    "SignInStatus",
    "UserContext",
    "describe_error_code",
    "format_location",
    "is_privileged_role",
]

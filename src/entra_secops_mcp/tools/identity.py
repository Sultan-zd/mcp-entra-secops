"""Outils Identity Protection : comptes à risque et détections unitaires."""

from __future__ import annotations

import logging
from typing import Annotated

from pydantic import Field

from ..config import get_settings
from ..models import RiskDetection, RiskDetectionsReport, RiskyUser, RiskyUsersReport
from ..runtime import get_client
from .odata import escape_odata, since_iso

logger = logging.getLogger(__name__)

RISKY_USERS_ENDPOINT = "/identityProtection/riskyUsers"
RISK_DETECTIONS_ENDPOINT = "/identityProtection/riskDetections"

#: Ordre de gravité, du plus grave au plus bénin, pour trier les comptes.
_RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "hidden": 3, "none": 4}


async def get_risky_users(
    limit: Annotated[
        int | None,
        Field(description="Nombre maximum de comptes retournés. Défaut 25, borné à 100.", ge=1),
    ] = None,
    only_active: Annotated[
        bool,
        Field(
            description=(
                "Si vrai (défaut), ne retourne que les comptes encore à risque "
                "(atRisk, confirmedCompromised) et écarte ceux déjà remédiés ou classés."
            )
        ),
    ] = True,
) -> RiskyUsersReport:
    """Liste les comptes signalés à risque par Entra Identity Protection, du plus
    risqué au moins risqué.

    À utiliser pour obtenir une vue d'ensemble de l'exposition du tenant, ou pour
    confirmer qu'un compte précis est bien considéré comme compromis.

    Nécessite une licence Entra ID P2.
    """
    settings = get_settings()
    size = settings.clamp_limit(limit)

    params: dict[str, object] = {"$top": size}
    if only_active:
        params["$filter"] = "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"

    logger.info(
        "Recherche des comptes à risque (max %d, actifs seulement : %s).", size, only_active
    )
    raw = await get_client().get(RISKY_USERS_ENDPOINT, params=params, max_items=size)

    users = [RiskyUser.from_graph(item) for item in raw]
    users.sort(key=lambda u: (_RISK_ORDER.get(u.risk_level, 9), u.user_principal_name))
    return RiskyUsersReport.build(users)


async def get_risk_detections(
    upn: Annotated[
        str | None,
        Field(
            description=(
                "UPN à cibler. Omettre pour obtenir les détections de tout le tenant."
            )
        ),
    ] = None,
    hours: Annotated[
        int | None,
        Field(description="Fenêtre de recherche en heures. Défaut 24, borné à 168.", ge=1),
    ] = None,
    limit: Annotated[
        int | None,
        Field(description="Nombre maximum de détections. Défaut 25, borné à 100.", ge=1),
    ] = None,
) -> RiskDetectionsReport:
    """Récupère les détections de risque unitaires : identifiants divulgués, IP
    anonymisée, voyage impossible, pulvérisation de mots de passe.

    C'est l'outil qui explique POURQUOI un compte est signalé à risque, là où
    `get_risky_users` se contente de dire QUE le compte l'est.

    Nécessite une licence Entra ID P2.
    """
    settings = get_settings()
    window = settings.clamp_hours(hours)
    size = settings.clamp_limit(limit)

    clauses = [f"detectedDateTime ge {since_iso(window)}"]
    if upn:
        clauses.append(f"userPrincipalName eq '{escape_odata(upn)}'")

    params = {
        "$filter": " and ".join(clauses),
        "$top": size,
        "$orderby": "detectedDateTime desc",
    }

    logger.info("Recherche des détections de risque (upn=%s, %d h, max %d).", upn, window, size)
    raw = await get_client().get(RISK_DETECTIONS_ENDPOINT, params=params, max_items=size)

    detections = [RiskDetection.from_graph(item) for item in raw]
    detections.sort(key=lambda d: d.detected_at, reverse=True)
    return RiskDetectionsReport.build(detections)

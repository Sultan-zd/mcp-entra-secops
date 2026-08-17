"""Outil `get_directory_audits` : dérive de configuration et persistance."""

from __future__ import annotations

import logging
from typing import Annotated

from pydantic import Field

from ..config import get_settings
from ..models import DirectoryAudit, DirectoryAuditsReport
from ..runtime import get_client
from .odata import escape_odata, since_iso

logger = logging.getLogger(__name__)

DIRECTORY_AUDITS_ENDPOINT = "/auditLogs/directoryAudits"


async def get_directory_audits(
    hours: Annotated[
        int | None,
        Field(description="Fenêtre de recherche en heures. Défaut 24, borné à 168.", ge=1),
    ] = None,
    limit: Annotated[
        int | None,
        Field(description="Nombre maximum d'entrées. Défaut 25, borné à 100.", ge=1),
    ] = None,
    initiated_by: Annotated[
        str | None,
        Field(
            description=(
                "UPN de l'auteur des modifications, pour ne retenir que ses actions. "
                "Omettre pour balayer toutes les modifications du tenant."
            )
        ),
    ] = None,
) -> DirectoryAuditsReport:
    """Récupère les modifications administratives récentes de l'annuaire, afin
    d'identifier une dérive de configuration ou un changement non autorisé.

    Signale automatiquement les opérations à valeur de persistance ou d'élévation
    de privilèges : attribution de rôle, ajout d'un secret applicatif, enrôlement
    d'une méthode MFA, modification d'une politique d'accès conditionnel.

    À utiliser après avoir constaté une connexion suspecte, pour déterminer ce
    que l'attaquant a fait une fois entré.
    """
    settings = get_settings()
    window = settings.clamp_hours(hours)
    size = settings.clamp_limit(limit)

    clauses = [f"activityDateTime ge {since_iso(window)}"]
    if initiated_by:
        clauses.append(f"initiatedBy/user/userPrincipalName eq '{escape_odata(initiated_by)}'")

    params = {
        "$filter": " and ".join(clauses),
        "$top": size,
        "$orderby": "activityDateTime desc",
    }

    logger.info(
        "Recherche des audits d'annuaire (%d h, max %d, auteur=%s).", window, size, initiated_by
    )
    raw = await get_client().get(DIRECTORY_AUDITS_ENDPOINT, params=params, max_items=size)

    entries = [DirectoryAudit.from_graph(item) for item in raw]
    entries.sort(key=lambda e: e.activity_date, reverse=True)
    return DirectoryAuditsReport.build(window_hours=window, entries=entries)

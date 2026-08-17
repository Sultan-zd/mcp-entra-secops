"""Outil `get_user_signins` : investigation des connexions d'un utilisateur.

La fonction est volontairement indépendante du serveur MCP : elle s'enregistre
depuis ``server.py``. Elle reste ainsi testable sans démarrer de serveur.
"""

from __future__ import annotations

import logging
from typing import Annotated

from pydantic import Field

from ..config import get_settings
from ..graph import GraphError
from ..models import SignInEvent, SignInReport
from ..runtime import get_client
from .odata import escape_odata, since_iso

logger = logging.getLogger(__name__)

SIGNINS_ENDPOINT = "/auditLogs/signIns"


async def get_user_signins(
    upn: Annotated[
        str,
        Field(description="User Principal Name complet, par exemple « alice@contoso.com »."),
    ],
    hours: Annotated[
        int | None,
        Field(
            description="Fenêtre de recherche en heures. Défaut 24, borné à 168 (7 jours).",
            ge=1,
        ),
    ] = None,
    limit: Annotated[
        int | None,
        Field(description="Nombre maximum d'événements retournés. Défaut 25, borné à 100.", ge=1),
    ] = None,
) -> SignInReport:
    """Récupère les connexions récentes d'un utilisateur pour investiguer un
    blocage d'authentification, une anomalie géographique ou une compromission.

    Retourne les événements réduits à leurs indicateurs de sécurité, plus une
    synthèse chiffrée (nombre d'échecs, IP distinctes, observations calculées).

    Args:
        upn: User Principal Name complet, par exemple « alice@contoso.com ».
        hours: Fenêtre de recherche en heures. Défaut 24, maximum 168 (7 jours).
        limit: Nombre maximum d'événements retournés. Défaut 25, maximum 100.
    """
    settings = get_settings()
    window = settings.clamp_hours(hours)
    size = settings.clamp_limit(limit)

    params = {
        # Le filtrage part côté Microsoft : filtrer en Python après coup
        # impliquerait de télécharger les journaux de tout le tenant.
        "$filter": (
            f"userPrincipalName eq '{escape_odata(upn)}' "
            f"and createdDateTime ge {since_iso(window)}"
        ),
        "$top": size,
        "$orderby": "createdDateTime desc",
    }

    logger.info("Recherche des connexions de %s sur %d h (max %d).", upn, window, size)
    try:
        raw_events = await get_client().get(SIGNINS_ENDPOINT, params=params, max_items=size)
    except GraphError as exc:
        # L'erreur est déjà formulée pour être lue ; on la laisse remonter au
        # client MCP, qui la présentera au modèle comme un échec d'outil.
        logger.error("Échec de la récupération des connexions de %s : %s", upn, exc)
        raise

    events = [SignInEvent.from_graph(item) for item in raw_events]
    events.sort(key=lambda event: event.timestamp, reverse=True)
    return SignInReport.build(upn=upn, window_hours=window, events=events)

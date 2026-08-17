"""Aides partagées pour construire des requêtes OData sûres.

Les valeurs injectées dans un `$filter` proviennent du modèle, donc
indirectement de données non fiables. Elles ne sont jamais interpolées telles
quelles.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

GRAPH_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def escape_odata(value: str) -> str:
    """Neutralise l'apostrophe, seul caractère spécial dans un littéral OData.

    Sans cela, une valeur contenant une apostrophe casserait la requête — et
    ouvrirait la porte à une injection de filtre.
    """
    return value.replace("'", "''")


def since_iso(hours: int) -> str:
    """Retourne l'horodatage UTC d'il y a `hours` heures, au format attendu par Graph."""
    return (datetime.now(UTC) - timedelta(hours=hours)).strftime(GRAPH_TIME_FORMAT)

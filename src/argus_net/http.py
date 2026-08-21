"""Client HTTP pour les sources publiques.

Un serveur d'analyse qui tombe parce qu'une source publique a hoqueté n'est pas
utilisable en astreinte. Ce client traite donc les trois pannes qui arrivent
réellement : la limitation de débit, l'indisponibilité passagère, et la
réponse qui n'arrive jamais.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

#: Codes qui méritent une nouvelle tentative. Un 404 n'en mérite pas : la
#: ressource n'existera pas davantage à la seconde tentative.
REESSAYABLES = frozenset({429, 500, 502, 503, 504})

#: Au-delà, l'analyste attend trop longtemps pour ce que ça rapporte.
MAX_TENTATIVES = 3


class HttpError(RuntimeError):
    """Une source publique n'a pas répondu utilement."""

    def __init__(self, source: str, message: str, *, status: int | None = None) -> None:
        super().__init__(f"{source} : {message}")
        self.source = source
        self.status = status


class PublicHttpClient:
    """Client partagé, avec réessai et plafond de taille.

    Le plafond n'est pas décoratif : certains catalogues publics pèsent
    plusieurs mégaoctets et grossissent chaque mois. Sans borne, une source qui
    déraille remplirait la mémoire du serveur.
    """

    def __init__(
        self,
        *,
        timeout: float = 30.0,
        user_agent: str = "ARGUS-SecOps/1.0 (+https://github.com/Sultan-zd/mcp-entra-secops)",
        max_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": user_agent, "Accept": "application/json"},
            follow_redirects=True,
        )
        self._max_bytes = max_bytes

    async def get_json(
        self,
        url: str,
        *,
        source: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Récupère un document JSON, en réessayant ce qui mérite de l'être."""
        derniere: Exception | None = None

        for tentative in range(1, MAX_TENTATIVES + 1):
            try:
                reponse = await self._client.get(url, params=params, headers=headers)
            except httpx.TimeoutException:
                derniere = HttpError(source, "délai dépassé.")
                logger.debug("%s : délai dépassé (tentative %d).", source, tentative)
            except httpx.HTTPError as exc:
                derniere = HttpError(source, f"erreur réseau ({type(exc).__name__}).")
                logger.debug("%s : erreur réseau %s.", source, exc)
            else:
                if reponse.status_code in REESSAYABLES:
                    derniere = HttpError(
                        source,
                        f"réponse {reponse.status_code}.",
                        status=reponse.status_code,
                    )
                    # Un « Retry-After » explicite prime sur notre estimation :
                    # la source sait mieux que nous quand elle sera prête.
                    attente = self._retry_after(reponse) or 2.0 * tentative
                    if tentative < MAX_TENTATIVES:
                        logger.debug("%s : nouvelle tentative dans %.1f s.", source, attente)
                        await asyncio.sleep(attente)
                        continue
                elif reponse.status_code >= 400:
                    raise HttpError(
                        source,
                        f"réponse {reponse.status_code}.",
                        status=reponse.status_code,
                    )
                else:
                    if len(reponse.content) > self._max_bytes:
                        raise HttpError(
                            source,
                            f"réponse de {len(reponse.content) // 1024} Kio, au-delà de la limite.",
                        )
                    try:
                        return reponse.json()
                    except ValueError as exc:
                        raise HttpError(source, "réponse illisible (JSON attendu).") from exc

            if tentative < MAX_TENTATIVES:
                await asyncio.sleep(1.5 * tentative)

        raise derniere or HttpError(source, "aucune réponse exploitable.")

    async def get_text(self, url: str, *, source: str) -> str:
        """Récupère un document texte — certains flux de menaces sont en CSV."""
        try:
            reponse = await self._client.get(url)
        except httpx.HTTPError as exc:
            raise HttpError(source, f"erreur réseau ({type(exc).__name__}).") from exc

        if reponse.status_code >= 400:
            raise HttpError(source, f"réponse {reponse.status_code}.", status=reponse.status_code)
        if len(reponse.content) > self._max_bytes:
            raise HttpError(source, "réponse trop volumineuse.")
        return reponse.text

    @staticmethod
    def _retry_after(reponse: httpx.Response) -> float | None:
        """Lit l'en-tête Retry-After s'il est présent et exploitable.

        Une valeur de zéro est une valeur : elle signifie « tout de suite ».
        Un test de vérité simple la confondrait avec l'absence d'en-tête.
        """
        brut = reponse.headers.get("Retry-After")
        if brut is None:
            return None
        try:
            return max(0.0, float(brut))
        except ValueError:
            return None

    async def aclose(self) -> None:
        await self._client.aclose()

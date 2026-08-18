"""Accès à Microsoft Graph : authentification, résilience et pagination.

Deux implémentations partagent la même interface :

* :class:`HttpGraphClient` interroge réellement Microsoft Graph ;
* :class:`FixtureGraphClient` rejoue des données locales, ce qui permet de
  développer et de démontrer le serveur sans tenant ni licence Entra ID P1/P2.

Les outils ne connaissent que l'interface, jamais l'implémentation.
"""

from __future__ import annotations

import abc
import asyncio
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from importlib import resources
from typing import Any

import httpx

from .config import Settings

logger = logging.getLogger(__name__)

#: Statuts qui justifient une nouvelle tentative : quota dépassé côté Graph,
#: ou incident transitoire côté Microsoft.
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

#: Correspondance entre un chemin Graph, le fichier de démonstration associé, et
#: les champs à recaler dans le temps.
#:
#: Un motif peut capturer un segment d'URL (l'identifiant d'un utilisateur, par
#: exemple) ; les enregistrements du fichier sont alors restreints à ceux dont
#: le champ `_scope` vaut ce segment. C'est ce qui permet de simuler des
#: endpoints paramétrés comme /users/{id}/memberOf.
#:
#: Le troisième élément liste les champs d'ÉVÉNEMENT, seuls concernés par le
#: recalage. La distinction est essentielle : `createdDateTime` désigne l'heure
#: d'une connexion sur /auditLogs/signIns, mais la date de création d'un compte
#: sur /users. Recaler la seconde ferait apparaître tous les comptes comme
#: créés il y a quelques mois — et un analyste en tirerait des conclusions.
_FIXTURE_PATTERNS: tuple[tuple[re.Pattern[str], str, tuple[str, ...]], ...] = (
    (re.compile(r"^/auditLogs/signIns$"), "signins.json", ("createdDateTime",)),
    (re.compile(r"^/auditLogs/directoryAudits$"), "directory_audits.json", ("activityDateTime",)),
    (
        re.compile(r"^/identityProtection/riskyUsers$"),
        "risky_users.json",
        ("riskLastUpdatedDateTime",),
    ),
    (
        re.compile(r"^/identityProtection/riskDetections$"),
        "risk_detections.json",
        ("activityDateTime", "detectedDateTime"),
    ),
    # Les dates de politique et de création de compte décrivent la configuration
    # du tenant, pas l'incident : elles restent telles quelles.
    (re.compile(r"^/identity/conditionalAccess/policies$"), "conditional_access.json", ()),
    (re.compile(r"^/users$"), "users.json", ()),
    (re.compile(r"^/users/([^/]+)/memberOf$"), "member_of.json", ()),
)

#: Dernier événement du scénario de démonstration, tous fichiers confondus.
#: Le décalage temporel est calculé UNE fois à partir de cette ancre, puis
#: appliqué identiquement partout. Un décalage calculé fichier par fichier
#: désynchroniserait les outils entre eux et détruirait la chronologie de
#: l'incident — précisément ce que la démonstration doit montrer.
_SCENARIO_ANCHOR = datetime(2026, 8, 17, 7, 2, 15, tzinfo=UTC)


class GraphError(RuntimeError):
    """Erreur exploitable côté outil, formulée pour être lue par un humain.

    Le message ne contient jamais de jeton ni de secret : il est destiné à
    remonter tel quel jusqu'au modèle.
    """


class GraphClient(abc.ABC):
    """Interface commune aux deux sources de données."""

    @abc.abstractmethod
    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        max_items: int | None = None,
    ) -> list[dict[str, Any]]:
        """Retourne la collection `value` d'un endpoint Graph, paginée si besoin."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Libère les ressources détenues par la source."""


# ---------------------------------------------------------------------------
# Implémentation réelle
# ---------------------------------------------------------------------------
class HttpGraphClient(GraphClient):
    """Client Microsoft Graph authentifié en OAuth 2.0 (flux client credentials)."""

    def __init__(self, settings: Settings) -> None:
        # Import tardif : azure-identity n'est pas nécessaire en mode fixture.
        from azure.identity.aio import ClientSecretCredential

        if not (
            settings.azure_tenant_id and settings.azure_client_id and settings.azure_client_secret
        ):
            raise GraphError(
                "Identifiants Azure incomplets. Vérifiez AZURE_TENANT_ID, AZURE_CLIENT_ID "
                "et AZURE_CLIENT_SECRET."
            )

        self._settings = settings
        self._credential = ClientSecretCredential(
            tenant_id=settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            client_secret=settings.azure_client_secret,
        )
        self._http = httpx.AsyncClient(
            base_url=settings.graph_base_url,
            timeout=settings.request_timeout_seconds,
            headers={"Accept": "application/json"},
        )

    async def _authorization_header(self) -> dict[str, str]:
        """Retourne l'en-tête Bearer. azure-identity gère le cache et la rotation."""
        try:
            token = await self._credential.get_token(self._settings.graph_scope)
        # Toute panne d'authentification est reformulée : le détail brut
        # d'azure-identity n'est pas exploitable par un analyste.
        except Exception as exc:
            raise GraphError(
                "Échec de l'obtention du jeton OAuth 2.0 auprès d'Entra ID. "
                "Vérifiez le tenant, l'identifiant d'application et le secret client. "
                f"Détail : {type(exc).__name__}"
            ) from exc
        return {"Authorization": f"Bearer {token.token}"}

    async def _request_page(self, url: str, params: dict[str, Any] | None) -> dict[str, Any]:
        """Exécute une requête en réessayant sur quota dépassé ou incident transitoire."""
        headers = await self._authorization_header()
        last_status: int | None = None

        for attempt in range(self._settings.max_retries + 1):
            response = await self._http.get(url, params=params, headers=headers)

            if response.status_code < 400:
                return dict(response.json())

            last_status = response.status_code
            if response.status_code not in _RETRYABLE_STATUS:
                raise self._explain_failure(response)

            if attempt == self._settings.max_retries:
                break

            # Graph indique lui-même combien de temps patienter ; on le respecte,
            # sinon on retombe sur un délai exponentiel. Le test explicite à None
            # est nécessaire : « Retry-After: 0 » est une consigne valide, qu'un
            # simple `or` interpréterait comme un en-tête absent.
            retry_after = _retry_after_seconds(response)
            delay = retry_after if retry_after is not None else 2.0**attempt
            logger.warning(
                "Graph a répondu %s ; nouvelle tentative dans %.1f s (%d/%d).",
                response.status_code,
                delay,
                attempt + 1,
                self._settings.max_retries,
            )
            await asyncio.sleep(delay)

        raise GraphError(
            f"Microsoft Graph reste indisponible (statut {last_status}) après "
            f"{self._settings.max_retries} nouvelles tentatives."
        )

    def _explain_failure(self, response: httpx.Response) -> GraphError:
        """Traduit une réponse d'erreur Graph en message actionnable."""
        try:
            detail = response.json().get("error", {})
            code = detail.get("code", "")
            message = detail.get("message", "")
        except (ValueError, AttributeError):
            code, message = "", response.text[:200]

        if response.status_code == 401:
            return GraphError(
                "Authentification refusée par Microsoft Graph (401). Le secret client est "
                "probablement expiré ou révoqué."
            )
        if response.status_code == 403:
            # Graph renvoie 403 aussi bien pour une permission manquante que
            # pour une licence absente. Les deux se corrigent à des endroits
            # différents : confondre les deux fait perdre des heures à chercher
            # une permission qui, elle, est bien accordée.
            if _is_licence_error(code, message):
                return GraphError(
                    "Licence Entra ID insuffisante (403). Les permissions sont accordées, "
                    "mais le tenant ne dispose pas de la licence requise : Entra ID P1 pour "
                    "les journaux de connexion, P2 pour Identity Protection. "
                    f"Détail Graph : {code} {message}"
                )
            return GraphError(
                "Permission insuffisante (403). L'application Entra n'a pas la permission "
                "applicative requise, ou le consentement administrateur n'a pas été accordé. "
                f"Détail Graph : {code} {message}"
            )
        if response.status_code == 404:
            return GraphError(f"Ressource introuvable (404). Détail Graph : {code} {message}")
        return GraphError(
            f"Microsoft Graph a renvoyé une erreur {response.status_code}. "
            f"Détail : {code} {message}"
        )

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        max_items: int | None = None,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        url: str = path
        query: dict[str, Any] | None = dict(params or {})

        # Deux garde-fous contre une pagination qui ne se termine pas : un
        # `@odata.nextLink` qui se répète, et un nombre de pages plafonné. Sans
        # eux, un endpoint défaillant ou malveillant bloquerait le serveur
        # indéfiniment, sans erreur ni journal.
        visited: set[str] = set()

        for page in range(1, self._settings.max_pages + 1):
            if url in visited:
                logger.warning(
                    "Pagination interrompue : Graph a renvoyé un lien déjà suivi (%s). "
                    "%d éléments collectés.",
                    url,
                    len(items),
                )
                break
            visited.add(url)

            payload = await self._request_page(url, query)
            items.extend(payload.get("value", []))

            if max_items is not None and len(items) >= max_items:
                return items[:max_items]

            # `@odata.nextLink` est une URL absolue qui porte déjà ses paramètres.
            next_link = payload.get("@odata.nextLink")
            if not next_link:
                break
            url, query = str(next_link), None

            if page == self._settings.max_pages:
                logger.warning(
                    "Pagination interrompue au plafond de %d pages ; %d éléments collectés. "
                    "Affinez le filtre ou augmentez ENTRA_MAX_PAGES.",
                    self._settings.max_pages,
                    len(items),
                )

        return items

    async def aclose(self) -> None:
        await self._http.aclose()
        await self._credential.close()


# ---------------------------------------------------------------------------
# Implémentation locale
# ---------------------------------------------------------------------------
_FILTER_CLAUSE = re.compile(
    r"^(?P<field>[A-Za-z_][\w]*)\s+(?P<op>eq|ne|ge|gt|le|lt)\s+(?P<value>'[^']*'|[^\s]+)$"
)


class FixtureGraphClient(GraphClient):
    """Rejoue des réponses Graph enregistrées, avec un sous-ensemble de `$filter`.

    Sont interprétées les clauses `champ eq 'valeur'` et les comparaisons de
    dates (`ge`, `le`, ...) sur des champs de premier niveau, combinées par
    `and`. C'est volontairement limité : l'objectif est de rendre les
    démonstrations crédibles, pas de réimplémenter OData.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _load(self, path: str) -> list[dict[str, Any]]:
        for pattern, filename, time_fields in _FIXTURE_PATTERNS:
            found = pattern.match(path)
            if found is None:
                continue

            source = resources.files("entra_secops_mcp.fixtures").joinpath(filename)
            payload = json.loads(source.read_text(encoding="utf-8"))
            records = list(payload.get("value", []))

            # Endpoint paramétré : on ne retient que les enregistrements
            # rattachés au segment capturé.
            if found.groups():
                scope = found.group(1)
                records = [r for r in records if r.get("_scope") == scope]

            return _rebase_to_now(records, time_fields)

        raise GraphError(
            f"Aucune donnée de démonstration pour l'endpoint « {path} ». "
            "Basculez sur ENTRA_DATA_SOURCE=graph, ou ajoutez le fichier correspondant "
            "dans src/entra_secops_mcp/fixtures/."
        )

    @staticmethod
    def _clause_matches(record: dict[str, Any], clause: str) -> bool | None:
        """Évalue une clause unique. Retourne None si elle n'est pas reconnue."""
        parsed = _FILTER_CLAUSE.match(clause.strip())
        if parsed is None:
            logger.debug("Clause de filtre ignorée en mode fixture : %s", clause)
            return None

        actual = record.get(parsed["field"])
        if actual is None:
            return False

        left, right, op = str(actual), parsed["value"].strip("'"), parsed["op"]
        if op == "eq":
            return left == right
        if op == "ne":
            return left != right
        if op == "gt":
            return left > right
        if op == "ge":
            return left >= right
        if op == "lt":
            return left < right
        return left <= right

    @classmethod
    def _matches(cls, record: dict[str, Any], expression: str) -> bool:
        """Évalue le sous-ensemble de `$filter` reconnu.

        Sont acceptées les expressions entièrement en `and` ou entièrement en
        `or`, sur des champs de premier niveau. Les combinaisons mixtes et les
        parenthèses ne le sont pas : c'est délibéré, l'objectif est de rendre
        les démonstrations crédibles, pas de réimplémenter OData. Une clause non
        reconnue est ignorée plutôt que d'écarter silencieusement des données.
        """
        if " or " in expression and " and " not in expression:
            verdicts = [cls._clause_matches(record, c) for c in expression.split(" or ")]
            connus = [v for v in verdicts if v is not None]
            return any(connus) if connus else True

        verdicts = [cls._clause_matches(record, c) for c in expression.split(" and ")]
        return all(v for v in verdicts if v is not None)

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        max_items: int | None = None,
    ) -> list[dict[str, Any]]:
        records = self._load(path)
        params = params or {}

        expression = params.get("$filter")
        if expression:
            records = [r for r in records if self._matches(r, str(expression))]

        top = params.get("$top")
        if top is not None:
            records = records[: int(top)]
        if max_items is not None:
            records = records[:max_items]
        return records

    async def aclose(self) -> None:
        """Aucune ressource à libérer : les données sont lues sur disque."""
        return None


def _scenario_offset() -> timedelta:
    """Écart entre l'instant présent et la fin du scénario de démonstration.

    Calculé à partir d'une ancre unique et fixe, donc identique pour tous les
    fichiers de démonstration : la chronologie relative entre les connexions,
    les détections de risque et les audits d'annuaire est préservée à la
    seconde près.
    """
    return datetime.now(UTC) - _SCENARIO_ANCHOR


def _rebase_to_now(
    records: list[dict[str, Any]], time_fields: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Décale les horodatages d'événement pour que le scénario se termine « maintenant ».

    Sans ce décalage, une fixture datée du jour de sa création cesserait
    d'apparaître dans une fenêtre de 24 h dès le lendemain, et les
    démonstrations cesseraient de fonctionner.

    Seuls les champs listés dans `time_fields` sont décalés. Les dates qui
    décrivent la configuration du tenant — création d'un compte, modification
    d'une politique — restent intactes : les décaler inventerait des
    coïncidences que l'analyste interpréterait comme des indices.
    """
    if not time_fields:
        return records

    offset = _scenario_offset()
    for record in records:
        for field in time_fields:
            if record.get(field):
                shifted = datetime.fromisoformat(str(record[field])) + offset
                record[field] = shifted.strftime("%Y-%m-%dT%H:%M:%SZ")
    return records


#: Marqueurs par lesquels Graph signale une licence manquante plutôt qu'une
#: permission manquante, alors qu'il renvoie 403 dans les deux cas.
_LICENCE_MARKERS = (
    "requestfromnonpremiumtenant",
    "not licensed",
    "premium license",
    "premium licence",
)


def _is_licence_error(code: str, message: str) -> bool:
    """Distingue un 403 de licence d'un 403 de permission."""
    haystack = f"{code} {message}".lower()
    return any(marker in haystack for marker in _LICENCE_MARKERS)


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """Lit l'en-tête `Retry-After` s'il est présent et exploitable."""
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        # La forme « date HTTP » est admise par la RFC mais Graph utilise des
        # secondes ; on préfère le repli exponentiel plutôt que de mal parser.
        return None


def build_client(settings: Settings) -> GraphClient:
    """Instancie la source de données correspondant à la configuration."""
    if settings.data_source == "fixture":
        logger.info("Source de données : fixtures locales (aucun appel à Microsoft Graph).")
        return FixtureGraphClient(settings)
    logger.info("Source de données : Microsoft Graph (%s).", settings.graph_base_url)
    return HttpGraphClient(settings)

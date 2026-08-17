"""Résilience du client Graph et fidélité de la source de démonstration."""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx

from entra_secops_mcp.config import Settings
from entra_secops_mcp.graph import FixtureGraphClient, GraphError, HttpGraphClient

SIGNINS_PATH = "/auditLogs/signIns"
SIGNINS_URL = f"https://graph.microsoft.com/v1.0{SIGNINS_PATH}"


class CredentialFactice:
    """Remplace ClientSecretCredential : aucun échange réseau avec Entra.

    Instancier le vrai credential dans une suite de tests l'amène à préparer un
    transport asynchrone lié à une boucle d'événements, ce qui bloque sous
    pytest. La substitution rend les tests hermétiques et instantanés, et permet
    d'exercer `_authorization_header` pour de vrai plutôt que de le neutraliser.
    """

    def __init__(self, **_: Any) -> None:
        self.closed = False

    async def get_token(self, *_scopes: str) -> SimpleNamespace:
        return SimpleNamespace(token="jeton-de-test")

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
async def http_client(
    graph_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[HttpGraphClient]:
    """Client Graph réel, branché sur un fournisseur de jeton factice.

    La fixture est asynchrone à dessein : `httpx.AsyncClient` doit être
    instancié dans la boucle d'événements qui l'utilisera. Créé en dehors, il
    se bloque au premier `await` — c'est aussi ainsi que le serveur procède,
    via le cycle de vie MCP.
    """
    monkeypatch.setattr("azure.identity.aio.ClientSecretCredential", CredentialFactice)
    client = HttpGraphClient(graph_settings)
    try:
        yield client
    finally:
        await client.aclose()


# --------------------------------------------------------------------------
# Client HTTP
# --------------------------------------------------------------------------
async def test_pagination_suit_le_next_link(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter
) -> None:
    # Une seule route à effets successifs : une route « sans query » capterait
    # aussi la page 2 et masquerait le comportement réel.
    respx_mock.get(SIGNINS_URL).mock(
        side_effect=[
            httpx.Response(
                200,
                json={"value": [{"id": "1"}], "@odata.nextLink": f"{SIGNINS_URL}?page=2"},
            ),
            httpx.Response(200, json={"value": [{"id": "2"}]}),
        ]
    )

    items = await http_client.get(SIGNINS_PATH)

    assert [item["id"] for item in items] == ["1", "2"]


async def test_pagination_en_boucle_est_interrompue(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter
) -> None:
    """Un `@odata.nextLink` qui pointe sur lui-même ne doit pas figer le serveur."""
    respx_mock.get(SIGNINS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"value": [{"id": "boucle"}], "@odata.nextLink": SIGNINS_URL},
        )
    )

    items = await http_client.get(SIGNINS_PATH)

    # Le premier appel utilise le chemin relatif, le lien suivant est absolu :
    # la répétition n'est donc détectée qu'au tour suivant. L'essentiel est que
    # la boucle s'arrête, et vite.
    assert items == [{"id": "boucle"}, {"id": "boucle"}]


async def test_plafond_de_pages_respecte(
    graph_settings: Settings, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
) -> None:
    """Des liens toujours nouveaux ne doivent pas provoquer une boucle infinie."""
    monkeypatch.setattr("azure.identity.aio.ClientSecretCredential", CredentialFactice)
    monkeypatch.setattr(graph_settings, "max_pages", 3)
    client = HttpGraphClient(graph_settings)

    compteur = itertools.count()
    respx_mock.get(url__startswith=SIGNINS_URL).mock(
        side_effect=lambda request: httpx.Response(
            200,
            json={
                "value": [{"id": "x"}],
                "@odata.nextLink": f"{SIGNINS_URL}?page={next(compteur)}",
            },
        )
    )

    items = await client.get(SIGNINS_PATH)

    assert len(items) == 3
    await client.aclose()


async def test_max_items_stoppe_la_pagination(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(SIGNINS_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [{"id": "1"}, {"id": "2"}],
                "@odata.nextLink": f"{SIGNINS_URL}?page=2",
            },
        )
    )

    items = await http_client.get(SIGNINS_PATH, max_items=1)

    assert len(items) == 1
    assert route.call_count == 1  # la page suivante n'a pas été demandée


async def test_reessai_sur_429_puis_succes(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(SIGNINS_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={"value": [{"id": "ok"}]}),
        ]
    )

    items = await http_client.get(SIGNINS_PATH)

    assert items == [{"id": "ok"}]
    assert route.call_count == 2


async def test_retry_after_zero_est_respecte(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter
) -> None:
    """« Retry-After: 0 » est une consigne valide, pas un en-tête absent.

    Traité par un `or`, il déclencherait le repli exponentiel et ferait
    patienter inutilement plusieurs secondes.
    """
    respx_mock.get(SIGNINS_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={"value": []}),
        ]
    )

    debut = datetime.now(UTC)
    await http_client.get(SIGNINS_PATH)
    duree = (datetime.now(UTC) - debut).total_seconds()

    assert duree < 0.5


async def test_abandon_apres_epuisement_des_tentatives(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(SIGNINS_URL).mock(
        return_value=httpx.Response(503, headers={"Retry-After": "0"})
    )

    with pytest.raises(GraphError, match="indisponible"):
        await http_client.get(SIGNINS_PATH)

    assert route.call_count == 3  # tentative initiale + 2 reprises


async def test_403_explique_la_permission_manquante(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(SIGNINS_URL).mock(
        return_value=httpx.Response(
            403,
            json={"error": {"code": "Authorization_RequestDenied", "message": "Insufficient."}},
        )
    )

    with pytest.raises(GraphError) as err:
        await http_client.get(SIGNINS_PATH)

    message = str(err.value)
    assert "consentement administrateur" in message
    assert "Authorization_RequestDenied" in message


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (
            "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
            "Tenant is not a B2C tenant and doesn't have premium license",
        ),
        ("Forbidden", "Your tenant is not licensed for this feature."),
    ],
)
async def test_403_de_licence_distingue_du_403_de_permission(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter, code: str, message: str
) -> None:
    """Graph renvoie 403 pour une licence absente comme pour une permission absente.

    Les confondre envoie l'analyste chercher une permission qui, elle, est bien
    accordée. Cas rencontré en conditions réelles sur un tenant sans P1/P2.
    """
    respx_mock.get(SIGNINS_URL).mock(
        return_value=httpx.Response(403, json={"error": {"code": code, "message": message}})
    )

    with pytest.raises(GraphError) as err:
        await http_client.get(SIGNINS_PATH)

    texte = str(err.value)
    assert "Licence Entra ID insuffisante" in texte
    assert "P1" in texte and "P2" in texte
    assert "consentement administrateur" not in texte


async def test_403_de_permission_reste_un_message_de_permission(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(SIGNINS_URL).mock(
        return_value=httpx.Response(
            403,
            json={
                "error": {
                    "code": "Authorization_RequestDenied",
                    "message": "Insufficient privileges to complete the operation.",
                }
            },
        )
    )

    with pytest.raises(GraphError) as err:
        await http_client.get(SIGNINS_PATH)

    assert "consentement administrateur" in str(err.value)
    assert "Licence" not in str(err.value)


async def test_401_designe_le_secret_expire(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(SIGNINS_URL).mock(return_value=httpx.Response(401, json={}))

    with pytest.raises(GraphError, match="secret client"):
        await http_client.get(SIGNINS_PATH)


async def test_erreur_non_reessayable_echoue_immediatement(
    http_client: HttpGraphClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(SIGNINS_URL).mock(return_value=httpx.Response(400, json={}))

    with pytest.raises(GraphError):
        await http_client.get(SIGNINS_PATH)

    assert route.call_count == 1


def test_identifiants_incomplets_refuses(fixture_settings: Settings) -> None:
    with pytest.raises(GraphError, match="Identifiants Azure incomplets"):
        HttpGraphClient(fixture_settings)


# --------------------------------------------------------------------------
# Source de démonstration
# --------------------------------------------------------------------------
async def test_fixture_filtre_par_upn(fixture_settings: Settings) -> None:
    client = FixtureGraphClient(fixture_settings)

    items = await client.get(
        SIGNINS_PATH,
        params={"$filter": "userPrincipalName eq 'ahmad.k@teknologiia.com'"},
    )

    assert items
    assert {item["userPrincipalName"] for item in items} == {"ahmad.k@teknologiia.com"}


async def test_fixture_applique_le_top(fixture_settings: Settings) -> None:
    client = FixtureGraphClient(fixture_settings)
    assert len(await client.get(SIGNINS_PATH, params={"$top": 3})) == 3


async def test_fixture_horodatages_recales_sur_maintenant(fixture_settings: Settings) -> None:
    """Sans recalage, la démonstration cesserait de fonctionner le lendemain."""
    client = FixtureGraphClient(fixture_settings)

    items = await client.get(SIGNINS_PATH)
    stamps = [datetime.fromisoformat(item["createdDateTime"]) for item in items]

    assert max(stamps) > datetime.now(UTC) - timedelta(minutes=5)


async def test_date_de_creation_de_compte_jamais_decalee(fixture_settings: Settings) -> None:
    """`createdDateTime` sur /users est une date de création, pas un événement.

    Le décaler faisait apparaître un compte créé en 2024 comme créé quelques
    mois plus tôt — et un analyste en tirait une conclusion sur l'ancienneté
    du compte.
    """
    client = FixtureGraphClient(fixture_settings)

    users = await client.get(
        "/users", params={"$filter": "userPrincipalName eq 'marketing@teknologiia.com'"}
    )

    assert users[0]["createdDateTime"] == "2024-09-02T08:30:00Z"


async def test_dates_de_politique_jamais_decalees(fixture_settings: Settings) -> None:
    """Une politique modifiée il y a des mois ne doit pas sembler l'avoir été
    pendant l'incident : ce serait une coïncidence inventée."""
    client = FixtureGraphClient(fixture_settings)

    politiques = await client.get("/identity/conditionalAccess/policies")
    pays = next(p for p in politiques if p["displayName"] == "Bloquer les pays à risque")

    assert pays["modifiedDateTime"] == "2026-08-15T11:02:00Z"


async def test_chronologie_coherente_entre_outils(fixture_settings: Settings) -> None:
    """Le décalage doit être IDENTIQUE pour tous les fichiers.

    Avec un décalage calculé fichier par fichier, chaque source glissait
    différemment et l'ordre réel des événements s'inversait d'un outil à
    l'autre. La fuite d'identifiants doit précéder la connexion réussie, qui
    doit elle-même précéder l'attribution de rôle.
    """
    client = FixtureGraphClient(fixture_settings)

    detections = await client.get("/identityProtection/riskDetections")
    signins = await client.get(SIGNINS_PATH)
    audits = await client.get("/auditLogs/directoryAudits")

    fuite = next(
        d for d in detections if d["riskEventType"] == "leakedCredentials"
    )
    succes = next(
        s
        for s in signins
        if s["userPrincipalName"] == "marketing@teknologiia.com"
        and s["status"]["errorCode"] == 0
        and s["clientAppUsed"] == "Browser"
    )
    role = next(a for a in audits if a["activityDisplayName"] == "Add member to role")

    assert fuite["detectedDateTime"] < succes["createdDateTime"]
    assert succes["createdDateTime"] < role["activityDateTime"]


async def test_fixture_filtre_de_date(fixture_settings: Settings) -> None:
    client = FixtureGraphClient(fixture_settings)
    since = (datetime.now(UTC) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    recents = await client.get(SIGNINS_PATH, params={"$filter": f"createdDateTime ge {since}"})
    total: list[dict[str, Any]] = await client.get(SIGNINS_PATH)

    assert 0 < len(recents) < len(total)


async def test_fixture_endpoint_inconnu_message_explicite(fixture_settings: Settings) -> None:
    client = FixtureGraphClient(fixture_settings)

    with pytest.raises(GraphError, match="Aucune donnée de démonstration"):
        await client.get("/inexistant")

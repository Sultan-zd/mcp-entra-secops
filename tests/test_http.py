"""Le transport HTTP, et les garde-fous qui empêchent de l'ouvrir trop grand.

Ouvrir un port change la nature du serveur : en stdio, le client lance
lui-même le processus et la surface réseau est *nulle*. Ces tests portent sur
la seule décision irréversible que le transport HTTP introduit — accepter de
servir 50 outils de sécurité, et les identifiants de tenant qui vont avec, à
quelqu'un d'autre que soi.

Le dernier test démarre un **vrai serveur** et lui envoie de **vraies
requêtes**. Il est plus lent que les autres, et c'est le seul qui prouve
quelque chose : une politique d'authentification qui n'a jamais reçu de requête
non authentifiée n'est qu'une intention.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from argus_bundle.http import (
    LONGUEUR_MINIMALE,
    ConfigurationHttpError,
    JetonPartage,
    est_boucle_locale,
    parametres_auth,
    parametres_securite,
    resoudre_jeton,
)

RACINE = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# Ce qui compte comme « la machine elle-même »
# --------------------------------------------------------------------------
@pytest.mark.parametrize("hote", ["127.0.0.1", "localhost", "::1", "127.0.0.53", ""])
def test_ces_adresses_sont_la_boucle_locale(hote: str) -> None:
    assert est_boucle_locale(hote) is True


@pytest.mark.parametrize(
    "hote",
    [
        "0.0.0.0",  # noqa: S104 - c'est précisément le cas dangereux à couvrir
        "192.168.1.10",
        "10.0.0.4",
        "203.0.113.7",
        "::",
        "argus.interne.example",
        "nom-non-resoluble",
    ],
)
def test_ces_adresses_ne_le_sont_pas(hote: str) -> None:
    """Un nom qu'on ne sait pas résoudre est traité comme public.

    Se tromper dans ce sens ferme le serveur ; se tromper dans l'autre
    l'ouvrirait en silence.
    """
    assert est_boucle_locale(hote) is False


# --------------------------------------------------------------------------
# La décision de démarrer, ou non
# --------------------------------------------------------------------------
def test_sans_jeton_la_boucle_locale_est_acceptee() -> None:
    """Le cas d'usage courant : un analyste, sa propre machine."""
    assert resoudre_jeton("127.0.0.1", None) is None


@pytest.mark.parametrize("hote", ["0.0.0.0", "192.168.1.10", "argus.interne.example"])  # noqa: S104
def test_sans_jeton_une_interface_publique_est_refusee(hote: str) -> None:
    """Le garde-fou central de ce module.

    La commande dangereuse — `--host 0.0.0.0` — est plus courte à taper que la
    commande sûre, et l'oubli n'est pas rattrapable une fois le port ouvert.
    Le serveur refuse donc de démarrer plutôt que d'avertir.
    """
    with pytest.raises(ConfigurationHttpError) as erreur:
        resoudre_jeton(hote, None)

    message = str(erreur.value)
    assert "ARGUS_HTTP_TOKEN" in message
    assert hote in message


def test_un_jeton_trop_court_est_refuse_meme_en_local() -> None:
    """Un jeton de test finit toujours par se retrouver en production."""
    with pytest.raises(ConfigurationHttpError):
        resoudre_jeton("127.0.0.1", "court")


def test_un_jeton_valable_est_accepte() -> None:
    jeton = "x" * LONGUEUR_MINIMALE
    assert resoudre_jeton("0.0.0.0", jeton) == jeton  # noqa: S104


def test_les_espaces_autour_du_jeton_sont_retires() -> None:
    """Une variable d'environnement copiée-collée traîne souvent un espace."""
    assert resoudre_jeton("127.0.0.1", f"  {'y' * 20}  ") == "y" * 20


def test_un_jeton_vide_ne_compte_pas_comme_un_jeton() -> None:
    with pytest.raises(ConfigurationHttpError):
        resoudre_jeton("0.0.0.0", "   ")  # noqa: S104


# --------------------------------------------------------------------------
# La vérification du jeton
# --------------------------------------------------------------------------
async def test_le_bon_jeton_est_accepte() -> None:
    verificateur = JetonPartage("s" * 32)

    accord = await verificateur.verify_token("s" * 32)

    assert accord is not None
    assert accord.scopes == ["argus:read"]


@pytest.mark.parametrize(
    "presente",
    [
        "",
        "s" * 31,  # bon préfixe, trop court
        "s" * 33,  # bon préfixe, trop long
        "t" * 32,
    ],
)
async def test_tout_autre_jeton_est_refuse(presente: str) -> None:
    verificateur = JetonPartage("s" * 32)

    assert await verificateur.verify_token(presente) is None


# --------------------------------------------------------------------------
# La configuration transmise au SDK
# --------------------------------------------------------------------------
def test_sans_jeton_aucune_authentification_n_est_declaree() -> None:
    """Le SDK refuse un vérificateur sans réglages, et inversement."""
    assert parametres_auth(None, "127.0.0.1", 8000) is None


def test_avec_jeton_les_reglages_designent_le_serveur_lui_meme() -> None:
    reglages = parametres_auth("z" * 20, "127.0.0.1", 8123)

    assert reglages is not None
    assert str(reglages.issuer_url).startswith("http://127.0.0.1:8123")
    assert reglages.required_scopes == ["argus:read"]


def test_la_protection_contre_le_rebinding_n_est_jamais_desactivee() -> None:
    """Sans elle, une page web visitée par l'analyste pilote son serveur local."""
    securite = parametres_securite("127.0.0.1", 8000)

    assert securite.enable_dns_rebinding_protection is True
    assert "http://127.0.0.1:8000" in securite.allowed_origins


# --------------------------------------------------------------------------
# Le seul test qui prouve quelque chose : un vrai serveur, de vraies requêtes
# --------------------------------------------------------------------------
def _port_libre() -> int:
    with socket.socket() as prise:
        prise.bind(("127.0.0.1", 0))
        return int(prise.getsockname()[1])


@pytest.fixture(scope="module")
def serveur_http() -> object:
    """Démarre un vrai serveur ARGUS en HTTP, sans aucune clé de domaine."""
    port = _port_libre()
    jeton = "jeton-de-test-suffisamment-long"

    env = dict(os.environ)
    env["ARGUS_HTTP_TOKEN"] = jeton
    env["PYTHONPATH"] = str(RACINE / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    for cle in (
        "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "ENTRA_DATA_SOURCE",
    ):
        env.pop(cle, None)

    processus = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "argus_bundle", "--http",
         "--port", str(port), "--log-level", "WARNING"],
        cwd=RACINE, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )

    for _ in range(120):
        with socket.socket() as prise:
            prise.settimeout(0.5)
            if prise.connect_ex(("127.0.0.1", port)) == 0:
                break
        if processus.poll() is not None:
            sortie = processus.stdout.read() if processus.stdout else ""
            pytest.fail(f"le serveur HTTP ne démarre pas :\n{sortie}")
        time.sleep(0.25)
    else:  # pragma: no cover - dépend de la machine
        processus.terminate()
        pytest.fail("le port n'a jamais été ouvert")

    yield {"url": f"http://127.0.0.1:{port}/mcp", "jeton": jeton, "port": port}

    processus.terminate()
    try:
        processus.wait(timeout=15)
    except subprocess.TimeoutExpired:  # pragma: no cover
        processus.kill()


def _entetes(serveur: dict[str, object], *, jeton: str | None) -> dict[str, str]:
    entetes = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Origin": f"http://127.0.0.1:{serveur['port']}",
    }
    if jeton is not None:
        entetes["Authorization"] = f"Bearer {jeton}"
    return entetes


INITIALISATION = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2026-07-28",
        "capabilities": {},
        "clientInfo": {"name": "tests", "version": "1"},
    },
}


def test_une_requete_sans_jeton_est_refusee(serveur_http: dict[str, object]) -> None:
    """Le comportement qu'aucun test unitaire ne peut établir."""
    import httpx

    reponse = httpx.post(
        str(serveur_http["url"]),
        json=INITIALISATION,
        headers=_entetes(serveur_http, jeton=None),
        timeout=30,
    )

    assert reponse.status_code == 401
    # L'en-tête doit orienter le client vers les métadonnées du serveur de
    # ressource : c'est ce qui rend la migration vers OAuth 2.1 transparente.
    assert "Bearer" in reponse.headers.get("www-authenticate", "")


def test_une_requete_avec_un_mauvais_jeton_est_refusee(serveur_http: dict[str, object]) -> None:
    import httpx

    reponse = httpx.post(
        str(serveur_http["url"]),
        json=INITIALISATION,
        headers=_entetes(serveur_http, jeton="mauvais-jeton-mais-assez-long"),
        timeout=30,
    )

    assert reponse.status_code == 401


def test_un_client_authentifie_obtient_les_outils(serveur_http: dict[str, object]) -> None:
    """La preuve que le transport fonctionne de bout en bout, sans aucune clé."""
    import httpx

    entetes = _entetes(serveur_http, jeton=str(serveur_http["jeton"]))
    url = str(serveur_http["url"])

    ouverture = httpx.post(url, json=INITIALISATION, headers=entetes, timeout=60)
    assert ouverture.status_code == 200

    session = ouverture.headers.get("mcp-session-id")
    assert session, "le serveur n'a pas ouvert de session"
    entetes["Mcp-Session-Id"] = session

    httpx.post(
        url,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=entetes,
        timeout=30,
    )
    liste = httpx.post(
        url,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        headers=entetes,
        timeout=90,
    )
    assert liste.status_code == 200

    outils: list[dict[str, object]] = []
    for ligne in liste.text.splitlines():
        if ligne.startswith("data: "):
            outils = json.loads(ligne[6:])["result"]["tools"]
            break

    # Le même compte qu'en stdio sans clé : le transport ne change pas ce qui
    # est exposé, seulement la façon d'y accéder.
    assert len(outils) == 47
    noms = {str(o["name"]) for o in outils}
    assert "prioritize_cves" in noms
    assert "analyze_sigma_rule" in noms
    assert "enrich_ip" not in noms


def test_une_origine_etrangere_est_refusee(serveur_http: dict[str, object]) -> None:
    """L'attaque par rebinding DNS, telle qu'un navigateur la produirait.

    Une page web ouverte par l'analyste émet la requête depuis son navigateur :
    elle porte donc un jeton si le navigateur en a un, mais son `Origin`
    trahit sa provenance. C'est le seul signal disponible.
    """
    import httpx

    entetes = _entetes(serveur_http, jeton=str(serveur_http["jeton"]))
    entetes["Origin"] = "http://site-malveillant.example"

    reponse = httpx.post(
        str(serveur_http["url"]), json=INITIALISATION, headers=entetes, timeout=30
    )

    assert reponse.status_code == 403

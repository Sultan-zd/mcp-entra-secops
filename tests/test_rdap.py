"""RDAP : à qui appartient ce domaine, cette adresse — et depuis quand.

Les réponses sont simulées : la suite ne touche jamais au réseau. Les charges
utilisées reproduisent la forme réelle de `rdap.org` et de RIPEstat, relevée
sur des requêtes véritables — une simulation inventée ne prouverait que la
cohérence du test avec lui-même.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx

from web_recon_mcp import rdap
from web_recon_mcp.runtime import build_http


@pytest.fixture(autouse=True)
def client_http(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Installe un client HTTP le temps du test.

    Les outils lisent le client ouvert par le cycle de vie du serveur ; hors
    serveur, il faut le fournir.
    """
    http = build_http()
    monkeypatch.setattr(rdap, "get_http", lambda: http)
    yield http


def _reponse_domaine(jours: int, **extra: Any) -> dict[str, Any]:
    """Une réponse RDAP de domaine, à l'image de celles de rdap.org."""
    creation = datetime.now(UTC) - timedelta(days=jours)
    # L'expiration reste dans le futur : un domaine ancien n'est pas un domaine
    # expiré, et les confondre faisait échouer le test sur un domaine sain.
    expiration = datetime.now(UTC) + timedelta(days=200)
    charge: dict[str, Any] = {
        "objectClassName": "domain",
        "ldhName": "exemple.test",
        "events": [
            {"eventAction": "registration", "eventDate": creation.isoformat()},
            {"eventAction": "expiration", "eventDate": expiration.isoformat()},
        ],
        "status": ["client transfer prohibited"],
        "nameservers": [{"ldhName": "NS1.EXEMPLE.TEST"}, {"ldhName": "NS2.EXEMPLE.TEST"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [
            {
                "roles": ["registrar"],
                "handle": "292",
                "vcardArray": ["vcard", [["fn", {}, "text", "Registrar Exemple"]]],
            }
        ],
    }
    charge.update(extra)
    return charge


# --------------------------------------------------------------------------
# L'âge d'un domaine : le signal que ce module apporte
# --------------------------------------------------------------------------
@respx.mock
async def test_un_domaine_tout_neuf_est_signale() -> None:
    """Le signal de hameçonnage le plus fort qu'un registre puisse donner."""
    respx.get("https://rdap.org/domain/exemple.test").mock(
        return_value=httpx.Response(200, json=_reponse_domaine(jours=3))
    )

    resultat = await rdap.enregistrement("exemple.test")

    assert resultat.age_days == 3
    assert any("hameçonnage" in f for f in resultat.findings)


@respx.mock
async def test_un_domaine_ancien_ne_declenche_rien() -> None:
    """Un garde-fou trop large signalerait chaque domaine légitime."""
    respx.get("https://rdap.org/domain/exemple.test").mock(
        return_value=httpx.Response(200, json=_reponse_domaine(jours=4000))
    )

    resultat = await rdap.enregistrement("exemple.test")

    assert resultat.age_days is not None and resultat.age_days > 3000
    assert resultat.findings == []


@respx.mock
async def test_le_registrar_est_extrait_du_vcard() -> None:
    """RDAP encapsule les entités en jCard : listes imbriquées, clé « fn »."""
    respx.get("https://rdap.org/domain/exemple.test").mock(
        return_value=httpx.Response(200, json=_reponse_domaine(jours=500))
    )

    resultat = await rdap.enregistrement("exemple.test")

    assert resultat.registrar == "Registrar Exemple"
    assert resultat.nameservers == ["ns1.exemple.test", "ns2.exemple.test"]
    assert resultat.dnssec is True


@respx.mock
async def test_un_domaine_expire_est_signale() -> None:
    """Un domaine expiré peut être racheté : tout ce qui en dépend suit."""
    creation = datetime.now(UTC) - timedelta(days=800)
    charge = _reponse_domaine(jours=800)
    charge["events"] = [
        {"eventAction": "registration", "eventDate": creation.isoformat()},
        {
            "eventAction": "expiration",
            "eventDate": (datetime.now(UTC) - timedelta(days=10)).isoformat(),
        },
    ]
    respx.get("https://rdap.org/domain/exemple.test").mock(
        return_value=httpx.Response(200, json=charge)
    )

    resultat = await rdap.enregistrement("exemple.test")

    assert any("racheté" in f for f in resultat.findings)


@respx.mock
async def test_un_etat_de_suspension_est_explique() -> None:
    charge = _reponse_domaine(jours=500, status=["clientHold"])
    respx.get("https://rdap.org/domain/exemple.test").mock(
        return_value=httpx.Response(200, json=charge)
    )

    resultat = await rdap.enregistrement("exemple.test")

    assert any("suspendu" in f for f in resultat.findings)


@respx.mock
async def test_un_registre_muet_ne_conclut_pas_a_l_inexistence() -> None:
    """« Pas de réponse » n'est pas « domaine inexistant ».

    Conclure serait un faux négatif : certaines extensions ne servent pas RDAP.
    """
    respx.get("https://rdap.org/domain/exemple.test").mock(
        return_value=httpx.Response(404)
    )

    resultat = await rdap.enregistrement("exemple.test")

    assert resultat.age_days is None
    assert any("ne dit rien de l'existence" in f for f in resultat.findings)


@respx.mock
async def test_l_absence_de_date_d_enregistrement_est_dite() -> None:
    """Tous les registres ne publient pas cet évènement."""
    charge = _reponse_domaine(jours=100)
    charge["events"] = [{"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"}]
    respx.get("https://rdap.org/domain/exemple.test").mock(
        return_value=httpx.Response(200, json=charge)
    )

    resultat = await rdap.enregistrement("exemple.test")

    assert resultat.age_days is None
    assert any("ne publie pas de date" in f for f in resultat.findings)


# --------------------------------------------------------------------------
# Propriétaire d'une adresse
# --------------------------------------------------------------------------
@pytest.mark.parametrize("adresse", ["10.0.0.5", "192.168.1.50", "172.16.4.9", "127.0.0.1"])
@respx.mock
async def test_une_adresse_interne_n_est_jamais_transmise(adresse: str) -> None:
    """Contrainte de sécurité du projet, pas simple hygiène.

    L'interroger chez un tiers révélerait la topologie du réseau interne — et
    `respx` échouerait sur toute requête non simulée, ce qui prouve ici
    qu'aucune n'est partie.
    """
    resultat = await rdap.proprietaire(adresse)

    assert resultat.asn is None
    assert any("topologie interne" in f for f in resultat.findings)
    assert not respx.calls


@respx.mock
async def test_une_adresse_invalide_est_refusee_sans_requete() -> None:
    resultat = await rdap.proprietaire("pas-une-adresse")

    assert any("n'est pas une adresse IP valide" in f for f in resultat.findings)
    assert not respx.calls


@respx.mock
async def test_l_allocation_et_l_asn_sont_croises() -> None:
    """Deux registres publics, aucune clé."""
    respx.get("https://rdap.org/ip/8.8.8.8").mock(
        return_value=httpx.Response(
            200,
            json={
                "handle": "NET-8-8-8-0-2",
                "startAddress": "8.8.8.0",
                "endAddress": "8.8.8.255",
                "name": "GOGL",
                "type": "DIRECT ALLOCATION",
            },
        )
    )
    respx.get("https://stat.ripe.net/data/prefix-overview/data.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "resource": "8.8.8.0/24",
                    "asns": [{"asn": 15169, "holder": "GOOGLE - Google LLC"}],
                    "announced": True,
                }
            },
        )
    )

    resultat = await rdap.proprietaire("8.8.8.8")

    assert resultat.name == "GOGL"
    assert resultat.network == "8.8.8.0 - 8.8.8.255"
    assert resultat.asn == 15169
    assert resultat.asn_holder == "GOOGLE - Google LLC"
    assert resultat.findings == []


@respx.mock
async def test_un_prefixe_non_annonce_est_signale() -> None:
    """L'adresse n'est alors joignable par personne."""
    respx.get("https://rdap.org/ip/45.83.64.12").mock(return_value=httpx.Response(404))
    respx.get("https://stat.ripe.net/data/prefix-overview/data.json").mock(
        return_value=httpx.Response(200, json={"data": {"asns": [], "announced": False}})
    )

    resultat = await rdap.proprietaire("45.83.64.12")

    assert any("annoncé par aucun opérateur" in f for f in resultat.findings)


@respx.mock
async def test_deux_registres_muets_ne_rassurent_pas() -> None:
    """« Inconnu » ne veut pas dire « sans danger » — l'invariant du projet."""
    respx.get("https://rdap.org/ip/45.83.64.12").mock(return_value=httpx.Response(500))
    respx.get("https://stat.ripe.net/data/prefix-overview/data.json").mock(
        return_value=httpx.Response(500)
    )

    resultat = await rdap.proprietaire("45.83.64.12")

    assert any("« inconnu » ne veut pas dire « sans danger »" in f for f in resultat.findings)

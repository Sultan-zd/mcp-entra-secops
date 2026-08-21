"""Reconnaissance web : validation, notation, et les pièges du domaine.

Le réseau est simulé partout où c'est possible. Les rares fonctions qui
ouvrent réellement une socket ne sont pas testées ici : un test qui dépend de
la joignabilité d'un hôte tiers finit par être ignoré.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from argus_net import PublicHttpClient
from web_recon_mcp import runtime
from web_recon_mcp.ct import CERTSPOTTER, _appartient, decouvrir
from web_recon_mcp.headers import analyser
from web_recon_mcp.tls import ResultatTls, _correspond, _noter
from web_recon_mcp.tools import _valider


@pytest.fixture
async def http_simule() -> AsyncIterator[PublicHttpClient]:
    client = PublicHttpClient(timeout=5.0)
    runtime._http = client
    try:
        yield client
    finally:
        runtime._http = None
        await client.aclose()


# --------------------------------------------------------------------------
# Validation des entrées
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("entree", "attendu"),
    [
        ("teknologiia.com", "teknologiia.com"),
        ("https://teknologiia.com", "teknologiia.com"),
        ("http://teknologiia.com/a/b", "teknologiia.com"),
        ("TEKNOLOGIIA.COM", "teknologiia.com"),
        ("teknologiia.com:8443", "teknologiia.com"),
    ],
)
def test_l_hote_est_extrait_et_normalise(entree: str, attendu: str) -> None:
    assert _valider(entree) == attendu


@pytest.mark.parametrize("entree", ["", "localhost", "pas un hôte", "-mauvais.com", "..", "a"])
def test_un_hote_invalide_est_refuse_avant_toute_connexion(entree: str) -> None:
    """Ouvrir une socket vers une saisie fautive coûte un délai d'attente complet."""
    with pytest.raises(ValueError, match="nom d'hôte valide"):
        _valider(entree)


# --------------------------------------------------------------------------
# Correspondance de nom sur certificat
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("hote", "san", "attendu"),
    [
        ("exemple.com", ["exemple.com"], True),
        ("www.exemple.com", ["*.exemple.com"], True),
        ("exemple.com", ["*.exemple.com"], False),  # le joker ne couvre pas l'apex
        ("a.b.exemple.com", ["*.exemple.com"], False),  # ni deux niveaux
        ("exemple.com", ["autre.com"], False),
        ("exemple.com", [], False),
        ("EXEMPLE.COM", ["exemple.com"], True),
    ],
)
def test_le_joker_ne_couvre_qu_un_seul_niveau(hote: str, san: list[str], attendu: bool) -> None:
    """C'est la règle de la norme, et elle surprend régulièrement.

    Traiter « *.exemple.com » comme couvrant « exemple.com » ferait passer pour
    valide un certificat que le navigateur rejettera.
    """
    assert _correspond(hote, san, None) is attendu


# --------------------------------------------------------------------------
# Notation TLS
# --------------------------------------------------------------------------
def test_une_version_depreciee_acceptee_fait_chuter_la_note() -> None:
    r = ResultatTls(host="x", port=443)
    r.supported_versions = {
        "TLSv1": "acceptée",
        "TLSv1.1": "refusée",
        "TLSv1.2": "acceptée",
        "TLSv1.3": "acceptée",
    }
    _noter(r)

    assert r.score <= 65
    assert any("RFC 8996" in f for f in r.findings)


def test_non_testable_n_est_pas_refusee() -> None:
    """La distinction évite un faux négatif d'audit.

    Une bibliothèque cliente qui refuse de proposer TLS 1.0 ne dit rien de ce
    que le serveur accepterait. Conclure « refusée » serait affirmer plus que
    ce qu'on a mesuré.
    """
    r = ResultatTls(host="x", port=443)
    r.supported_versions = {
        "TLSv1": "non testable",
        "TLSv1.1": "non testable",
        "TLSv1.2": "acceptée",
        "TLSv1.3": "acceptée",
    }
    _noter(r)

    # Pas de pénalité, mais l'incertitude est dite.
    assert r.score == 100
    assert any("non testable" in f for f in r.findings)


def test_un_certificat_expire_est_critique() -> None:
    r = ResultatTls(host="x", port=443, days_until_expiry=-3)
    r.supported_versions = {"TLSv1.2": "acceptée", "TLSv1.3": "acceptée"}
    _noter(r)

    assert r.severity in {"critical", "high"}
    assert any("expiré" in f for f in r.findings)


def test_une_cle_rsa_faible_est_signalee() -> None:
    r = ResultatTls(host="x", port=443, key_type="RSA", key_bits=1024)
    r.supported_versions = {"TLSv1.3": "acceptée"}
    _noter(r)

    assert any("2048" in f for f in r.findings)


def test_une_signature_sha1_est_signalee() -> None:
    r = ResultatTls(host="x", port=443, signature_algorithm="sha1")
    r.supported_versions = {"TLSv1.3": "acceptée"}
    _noter(r)

    assert any("SHA1" in f for f in r.findings)


# --------------------------------------------------------------------------
# En-têtes de sécurité
# --------------------------------------------------------------------------
@respx.mock
async def test_tous_les_entetes_presents_donnent_la_meilleure_note() -> None:
    respx.get("https://exemple.test").mock(
        return_value=httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=63072000; includeSubDomains",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
            },
        )
    )

    resultat = await analyser("exemple.test")

    assert resultat.score == 100
    assert resultat.grade == "A"
    assert resultat.missing == []


@respx.mock
async def test_une_csp_permissive_est_presente_mais_desarmee() -> None:
    """Compter la CSP comme acquise parce qu'elle existe serait faux.

    « unsafe-inline » annule précisément la protection pour laquelle la CSP
    a été écrite.
    """
    respx.get("https://exemple.test").mock(
        return_value=httpx.Response(
            200,
            headers={
                "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
                "strict-transport-security": "max-age=63072000; includeSubDomains",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
            },
        )
    )

    resultat = await analyser("exemple.test")

    assert resultat.score < 90
    assert any("unsafe-inline" in f for f in resultat.findings)


@respx.mock
async def test_un_hsts_trop_court_est_une_demi_mesure() -> None:
    respx.get("https://exemple.test").mock(
        return_value=httpx.Response(200, headers={"strict-transport-security": "max-age=3600"})
    )

    resultat = await analyser("exemple.test")

    assert any("six mois" in f for f in resultat.findings)
    assert any("sous-domaines" in f for f in resultat.findings)


@respx.mock
async def test_un_cookie_sans_httponly_est_signale() -> None:
    respx.get("https://exemple.test").mock(
        return_value=httpx.Response(200, headers={"set-cookie": "session=abc; Path=/"})
    )

    resultat = await analyser("exemple.test")

    assert resultat.cookies[0]["http_only"] is False
    assert any("vol de session" in f for f in resultat.findings)


@respx.mock
async def test_les_entetes_bavards_sont_releves() -> None:
    respx.get("https://exemple.test").mock(
        return_value=httpx.Response(
            200, headers={"server": "Apache/2.4.29", "x-powered-by": "PHP/7.2"}
        )
    )

    resultat = await analyser("exemple.test")

    assert "server" in resultat.disclosed
    assert "x-powered-by" in resultat.disclosed


@respx.mock
async def test_aucun_entete_donne_la_pire_note() -> None:
    respx.get("https://exemple.test").mock(return_value=httpx.Response(200))

    resultat = await analyser("exemple.test")

    assert resultat.grade == "F"
    assert len(resultat.missing) == 6


# --------------------------------------------------------------------------
# Transparence des certificats — le piège du domaine
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("nom", "domaine", "attendu"),
    [
        ("teknologiia.com", "teknologiia.com", True),
        ("www.teknologiia.com", "teknologiia.com", True),
        ("*.teknologiia.com", "teknologiia.com", True),
        ("faux-teknologiia.com", "teknologiia.com", False),
        ("teknologiia.com.attaquant.net", "teknologiia.com", False),
        ("autre.com", "teknologiia.com", False),
    ],
)
def test_l_appartenance_se_juge_sur_les_etiquettes(nom: str, domaine: str, attendu: bool) -> None:
    """Une comparaison textuelle ferait passer « faux-teknologiia.com » pour un sous-domaine."""
    assert _appartient(nom, domaine) is attendu


@respx.mock
async def test_les_noms_tiers_sont_exclus_et_comptes(http_simule: PublicHttpClient) -> None:
    """Le piège des certificats mutualisés.

    Un hébergeur regroupe des dizaines de clients dans un même certificat. Les
    présenter comme les sous-domaines du domaine interrogé serait faux, et un
    rapport d'audit qui l'affirme perd toute crédibilité.
    """
    respx.get(CERTSPOTTER).mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "dns_names": [
                        "teknologiia.com",
                        "www.teknologiia.com",
                        "*.teknologiia.com",
                        "client-autre.com",
                        "sni.cloudflaressl.com",
                    ]
                }
            ],
        )
    )

    resultat = await decouvrir("teknologiia.com", http_simule)

    assert set(resultat.subdomains) == {"teknologiia.com", "www.teknologiia.com"}
    assert resultat.wildcards == ["*.teknologiia.com"]
    assert resultat.foreign_names_excluded == 2
    assert any("appartiennent à d'autres domaines" in f for f in resultat.findings)


@respx.mock
async def test_les_environnements_hors_production_sont_signales(
    http_simule: PublicHttpClient,
) -> None:
    """Ils portent souvent des données réelles et des protections moindres."""
    respx.get(CERTSPOTTER).mock(
        return_value=httpx.Response(
            200,
            json=[{"dns_names": ["exemple.com", "staging.exemple.com", "dev.exemple.com"]}],
        )
    )

    resultat = await decouvrir("exemple.com", http_simule)

    assert any("hors production" in f for f in resultat.findings)


@respx.mock
async def test_un_certificat_joker_est_signale(http_simule: PublicHttpClient) -> None:
    respx.get(CERTSPOTTER).mock(
        return_value=httpx.Response(200, json=[{"dns_names": ["*.exemple.com"]}])
    )

    resultat = await decouvrir("exemple.com", http_simule)

    assert any("joker" in f for f in resultat.findings)

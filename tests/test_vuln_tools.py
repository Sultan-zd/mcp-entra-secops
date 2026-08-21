"""Les outils de vulnérabilités, sources simulées.

Le réseau est simulé : un test qui dépend du NVD échoue le jour où le NVD est
en maintenance, et un test qui échoue pour une raison étrangère au code finit
par être ignoré.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import respx

from argus_net import FeedCache, PublicHttpClient
from vuln_intel_mcp import runtime
from vuln_intel_mcp.sources import EPSS_API, KEV_URL, NVD_API, VulnSources, normaliser_cve
from vuln_intel_mcp.tools import (
    check_kev,
    get_epss,
    lookup_cve,
    parse_cvss,
    prioritize_cves,
    search_cve,
)


def _fiche_nvd(
    cve: str = "CVE-2021-44228",
    *,
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Une fiche NVD réduite à ce que les outils lisent."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve,
                    "published": "2021-12-10T10:15:09.143",
                    "lastModified": "2023-11-07T03:39:29.017",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Remote code execution in Log4j."}],
                    "metrics": metrics
                    if metrics is not None
                    else {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "source": "nvd@nist.gov",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ]
                    },
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://example.test/advisory", "tags": ["Vendor Advisory"]},
                        {"url": "https://example.test/blog", "tags": []},
                    ],
                }
            }
        ],
        "totalResults": 1,
    }


def _catalogue_kev(*cves: str) -> dict[str, Any]:
    return {
        "catalogVersion": "2026.08.20",
        "dateReleased": "2026-08-20T17:00:00Z",
        "count": len(cves),
        "vulnerabilities": [
            {
                "cveID": cve,
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 RCE",
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "requiredAction": "Appliquer les mises à jour.",
                "knownRansomwareCampaignUse": "Known",
            }
            for cve in cves
        ],
    }


def _epss(cve: str, score: float, percentile: float = 0.99) -> dict[str, Any]:
    return {"data": [{"cve": cve, "epss": str(score), "percentile": str(percentile)}]}


@pytest.fixture
async def sources_simulees() -> AsyncIterator[VulnSources]:
    """Installe des sources visant un réseau simulé, comme le fait le serveur."""
    http = PublicHttpClient(timeout=5.0)
    sources = VulnSources(http, FeedCache(ttl_seconds=60))
    runtime._sources = sources
    try:
        yield sources
    finally:
        runtime._sources = None
        await http.aclose()


# --------------------------------------------------------------------------
# lookup_cve
# --------------------------------------------------------------------------
@respx.mock
async def test_lookup_croise_les_trois_sources(sources_simulees: VulnSources) -> None:
    respx.get(NVD_API).mock(return_value=httpx.Response(200, json=_fiche_nvd()))
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=_catalogue_kev("CVE-2021-44228")))
    respx.get(EPSS_API).mock(return_value=httpx.Response(200, json=_epss("CVE-2021-44228", 0.97)))

    rapport = await lookup_cve("CVE-2021-44228")

    assert rapport.cvss.base_score == 10.0
    assert rapport.cvss.computed_locally is True
    assert rapport.kev.listed is True
    assert rapport.kev.known_ransomware is True
    assert rapport.epss.score == pytest.approx(0.97)
    # Exploitée : le palier ne dépend pas de la note.
    assert rapport.priority == "immediate"


@respx.mock
async def test_la_note_publiee_incoherente_est_signalee(
    sources_simulees: VulnSources,
) -> None:
    """Si le vecteur et la note ne concordent pas, l'un des deux est faux.

    Le taire laisserait l'analyste décider sur un chiffre erroné.
    """
    fiche = _fiche_nvd(
        metrics={
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "source": "nvd@nist.gov",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 4.2,  # ne correspond pas au vecteur
                        "baseSeverity": "MEDIUM",
                    },
                }
            ]
        }
    )
    respx.get(NVD_API).mock(return_value=httpx.Response(200, json=fiche))
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=_catalogue_kev()))
    respx.get(EPSS_API).mock(return_value=httpx.Response(200, json={"data": []}))

    rapport = await lookup_cve("CVE-2021-44228")

    assert rapport.cvss.base_score == 10.0
    assert rapport.cvss.matches_published is False
    assert any("ne correspond pas" in n for n in rapport.notes)


@respx.mock
async def test_la_notation_primaire_prime_sur_celle_de_l_editeur(
    sources_simulees: VulnSources,
) -> None:
    """Le NVD publie parfois deux notes très différentes pour une même CVE.

    Pour Zerologon, l'éditeur annonce 5.5 et le NIST 10.0. Prendre la première
    venue ferait passer une faille critique pour une faille moyenne.
    """
    fiche = _fiche_nvd(
        metrics={
            "cvssMetricV31": [
                {
                    "type": "Secondary",
                    "source": "secure@microsoft.com",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                        "baseScore": 5.5,
                        "baseSeverity": "MEDIUM",
                    },
                },
                {
                    "type": "Primary",
                    "source": "nvd@nist.gov",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                    },
                },
            ]
        }
    )
    respx.get(NVD_API).mock(return_value=httpx.Response(200, json=fiche))
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=_catalogue_kev()))
    respx.get(EPSS_API).mock(return_value=httpx.Response(200, json={"data": []}))

    rapport = await lookup_cve("CVE-2020-1472")

    assert rapport.cvss.base_score == 10.0
    assert rapport.cvss.severity == "critical"
    assert any("ne s'accordent pas" in n for n in rapport.notes)


@respx.mock
async def test_une_cve_inconnue_le_dit_clairement(sources_simulees: VulnSources) -> None:
    respx.get(NVD_API).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))

    with pytest.raises(ValueError, match="inconnue"):
        await lookup_cve("CVE-1999-9999")


@pytest.mark.parametrize(
    "entree", ["", "log4shell", "CVE-21-44228", "2021-44228", "CVE-2021-123", "CVE-2021-"]
)
async def test_un_identifiant_mal_forme_est_refuse(entree: str) -> None:
    """Sans validation, la chaîne partirait au NVD, qui répondrait « vide ».

    Un résultat vide serait indiscernable d'une CVE réellement inconnue.
    """
    with pytest.raises(ValueError, match="identifiant CVE"):
        normaliser_cve(entree)


# --------------------------------------------------------------------------
# check_kev
# --------------------------------------------------------------------------
@respx.mock
async def test_kev_absent_ne_veut_pas_dire_sans_risque(
    sources_simulees: VulnSources,
) -> None:
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=_catalogue_kev()))

    resultat = await check_kev("CVE-2021-44228")

    assert resultat.listed is False
    assert resultat.due_date is None


@respx.mock
async def test_le_catalogue_n_est_telecharge_qu_une_fois(
    sources_simulees: VulnSources,
) -> None:
    """Le catalogue pèse plus d'un mégaoctet et ne change qu'une fois par jour."""
    route = respx.get(KEV_URL).mock(
        return_value=httpx.Response(200, json=_catalogue_kev("CVE-2021-44228"))
    )

    for _ in range(5):
        await check_kev("CVE-2021-44228")

    assert route.call_count == 1


@respx.mock
async def test_un_catalogue_perime_est_servi_plutot_qu_une_panne(
    sources_simulees: VulnSources,
) -> None:
    """Un catalogue de la veille répond à presque tout ; une erreur, à rien.

    La réponse doit le dire — sans quoi elle se ferait passer pour fraîche.
    """
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=_catalogue_kev("CVE-2021-44228")))
    premier = await check_kev("CVE-2021-44228")
    assert premier.listed is True
    assert premier.catalog_stale is False

    # Le cache expire, et la source tombe.
    sources_simulees._feeds._entrees["cisa-kev"].expire_a = 0
    respx.get(KEV_URL).mock(return_value=httpx.Response(503))

    second = await check_kev("CVE-2021-44228")

    assert second.listed is True
    assert second.catalog_stale is True


# --------------------------------------------------------------------------
# prioritize_cves
# --------------------------------------------------------------------------
@respx.mock
async def test_prioriser_place_l_exploitee_en_tete(sources_simulees: VulnSources) -> None:
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=_catalogue_kev("CVE-2000-0002")))
    respx.get(EPSS_API).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"cve": "CVE-2000-0001", "epss": "0.0001", "percentile": "0.1"},
                    {"cve": "CVE-2000-0002", "epss": "0.9", "percentile": "0.99"},
                ]
            },
        )
    )
    respx.get(NVD_API).mock(return_value=httpx.Response(200, json=_fiche_nvd()))

    resultat = await prioritize_cves(["CVE-2000-0001", "CVE-2000-0002"])

    assert resultat.ranked[0]["cve"] == "CVE-2000-0002"
    assert resultat.ranked[0]["tier"] == "immediate"


async def test_prioriser_refuse_un_lot_vide() -> None:
    with pytest.raises(ValueError, match="au moins un"):
        await prioritize_cves([])


async def test_prioriser_borne_la_taille_du_lot() -> None:
    """Au-delà, l'attente due aux quotas dépasse ce que ça rapporte."""
    with pytest.raises(ValueError, match="100 au maximum"):
        await prioritize_cves([f"CVE-2000-{i:04d}" for i in range(101)])


# --------------------------------------------------------------------------
# search_cve
# --------------------------------------------------------------------------
@respx.mock
async def test_la_recherche_annonce_le_total_reel(sources_simulees: VulnSources) -> None:
    """Savoir qu'il existe 800 résultats change la lecture des dix premiers."""
    charge = _fiche_nvd()
    charge["totalResults"] = 812
    respx.get(NVD_API).mock(return_value=httpx.Response(200, json=charge))
    respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=_catalogue_kev()))
    respx.get(EPSS_API).mock(return_value=httpx.Response(200, json={"data": []}))

    resultat = await search_cve("log4j", limit=10)

    assert resultat.total_available == 812
    assert resultat.returned == 1
    assert any("812" in n for n in resultat.notes)


async def test_une_recherche_vide_est_refusee() -> None:
    with pytest.raises(ValueError, match="mots-clés"):
        await search_cve("   ")


# --------------------------------------------------------------------------
# get_epss
# --------------------------------------------------------------------------
@respx.mock
async def test_une_cve_sans_score_epss_n_est_pas_une_cve_sure(
    sources_simulees: VulnSources,
) -> None:
    respx.get(EPSS_API).mock(return_value=httpx.Response(200, json={"data": []}))

    resultat = await get_epss(["CVE-2021-44228"])

    ligne = resultat["results"][0]
    assert ligne["epss"] is None
    assert "trop récente" in ligne["note"]


# --------------------------------------------------------------------------
# parse_cvss — aucun réseau
# --------------------------------------------------------------------------
async def test_parse_cvss_ne_touche_pas_au_reseau() -> None:
    """Le seul outil utilisable hors ligne, et il doit le rester."""
    with respx.mock(assert_all_called=False) as simule:
        resultat = await parse_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert len(simule.calls) == 0

    assert resultat.base_score == 10.0
    assert resultat.computed_locally is True


async def test_parse_cvss_confronte_la_note_annoncee() -> None:
    resultat = await parse_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", published_score=7.5)

    assert any("INCOHÉRENCE" in n for n in resultat.notes)


async def test_parse_cvss_signale_l_exposition_directe() -> None:
    resultat = await parse_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    assert any("sans authentification" in n for n in resultat.notes)


async def test_parse_cvss_refuse_un_vecteur_illisible() -> None:
    with pytest.raises(ValueError):
        await parse_cvss("pas un vecteur")

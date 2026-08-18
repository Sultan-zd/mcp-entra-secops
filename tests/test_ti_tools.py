"""Cache, orchestration et outils MCP de bout en bout."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from threat_intel_mcp import runtime
from threat_intel_mcp.cache import MemoryVerdictCache, cache_key
from threat_intel_mcp.config import Settings
from threat_intel_mcp.enrichment import EnrichmentService
from threat_intel_mcp.models import IndicatorVerdict
from threat_intel_mcp.tools import bulk_enrich, enrich_domain, enrich_file_hash, enrich_ip

VT_URL = "https://www.virustotal.com/api/v3"


def verdict(indicateur: str = "1.2.3.4", score: int = 42) -> IndicatorVerdict:
    return IndicatorVerdict(
        indicator=indicateur,
        kind="ip",
        verdict="suspicious",
        score=score,
        confidence="high",
        explanation="test",
        sources=[],
    )


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------
async def test_le_cache_marque_les_reponses_qu_il_sert() -> None:
    """L'analyste doit savoir si le verdict est frais ou mémorisé."""
    cache = MemoryVerdictCache(ttl_seconds=60, max_entries=10)
    await cache.set("k", verdict())

    memorise = await cache.get("k")

    assert memorise is not None
    assert memorise.cached is True


async def test_entree_perimee_non_servie() -> None:
    cache = MemoryVerdictCache(ttl_seconds=0, max_entries=10)
    await cache.set("k", verdict())
    assert await cache.get("k") is None


async def test_eviction_des_entrees_les_moins_recentes() -> None:
    """La borne évite qu'une longue session ne fasse enfler le processus."""
    cache = MemoryVerdictCache(ttl_seconds=60, max_entries=2)
    await cache.set("a", verdict("a"))
    await cache.set("b", verdict("b"))
    await cache.get("a")  # « a » redevient la plus récente
    await cache.set("c", verdict("c"))

    assert await cache.get("b") is None  # « b » est sortie
    assert await cache.get("a") is not None
    assert await cache.get("c") is not None


def test_cle_de_cache_insensible_a_la_casse() -> None:
    """Sans normalisation, le même condensat occuperait deux entrées."""
    assert cache_key("file_hash", "ABCDEF") == cache_key("file_hash", "  abcdef ")


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
@pytest.fixture
async def service_live(ti_live_settings: Settings) -> AsyncIterator[EnrichmentService]:
    cache = MemoryVerdictCache(ttl_seconds=60, max_entries=100)
    service = EnrichmentService(ti_live_settings, cache)
    try:
        yield service
    finally:
        await service.aclose()


async def test_adresse_privee_ne_declenche_aucun_appel_reseau(
    service_live: EnrichmentService, respx_mock: respx.MockRouter
) -> None:
    """Le test le plus important du module : rien ne doit sortir du réseau."""
    route = respx_mock.get(url__startswith=VT_URL).mock(return_value=httpx.Response(200, json={}))

    resultat = await service_live.enrich("192.168.1.50")

    assert resultat.verdict == "internal"
    assert route.call_count == 0


async def test_second_appel_servi_par_le_cache(
    service_live: EnrichmentService, respx_mock: respx.MockRouter
) -> None:
    """Sans cache, le quota gratuit est épuisé au milieu de la première enquête."""
    respx_mock.get(url__startswith=VT_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 62}}}
            },
        )
    )
    respx_mock.get(url__startswith="https://api.abuseipdb.com").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0}})
    )
    respx_mock.get(url__startswith="https://api.greynoise.io").mock(
        return_value=httpx.Response(200, json={"classification": "unknown"})
    )

    premier = await service_live.enrich("93.184.216.34", kind="ip")
    appels_apres_premier = sum(r.call_count for r in respx_mock.routes)
    second = await service_live.enrich("93.184.216.34", kind="ip")

    assert premier.cached is False
    assert second.cached is True
    assert sum(r.call_count for r in respx_mock.routes) == appels_apres_premier


async def test_sources_interrogees_en_parallele(
    service_live: EnrichmentService, respx_mock: respx.MockRouter
) -> None:
    """Trois appels séquentiels de 200 ms feraient 600 ms ; en parallèle, ~200 ms."""

    async def lent(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.2)
        return httpx.Response(
            200,
            json={
                "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 62}}}
            },
        )

    respx_mock.get(url__startswith=VT_URL).mock(side_effect=lent)
    respx_mock.get(url__startswith="https://api.abuseipdb.com").mock(side_effect=lent)
    respx_mock.get(url__startswith="https://api.greynoise.io").mock(side_effect=lent)

    debut = asyncio.get_running_loop().time()
    await service_live.enrich("93.184.216.35", kind="ip")
    duree = asyncio.get_running_loop().time() - debut

    assert duree < 0.5


# --------------------------------------------------------------------------
# Outils MCP, en mode démonstration
# --------------------------------------------------------------------------
@pytest.fixture(autouse=True)
async def service_fixture(
    ti_fixture_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[None]:
    cache = MemoryVerdictCache(ttl_seconds=60, max_entries=100)
    service = EnrichmentService(ti_fixture_settings, cache)
    monkeypatch.setattr(runtime, "_service", service)
    monkeypatch.setattr("threat_intel_mcp.tools.get_settings", lambda: ti_fixture_settings)
    try:
        yield
    finally:
        await service.aclose()
        monkeypatch.setattr(runtime, "_service", None)


async def test_ip_de_l_incident_entra_jugee_malveillante() -> None:
    """Cohérence entre les deux serveurs : c'est l'IP du scénario d'identité."""
    resultat = await enrich_ip(ip_address="185.220.101.47")

    assert resultat.verdict == "malicious"
    assert resultat.score >= 90
    assert resultat.confidence == "high"
    assert resultat.attributes.get("tor") == "oui"


async def test_scanner_legitime_non_signale() -> None:
    resultat = await enrich_ip(ip_address="162.142.125.13")
    assert resultat.verdict == "benign"


async def test_domaine_d_hameconnage_signale() -> None:
    resultat = await enrich_domain(domain="secure-login-teknologiia.com")

    assert resultat.verdict == "malicious"
    assert "4 jours" in resultat.attributes.get("age_du_domaine", "")


async def test_condensat_connu_et_algorithme_deduit() -> None:
    resultat = await enrich_file_hash(file_hash="44d88612fea8a8f36de82e1278abb02f")

    assert resultat.verdict == "malicious"
    assert resultat.attributes.get("algorithme") == "MD5"


async def test_indicateur_mal_forme_refuse_clairement() -> None:
    with pytest.raises(ValueError, match=r"ressemble a? un indicateur|ni une adresse IP"):
        await enrich_domain(domain="https://exemple.com/chemin")


async def test_groupe_trie_et_compte() -> None:
    rapport = await bulk_enrich(
        indicators=[
            "8.8.8.8",
            "185.220.101.47",
            "10.0.0.1",
            "secure-login-teknologiia.com",
            "196.28.240.9",
        ]
    )

    assert rapport.total == 5
    assert rapport.malicious == 2
    assert rapport.internal == 1
    assert rapport.results[0].indicator == "185.220.101.47"  # le pire en tête
    assert any("priorité" in n for n in rapport.notes)
    assert any("non routable" in n for n in rapport.notes)


async def test_groupe_vide_refuse() -> None:
    with pytest.raises(ValueError, match="vide"):
        await bulk_enrich(indicators=[])


async def test_plafond_du_groupe_applique(ti_fixture_settings: Settings) -> None:
    """Protège les quotas externes et la fenêtre de contexte du modèle."""
    trop = [f"93.184.216.{i}" for i in range(1, ti_fixture_settings.max_bulk_indicators + 6)]

    rapport = await bulk_enrich(indicators=trop)

    assert rapport.total == ti_fixture_settings.max_bulk_indicators
    assert any("limite" in n for n in rapport.notes)


async def test_indicateur_invalide_dans_un_groupe_n_annule_pas_les_autres() -> None:
    rapport = await bulk_enrich(indicators=["185.220.101.47", "pas-un-indicateur"])

    assert rapport.total == 2
    assert rapport.malicious == 1
    assert any(r.verdict == "unknown" for r in rapport.results)

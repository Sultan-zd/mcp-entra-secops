"""Sources externes : traduction des réponses et résistance aux pannes."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from threat_intel_mcp.ratelimit import QuotaExceededError, RateLimiterRegistry, TokenBucket
from threat_intel_mcp.sources import AbuseIPDBSource, GreyNoiseSource, VirusTotalSource

VT_URL = "https://www.virustotal.com/api/v3"
ABUSE_URL = "https://api.abuseipdb.com/api/v2"
GN_URL = "https://api.greynoise.io/v3/community"


@pytest.fixture
def limiter() -> RateLimiterRegistry:
    """Limiteur généreux : les tests portent sur la traduction, pas sur le débit."""
    return RateLimiterRegistry({"virustotal": 600, "abuseipdb": 600, "greynoise": 600})


@pytest.fixture
async def vt(limiter: RateLimiterRegistry) -> AsyncIterator[VirusTotalSource]:
    client = httpx.AsyncClient(base_url=VT_URL, timeout=5.0)
    try:
        yield VirusTotalSource(client, limiter, "cle-test")
    finally:
        await client.aclose()


@pytest.fixture
async def abuse(limiter: RateLimiterRegistry) -> AsyncIterator[AbuseIPDBSource]:
    client = httpx.AsyncClient(base_url=ABUSE_URL, timeout=5.0)
    try:
        yield AbuseIPDBSource(client, limiter, "cle-test")
    finally:
        await client.aclose()


@pytest.fixture
async def greynoise(limiter: RateLimiterRegistry) -> AsyncIterator[GreyNoiseSource]:
    client = httpx.AsyncClient(base_url=GN_URL, timeout=5.0)
    try:
        yield GreyNoiseSource(client, limiter, "cle-test")
    finally:
        await client.aclose()


def _vt_payload(malicious: int, suspicious: int = 0, harmless: int = 60) -> dict[str, object]:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": 0,
                }
            }
        }
    }


# --------------------------------------------------------------------------
# VirusTotal
# --------------------------------------------------------------------------
async def test_vt_traduit_le_ratio_de_moteurs(
    vt: VirusTotalSource, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{VT_URL}/ip_addresses/1.2.3.4").mock(
        return_value=httpx.Response(200, json=_vt_payload(malicious=30, harmless=30))
    )

    signal = await vt.query("1.2.3.4", "ip")

    assert signal.result.status == "ok"
    assert signal.result.score == pytest.approx(50.0)


async def test_vt_attenue_une_detection_isolee(
    vt: VirusTotalSource, respx_mock: respx.MockRouter
) -> None:
    """Un moteur isolé se trompe souvent ; trois qui concordent, beaucoup moins.

    Sans cette atténuation, l'outil produit des faux positifs à répétition.
    """
    respx_mock.get(f"{VT_URL}/ip_addresses/1.2.3.4").mock(
        return_value=httpx.Response(200, json=_vt_payload(malicious=1, harmless=61))
    )

    signal = await vt.query("1.2.3.4", "ip")

    assert signal.result.score == pytest.approx(round(1 / 62 * 100 * 0.5, 1))
    assert "atténué" in (signal.result.detail or "")


async def test_vt_sans_analyse_repond_inconnu(
    vt: VirusTotalSource, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{VT_URL}/domains/exemple.com").mock(
        return_value=httpx.Response(200, json={"data": {"attributes": {}}})
    )

    assert (await vt.query("exemple.com", "domain")).result.status == "not_found"


async def test_vt_404_est_un_inconnu_pas_une_panne(
    vt: VirusTotalSource, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{VT_URL}/files/{'a' * 64}").mock(return_value=httpx.Response(404, json={}))
    assert (await vt.query("a" * 64, "file_hash")).result.status == "not_found"


async def test_vt_429_signale_un_quota_epuise(
    vt: VirusTotalSource, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{VT_URL}/ip_addresses/1.2.3.4").mock(return_value=httpx.Response(429, json={}))
    assert (await vt.query("1.2.3.4", "ip")).result.status == "quota_exceeded"


async def test_vt_cle_refusee_est_signalee_clairement(
    vt: VirusTotalSource, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{VT_URL}/ip_addresses/1.2.3.4").mock(return_value=httpx.Response(401, json={}))

    signal = await vt.query("1.2.3.4", "ip")

    assert signal.result.status == "unavailable"
    assert "refusée" in (signal.result.detail or "")


# --------------------------------------------------------------------------
# AbuseIPDB
# --------------------------------------------------------------------------
async def test_abuseipdb_liste_blanche_impose_un_verdict_benin(
    abuse: AbuseIPDBSource, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{ABUSE_URL}/check").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"abuseConfidenceScore": 0, "isWhitelisted": True, "isp": "Google LLC"}},
        )
    )

    signal = await abuse.query("8.8.8.8", "ip")

    assert signal.override == "benign"
    assert "Google LLC" in (signal.override_reason or "")


async def test_abuseipdb_attenue_un_score_fonde_sur_peu_de_signalements(
    abuse: AbuseIPDBSource, respx_mock: respx.MockRouter
) -> None:
    """N'importe qui peut déclarer un abus : le volume fait la fiabilité."""
    respx_mock.get(f"{ABUSE_URL}/check").mock(
        return_value=httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 100, "totalReports": 1}}
        )
    )

    signal = await abuse.query("1.2.3.4", "ip")

    assert signal.result.score == pytest.approx(50.0)
    assert "atténué" in (signal.result.detail or "")


async def test_abuseipdb_conserve_un_score_bien_etaye(
    abuse: AbuseIPDBSource, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{ABUSE_URL}/check").mock(
        return_value=httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 214}}
        )
    )

    assert (await abuse.query("1.2.3.4", "ip")).result.score == pytest.approx(90.0)


def test_abuseipdb_ne_traite_pas_les_domaines(abuse: AbuseIPDBSource) -> None:
    assert abuse.handles("ip")
    assert not abuse.handles("domain")
    assert not abuse.handles("file_hash")


# --------------------------------------------------------------------------
# GreyNoise
# --------------------------------------------------------------------------
async def test_greynoise_riot_impose_benin(
    greynoise: GreyNoiseSource, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{GN_URL}/8.8.8.8").mock(
        return_value=httpx.Response(200, json={"riot": True, "name": "Google Public DNS"})
    )

    signal = await greynoise.query("8.8.8.8", "ip")

    assert signal.override == "benign"
    assert "Google Public DNS" in (signal.override_reason or "")


async def test_greynoise_scanner_legitime_impose_benin(
    greynoise: GreyNoiseSource, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{GN_URL}/162.142.125.13").mock(
        return_value=httpx.Response(200, json={"classification": "benign", "name": "Censys"})
    )

    assert (await greynoise.query("162.142.125.13", "ip")).override == "benign"


async def test_greynoise_malveillant_donne_un_bonus_pas_un_verdict(
    greynoise: GreyNoiseSource, respx_mock: respx.MockRouter
) -> None:
    """Observer une activité à grande échelle renforce un soupçon sans le créer."""
    respx_mock.get(f"{GN_URL}/1.2.3.4").mock(
        return_value=httpx.Response(
            200, json={"classification": "malicious", "name": "Tor Exit Node"}
        )
    )

    signal = await greynoise.query("1.2.3.4", "ip")

    assert signal.override is None
    assert signal.bonus == 25


async def test_greynoise_absence_du_bruit_de_fond_est_une_information(
    greynoise: GreyNoiseSource, respx_mock: respx.MockRouter
) -> None:
    """Une IP inconnue de GreyNoise suggère un ciblage, pas une innocuité."""
    respx_mock.get(f"{GN_URL}/1.2.3.4").mock(
        return_value=httpx.Response(
            200, json={"noise": False, "riot": False, "classification": "unknown"}
        )
    )

    signal = await greynoise.query("1.2.3.4", "ip")

    assert signal.result.status == "not_found"
    assert "ciblée" in (signal.result.detail or "")


# --------------------------------------------------------------------------
# Résistance aux pannes
# --------------------------------------------------------------------------
async def test_delai_depasse_ne_leve_pas_d_exception(
    vt: VirusTotalSource, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{VT_URL}/ip_addresses/1.2.3.4").mock(
        side_effect=httpx.ConnectTimeout("délai dépassé")
    )

    signal = await vt.query("1.2.3.4", "ip")

    assert signal.result.status == "unavailable"


async def test_reponse_inattendue_ne_fait_pas_tomber_l_enquete(
    vt: VirusTotalSource, respx_mock: respx.MockRouter
) -> None:
    """Une API tierce qui change son format ne doit pas interrompre une investigation."""
    respx_mock.get(f"{VT_URL}/ip_addresses/1.2.3.4").mock(
        return_value=httpx.Response(200, json={"format": "totalement inattendu"})
    )

    signal = await vt.query("1.2.3.4", "ip")

    assert signal.result.status in {"not_found", "unavailable"}


async def test_source_non_configuree_le_dit(limiter: RateLimiterRegistry) -> None:
    client = httpx.AsyncClient(base_url=VT_URL)
    try:
        source = VirusTotalSource(client, limiter, None)
        signal = await source.query("1.2.3.4", "ip")
    finally:
        await client.aclose()

    assert signal.result.status == "not_configured"
    assert not source.configured


# --------------------------------------------------------------------------
# Limitation de débit
# --------------------------------------------------------------------------
async def test_le_seau_autorise_une_rafale_puis_lisse() -> None:
    seau = TokenBucket(rate_per_minute=4, name="test")

    debut = asyncio.get_running_loop().time()
    for _ in range(4):
        await seau.acquire()
    duree = asyncio.get_running_loop().time() - debut

    assert duree < 0.2  # la rafale initiale ne bloque pas


async def test_quota_atteint_leve_plutot_que_de_faire_attendre() -> None:
    """Bloquer un enrichissement groupé cinq minutes serait pire que le dégrader."""
    seau = TokenBucket(rate_per_minute=1, name="test")
    await seau.acquire()

    with pytest.raises(QuotaExceededError, match="quota atteint"):
        await seau.acquire(max_wait_seconds=0.01)


async def test_source_inconnue_du_limiteur_passe_sans_blocage() -> None:
    registre = RateLimiterRegistry({"virustotal": 1})
    await registre.acquire("source-absente")  # ne doit pas lever

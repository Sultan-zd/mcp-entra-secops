"""Les trois sources publiques du renseignement sur les vulnérabilités.

Aucune ne demande de clé. Chacune répond à une question différente, et c'est
leur croisement qui a de la valeur :

* **NVD** — qu'est-ce que cette faille, et quelle est sa note théorique ?
* **CISA KEV** — est-elle *réellement* exploitée, aujourd'hui, dans la nature ?
* **EPSS** — quelle probabilité qu'elle le soit dans les trente jours ?

Une note CVSS élevée sur une faille que personne n'exploite mérite moins
d'urgence qu'une note moyenne sur une faille au catalogue KEV. Aucune des trois
sources ne le dit seule.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from argus_net import FeedCache, PublicHttpClient
from argus_net.ratelimit import RateLimiterRegistry

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"

#: Le NVD tolère cinq requêtes par tranche de trente secondes sans clé, soit
#: dix par minute. On reste en dessous : dépasser fait tomber l'adresse en
#: blocage temporaire, ce qui coûte bien plus cher qu'une seconde d'attente.
DEBITS = {"nvd": 8, "epss": 60, "kev": 4}

#: La norme impose quatre chiffres au minimum pour le numero de sequence,
#: et n'en fixe aucun maximum. Borner par le haut rejetterait une CVE
#: valide le jour ou les compteurs deborderont.
CVE_VALIDE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class InvalidCveError(ValueError):
    """Un identifiant qui n'a pas la forme d'une CVE."""


def normaliser_cve(brut: str) -> str:
    """Met un identifiant en forme canonique, ou refuse.

    La validation a lieu ici et pas seulement à l'entrée des outils : sans
    elle, une chaîne quelconque partirait vers le NVD, qui répondrait par un
    résultat vide — indiscernable d'une CVE inconnue.
    """
    valeur = brut.strip().upper()
    if not CVE_VALIDE.match(valeur):
        raise InvalidCveError(
            f"« {brut} » n'est pas un identifiant CVE. Format attendu : CVE-2021-44228."
        )
    return valeur


class VulnSources:
    """Accès mutualisé aux trois sources, avec quotas et cache."""

    def __init__(self, http: PublicHttpClient, feeds: FeedCache) -> None:
        self._http = http
        self._feeds = feeds
        self._quotas = RateLimiterRegistry(DEBITS)

    # ------------------------------------------------------------------ NVD
    async def nvd_cve(self, cve: str) -> dict[str, Any] | None:
        """Fiche NVD d'une CVE, ou None si elle est inconnue."""
        await self._quotas.acquire("nvd", max_wait_seconds=20)
        charge = await self._http.get_json(NVD_API, source="NVD", params={"cveId": cve})
        vulns = charge.get("vulnerabilities") or []
        return vulns[0].get("cve") if vulns else None

    async def nvd_search(
        self, mot_cle: str, *, limite: int, severite: str | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        """Recherche par mots-clés. Rend les fiches et le total disponible."""
        await self._quotas.acquire("nvd", max_wait_seconds=20)
        params: dict[str, Any] = {
            "keywordSearch": mot_cle,
            "resultsPerPage": min(max(limite, 1), 100),
        }
        if severite:
            params["cvssV3Severity"] = severite.upper()

        charge = await self._http.get_json(NVD_API, source="NVD", params=params)
        fiches = [v.get("cve", {}) for v in charge.get("vulnerabilities") or []]
        return fiches, int(charge.get("totalResults") or 0)

    async def nvd_par_cpe(self, cpe: str, *, limite: int) -> tuple[list[dict[str, Any]], int]:
        """CVE affectant un produit désigné par son identifiant CPE."""
        await self._quotas.acquire("nvd", max_wait_seconds=20)
        charge = await self._http.get_json(
            NVD_API,
            source="NVD",
            params={"cpeName": cpe, "resultsPerPage": min(max(limite, 1), 100)},
        )
        fiches = [v.get("cve", {}) for v in charge.get("vulnerabilities") or []]
        return fiches, int(charge.get("totalResults") or 0)

    # ------------------------------------------------------------------ KEV
    async def kev_index(self) -> dict[str, dict[str, Any]]:
        """Catalogue CISA, indexé par CVE.

        Le catalogue entier est chargé une fois puis gardé : il pèse plus d'un
        mégaoctet et ne change qu'une fois par jour. Le retélécharger à chaque
        question ferait attendre l'analyste pour rien.
        """

        async def charger() -> dict[str, dict[str, Any]]:
            await self._quotas.acquire("kev", max_wait_seconds=30)
            charge = await self._http.get_json(KEV_URL, source="CISA KEV")
            entrees = charge.get("vulnerabilities") or []
            index = {e["cveID"].upper(): e for e in entrees if e.get("cveID")}
            index["__meta__"] = {
                "catalog_version": charge.get("catalogVersion"),
                "released": charge.get("dateReleased"),
                "count": charge.get("count"),
            }
            return index

        index: dict[str, dict[str, Any]] = await self._feeds.get("cisa-kev", charger)
        return index

    async def kev_entree(self, cve: str) -> dict[str, Any] | None:
        index = await self.kev_index()
        return index.get(cve.upper())

    def kev_perime(self) -> bool:
        return self._feeds.est_perime("cisa-kev")

    # ----------------------------------------------------------------- EPSS
    async def epss(self, cves: list[str]) -> dict[str, dict[str, float]]:
        """Probabilités d'exploitation, plusieurs CVE d'un coup.

        L'API accepte une liste séparée par des virgules ; la découper en
        paquets évite une URL démesurée sur un lot de cent identifiants.
        """
        resultats: dict[str, dict[str, float]] = {}
        for depart in range(0, len(cves), 50):
            paquet = cves[depart : depart + 50]
            await self._quotas.acquire("epss", max_wait_seconds=15)
            charge = await self._http.get_json(
                EPSS_API, source="EPSS", params={"cve": ",".join(paquet)}
            )
            for ligne in charge.get("data") or []:
                identifiant = str(ligne.get("cve", "")).upper()
                if not identifiant:
                    continue
                resultats[identifiant] = {
                    "epss": float(ligne.get("epss") or 0.0),
                    "percentile": float(ligne.get("percentile") or 0.0),
                }
        return resultats

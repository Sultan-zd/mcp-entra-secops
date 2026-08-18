"""Source GreyNoise : qui balaie Internet en permanence, et pourquoi.

GreyNoise n'est pas un antivirus. Il observe le bruit de fond d'Internet et
répond à une question que les autres sources ne traitent pas : *cette adresse
scanne-t-elle tout le monde, ou vise-t-elle spécifiquement notre organisation ?*

C'est ce qui permet d'écarter les scanners de recherche légitimes (Shodan,
Censys, Shadowserver) au lieu d'alerter sur eux à longueur de journée.
"""

from __future__ import annotations

from typing import Any

from ..fusion import SourceSignal
from ..models import IndicatorKind
from .base import ThreatIntelSource


class GreyNoiseSource(ThreatIntelSource):
    """Interroge l'API communautaire de GreyNoise."""

    name = "greynoise"
    supports: tuple[IndicatorKind, ...] = ("ip",)

    async def _lookup(self, indicator: str, kind: IndicatorKind) -> SourceSignal:
        response = await self._client.get(
            f"/{indicator}", headers={"key": self._api_key or "", "Accept": "application/json"}
        )

        probleme = self._handle_status(response)
        if probleme is not None:
            return probleme

        donnees: dict[str, Any] = response.json() or {}
        classification = str(donnees.get("classification", "")).lower()
        nom = donnees.get("name") or "acteur non nommé"
        bruit = bool(donnees.get("noise"))
        riot = bool(donnees.get("riot"))

        # RIOT — « Rule It Out » — recense les services courants dont le trafic
        # est légitime par nature : résolveurs DNS publics, mises à jour de
        # systèmes d'exploitation, services d'infrastructure majeurs.
        if riot or classification == "benign":
            motif = (
                f"Service d'infrastructure courant référencé par GreyNoise ({nom})."
                if riot
                else f"Scanner Internet légitime référencé par GreyNoise ({nom})."
            )
            return self._signal(
                "ok",
                score=0.0,
                detail=motif,
                override="benign",
                override_reason=motif,
            )

        if classification == "malicious":
            # Bonus et non verdict imposé : GreyNoise observe une activité
            # malveillante à grande échelle, ce qui renforce un soupçon mais ne
            # suffit pas seul à condamner une adresse.
            return self._signal(
                "ok",
                score=60.0,
                detail=f"Activité malveillante observée à grande échelle ({nom}).",
                bonus=25,
            )

        if bruit:
            return self._signal(
                "ok",
                score=20.0,
                detail=(
                    f"Balayage indifférencié d'Internet observé ({nom}) : l'adresse ne vise "
                    "pas spécifiquement l'organisation."
                ),
            )

        # Adresse absente du bruit de fond : c'est une information à part
        # entière. Une IP inconnue de GreyNoise qui apparaît dans nos journaux
        # est plus préoccupante qu'un scanner de masse, car elle suggère un
        # ciblage.
        return self._signal(
            "not_found",
            detail=(
                "Absente du bruit de fond d'Internet : l'adresse ne balaie pas "
                "massivement, ce qui peut indiquer une activité ciblée."
            ),
        )

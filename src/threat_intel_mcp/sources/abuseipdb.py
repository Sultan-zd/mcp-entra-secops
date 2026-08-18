"""Source AbuseIPDB : signalements d'abus déclarés par la communauté."""

from __future__ import annotations

from typing import Any

from ..fusion import SourceSignal
from ..models import IndicatorKind
from .base import ThreatIntelSource


class AbuseIPDBSource(ThreatIntelSource):
    """Interroge l'API v2 d'AbuseIPDB.

    Le score renvoyé est déjà exprimé de 0 à 100 : aucune conversion n'est
    nécessaire. En revanche, deux corrections sont indispensables.
    """

    name = "abuseipdb"
    supports: tuple[IndicatorKind, ...] = ("ip",)

    async def _lookup(self, indicator: str, kind: IndicatorKind) -> SourceSignal:
        response = await self._client.get(
            "/check",
            params={"ipAddress": indicator, "maxAgeInDays": 90},
            headers={"Key": self._api_key or "", "Accept": "application/json"},
        )

        probleme = self._handle_status(response)
        if probleme is not None:
            return probleme

        donnees: dict[str, Any] = response.json().get("data", {}) or {}
        score = float(donnees.get("abuseConfidenceScore", 0))
        signalements = int(donnees.get("totalReports", 0))

        # Les listes blanches d'AbuseIPDB recensent des infrastructures
        # connues : résolveurs DNS publics, moteurs de recherche, fournisseurs
        # majeurs. Les signaler produirait des alertes systématiques sur des
        # adresses parfaitement légitimes.
        if donnees.get("isWhitelisted"):
            return self._signal(
                "ok",
                score=0.0,
                detail="Adresse figurant sur la liste blanche d'AbuseIPDB.",
                override="benign",
                override_reason=(
                    "Infrastructure référencée comme légitime par AbuseIPDB "
                    f"({donnees.get('isp') or 'hébergeur inconnu'})."
                ),
            )

        # Un score élevé fondé sur un ou deux signalements est fragile : n'importe
        # qui peut déclarer un abus. Le volume de signalements est le vrai
        # indicateur de fiabilité.
        if signalements < 3 and score > 0:
            score *= 0.5
            detail = (
                f"Score {donnees.get('abuseConfidenceScore')}/100 mais seulement "
                f"{signalements} signalement(s) : score atténué"
            )
        else:
            detail = f"Score de confiance {score:.0f}/100 sur {signalements} signalement(s)"

        usage = donnees.get("usageType")
        if usage:
            detail += f" — usage déclaré : {usage}"

        return self._signal("ok", score=round(score, 1), detail=detail)

    @staticmethod
    def extract_attributes(payload: dict[str, Any]) -> dict[str, str]:
        """Attributs d'enquête utiles, extraits d'une réponse AbuseIPDB."""
        donnees = payload.get("data", {}) or {}
        brut = {
            "pays": donnees.get("countryCode"),
            "hebergeur": donnees.get("isp"),
            "domaine": donnees.get("domain"),
            "type_usage": donnees.get("usageType"),
            "tor": "oui" if donnees.get("isTor") else None,
        }
        return {k: str(v) for k, v in brut.items() if v}

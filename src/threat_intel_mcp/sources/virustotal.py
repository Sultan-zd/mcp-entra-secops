"""Source VirusTotal : agrégateur de moteurs antivirus et de listes de réputation."""

from __future__ import annotations

from typing import Any

from ..fusion import SourceSignal
from ..models import IndicatorKind
from .base import ThreatIntelSource

#: Chemin de l'API selon le type d'indicateur.
_CHEMINS: dict[str, str] = {
    "ip": "/ip_addresses/{}",
    "domain": "/domains/{}",
    "file_hash": "/files/{}",
}

#: Nombre de moteurs signalant une menace à partir duquel on considère que la
#: détection n'est pas un cas isolé. Un unique moteur se trompe souvent ; trois
#: qui concordent, beaucoup moins.
_SEUIL_CONSENSUS = 3


class VirusTotalSource(ThreatIntelSource):
    """Interroge l'API v3 de VirusTotal.

    Seuls des *identifiants* sont transmis : adresses, domaines et condensats.
    **Aucun fichier n'est envoyé.** Téléverser un fichier sur VirusTotal le rend
    accessible aux abonnés du service : un document interne y deviendrait
    consultable par des tiers.
    """

    name = "virustotal"
    supports: tuple[IndicatorKind, ...] = ("ip", "domain", "file_hash")

    async def _lookup(self, indicator: str, kind: IndicatorKind) -> SourceSignal:
        chemin = _CHEMINS[kind].format(indicator)
        response = await self._client.get(chemin, headers={"x-apikey": self._api_key or ""})

        probleme = self._handle_status(response)
        if probleme is not None:
            return probleme

        attributs: dict[str, Any] = response.json().get("data", {}).get("attributes", {})
        stats: dict[str, int] = attributs.get("last_analysis_stats", {}) or {}

        malveillants = int(stats.get("malicious", 0))
        suspects = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 0

        if total == 0:
            return self._signal("not_found", detail="Aucune analyse disponible.")

        # Les moteurs « suspicious » comptent pour moitié : ils signalent un
        # doute, pas une détection ferme.
        score = (malveillants + suspects * 0.5) / total * 100

        detail = f"{malveillants}/{total} moteurs signalent une menace"
        if suspects:
            detail += f", {suspects} la jugent suspecte"

        familles = attributs.get("popular_threat_classification", {}) or {}
        etiquette = familles.get("suggested_threat_label")
        if etiquette:
            detail += f" — famille suggérée : {etiquette}"

        # Une détection isolée reste signalée, mais son score est atténué : la
        # remonter au même niveau qu'un consensus produirait des faux positifs
        # à répétition, et l'équipe cesserait de lire l'outil.
        if 0 < malveillants < _SEUIL_CONSENSUS:
            score *= 0.5
            detail += " (détection isolée, score atténué)"

        return self._signal("ok", score=round(score, 1), detail=detail)

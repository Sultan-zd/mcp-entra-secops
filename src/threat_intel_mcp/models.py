"""Modèles de sortie : un verdict unique et explicable, quelle que soit la source.

Chaque source renvoie une échelle différente — un ratio de moteurs chez
VirusTotal, un score de confiance sur 100 chez AbuseIPDB, une classification
qualitative chez GreyNoise. Ces modèles imposent une échelle commune, pour que
l'agent n'ait jamais à arbitrer entre des formats incomparables.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Verdict = Literal["malicious", "suspicious", "benign", "unknown", "internal"]
IndicatorKind = Literal["ip", "domain", "url", "file_hash"]
SourceStatus = Literal["ok", "not_found", "not_configured", "quota_exceeded", "unavailable"]
Confidence = Literal["high", "medium", "low"]


class SourceResult(BaseModel):
    """Ce qu'une source a répondu, y compris quand elle n'a pas répondu.

    Distinguer « aucune source ne connaît cet indicateur » de « les sources
    n'ont pas pu être interrogées » est essentiel : le premier cas est une
    information, le second est une panne.
    """

    source: str = Field(description="Nom de la source interrogée.")
    status: SourceStatus = Field(
        description=(
            "ok : la source a répondu. not_found : indicateur inconnu d'elle. "
            "not_configured : aucune clé d'API. quota_exceeded : quota épuisé. "
            "unavailable : panne ou délai dépassé."
        )
    )
    score: float | None = Field(
        default=None, description="Score normalisé de 0 à 100 proposé par cette source."
    )
    detail: str | None = Field(default=None, description="Précision lisible sur la réponse.")


class IndicatorVerdict(BaseModel):
    """Verdict consolidé sur un indicateur de compromission."""

    indicator: str = Field(description="Indicateur analysé, tel que fourni.")
    kind: IndicatorKind = Field(description="Nature de l'indicateur.")
    verdict: Verdict = Field(
        description=(
            "malicious, suspicious, benign, unknown (aucune source ne le connaît), "
            "ou internal (adresse privée, non soumise aux services externes)."
        )
    )
    score: int = Field(ge=0, le=100, description="Score de malveillance consolidé, de 0 à 100.")
    confidence: Confidence = Field(
        description=(
            "Fiabilité du verdict, fondée sur le nombre de sources ayant répondu. "
            "Un verdict en confiance « low » doit être confirmé autrement."
        )
    )
    explanation: str = Field(description="Pourquoi ce verdict, en une phrase exploitable.")
    sources: list[SourceResult] = Field(description="Détail par source, pannes comprises.")
    attributes: dict[str, str] = Field(
        default_factory=dict,
        description="Attributs utiles à l'enquête : ASN, pays, hébergeur, type d'usage.",
    )
    cached: bool = Field(default=False, description="Réponse servie depuis le cache.")
    notes: list[str] = Field(
        default_factory=list, description="Observations calculées, à confirmer par l'analyste."
    )

    @property
    def answered_sources(self) -> int:
        """Nombre de sources ayant effectivement répondu."""
        return sum(1 for s in self.sources if s.status in {"ok", "not_found"})


class BulkEnrichmentReport(BaseModel):
    """Résultat de `bulk_enrich` : plusieurs indicateurs, plus une synthèse.

    Les compteurs sont calculés en Python. Un agent qui doit dénombrer les
    indicateurs malveillants dans une liste de vingt se trompe ; une valeur
    pré-calculée, non.
    """

    total: int = Field(description="Nombre d'indicateurs analysés.")
    malicious: int = Field(description="Indicateurs jugés malveillants.")
    suspicious: int = Field(description="Indicateurs jugés suspects.")
    benign: int = Field(description="Indicateurs jugés bénins.")
    unknown: int = Field(description="Indicateurs qu'aucune source ne connaît.")
    internal: int = Field(description="Adresses privées, écartées avant tout appel externe.")
    from_cache: int = Field(description="Réponses servies depuis le cache.")
    results: list[IndicatorVerdict] = Field(
        description="Verdicts, du plus malveillant au plus bénin."
    )
    notes: list[str] = Field(default_factory=list, description="Observations calculées.")

    @classmethod
    def build(cls, results: list[IndicatorVerdict]) -> BulkEnrichmentReport:
        """Assemble le rapport et calcule les agrégats de manière déterministe."""
        ordre = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3, "internal": 4}
        classes = sorted(results, key=lambda r: (ordre[r.verdict], -r.score))

        compte = {v: sum(1 for r in results if r.verdict == v) for v in ordre}

        notes: list[str] = []
        if compte["malicious"]:
            noms = ", ".join(r.indicator for r in classes if r.verdict == "malicious")
            notes.append(
                f"{compte['malicious']} indicateur(s) malveillant(s), à traiter en "
                f"priorité : {noms}."
            )
        if compte["internal"]:
            notes.append(
                f"{compte['internal']} adresse(s) non routable(s) écartée(s) : elles n'ont pas été "
                "soumises aux services externes, pour ne pas divulguer la topologie interne."
            )
        faibles = [
            r.indicator for r in results if r.confidence == "low" and r.verdict != "internal"
        ]
        if faibles:
            notes.append(
                "Confiance faible sur : "
                + ", ".join(faibles)
                + ". Trop peu de sources ont répondu ; confirmer autrement avant de conclure."
            )

        return cls(
            total=len(results),
            malicious=compte["malicious"],
            suspicious=compte["suspicious"],
            benign=compte["benign"],
            unknown=compte["unknown"],
            internal=compte["internal"],
            from_cache=sum(1 for r in results if r.cached),
            results=classes,
            notes=notes,
        )


class SourceHealth(BaseModel):
    """État d'une source, tel que rapporté par le diagnostic."""

    source: str
    configured: bool
    reachable: bool | None = None
    detail: str


def as_attributes(raw: dict[str, Any]) -> dict[str, str]:
    """Réduit un dictionnaire hétérogène à des paires de chaînes non vides.

    Les attributs partent vers le contexte du modèle : ils doivent être courts,
    plats et lisibles, jamais des structures imbriquées.
    """
    return {
        str(k): str(v)
        for k, v in raw.items()
        if v not in (None, "", [], {}) and not isinstance(v, (dict, list))
    }

"""Fusion des sources en un verdict unique.

C'est le cœur du serveur, et la raison pour laquelle il ne s'agit pas d'un
simple relais d'API.

Trois sources renvoient trois échelles incomparables. Laisser le modèle
arbitrer entre elles reviendrait à lui demander de deviner — et un texte
injecté par un attaquant dans un champ libre pourrait alors influencer le
verdict. Ici, la décision est prise par du code déterministe et testé : aucune
donnée externe ne peut renverser un score.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import Confidence, IndicatorKind, IndicatorVerdict, SourceResult, Verdict

#: Seuils de classification. Volontairement bas côté « suspicious » : en SOC,
#: un faux positif coûte quelques minutes d'analyse, un faux négatif laisse un
#: attaquant dans le système. Les deux erreurs ne se valent pas.
SEUIL_MALVEILLANT = 70
SEUIL_SUSPECT = 30

#: Bonus appliqué quand GreyNoise observe une activité malveillante à grande
#: échelle. Il renforce un signal existant sans jamais suffire à lui seul.
BONUS_GREYNOISE = 25


@dataclass(frozen=True)
class SourceSignal:
    """Ce qu'une source apporte à la décision, une fois normalisé."""

    result: SourceResult
    #: Verdict imposé quelle que soit la suite : sert aux signaux d'innocence
    #: forts (scanner référencé, infrastructure d'un service courant).
    override: Verdict | None = None
    override_reason: str | None = None
    #: Bonus additif appliqué au score, sans écraser les autres sources.
    bonus: int = 0


def classify_private_ip(value: str) -> IndicatorVerdict | None:
    """Court-circuite les adresses non routables sur Internet.

    Deux raisons, et la seconde est la plus importante :

    1. Aucun service de réputation ne connaît 10.0.0.5 : l'appel est gaspillé,
       et il consomme un quota rare.
    2. **Soumettre une adresse interne à un service tiers divulgue la topologie
       du réseau de l'entreprise.** C'est une fuite d'information discrète, et
       irréversible une fois la requête partie.
    """
    try:
        adresse = ipaddress.ip_address(value.strip())
    except ValueError:
        return None

    if adresse.is_global:
        return None

    if adresse.is_private:
        motif = "adresse privée (RFC 1918 ou équivalent IPv6)"
    elif adresse.is_loopback:
        motif = "adresse de bouclage"
    elif adresse.is_link_local:
        motif = "adresse de lien local"
    elif adresse.is_multicast:
        motif = "adresse de multidiffusion"
    else:
        motif = "adresse réservée, non routable sur Internet"

    return IndicatorVerdict(
        indicator=value,
        kind="ip",
        verdict="internal",
        score=0,
        confidence="high",
        explanation=(
            f"Non soumise aux services externes : {motif}. Les interroger serait "
            "inutile et divulguerait la topologie du réseau interne."
        ),
        sources=[],
        notes=["Pour tracer cette adresse, utiliser les journaux internes (DHCP, annuaire)."],
    )


def _confidence(signals: list[SourceSignal]) -> Confidence:
    """Déduit la fiabilité du verdict des sources ayant répondu.

    La mesure est **relative aux sources capables de traiter cet indicateur**,
    et non absolue. Seul VirusTotal sait analyser un condensat de fichier : une
    confiance calculée sur un décompte brut classerait tout verdict de fichier
    en « faible », alors qu'aucune source supplémentaire n'était disponible.
    L'utilisateur en conclurait à tort que quelque chose a échoué.
    """
    capables = len(signals)
    repondu = sum(1 for s in signals if s.result.status in {"ok", "not_found"})

    if capables == 0 or repondu == 0:
        return "low"
    if capables == 1:
        # Meilleur niveau atteignable pour ce type d'indicateur : une source
        # unique par nature ne vaut pas un croisement, mais ce n'est pas une
        # défaillance.
        return "medium"
    if repondu == capables and capables >= 3:
        return "high"
    if repondu >= 2:
        return "medium"
    return "low"


def fuse(
    indicator: str,
    kind: IndicatorKind,
    signals: list[SourceSignal],
) -> IndicatorVerdict:
    """Combine les signaux en un verdict unique, explicable et reproductible."""
    resultats = [s.result for s in signals]
    confiance = _confidence(signals)

    # --- Verdict imposé : un signal d'innocence fort prime sur les scores ----
    # Un scanner de recherche référencé (Shodan, Censys) ou l'infrastructure
    # d'un service courant déclenche des détections chez d'autres sources. Sans
    # cette règle, l'outil produit des alertes à répétition sur des adresses
    # parfaitement légitimes, et l'équipe cesse de le lire.
    for signal in signals:
        if signal.override is not None:
            return IndicatorVerdict(
                indicator=indicator,
                kind=kind,
                verdict=signal.override,
                score=0 if signal.override == "benign" else 100,
                confidence=confiance,
                explanation=signal.override_reason or "Verdict imposé par une source de confiance.",
                sources=resultats,
            )

    scores = [
        s.result.score for s in signals if s.result.status == "ok" and s.result.score is not None
    ]

    if not scores:
        connu = any(s.result.status == "not_found" for s in signals)
        return IndicatorVerdict(
            indicator=indicator,
            kind=kind,
            verdict="unknown",
            score=0,
            confidence=confiance,
            explanation=(
                "Aucune source ne connaît cet indicateur."
                if connu
                else "Aucune source n'a pu être interrogée : le verdict est indisponible, "
                "et non « bénin »."
            ),
            sources=resultats,
            notes=(
                []
                if connu
                else ["Absence de réponse : ne pas conclure à l'innocuité de l'indicateur."]
            ),
        )

    # --- Score consolidé -----------------------------------------------------
    # Le maximum, et non la moyenne : une seule source qui détecte une menace
    # suffit à la signaler. Une moyenne diluerait ce signal dans le silence des
    # autres, ce qui est exactement l'erreur à ne pas commettre en sécurité.
    score = max(scores)
    bonus = sum(s.bonus for s in signals)
    score = max(0, min(100, round(score + bonus)))

    if score >= SEUIL_MALVEILLANT:
        verdict: Verdict = "malicious"
    elif score >= SEUIL_SUSPECT:
        verdict = "suspicious"
    else:
        verdict = "benign"

    contributions = [
        f"{s.result.source} {s.result.score:.0f}/100"
        for s in signals
        if s.result.status == "ok" and s.result.score is not None
    ]
    explication = f"Score consolidé {score}/100 — " + ", ".join(contributions) + "."
    if bonus:
        explication += f" Ajusté de {bonus:+d} par l'observation d'activité à grande échelle."

    notes: list[str] = []
    if confiance == "low":
        notes.append(
            "Moins de sources que prévu ont répondu : confirmer par un autre moyen "
            "avant de conclure."
        )
    indisponibles = [s.result.source for s in signals if s.result.status == "unavailable"]
    if indisponibles:
        notes.append(
            "Sources injoignables lors de cette analyse : "
            + ", ".join(indisponibles)
            + ". Le verdict repose sur les sources restantes."
        )
    epuisees = [s.result.source for s in signals if s.result.status == "quota_exceeded"]
    if epuisees:
        notes.append(
            "Quota épuisé sur : "
            + ", ".join(epuisees)
            + ". Les résultats en cache restent valides ; les nouveaux indicateurs seront "
            "moins bien couverts jusqu'au renouvellement."
        )

    return IndicatorVerdict(
        indicator=indicator,
        kind=kind,
        verdict=verdict,
        score=score,
        confidence=confiance,
        explanation=explication,
        sources=resultats,
        notes=notes,
    )

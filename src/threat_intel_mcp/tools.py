"""Outils MCP exposés par le serveur de renseignement sur les menaces.

Les fonctions sont indépendantes du serveur : elles s'enregistrent depuis
``server.py`` et restent testables sans démarrer de serveur MCP.
"""

from __future__ import annotations

import logging
from typing import Annotated

from pydantic import Field

from .config import get_settings
from .enrichment import InvalidIndicatorError
from .models import BulkEnrichmentReport, IndicatorVerdict
from .runtime import get_service

logger = logging.getLogger(__name__)


async def enrich_ip(
    ip_address: Annotated[
        str,
        Field(description="Adresse IPv4 ou IPv6 à analyser, par exemple « 185.220.101.47 »."),
    ],
) -> IndicatorVerdict:
    """Établit la réputation d'une adresse IP en croisant VirusTotal, AbuseIPDB
    et GreyNoise, et rend un verdict unique de 0 à 100.

    À utiliser dès qu'une adresse IP apparaît dans une investigation : connexion
    suspecte, expéditeur de courriel, auteur d'une modification d'annuaire.

    Les adresses privées ne sont jamais transmises aux services externes : elles
    sont identifiées comme internes, sans appel réseau.

    Le champ `confidence` indique combien de sources ont répondu. Un verdict en
    confiance « low » ne doit pas être présenté comme certain.
    """
    try:
        return await get_service().enrich(ip_address, kind="ip")
    except InvalidIndicatorError as exc:
        raise ValueError(str(exc)) from exc


async def enrich_domain(
    domain: Annotated[
        str,
        Field(description="Nom de domaine, sans schéma ni chemin, par exemple « exemple.com »."),
    ],
) -> IndicatorVerdict:
    """Établit la réputation d'un nom de domaine auprès de VirusTotal.

    À utiliser pour un domaine expéditeur de courriel, un lien signalé par un
    utilisateur, ou un domaine ressemblant à celui de l'organisation.

    L'attribut `age_du_domaine`, quand il est disponible, est un indice fort :
    un domaine créé il y a quelques jours et utilisé dans un courriel est
    caractéristique d'une campagne d'hameçonnage.
    """
    try:
        return await get_service().enrich(domain, kind="domain")
    except InvalidIndicatorError as exc:
        raise ValueError(str(exc)) from exc


async def enrich_file_hash(
    file_hash: Annotated[
        str,
        Field(description="Condensat MD5, SHA-1 ou SHA-256 du fichier, en hexadécimal."),
    ],
) -> IndicatorVerdict:
    """Établit la réputation d'un fichier à partir de son condensat.

    IMPORTANT : seul le condensat est transmis, jamais le fichier. Téléverser un
    fichier sur VirusTotal le rendrait consultable par les abonnés du service ;
    un document interne y deviendrait accessible à des tiers. Calculez le
    condensat localement et ne fournissez que celui-ci.
    """
    try:
        return await get_service().enrich(file_hash, kind="file_hash")
    except InvalidIndicatorError as exc:
        raise ValueError(str(exc)) from exc


async def bulk_enrich(
    indicators: Annotated[
        list[str],
        Field(
            description=(
                "Indicateurs à analyser, mélangeant adresses IP, domaines et condensats. "
                "Le type de chacun est déduit automatiquement."
            )
        ),
    ],
) -> BulkEnrichmentReport:
    """Analyse plusieurs indicateurs en une seule fois et rend une synthèse
    chiffrée, triée du plus malveillant au plus bénin.

    À privilégier systématiquement quand une investigation produit plusieurs
    indicateurs : un appel groupé interroge les sources en parallèle, là où
    des appels séparés les enchaînent et épuisent les quotas.

    Les compteurs du rapport sont calculés côté serveur : utilisez-les tels
    quels plutôt que de recompter la liste.
    """
    settings = get_settings()
    if not indicators:
        raise ValueError("La liste d'indicateurs est vide.")

    # Le plafond protège à la fois les quotas des API externes et la fenêtre de
    # contexte du modèle : vingt verdicts détaillés suffisent à saturer un
    # message si on ne borne pas.
    retenus = indicators[: settings.max_bulk_indicators]
    if len(indicators) > len(retenus):
        logger.info(
            "Enrichissement groupé tronqué : %d indicateurs demandés, %d retenus.",
            len(indicators),
            len(retenus),
        )

    verdicts = await get_service().enrich_many(retenus)
    rapport = BulkEnrichmentReport.build(verdicts)

    if len(indicators) > len(retenus):
        rapport.notes.append(
            f"{len(indicators)} indicateurs fournis, {len(retenus)} analysés : la limite "
            f"de {settings.max_bulk_indicators} par appel a été appliquée."
        )
    return rapport

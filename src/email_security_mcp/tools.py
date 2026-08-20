"""Outils MCP exposés par le serveur de sécurité de la messagerie."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Annotated

from pydantic import Field

from .config import get_settings
from .dkim import analyse_dkim
from .dmarc import analyse_dmarc
from .headers import analyse_headers
from .models import DkimReport, DmarcReport, DomainPosture, HeaderAnalysis, SpfReport
from .posture import build_posture
from .runtime import get_resolver
from .spf import analyse_spf

logger = logging.getLogger(__name__)

_DOMAINE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$")


def _valider_domaine(valeur: str) -> str:
    """Refuse explicitement ce qui n'est pas un domaine.

    Accepter une URL et interroger le DNS avec produirait « aucun
    enregistrement » — une réponse rassurante et fausse sur la posture réelle.
    """
    domaine = valeur.strip().lower().rstrip(".")
    if not _DOMAINE.match(domaine):
        raise ValueError(
            f"« {valeur} » n'est pas un nom de domaine valide. Fournir le domaine seul, "
            "sans schéma ni chemin — par exemple « exemple.com »."
        )
    return domaine


async def check_spf(
    domain: Annotated[str, Field(description="Domaine à analyser, sans schéma ni chemin.")],
) -> SpfReport:
    """Analyse l'enregistrement SPF d'un domaine et **compte les résolutions DNS
    qu'il déclenche**.

    La norme plafonne ce nombre à 10. Au-delà, l'évaluation renvoie `permerror`
    et SPF cesse de protéger le domaine — alors que l'enregistrement paraît
    parfaitement correct dans le portail DNS. C'est la panne la plus fréquente,
    et la plus silencieuse, de la sécurité de la messagerie.

    Le champ `dns_lookups` donne la mesure exacte, `findings` explique quoi faire.
    """
    return await analyse_spf(_valider_domaine(domain), get_resolver())


async def check_dkim(
    domain: Annotated[str, Field(description="Domaine à analyser.")],
    selectors: Annotated[
        list[str] | None,
        Field(
            description=(
                "Sélecteurs à interroger. Omettre pour essayer les sélecteurs courants "
                "(selector1 et selector2 pour Microsoft 365, google pour Workspace…). "
                "Aucun standard ne permet de les énumérer depuis le DNS."
            )
        ),
    ] = None,
) -> DkimReport:
    """Vérifie les clés DKIM publiées : présence, type, taille et état.

    Signale les clés RSA de moins de 2048 bits, les clés révoquées (`p=` vide),
    et l'indicateur `t=y` qui demande aux destinataires d'**ignorer** les échecs
    de vérification — auquel cas DKIM n'apporte aucune protection réelle.
    """
    settings = get_settings()
    retenus = selectors[: settings.max_selectors] if selectors else None
    return await analyse_dkim(_valider_domaine(domain), get_resolver(), retenus)


async def check_dmarc(
    domain: Annotated[str, Field(description="Domaine à analyser.")],
) -> DmarcReport:
    """Lit la politique DMARC d'un domaine et évalue ce qu'elle protège réellement.

    Attention à deux pièges fréquents : `p=none` n'est qu'un mode d'observation
    et ne bloque rien, et `pct=` inférieur à 100 n'applique la politique qu'à
    une fraction du trafic. Dans les deux cas, le domaine paraît protégé sans
    l'être.
    """
    return await analyse_dmarc(_valider_domaine(domain), get_resolver())


async def analyze_email_headers(
    raw_headers: Annotated[
        str,
        Field(
            description=(
                "En-têtes bruts du message, tels que copiés depuis le client de "
                "messagerie (« afficher la source » ou « en-têtes Internet »)."
            )
        ),
    ],
) -> HeaderAnalysis:
    """Détermine si un message reçu est usurpé, en vérifiant l'ALIGNEMENT.

    Le point central : SPF valide le `Return-Path:` (l'enveloppe), pas le
    `From:` affiché à l'utilisateur. Un attaquant met l'adresse de sa cible dans
    `From:` et la sienne dans `Return-Path:` — SPF passe, et le message paraît
    authentique. Cet outil met ce décalage en évidence.

    Le champ `indicators` liste les adresses IP et domaines extraits : les
    passer ensuite à `bulk_enrich` du serveur de renseignement complète
    l'analyse.

    Le verdict est calculé par du code, jamais déduit du texte du message — dont
    l'objet et le corps sont entièrement contrôlés par l'attaquant.
    """
    settings = get_settings()
    if not raw_headers.strip():
        raise ValueError("Les en-têtes fournis sont vides.")

    tronque = raw_headers[: settings.max_header_bytes]
    if len(raw_headers) > len(tronque):
        logger.info(
            "En-têtes tronqués : %d octets fournis, %d retenus.",
            len(raw_headers),
            len(tronque),
        )

    resultat = analyse_headers(tronque)
    if len(raw_headers) > len(tronque):
        resultat.findings.append(
            f"En-têtes tronqués à {settings.max_header_bytes} octets : l'analyse porte "
            "sur le début du message."
        )
    return resultat


async def check_domain_posture(
    domain: Annotated[str, Field(description="Domaine à évaluer.")],
) -> DomainPosture:
    """Évalue SPF, DKIM et DMARC ensemble, et rend une note de 0 à 100 assortie
    d'actions classées par gain de sécurité décroissant.

    À utiliser pour répondre à « notre domaine est-il protégé contre
    l'usurpation ? », ou pour évaluer celui d'un partenaire avant de lui faire
    confiance.

    Les trois analyses sont menées en parallèle.
    """
    domaine = _valider_domaine(domain)
    resolveur = get_resolver()

    spf, dkim, dmarc = await asyncio.gather(
        analyse_spf(domaine, resolveur),
        analyse_dkim(domaine, resolveur),
        analyse_dmarc(domaine, resolveur),
    )
    return build_posture(domaine, spf, dkim, dmarc)

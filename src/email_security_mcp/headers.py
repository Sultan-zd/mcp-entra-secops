"""Analyse des en-têtes d'un message reçu : est-il usurpé ?

Le mécanisme d'usurpation le plus courant n'exige aucune compétence technique :
l'attaquant met l'adresse de sa cible dans `From:`, et sa propre adresse dans
`Return-Path:`. SPF vérifie le `Return-Path:`, pas le `From:` — donc SPF passe,
alors que l'adresse affichée à l'utilisateur est fausse.

C'est précisément ce décalage que DMARC appelle l'**alignement**, et c'est ce
que ce module met en évidence.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from email import message_from_string
from email.utils import parseaddr
from typing import Literal, cast

from .models import AuthResult, HeaderAnalysis, Severity

logger = logging.getLogger(__name__)

_RESULTAT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)
_DKIM_DOMAINE = re.compile(r"\bd\s*=\s*([A-Za-z0-9.\-]+)", re.IGNORECASE)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_RESULTATS_VALIDES = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
}


def domain_of(address: str | None) -> str | None:
    """Extrait le domaine d'une adresse, en tolérant les formes décorées."""
    if not address:
        return None
    _, adresse = parseaddr(address)
    if "@" not in adresse:
        return None
    return adresse.rsplit("@", 1)[1].strip().lower().rstrip(">").rstrip(".") or None


def organizational_domain(domain: str | None) -> str | None:
    """Approxime le domaine organisationnel, pour l'alignement relâché.

    L'exactitude demanderait la liste publique des suffixes ; les deux derniers
    libellés suffisent dans l'immense majorité des cas, et l'approximation est
    signalée plutôt que masquée.
    """
    if not domain:
        return None
    parties = domain.split(".")
    return ".".join(parties[-2:]) if len(parties) >= 2 else domain


def _resultats_authentification(message: object) -> dict[str, AuthResult]:
    """Lit les verdicts SPF, DKIM et DMARC déclarés par le serveur de réception."""
    trouves: dict[str, AuthResult] = {}
    entetes = message.get_all("Authentication-Results") or []  # type: ignore[attr-defined]
    for entete in entetes:
        for mecanisme, resultat in _RESULTAT.findall(entete):
            cle = mecanisme.lower()
            valeur = resultat.lower()
            if cle not in trouves and valeur in _RESULTATS_VALIDES:
                trouves[cle] = cast(AuthResult, valeur)
    return trouves


def analyse_headers(raw_headers: str) -> HeaderAnalysis:
    """Décompose les en-têtes et conclut sur l'authenticité du message."""
    message = message_from_string(raw_headers)

    domaine_affiche = domain_of(message.get("From"))
    domaine_retour = domain_of(message.get("Return-Path") or message.get("Sender"))
    reply_to = message.get("Reply-To")
    domaine_reponse = domain_of(reply_to)

    resultats = _resultats_authentification(message)
    spf = resultats.get("spf", "none")
    dkim = resultats.get("dkim", "none")
    dmarc = resultats.get("dmarc", "none")

    domaine_dkim = None
    for entete in (message.get_all("DKIM-Signature") or []) + (
        message.get_all("Authentication-Results") or []
    ):
        trouve = _DKIM_DOMAINE.search(entete)
        if trouve:
            domaine_dkim = trouve.group(1).lower()
            break

    org_affiche = organizational_domain(domaine_affiche)
    spf_aligne = bool(org_affiche) and organizational_domain(domaine_retour) == org_affiche
    dkim_aligne = bool(org_affiche) and organizational_domain(domaine_dkim) == org_affiche

    constats: list[str] = []

    # --- Le décalage central -------------------------------------------------
    if domaine_affiche and domaine_retour and not spf_aligne:
        constats.append(
            f"DÉSALIGNEMENT : l'adresse affichée est en « {domaine_affiche} » mais "
            f"l'enveloppe d'envoi est en « {domaine_retour} ». SPF valide l'enveloppe, "
            "pas l'adresse affichée : un `spf=pass` ne prouve donc RIEN sur "
            "l'expéditeur visible."
        )

    if domaine_affiche and domaine_dkim and not dkim_aligne:
        constats.append(
            f"La signature DKIM est apposée par « {domaine_dkim} », pas par "
            f"« {domaine_affiche} » : la signature n'authentifie pas l'expéditeur affiché."
        )

    if domaine_reponse and org_affiche and organizational_domain(domaine_reponse) != org_affiche:
        constats.append(
            f"L'adresse de réponse pointe vers « {domaine_reponse} », différente du "
            "domaine affiché : toute réponse partira chez l'attaquant. Motif "
            "caractéristique de la fraude au président."
        )

    if dmarc == "fail":
        constats.append(
            "DMARC échoue : le domaine affiché a publié une politique, et ce message "
            "ne la respecte pas. C'est le signal le plus fort d'une usurpation."
        )
    elif dmarc == "none":
        constats.append(
            "Aucun verdict DMARC : soit le domaine n'en publie pas, soit le serveur de "
            "réception ne l'évalue pas. L'absence de verdict n'est pas un verdict "
            "favorable."
        )

    if spf == "fail":
        constats.append("SPF échoue : le serveur émetteur n'est pas autorisé par le domaine.")
    if dkim == "fail":
        constats.append("DKIM échoue : le message a été altéré, ou la signature est invalide.")

    # --- Indicateurs à enrichir ---------------------------------------------
    indicateurs: list[str] = []
    for entete in message.get_all("Received") or []:
        for brute in _IP.findall(entete):
            try:
                adresse = ipaddress.ip_address(brute)
            except ValueError:
                continue
            if adresse.is_global and brute not in indicateurs:
                indicateurs.append(brute)
    for domaine in (domaine_retour, domaine_dkim, domaine_reponse):
        if domaine and domaine != domaine_affiche and domaine not in indicateurs:
            indicateurs.append(domaine)

    verdict, gravite = _conclure(dmarc, spf, dkim, spf_aligne, dkim_aligne, domaine_affiche)

    if indicateurs:
        constats.append(
            "Indicateurs extraits pour enrichissement : " + ", ".join(indicateurs[:8]) + "."
        )

    return HeaderAnalysis(
        from_domain=domaine_affiche,
        return_path_domain=domaine_retour,
        dkim_domain=domaine_dkim,
        reply_to=reply_to,
        subject=message.get("Subject"),
        spf_result=spf,
        dkim_result=dkim,
        dmarc_result=dmarc,
        spf_aligned=spf_aligne,
        dkim_aligned=dkim_aligne,
        verdict=verdict,
        indicators=indicateurs[:20],
        findings=constats,
        severity=gravite,
    )


def _conclure(
    dmarc: str,
    spf: str,
    dkim: str,
    spf_aligne: bool,
    dkim_aligne: bool,
    domaine_affiche: str | None,
) -> tuple[Literal["legitimate", "suspicious", "spoofed", "unknown"], Severity]:
    """Tranche sur l'authenticité, et rien d'autre.

    La décision est prise ici, dans du code testé, et non laissée au modèle :
    un objet de courriel est entièrement contrôlé par l'attaquant, et pourrait
    contenir un texte cherchant à influencer un verdict rendu par un prompt.
    """
    if domaine_affiche is None:
        return "unknown", "medium"

    if dmarc == "fail":
        return "spoofed", "high"

    # Un message aligné sur au moins un mécanisme, sans échec, est authentique.
    if dmarc == "pass" or (spf == "pass" and spf_aligne) or (dkim == "pass" and dkim_aligne):
        if spf == "fail" or dkim == "fail":
            return "suspicious", "medium"
        return "legitimate", "none"

    if spf == "fail" or dkim == "fail":
        return "spoofed", "high"

    # SPF passe mais sur un autre domaine que celui affiché : c'est le cas le
    # plus trompeur, car les indicateurs visuels du client de messagerie sont
    # au vert.
    if spf == "pass" and not spf_aligne:
        return "suspicious", "high"

    return "unknown", "medium"

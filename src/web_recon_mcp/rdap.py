"""À qui appartient ce domaine, cette adresse — et depuis quand.

**Le signal que ce module apporte et qui manquait.** L'âge d'un domaine est
l'un des indicateurs de hameçonnage les plus forts qui existent : une campagne
utilise des domaines enregistrés depuis quelques jours, parce qu'un domaine
ancien coûte cher et se rachète mal. Jusqu'ici, rien dans ARGUS ne disait
depuis quand un domaine existe.

RDAP remplace WHOIS : réponses en JSON structuré, pas de texte libre à
analyser, **et aucune clé d'API**. Le redirecteur `rdap.org` route vers le
registre compétent, y compris pour des extensions peu servies.

L'ASN d'une adresse vient de RIPEstat : savoir qu'une adresse appartient à un
hébergeur pare-balles plutôt qu'à un fournisseur d'accès grand public change
la lecture d'un incident.

**Ce que ce module refuse de faire.** Interroger un registre pour une adresse
privée : cela révélerait la topologie interne à un tiers, et le registre n'a
de toute façon rien à en dire.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from argus_net import HttpError

from .runtime import get_http

#: Redirecteur RDAP : route vers le registre compétent selon l'extension ou la
#: plage d'adresses. Évite d'embarquer la table de correspondance de l'IANA,
#: qui change à chaque nouveau domaine de premier niveau.
BASE_RDAP = "https://rdap.org"

#: Origine de l'ASN. RDAP le rend parfois, mais sous une clé qui dépend du
#: registre régional ; RIPEstat le donne uniformément.
BASE_RIPESTAT = "https://stat.ripe.net/data/prefix-overview/data.json"

#: En dessous, un domaine mérite une mention explicite. Le seuil vient de
#: l'usage : les campagnes de hameçonnage consomment des domaines de quelques
#: jours à quelques semaines.
SEUIL_TRES_RECENT = 30
SEUIL_RECENT = 90

#: Codes d'état EPP qui disent quelque chose d'un incident.
ETATS_PARLANTS = {
    "clienthold": "le registrar a suspendu la résolution du domaine",
    "serverhold": "le registre a suspendu la résolution du domaine",
    "pendingdelete": "le domaine est en cours de suppression",
    "redemptionperiod": "le domaine a expiré et est en période de rachat",
    "clienttransferprohibited": "transfert bloqué par le registrar (protection courante)",
    "serverdeleteprohibited": "suppression bloquée par le registre",
}


@dataclass
class Enregistrement:
    """Ce qu'un registre dit d'un domaine."""

    domain: str
    registered_on: str | None = None
    expires_on: str | None = None
    last_changed: str | None = None
    age_days: int | None = None
    registrar: str | None = None
    nameservers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    dnssec: bool | None = None
    findings: list[str] = field(default_factory=list)
    source: str = "rdap.org"


@dataclass
class Proprietaire:
    """Ce qu'un registre dit d'une adresse IP."""

    ip: str
    network: str | None = None
    name: str | None = None
    allocation_type: str | None = None
    country: str | None = None
    asn: int | None = None
    asn_holder: str | None = None
    announced: bool | None = None
    findings: list[str] = field(default_factory=list)


def _date(valeur: str | None) -> datetime | None:
    if not valeur:
        return None
    try:
        return datetime.fromisoformat(valeur.replace("Z", "+00:00"))
    except ValueError:
        return None


def _evenement(charge: dict[str, Any], action: str) -> str | None:
    """La date d'un évènement RDAP, s'il est présent.

    Les registres ne publient pas tous les mêmes évènements : l'absence est
    normale et ne doit pas faire échouer l'analyse.
    """
    for evenement in charge.get("events") or []:
        if str(evenement.get("eventAction", "")).lower() == action:
            return str(evenement.get("eventDate"))
    return None


def _registrar(charge: dict[str, Any]) -> str | None:
    """Le nom du registrar, extrait du vCard imbriqué.

    RDAP encapsule les entités en jCard — une structure en listes imbriquées
    héritée de vCard. Le nom se trouve dans une entrée « fn ».
    """
    for entite in charge.get("entities") or []:
        roles = [str(r).lower() for r in entite.get("roles") or []]
        if "registrar" not in roles:
            continue
        vcard = entite.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for champ in vcard[1]:
                if isinstance(champ, list) and champ and champ[0] == "fn":
                    return str(champ[3])
        if entite.get("handle"):
            return f"handle {entite['handle']}"
    return None


async def enregistrement(domaine: str) -> Enregistrement:
    """Interroge RDAP sur un domaine."""
    nom = domaine.strip().lower().rstrip(".")
    resultat = Enregistrement(domain=nom)

    try:
        charge = await get_http().get_json(
            f"{BASE_RDAP}/domain/{nom}",
            source="rdap",
            headers={"Accept": "application/rdap+json"},
        )
    except HttpError as exc:
        # Un registre muet ne veut pas dire « domaine inexistant » : le dire
        # serait un faux négatif, et certaines extensions ne servent pas RDAP.
        resultat.findings.append(
            f"Le registre n'a pas répondu ({exc}). L'absence de réponse ne dit "
            "rien de l'existence du domaine."
        )
        return resultat

    if not isinstance(charge, dict):
        resultat.findings.append("Réponse RDAP inattendue.")
        return resultat

    resultat.registered_on = _evenement(charge, "registration")
    resultat.expires_on = _evenement(charge, "expiration")
    resultat.last_changed = _evenement(charge, "last changed")
    resultat.registrar = _registrar(charge)
    resultat.status = [str(s) for s in charge.get("status") or []]
    resultat.nameservers = sorted(
        str(n.get("ldhName", "")).lower()
        for n in charge.get("nameservers") or []
        if n.get("ldhName")
    )

    securise = charge.get("secureDNS")
    if isinstance(securise, dict):
        resultat.dnssec = bool(securise.get("delegationSigned"))

    # --- l'âge, et ce qu'il vaut -----------------------------------------
    creation = _date(resultat.registered_on)
    if creation:
        resultat.age_days = (datetime.now(UTC) - creation).days
        if resultat.age_days < SEUIL_TRES_RECENT:
            resultat.findings.append(
                f"Domaine enregistré il y a {resultat.age_days} jour(s). Les "
                "campagnes de hameçonnage consomment des domaines de cet âge : "
                "traiter tout contenu associé avec une prudence particulière."
            )
        elif resultat.age_days < SEUIL_RECENT:
            resultat.findings.append(
                f"Domaine enregistré il y a {resultat.age_days} jour(s) — récent, "
                "sans être caractéristique à lui seul."
            )
    else:
        resultat.findings.append(
            "Le registre ne publie pas de date d'enregistrement : l'âge du "
            "domaine ne peut pas servir de signal ici."
        )

    # --- expiration -------------------------------------------------------
    fin = _date(resultat.expires_on)
    if fin:
        restants = (fin - datetime.now(UTC)).days
        if restants < 0:
            resultat.findings.append(
                f"Domaine expiré depuis {abs(restants)} jour(s) : il peut être "
                "racheté par un tiers, ce qui transfère tout ce qui en dépend."
            )
        elif restants < 30:
            resultat.findings.append(f"Le domaine expire dans {restants} jour(s).")

    for etat in resultat.status:
        explication = ETATS_PARLANTS.get(etat.replace(" ", "").lower())
        if explication and "prohibited" not in etat.lower():
            resultat.findings.append(f"État « {etat} » : {explication}.")

    return resultat


async def proprietaire(adresse: str) -> Proprietaire:
    """Interroge RDAP et RIPEstat sur une adresse IP."""
    valeur = adresse.strip()
    resultat = Proprietaire(ip=valeur)

    try:
        ip = ipaddress.ip_address(valeur)
    except ValueError:
        resultat.findings.append(f"« {valeur} » n'est pas une adresse IP valide.")
        return resultat

    # Contrainte de sécurité du projet : une adresse interne ne part jamais
    # chez un tiers. Le registre n'en dirait rien, et l'envoyer révélerait la
    # topologie du réseau.
    if not ip.is_global:
        resultat.findings.append(
            "Adresse non routable sur Internet : aucune requête n'a été émise. "
            "L'interroger chez un tiers révélerait la topologie interne."
        )
        return resultat

    try:
        charge = await get_http().get_json(
            f"{BASE_RDAP}/ip/{valeur}",
            source="rdap",
            headers={"Accept": "application/rdap+json"},
        )
        if isinstance(charge, dict):
            debut, fin = charge.get("startAddress"), charge.get("endAddress")
            resultat.network = f"{debut} - {fin}" if debut and fin else None
            resultat.name = charge.get("name")
            resultat.allocation_type = charge.get("type")
            resultat.country = charge.get("country")
    except HttpError as exc:
        resultat.findings.append(f"RDAP n'a pas répondu ({exc}).")

    # --- ASN ---------------------------------------------------------------
    try:
        reponse = await get_http().get_json(
            BASE_RIPESTAT, source="ripestat", params={"resource": valeur}
        )
        donnees = (reponse or {}).get("data") or {}
        asns = donnees.get("asns") or []
        if asns:
            resultat.asn = asns[0].get("asn")
            resultat.asn_holder = asns[0].get("holder")
        resultat.announced = donnees.get("announced")
        if resultat.announced is False:
            resultat.findings.append(
                "Le préfixe n'est annoncé par aucun opérateur : l'adresse n'est "
                "pas joignable depuis Internet en ce moment."
            )
    except HttpError as exc:
        resultat.findings.append(f"L'origine de l'ASN n'a pas pu être établie ({exc}).")

    if not resultat.asn and not resultat.name:
        resultat.findings.append(
            "Aucun registre n'a rendu d'information : « inconnu » ne veut pas "
            "dire « sans danger »."
        )

    return resultat

"""Hygiène DNS : DNSSEC, CAA, transfert de zone, alias pendants.

Quatre contrôles que presque personne ne fait, et dont trois révèlent des
défauts sérieux et concrets.

Le plus grave est l'**alias pendant** : un CNAME qui pointe vers un service
infogéré désormais libéré. Quiconque réenregistre ce service reçoit le trafic
d'un sous-domaine légitime — et peut faire émettre un certificat valide à son
nom.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import dns.zone

logger = logging.getLogger(__name__)

#: Services infogérés dont un enregistrement libéré est réappropriable. La
#: liste couvre les cas les plus courants ; elle n'a pas vocation à être
#: exhaustive, et l'outil le dit.
SERVICES_INFOGERES = {
    "s3.amazonaws.com": "Amazon S3",
    "cloudfront.net": "Amazon CloudFront",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure Cloud Service",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "netlify.app": "Netlify",
    "ghost.io": "Ghost",
    "wpengine.com": "WP Engine",
    "pantheonsite.io": "Pantheon",
    "zendesk.com": "Zendesk",
    "statuspage.io": "Statuspage",
    "surge.sh": "Surge",
    "fastly.net": "Fastly",
}

#: Sous-domaines à sonder pour repérer un alias pendant. Ce sont ceux qu'on
#: crée pour un essai puis qu'on oublie.
SONDES = (
    "www",
    "mail",
    "blog",
    "shop",
    "docs",
    "status",
    "support",
    "dev",
    "test",
    "staging",
    "api",
    "cdn",
    "assets",
    "files",
    "portal",
    "app",
)


@dataclass
class ResultatHygiene:
    """État de l'hygiène DNS d'un domaine."""

    domain: str
    dnssec: str = "inconnu"
    caa_records: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    zone_transfer_open: list[str] = field(default_factory=list)
    dangling_cnames: list[dict[str, str]] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    severity: str = "none"
    score: int = 100


def _resolveur(delai: float) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.timeout = delai
    r.lifetime = delai
    return r


async def _dnssec(domaine: str, resolveur: dns.asyncresolver.Resolver) -> str:
    """Le domaine publie-t-il une signature DNSSEC ?

    On teste la présence d'un enregistrement DNSKEY. Cela ne prouve pas que la
    chaîne de confiance est complète — la valider exigerait de remonter jusqu'à
    la racine — et la sortie ne prétend donc pas davantage.
    """
    try:
        reponse = await resolveur.resolve(domaine, "DNSKEY")
        return "signé" if reponse else "non signé"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "non signé"
    except dns.exception.DNSException:
        return "inconnu"


async def _caa(domaine: str, resolveur: dns.asyncresolver.Resolver) -> list[str]:
    try:
        reponse = await resolveur.resolve(domaine, "CAA")
        return [r.to_text() for r in reponse]
    except dns.exception.DNSException:
        return []


async def _serveurs_de_noms(domaine: str, resolveur: dns.asyncresolver.Resolver) -> list[str]:
    try:
        reponse = await resolveur.resolve(domaine, "NS")
        return sorted(str(r.target).rstrip(".") for r in reponse)
    except dns.exception.DNSException:
        return []


def _tenter_transfert(serveur: str, domaine: str, delai: float) -> bool:
    """Un transfert de zone ouvert livre l'annuaire complet du domaine."""
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(serveur, domaine, timeout=delai))
        return zone is not None
    except Exception:
        return False


async def _alias_pendants(
    domaine: str, resolveur: dns.asyncresolver.Resolver
) -> list[dict[str, str]]:
    """Cherche des CNAME vers un service infogéré qui ne répond plus.

    Le motif recherché : le CNAME existe, il pointe vers un service connu, mais
    la cible ne se résout pas. C'est la signature d'un service libéré et
    réappropriable.
    """
    pendants: list[dict[str, str]] = []

    async def examiner(sonde: str) -> None:
        nom = f"{sonde}.{domaine}"
        try:
            reponse = await resolveur.resolve(nom, "CNAME")
        except dns.exception.DNSException:
            return

        for enregistrement in reponse:
            cible = str(enregistrement.target).rstrip(".").lower()
            service = next(
                (
                    nom_service
                    for suffixe, nom_service in SERVICES_INFOGERES.items()
                    if cible.endswith(suffixe)
                ),
                None,
            )
            if service is None:
                continue
            try:
                await resolveur.resolve(cible, "A")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pendants.append({"name": nom, "target": cible, "service": service})
            except dns.exception.DNSException:
                # Une panne de résolution passagère n'est pas un alias pendant :
                # l'annoncer comme tel enverrait l'équipe sur une fausse piste.
                logger.debug("Résolution incertaine pour %s", cible)

    await asyncio.gather(*(examiner(s) for s in SONDES))
    return pendants


async def examiner(
    domaine: str, *, delai: float = 8.0, tester_transfert: bool = True
) -> ResultatHygiene:
    """Applique les quatre contrôles d'hygiène."""
    resultat = ResultatHygiene(domain=domaine)
    resolveur = _resolveur(delai)

    (
        resultat.dnssec,
        resultat.caa_records,
        resultat.nameservers,
        resultat.dangling_cnames,
    ) = await asyncio.gather(
        _dnssec(domaine, resolveur),
        _caa(domaine, resolveur),
        _serveurs_de_noms(domaine, resolveur),
        _alias_pendants(domaine, resolveur),
    )

    if tester_transfert and resultat.nameservers:
        boucle = asyncio.get_running_loop()
        resultats = await asyncio.gather(
            *(
                boucle.run_in_executor(None, _tenter_transfert, ns, domaine, delai)
                for ns in resultat.nameservers[:4]
            )
        )
        resultat.zone_transfer_open = [
            ns for ns, ouvert in zip(resultat.nameservers[:4], resultats, strict=False) if ouvert
        ]

    _noter(resultat)
    return resultat


def _noter(resultat: ResultatHygiene) -> None:
    constats: list[str] = []
    penalite = 0

    if resultat.dangling_cnames:
        noms = ", ".join(d["name"] for d in resultat.dangling_cnames[:3])
        constats.append(
            f"ALIAS PENDANT : {noms} pointe vers un service infogéré qui ne répond "
            "plus. Quiconque réenregistre ce service reçoit le trafic de ce "
            "sous-domaine, et peut faire émettre un certificat valide à son nom."
        )
        penalite += 45

    if resultat.zone_transfer_open:
        constats.append(
            f"Transfert de zone accepté par {', '.join(resultat.zone_transfer_open)} : "
            "l'annuaire complet du domaine est téléchargeable par n'importe qui."
        )
        penalite += 35

    if resultat.dnssec == "non signé":
        constats.append(
            "DNSSEC absent : les réponses DNS de ce domaine ne sont pas signées et "
            "peuvent être falsifiées en chemin."
        )
        penalite += 15
    elif resultat.dnssec == "inconnu":
        constats.append("État DNSSEC indéterminé : le résolveur n'a pas répondu.")

    if not resultat.caa_records:
        constats.append(
            "Aucun enregistrement CAA : n'importe quelle autorité de certification "
            "peut émettre un certificat pour ce domaine."
        )
        penalite += 10

    if len(resultat.nameservers) < 2:
        constats.append(
            f"{len(resultat.nameservers)} serveur(s) de noms : sans redondance, une "
            "panne rend le domaine entièrement injoignable."
        )
        penalite += 10

    resultat.score = max(0, 100 - penalite)
    resultat.findings = constats
    resultat.severity = (
        "critical"
        if resultat.score < 45
        else "high"
        if resultat.score < 65
        else "medium"
        if resultat.score < 85
        else "none"
    )

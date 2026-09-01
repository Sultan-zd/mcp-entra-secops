"""Les outils de reconnaissance web et TLS.

Trois d'entre eux n'interrogent aucune API : ils ouvrent eux-mêmes la
connexion. Cela les rend utilisables sur un hôte interne, qu'aucun service en
ligne ne pourrait atteindre — et garantit que la note ne change pas parce qu'un
prestataire a modifié son barème.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Annotated, Any

from pydantic import Field

from . import ct, rdap
from .dnshygiene import examiner as examiner_dns
from .headers import analyser as analyser_entetes
from .models import (
    CertificateInventory,
    DnsHygieneReport,
    DomainRegistration,
    IpOwner,
    SecurityHeadersReport,
    SubdomainReport,
    TlsReport,
    WebExposureReport,
)
from .runtime import get_http
from .tls import TlsError
from .tls import inspecter as inspecter_tls

logger = logging.getLogger(__name__)

#: Un nom d'hôte plausible. Le contrôle a lieu avant toute connexion : ouvrir
#: une socket vers une saisie fautive coûte un délai d'attente complet.
HOTE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def _valider(hote: str) -> str:
    propre = hote.strip().lower().removeprefix("https://").removeprefix("http://")
    propre = propre.split("/")[0].split(":")[0]
    if not HOTE.match(propre):
        raise ValueError(f"« {hote} » n'est pas un nom d'hôte valide. Exemple : teknologiia.com.")
    return propre


async def check_tls(
    host: Annotated[str, Field(description="Nom d'hôte, par exemple teknologiia.com.")],
    port: Annotated[int, Field(description="Port TLS.", ge=1, le=65535)] = 443,
    test_protocol_versions: Annotated[
        bool,
        Field(description="Tester chaque version du protocole une par une (plus lent)."),
    ] = True,
) -> TlsReport:
    """Inspecte la configuration TLS d'un hôte, par connexion directe.

    Aucune API tierce n'est consultée : le serveur ouvre lui-même la connexion.
    Cela fonctionne donc sur un hôte **interne**, et le résultat ne dépend
    d'aucun prestataire.

    Le constat le plus utile n'est pas le certificat mais **quelles versions du
    protocole restent acceptées** : un serveur qui négocie TLS 1.3 avec un
    navigateur moderne peut très bien accepter TLS 1.0 avec un client qui le
    demande. Chaque version est donc testée séparément.

    Une version marquée « non testable » n'est pas une version refusée : la
    bibliothèque cliente peut refuser de la proposer. La distinction est
    maintenue plutôt que masquée — conclure « refusée » serait un faux négatif.
    """
    cible = _valider(host)
    try:
        resultat = await inspecter_tls(cible, port, tester_versions=test_protocol_versions)
    except TlsError as exc:
        raise ValueError(str(exc)) from exc

    return TlsReport(**resultat.__dict__)


async def check_certificate_expiry(
    hosts: Annotated[list[str], Field(description="Hôtes à vérifier, 25 au plus.")],
    warn_days: Annotated[int, Field(description="Seuil d'alerte, en jours.", ge=1, le=365)] = 30,
) -> CertificateInventory:
    """Vérifie l'expiration des certificats de plusieurs hôtes d'un coup.

    L'expiration d'un certificat coupe le service, et les chaînes de
    renouvellement automatique échouent plus souvent qu'on ne le croit — souvent
    en silence. C'est le contrôle le plus rentable d'un inventaire.

    Les hôtes sont interrogés en parallèle ; un hôte injoignable n'interrompt
    pas les autres.
    """
    if not hosts:
        raise ValueError("Fournissez au moins un hôte.")
    if len(hosts) > 25:
        raise ValueError(f"{len(hosts)} hôtes demandés, 25 au maximum.")

    async def un(hote: str) -> dict[str, Any]:
        try:
            cible = _valider(hote)
        except ValueError as exc:
            return {"host": hote, "error": str(exc)}
        try:
            r = await inspecter_tls(cible, 443, tester_versions=False)
        except TlsError as exc:
            return {"host": cible, "error": str(exc)}
        return {
            "host": cible,
            "issuer": r.issuer,
            "not_after": r.not_after,
            "days_until_expiry": r.days_until_expiry,
            "hostname_matches": r.hostname_matches,
        }

    resultats = await asyncio.gather(*(un(h) for h in hosts))

    valides = [r for r in resultats if "error" not in r]
    injoignables = [r for r in resultats if "error" in r]
    expires = [r for r in valides if (r["days_until_expiry"] or 0) < 0]
    bientot = [r for r in valides if 0 <= (r["days_until_expiry"] or 999) <= warn_days]

    if expires:
        message = f"{len(expires)} certificat(s) déjà expiré(s) : le service est rompu."
    elif bientot:
        message = f"{len(bientot)} certificat(s) expirent dans moins de {warn_days} jours."
    elif injoignables:
        message = f"{len(injoignables)} hôte(s) injoignable(s) ; les autres sont valides."
    else:
        message = "Aucun certificat n'expire dans la fenêtre surveillée."

    return CertificateInventory(
        checked=len(hosts),
        reachable=len(valides),
        expired=len(expires),
        expiring_soon=len(bientot),
        warn_days=warn_days,
        summary=message,
        certificates=sorted(valides, key=lambda r: r["days_until_expiry"] or 9999),
        unreachable=injoignables,
    )


async def check_security_headers(
    url: Annotated[str, Field(description="URL ou nom d'hôte à auditer.")],
) -> SecurityHeadersReport:
    """Récupère une page et note ses en-têtes de sécurité sur 100.

    La page est récupérée par ce serveur, et la note est calculée par du code
    testé — pas obtenue d'un service tiers. Les pondérations reflètent ce qu'un
    attaquant peut faire de l'absence : HSTS et CSP dominent parce que leur
    absence ouvre des attaques concrètes.

    L'outil ne se contente pas de la présence des en-têtes : une CSP qui
    autorise `unsafe-inline` est présente mais désarmée, et un HSTS de deux
    jours ne protège de rien. Ces demi-mesures sont signalées.
    """
    resultat = await analyser_entetes(url)
    return SecurityHeadersReport(**resultat.__dict__)


async def check_dns_hygiene(
    domain: Annotated[str, Field(description="Domaine à examiner.")],
    test_zone_transfer: Annotated[
        bool, Field(description="Tenter un transfert de zone sur les serveurs de noms.")
    ] = True,
) -> DnsHygieneReport:
    """Quatre contrôles DNS que presque personne ne fait.

    Le plus grave est l'**alias pendant** : un CNAME qui pointe vers un service
    infogéré désormais libéré. Quiconque réenregistre ce service reçoit le
    trafic d'un sous-domaine légitime, et peut faire émettre un certificat
    valide à son nom. Seize sous-domaines courants sont sondés.

    Les trois autres : DNSSEC, enregistrements CAA, et transfert de zone
    ouvert — ce dernier livrant l'annuaire complet du domaine à qui le demande.

    Une résolution incertaine n'est jamais rapportée comme un alias pendant :
    envoyer une équipe sur une fausse piste coûte plus cher que de se taire.
    """
    cible = _valider(domain)
    resultat = await examiner_dns(cible, tester_transfert=test_zone_transfer)
    return DnsHygieneReport(**resultat.__dict__)


async def find_subdomains(
    domain: Annotated[str, Field(description="Domaine dont chercher les sous-domaines.")],
    limit: Annotated[int, Field(description="Nombre de noms rendus.", ge=1, le=500)] = 100,
) -> SubdomainReport:
    """Découvre les sous-domaines via les journaux de transparence des certificats.

    Chaque certificat émis publiquement y est inscrit. C'est la meilleure source
    de découverte qui soit : elle ne demande aucune permission, ne touche pas au
    domaine, et révèle même ce qui n'a jamais eu d'enregistrement DNS public.

    **Les noms appartenant à d'autres domaines sont exclus.** Les hébergeurs
    mutualisés regroupent des dizaines de clients dans un même certificat ; les
    présenter comme vos sous-domaines serait faux. Leur nombre est rapporté
    séparément.
    """
    cible = _valider(domain)
    resultat = await ct.decouvrir(cible, get_http(), limite=limit)
    return SubdomainReport(**resultat.__dict__)


async def check_web_exposure(
    domain: Annotated[str, Field(description="Domaine à auditer de bout en bout.")],
) -> WebExposureReport:
    """Audit complet d'un domaine : TLS, en-têtes, hygiène DNS, sous-domaines.

    Les quatre analyses sont menées **en parallèle** et rendues avec une note
    d'ensemble. À utiliser pour « ce domaine est-il correctement exposé ? »
    plutôt que d'enchaîner quatre appels.

    Une analyse en échec n'annule pas les autres : son absence est signalée et
    la note globale ne porte que sur ce qui a pu être mesuré. Une note calculée
    sur des données partielles qui ne le dirait pas serait trompeuse.
    """
    cible = _valider(domain)

    tls, entetes, dns_, sous = await asyncio.gather(
        inspecter_tls(cible, 443, tester_versions=True),
        analyser_entetes(cible),
        examiner_dns(cible),
        ct.decouvrir(cible, get_http()),
        return_exceptions=True,
    )

    notes: list[int] = []
    constats: list[str] = []
    indisponibles: list[str] = []

    rapport = WebExposureReport(domain=cible)

    if isinstance(tls, BaseException):
        indisponibles.append(f"TLS : {tls}")
    else:
        rapport.tls = TlsReport(**tls.__dict__)
        notes.append(tls.score)
        constats.extend(tls.findings)

    if isinstance(entetes, BaseException):
        indisponibles.append(f"En-têtes : {entetes}")
    else:
        rapport.headers = SecurityHeadersReport(**entetes.__dict__)
        notes.append(entetes.score)
        constats.extend(entetes.findings)

    if isinstance(dns_, BaseException):
        indisponibles.append(f"DNS : {dns_}")
    else:
        rapport.dns = DnsHygieneReport(**dns_.__dict__)
        notes.append(dns_.score)
        constats.extend(dns_.findings)

    if isinstance(sous, BaseException):
        indisponibles.append(f"Sous-domaines : {sous}")
    else:
        rapport.subdomains = SubdomainReport(**sous.__dict__)
        constats.extend(sous.findings)

    rapport.unavailable = indisponibles
    rapport.score = round(sum(notes) / len(notes)) if notes else 0
    rapport.findings = constats[:20]
    rapport.severity = (
        "critical"
        if rapport.score < 45
        else "high"
        if rapport.score < 65
        else "medium"
        if rapport.score < 85
        else "none"
    )
    rapport.summary = f"Note d'exposition {rapport.score}/100 sur {len(notes)} analyse(s)." + (
        f" {len(indisponibles)} analyse(s) n'ont pas abouti : la note ne porte "
        "que sur ce qui a pu être mesuré."
        if indisponibles
        else ""
    )
    return rapport


async def lookup_domain_registration(
    domain: Annotated[
        str,
        Field(description="Le domaine à interroger, par exemple « exemple.com ».", max_length=253),
    ],
) -> DomainRegistration:
    """Depuis quand ce domaine existe, et qui l'a enregistré.

    **L'âge d'un domaine est l'un des signaux de hameçonnage les plus forts qui
    existent.** Une campagne consomme des domaines enregistrés depuis quelques
    jours, parce qu'un domaine ancien coûte cher et se rachète mal. Un domaine
    de moins de trente jours, cité dans un courriel suspect, mérite à lui seul
    une prudence particulière.

    Interroge RDAP — le successeur de WHOIS : réponses structurées, **aucune
    clé d'API**, et une couverture qui inclut les extensions nationales.

    Rend aussi les codes d'état du registre. Certains sont parlants pour un
    incident : `clientHold` signifie que le registrar a suspendu la résolution
    du domaine, `redemptionPeriod` qu'il a expiré et peut être racheté par un
    tiers — ce qui transfère tout ce qui en dépend.

    Un registre muet ne veut pas dire « domaine inexistant » : l'outil le dit
    au lieu de conclure.
    """
    resultat = await rdap.enregistrement(domain)
    return DomainRegistration(
        domain=resultat.domain,
        registered_on=resultat.registered_on,
        expires_on=resultat.expires_on,
        last_changed=resultat.last_changed,
        age_days=resultat.age_days,
        registrar=resultat.registrar,
        nameservers=resultat.nameservers,
        status=resultat.status,
        dnssec=resultat.dnssec,
        findings=resultat.findings,
        source=resultat.source,
    )


async def lookup_ip_owner(
    ip: Annotated[str, Field(description="L'adresse IP à situer.", max_length=45)],
) -> IpOwner:
    """À qui appartient cette adresse, et quel opérateur l'annonce.

    Savoir qu'une adresse appartient à un hébergeur pare-balles plutôt qu'à un
    fournisseur d'accès grand public change la lecture d'un incident — et
    aucune source de réputation ne le dit.

    Croise deux registres publics, **sans aucune clé** : RDAP pour
    l'allocation (plage, organisation, type), RIPEstat pour le numéro de
    système autonome et son détenteur.

    Un préfixe **non annoncé** est signalé : l'adresse n'est alors joignable
    par personne, ce qui rend suspecte sa présence dans un journal récent.

    **Une adresse privée n'est jamais transmise.** L'interroger chez un tiers
    révélerait la topologie du réseau interne, et aucun registre n'en dirait
    rien.
    """
    resultat = await rdap.proprietaire(ip)
    return IpOwner(
        ip=resultat.ip,
        network=resultat.network,
        name=resultat.name,
        allocation_type=resultat.allocation_type,
        country=resultat.country,
        asn=resultat.asn,
        asn_holder=resultat.asn_holder,
        announced=resultat.announced,
        findings=resultat.findings,
    )

"""Inspection TLS par connexion directe.

Aucune API tierce n'est interrogée : le serveur ouvre lui-même la connexion et
lit ce que l'hôte présente. C'est la différence entre demander à quelqu'un ce
qu'il a vu et regarder soi-même — et cela fonctionne sur un hôte interne qu'un
service en ligne ne pourrait jamais atteindre.

Le point le plus utile n'est pas le certificat, que tout le monde regarde, mais
**quelles versions du protocole restent acceptées**. Un serveur qui négocie
TLS 1.3 avec un navigateur moderne peut très bien accepter TLS 1.0 avec un
client qui le demande.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

logger = logging.getLogger(__name__)

#: Versions à tester une par une. Les deux premières sont dépréciées depuis
#: 2021 (RFC 8996) et leur présence est un constat, pas une nuance.
VERSIONS = (
    ("TLSv1", ssl.TLSVersion.TLSv1, True),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, True),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, False),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, False),
)

#: En dessous, le renouvellement devient urgent : une expiration en production
#: coupe le service, et les chaînes de renouvellement automatique échouent
#: silencieusement plus souvent qu'on ne le croit.
SEUIL_EXPIRATION_URGENT = 14
SEUIL_EXPIRATION_ALERTE = 30


class TlsError(RuntimeError):
    """L'hôte n'a pas pu être joint en TLS."""


@dataclass
class ResultatTls:
    """Ce qu'une connexion directe a permis d'observer."""

    host: str
    port: int
    negotiated_version: str | None = None
    negotiated_cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    san: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    hostname_matches: bool | None = None
    self_signed: bool | None = None
    key_type: str | None = None
    key_bits: int | None = None
    signature_algorithm: str | None = None
    supported_versions: dict[str, str] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    severity: str = "none"
    score: int = 100


def _connecter(
    hote: str, port: int, delai: float, contexte: ssl.SSLContext
) -> tuple[bytes | None, tuple[str | None, Any]]:
    """Ouvre une connexion TLS et rend le certificat brut et la session.

    Le certificat est récupéré sous forme DER, pas via `getpeercert()`. Ce
    dernier rend un dictionnaire **vide** lorsque la vérification est
    désactivée — or c'est exactement le mode requis pour inspecter un
    certificat expiré ou auto-signé. Le piège est silencieux : la connexion
    réussit, la structure est vide, et l'audit conclut que tout va bien.
    """
    with (
        socket.create_connection((hote, port), timeout=delai) as brut,
        contexte.wrap_socket(brut, server_hostname=hote) as securise,
    ):
        return securise.getpeercert(binary_form=True), (
            securise.version(),
            securise.cipher(),
        )


def _tester_version(hote: str, port: int, delai: float, version: ssl.TLSVersion) -> str:
    """Teste si une version précise du protocole est acceptée.

    Rend « acceptée », « refusée », ou « non testable ». La dernière valeur est
    importante : les bibliothèques récentes désactivent TLS 1.0 et 1.1 côté
    client, et on ne peut alors rien conclure sur le serveur. Répondre
    « refusée » dans ce cas serait un faux négatif — exactement l'erreur qu'un
    audit ne doit pas commettre.
    """
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexte.check_hostname = False
    contexte.verify_mode = ssl.CERT_NONE
    try:
        contexte.minimum_version = version
        contexte.maximum_version = version
    except ValueError:
        return "non testable"

    # Les versions anciennes exigent souvent des suites que la configuration
    # par défaut d'OpenSSL 3 exclut.
    if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        try:
            contexte.set_ciphers("DEFAULT@SECLEVEL=0")
        except ssl.SSLError:
            return "non testable"

    try:
        with (
            socket.create_connection((hote, port), timeout=delai) as brut,
            contexte.wrap_socket(brut, server_hostname=hote),
        ):
            return "acceptée"
    except ssl.SSLError:
        return "refusée"
    except (OSError, TimeoutError):
        return "non testable"


async def inspecter(
    hote: str, port: int = 443, *, delai: float = 12.0, tester_versions: bool = True
) -> ResultatTls:
    """Ouvre une connexion TLS et rend tout ce qu'elle révèle."""
    resultat = ResultatTls(host=hote, port=port)

    # La vérification est désactivée pour l'inspection : un certificat expiré
    # ou auto-signé est précisément ce qu'on veut constater, pas une raison de
    # renoncer à l'examiner.
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexte.check_hostname = False
    contexte.verify_mode = ssl.CERT_NONE

    boucle = asyncio.get_running_loop()
    try:
        certificat, session = await boucle.run_in_executor(
            None, _connecter, hote, port, delai, contexte
        )
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        raise TlsError(
            f"Connexion TLS impossible vers {hote}:{port} ({type(exc).__name__})."
        ) from exc

    version, chiffrement = session
    resultat.negotiated_version = version
    resultat.negotiated_cipher = chiffrement[0] if chiffrement else None

    if certificat:
        _lire_certificat(certificat, resultat)

    if tester_versions:
        for libelle, version_ssl, _ in VERSIONS:
            resultat.supported_versions[libelle] = await boucle.run_in_executor(
                None, _tester_version, hote, port, delai, version_ssl
            )

    _noter(resultat)
    return resultat


def _lire_certificat(der: bytes, resultat: ResultatTls) -> None:
    """Décode le certificat X.509 et renseigne le résultat."""
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        resultat.findings.append(f"Certificat illisible : {exc}")
        return

    resultat.subject = cert.subject.rfc4514_string()
    resultat.issuer = cert.issuer.rfc4514_string()
    resultat.self_signed = cert.subject == cert.issuer

    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        resultat.san = extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        resultat.san = []

    debut = cert.not_valid_before_utc
    fin = cert.not_valid_after_utc
    resultat.not_before = debut.isoformat()
    resultat.not_after = fin.isoformat()
    resultat.days_until_expiry = (fin - datetime.now(UTC)).days

    cle = cert.public_key()
    if isinstance(cle, rsa.RSAPublicKey):
        resultat.key_type, resultat.key_bits = "RSA", cle.key_size
    elif isinstance(cle, ec.EllipticCurvePublicKey):
        resultat.key_type, resultat.key_bits = f"EC ({cle.curve.name})", cle.curve.key_size
    else:
        resultat.key_type = type(cle).__name__

    algorithme = cert.signature_hash_algorithm
    resultat.signature_algorithm = algorithme.name if algorithme else None

    resultat.hostname_matches = _correspond(resultat.host, resultat.san, resultat.subject)


def _correspond(hote: str, san: list[str], sujet: str | None) -> bool:
    """Le certificat couvre-t-il ce nom d'hôte, jokers compris ?"""
    cible = hote.lower().rstrip(".")
    noms = [s.lower().rstrip(".") for s in san]
    if not noms and sujet:
        for morceau in sujet.split(","):
            if morceau.strip().lower().startswith("commonname="):
                noms.append(morceau.split("=", 1)[1].strip().lower())

    for nom in noms:
        if nom == cible:
            return True
        if nom.startswith("*."):
            # Un joker ne couvre qu'un seul niveau : *.exemple.com couvre
            # a.exemple.com mais pas a.b.exemple.com.
            suffixe = nom[1:]
            if cible.endswith(suffixe) and cible.count(".") == nom.count("."):
                return True
    return False


#: Ordre des gravités, du plus grave au moins grave.
ECHELLE = ("critical", "high", "medium", "low", "none")


def _pire(a: str, b: str) -> str:
    """Rend la plus grave de deux gravités."""
    return a if ECHELLE.index(a) <= ECHELLE.index(b) else b


def _noter(resultat: ResultatTls) -> None:
    """Constats, note, et gravité — déterministes.

    Les pénalités reflètent ce qu'un attaquant peut réellement en faire, pas la
    gravité théorique du défaut.

    **Certains constats ne s'additionnent pas, ils tranchent.** Un certificat
    expiré n'est pas « moyennement bon » : le navigateur le refuse, le service
    est rompu. Une note calculée par soustraction le ramenait à « medium », ce
    qu'un test a révélé. Ces constats posent donc un plancher de gravité que la
    note ne peut pas adoucir.
    """
    constats: list[str] = []
    penalite = 0
    plancher = "none"

    obsoletes = [
        libelle
        for libelle, _, deprecie in VERSIONS
        if deprecie and resultat.supported_versions.get(libelle) == "acceptée"
    ]
    if obsoletes:
        constats.append(
            f"Versions dépréciées encore acceptées : {', '.join(obsoletes)}. "
            "La RFC 8996 les interdit depuis 2021 ; elles permettent des attaques "
            "de rétrogradation."
        )
        penalite += 35

    if resultat.supported_versions.get("TLSv1.3") == "refusée":
        constats.append(
            "TLS 1.3 n'est pas accepté : le serveur reste sur des échanges de clés "
            "plus anciens et des reprises de session moins protégées."
        )
        penalite += 10

    non_testables = [
        libelle for libelle, etat in resultat.supported_versions.items() if etat == "non testable"
    ]
    if non_testables:
        constats.append(
            f"Versions non testables depuis ce poste : {', '.join(non_testables)}. "
            "La bibliothèque cliente les refuse ; l'état du serveur reste inconnu "
            "pour celles-ci."
        )

    if resultat.self_signed:
        constats.append(
            "Certificat auto-signé : aucune autorité ne se porte garante de cette identité."
        )
        penalite += 30
        plancher = _pire(plancher, "high")

    if resultat.hostname_matches is False:
        constats.append(
            f"Le certificat ne couvre pas « {resultat.host} » : "
            f"noms présentés {resultat.san[:4] or ['aucun']}."
        )
        penalite += 30

    if resultat.key_type == "RSA" and resultat.key_bits and resultat.key_bits < 2048:
        constats.append(
            f"Clé RSA de {resultat.key_bits} bits : en dessous du minimum de 2048 "
            "exigé depuis 2014."
        )
        penalite += 30

    if resultat.signature_algorithm in {"md5", "sha1"}:
        plancher = _pire(plancher, "high")
        constats.append(
            f"Signature en {resultat.signature_algorithm.upper()} : cet algorithme est "
            "cassé et permet de forger un certificat."
        )
        penalite += 35

    jours = resultat.days_until_expiry
    if jours is not None:
        if jours < 0:
            constats.append(
                f"Certificat expiré depuis {abs(jours)} jour(s) : les navigateurs le "
                "refusent, le service est rompu."
            )
            penalite += 40
            plancher = _pire(plancher, "critical")
        elif jours <= SEUIL_EXPIRATION_URGENT:
            constats.append(
                f"Expiration dans {jours} jour(s) : renouvellement urgent. "
                "Les chaînes automatiques échouent plus souvent qu'on ne le croit."
            )
            penalite += 20
        elif jours <= SEUIL_EXPIRATION_ALERTE:
            constats.append(f"Expiration dans {jours} jour(s) : à planifier.")
            penalite += 5

    resultat.score = max(0, 100 - penalite)
    resultat.findings = constats
    par_la_note = (
        "critical"
        if resultat.score < 40
        else "high"
        if resultat.score < 60
        else "medium"
        if resultat.score < 85
        else "none"
    )
    resultat.severity = _pire(par_la_note, plancher)

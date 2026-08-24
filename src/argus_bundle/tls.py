"""Terminaison TLS pour le transport HTTP.

**Ce que la recherche du projet recommande, et pourquoi ce module existe
quand même.** Le brief technique désigne le proxy inverse — Caddy, Traefik,
nginx — comme cible de production : il renouvelle les certificats par ACME,
limite le débit, et se met à jour indépendamment du serveur. Cette
recommandation ne change pas.

Mais elle suppose une infrastructure. Une équipe SOC qui veut partager une
instance sur son réseau interne, avec un certificat émis par son autorité
interne, n'a pas de proxy à sa disposition — et l'alternative, en pratique,
n'est pas « un proxy » mais **du HTTP en clair**. Terminer TLS ici est alors le
choix le plus sûr disponible.

**Ce que ce module refuse de laisser passer :**

* Un certificat **expiré**, ou qui expire bientôt. Un serveur qui note la
  configuration TLS des autres ne peut pas servir un certificat périmé sans le
  dire. La vérification a lieu **avant** l'ouverture du port.
* Une **clé qui ne correspond pas** au certificat. L'erreur d'OpenSSL au
  moment du handshake est illisible ; le dire au démarrage fait gagner l'heure
  que coûte ce diagnostic.
* **TLS 1.0 et 1.1.** Le minimum est fixé à 1.2, explicitement, plutôt que
  laissé au défaut de la bibliothèque — un défaut peut changer, et l'outil
  `check_tls` de ce même projet sanctionne ces versions chez les autres.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Les seuils sont ceux qu'applique déjà `check_tls` aux hôtes analysés. Se
# juger moins sévèrement qu'on ne juge les autres serait indéfendable.
from web_recon_mcp.tls import SEUIL_EXPIRATION_ALERTE, SEUIL_EXPIRATION_URGENT

#: Version minimale servie. Fixée ici plutôt que laissée au défaut du module
#: `ssl` : ce défaut a déjà changé entre versions de Python, et un serveur de
#: sécurité ne doit pas dépendre d'un réglage implicite.
VERSION_MINIMALE = ssl.TLSVersion.TLSv1_2


class MaterielTlsError(RuntimeError):
    """Le certificat ou la clé ne permettent pas de servir en TLS."""


@dataclass
class InfoCertificat:
    """Ce que le certificat annonce, lu avant d'ouvrir le port."""

    sujet: str = ""
    emetteur: str = ""
    expire_le: datetime | None = None
    jours_restants: int | None = None
    noms: list[str] = field(default_factory=list)
    auto_signe: bool = False
    avertissements: list[str] = field(default_factory=list)


def _nom_commun(nom: Any) -> str:
    from cryptography.x509.oid import NameOID

    valeurs = nom.get_attributes_for_oid(NameOID.COMMON_NAME)
    if valeurs:
        return str(valeurs[0].value)
    return str(nom.rfc4514_string())


def verifier_materiel(certificat: Path, cle: Path) -> InfoCertificat:
    """Contrôle le couple certificat/clé avant toute écoute.

    Échouer ici est bien moins coûteux qu'échouer au premier handshake : à ce
    moment-là, le port est ouvert, le client reçoit une erreur TLS opaque, et
    rien dans les journaux ne dit laquelle des deux moitiés est en cause.
    """
    for chemin, role in ((certificat, "certificat"), (cle, "clé privée")):
        if not chemin.exists():
            raise MaterielTlsError(f"{role.capitalize()} introuvable : {chemin}")
        if not chemin.is_file():
            raise MaterielTlsError(f"{chemin} n'est pas un fichier ({role}).")

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        pem = certificat.read_bytes()
        cert = x509.load_pem_x509_certificate(pem)
    except Exception as exc:
        raise MaterielTlsError(
            f"Certificat illisible ({certificat}) : {exc}. "
            "Le format attendu est PEM (« -----BEGIN CERTIFICATE----- »)."
        ) from exc

    try:
        prive = load_pem_private_key(cle.read_bytes(), password=None)
    except TypeError as exc:
        raise MaterielTlsError(
            f"La clé privée {cle} est protégée par une phrase secrète. "
            "Fournissez une clé sans phrase, ou terminez TLS en amont."
        ) from exc
    except Exception as exc:
        raise MaterielTlsError(f"Clé privée illisible ({cle}) : {exc}") from exc

    # --- la clé correspond-elle au certificat ? ---------------------------
    if prive.public_key().public_numbers() != cert.public_key().public_numbers():  # type: ignore[union-attr]
        raise MaterielTlsError(
            f"La clé {cle.name} ne correspond pas au certificat {certificat.name}. "
            "OpenSSL ne le signalerait qu'au premier handshake, par une erreur "
            "illisible."
        )

    expiration = cert.not_valid_after_utc
    info = InfoCertificat(
        sujet=_nom_commun(cert.subject),
        emetteur=_nom_commun(cert.issuer),
        expire_le=expiration,
        jours_restants=(expiration - datetime.now(UTC)).days,
        auto_signe=cert.issuer == cert.subject,
    )

    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info.noms = list(extension.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        info.avertissements.append(
            "Le certificat n'a pas d'extension SubjectAlternativeName : les clients "
            "modernes le refuseront, le nom commun seul ne suffit plus."
        )

    # --- validité dans le temps -------------------------------------------
    if cert.not_valid_before_utc > datetime.now(UTC):
        raise MaterielTlsError(
            f"Le certificat n'est pas encore valide (début : "
            f"{cert.not_valid_before_utc:%Y-%m-%d}). Vérifiez l'horloge de la machine."
        )
    jours = (expiration - datetime.now(UTC)).days
    if jours < 0:
        raise MaterielTlsError(
            f"Le certificat a expiré il y a {abs(jours)} jour(s), le "
            f"{expiration:%Y-%m-%d}. Les clients refuseront la connexion : "
            "démarrer servirait un service que personne ne peut joindre."
        )
    if jours < SEUIL_EXPIRATION_URGENT:
        info.avertissements.append(
            f"Le certificat expire dans {jours} jour(s) — renouvellement URGENT."
        )
    elif jours < SEUIL_EXPIRATION_ALERTE:
        info.avertissements.append(
            f"Le certificat expire dans {jours} jour(s) : planifiez le renouvellement."
        )

    if info.auto_signe:
        info.avertissements.append(
            "Certificat auto-signé : chaque client devra l'approuver explicitement. "
            "Acceptable en interne, à remplacer par un certificat d'autorité pour "
            "un usage partagé durable."
        )

    return info


def fabrique_contexte() -> Any:
    """Rend la fabrique de contexte SSL attendue par uvicorn.

    uvicorn charge lui-même le couple certificat/clé, à partir de sa propre
    configuration, et passe une fabrique par défaut. On l'appelle, puis on
    durcit la seule chose qu'elle laisse au hasard : la version minimale.
    Reconstruire le contexte de zéro ferait perdre les autres réglages
    qu'uvicorn applique.
    """

    def fabrique(_config: Any, defaut: Any) -> ssl.SSLContext:
        contexte: ssl.SSLContext = defaut()
        contexte.minimum_version = VERSION_MINIMALE
        return contexte

    return fabrique

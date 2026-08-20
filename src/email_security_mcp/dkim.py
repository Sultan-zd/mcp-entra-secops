"""Analyse DKIM : les clés publiées, leur taille et leur état.

DKIM se vérifie par sélecteur : il n'existe aucun moyen d'énumérer les
sélecteurs d'un domaine depuis le DNS. Le serveur essaie donc une liste de
sélecteurs courants, et accepte qu'on lui en fournisse d'autres.
"""

from __future__ import annotations

import base64
import logging

from .dns_client import DnsResolver
from .models import DkimKey, DkimReport, Severity

logger = logging.getLogger(__name__)

#: Sélecteurs utilisés par les principaux prestataires. Aucun standard ne les
#: impose : cette liste est empirique, et c'est pourquoi l'outil accepte des
#: sélecteurs supplémentaires en paramètre.
SELECTEURS_COURANTS = (
    "selector1",  # Microsoft 365
    "selector2",  # Microsoft 365
    "google",  # Google Workspace
    "default",
    "dkim",
    "mail",
    "k1",  # Mailchimp
    "s1",
    "s2",
    "smtp",
)

#: En deçà, la clé est considérée comme trop courte par les recommandations
#: actuelles. 1024 bits reste très répandu, mais n'est plus recommandé.
TAILLE_MINIMALE = 2048


def _rsa_key_bits(public_key_b64: str) -> int | None:
    """Déduit la taille d'une clé RSA de sa représentation DER.

    On parcourt le minimum d'ASN.1 nécessaire pour atteindre le modulus, plutôt
    que d'estimer d'après la longueur du base64 : l'estimation se trompe sur
    les clés à exposant inhabituel, et une taille de clé annoncée à tort
    fausserait un constat de sécurité.
    """
    try:
        der = base64.b64decode(public_key_b64 + "=" * (-len(public_key_b64) % 4))
    except Exception:
        return None

    def lire_longueur(data: bytes, i: int) -> tuple[int, int]:
        """Retourne (longueur, index suivant) pour un champ ASN.1."""
        premier = data[i]
        if premier < 0x80:
            return premier, i + 1
        octets = premier & 0x7F
        return int.from_bytes(data[i + 1 : i + 1 + octets], "big"), i + 1 + octets

    try:
        i = 0
        if der[i] != 0x30:  # SEQUENCE : SubjectPublicKeyInfo
            return None
        _, i = lire_longueur(der, i + 1)

        if der[i] == 0x30:  # AlgorithmIdentifier, que l'on saute
            longueur, suivant = lire_longueur(der, i + 1)
            i = suivant + longueur

        if der[i] != 0x03:  # BIT STRING enveloppant la clé RSA
            return None
        _, i = lire_longueur(der, i + 1)
        i += 1  # octet de bits inutilisés

        if der[i] != 0x30:  # SEQUENCE : RSAPublicKey
            return None
        _, i = lire_longueur(der, i + 1)

        if der[i] != 0x02:  # INTEGER : modulus
            return None
        longueur, i = lire_longueur(der, i + 1)

        # Un octet de tête nul sert uniquement à marquer le signe positif.
        if der[i] == 0x00:
            longueur -= 1
        return longueur * 8
    except (IndexError, ValueError):
        return None


def _parse_dkim_txt(txt: str) -> dict[str, str]:
    """Décompose un enregistrement DKIM en paires clé/valeur."""
    champs: dict[str, str] = {}
    for partie in txt.split(";"):
        if "=" not in partie:
            continue
        cle, _, valeur = partie.partition("=")
        champs[cle.strip().lower()] = valeur.strip()
    return champs


async def analyse_dkim(
    domain: str, resolver: DnsResolver, selectors: list[str] | None = None
) -> DkimReport:
    """Interroge les sélecteurs DKIM d'un domaine et évalue les clés trouvées."""
    domaine = domain.strip().lower().rstrip(".")
    a_tester = list(selectors) if selectors else list(SELECTEURS_COURANTS)

    cles: list[DkimKey] = []
    for selecteur in a_tester:
        txt = await resolver.txt(f"{selecteur}._domainkey.{domaine}")
        brut = next((t for t in txt if "p=" in t or t.lower().startswith("v=dkim1")), None)

        if brut is None:
            cles.append(DkimKey(selector=selecteur, found=False))
            continue

        champs = _parse_dkim_txt(brut)
        cle_publique = champs.get("p", "")
        type_cle = champs.get("k", "rsa").lower()
        constats: list[str] = []

        revoquee = cle_publique == ""
        if revoquee:
            constats.append(
                "Clé révoquée (p= vide) : toute signature émise avec ce sélecteur "
                "échouera à la vérification."
            )

        bits = _rsa_key_bits(cle_publique) if cle_publique and type_cle == "rsa" else None
        if bits is not None and bits < TAILLE_MINIMALE:
            constats.append(
                f"Clé RSA de {bits} bits : en deçà des {TAILLE_MINIMALE} bits recommandés. "
                "Régénérer la paire de clés auprès du prestataire d'envoi."
            )

        en_test = champs.get("t", "").lower().startswith("y")
        if en_test:
            constats.append(
                "Indicateur t=y : les destinataires sont invités à IGNORER les échecs de "
                "vérification. À retirer une fois le déploiement terminé, sinon DKIM "
                "n'apporte aucune protection réelle."
            )

        cles.append(
            DkimKey(
                selector=selecteur,
                found=True,
                key_type=type_cle,
                key_bits=bits,
                revoked=revoquee,
                testing=en_test,
                findings=constats,
            )
        )

    trouvees = [c for c in cles if c.found and not c.revoked]
    constats_globaux: list[str] = []

    if not trouvees:
        constats_globaux.append(
            "Aucune clé DKIM active trouvée parmi les sélecteurs testés "
            f"({', '.join(a_tester[:5])}…). Soit le domaine ne signe pas ses messages, "
            "soit il utilise un sélecteur non standard : le préciser explicitement."
        )
        gravite: Severity = "high"
    else:
        noms = ", ".join(c.selector for c in trouvees)
        constats_globaux.append(f"{len(trouvees)} sélecteur(s) actif(s) : {noms}.")
        faibles = [c for c in trouvees if c.key_bits and c.key_bits < TAILLE_MINIMALE]
        # Nom distinct de la variable `en_test` de la boucle ci-dessus : la
        # reutiliser melangeait un booleen et une liste dans la meme portee.
        cles_en_test = [c for c in trouvees if c.testing]
        gravite = "medium" if (faibles or cles_en_test) else "low"

    for cle in cles:
        constats_globaux.extend(f"[{cle.selector}] {c}" for c in cle.findings)

    return DkimReport(
        domain=domaine,
        keys=cles,
        keys_found=len(trouvees),
        findings=constats_globaux,
        severity=gravite,
    )

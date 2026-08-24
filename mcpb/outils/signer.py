"""Signe l'extension `.mcpb`, et publie son empreinte.

    python mcpb/outils/signer.py

**Ce que la signature apporte, et ce qu'elle n'apporte pas.** Le certificat est
auto-signé : aucune autorité ne se porte garante de l'identité du signataire, et
l'hôte affichera toujours un avertissement à l'installation. Ce que la signature
donne, c'est une **enveloppe d'intégrité** — le paquet ne peut plus être modifié
en chemin sans invalider le bloc — et une **identité stable** : une équipe SOC
qui a vérifié l'empreinte une fois peut refuser toute version qui ne la porte
pas.

C'est ce qui distingue « non signé » de « signé par une clé dont vous connaissez
l'empreinte ». Sans autorité, la seconde vaut ce que vaut la publication de
l'empreinte — d'où la sortie de ce script.

**Sur `mcpb verify`.** Il répondra « Extension is not signed » quelle que soit la
signature. Ce n'est pas un défaut du paquet : la bibliothèque qu'utilise la CLI
(`node-forge`) lève « PKCS#7 signature verification not yet implemented », et la
CLI traite toute exception comme une absence de signature. Ce script vérifie
donc le bloc lui-même, en lisant le PKCS#7 produit.

La clé privée n'est **jamais** versionnée : `mcpb/signature/` est exclu de git.
La perdre signifie changer d'empreinte, donc prévenir les destinataires.
"""

from __future__ import annotations

import datetime as dt
import shutil
import struct
import subprocess
import sys
from pathlib import Path

MCPB = Path(__file__).resolve().parent.parent
RACINE = MCPB.parent
SIGNATURE = MCPB / "signature"
CERT = SIGNATURE / "cert.pem"
CLE = SIGNATURE / "cle.pem"

#: Durée de validité du certificat de signature. Dix ans : le renouveler
#: change l'empreinte, donc oblige à prévenir tous les destinataires.
ANNEES = 10

ENTETE = b"MCPB_SIG_V1"
PIED = b"MCPB_SIG_END"


def _generer() -> None:
    """Crée le couple de signature, s'il n'existe pas déjà."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    SIGNATURE.mkdir(exist_ok=True)
    cle = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    nom = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "ARGUS SecOps Extension Signing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Teknologiia"),
        ]
    )
    maintenant = dt.datetime.now(dt.UTC)
    certificat = (
        x509.CertificateBuilder()
        .subject_name(nom)
        .issuer_name(nom)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - dt.timedelta(days=1))
        .not_valid_after(maintenant + dt.timedelta(days=365 * ANNEES))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # Un certificat de signature de code ne doit pas pouvoir servir à
        # chiffrer une session TLS : le déclarer restreint son usage.
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .sign(cle, hashes.SHA256())
    )

    CERT.write_bytes(certificat.public_bytes(serialization.Encoding.PEM))
    CLE.write_bytes(
        cle.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    print(f"  ✓ couple de signature créé dans {SIGNATURE.relative_to(RACINE)}")
    print("    La clé privée n'est pas versionnée. Sauvegardez-la : la perdre")
    print("    oblige à changer d'empreinte, donc à prévenir les destinataires.")


def empreinte_certificat() -> str:
    """L'empreinte SHA-256 du certificat, à publier."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    certificat = x509.load_pem_x509_certificate(CERT.read_bytes())
    return certificat.fingerprint(hashes.SHA256()).hex(":").upper()


def _controler_bloc(archive: Path) -> bool:
    """Relit le bloc de signature écrit dans l'archive.

    `mcpb verify` étant inopérant, c'est ce contrôle qui atteste que la
    signature est présente et bien formée.
    """
    brut = archive.read_bytes()
    if not brut.endswith(PIED):
        print("  ✗ pas de pied de signature en fin de fichier")
        return False

    debut = brut.rfind(ENTETE)
    if debut == -1:
        print("  ✗ en-tête de signature introuvable")
        return False

    longueur = struct.unpack("<I", brut[debut + len(ENTETE) : debut + len(ENTETE) + 4])[0]
    pkcs7 = brut[debut + len(ENTETE) + 4 : debut + len(ENTETE) + 4 + longueur]
    attendu = debut + len(ENTETE) + 4 + longueur + len(PIED)
    if attendu != len(brut):
        print(f"  ✗ longueur incohérente : {attendu} annoncé, {len(brut)} réel")
        return False

    try:
        import warnings

        from cryptography.hazmat.primitives.serialization import pkcs7 as p7

        # La CLI écrit les attributs authentifiés dans un ordre de SET non
        # canonique : la lecture bascule en BER et prévient. Le bloc reste
        # exploitable, et l'avertissement n'apprend rien à qui signe.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            certificats = p7.load_der_pkcs7_certificates(pkcs7)
    except Exception as exc:
        print(f"  ✗ bloc PKCS#7 illisible : {exc}")
        return False

    if not certificats:
        print("  ✗ le bloc ne contient aucun certificat")
        return False

    from cryptography import x509

    sujet = certificats[0].subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    print(f"  ✓ bloc PKCS#7 valide, {longueur} octets")
    print(f"  ✓ signé par : {sujet[0].value if sujet else '(sans nom commun)'}")
    return True


def main() -> int:
    sys.path.insert(0, str(RACINE / "src"))
    from argus_net import forcer_utf8

    forcer_utf8()

    archives = sorted((MCPB / "dist").glob("*.mcpb"))
    if not archives:
        print()
        print("  ✗ aucun paquet dans mcpb/dist — lancez d'abord :")
        print("      python mcpb/outils/construire.py")
        print()
        return 1
    archive = archives[-1]

    print()
    print("Certificat de signature")
    print("─" * 23)
    if CERT.exists() and CLE.exists():
        print(f"  · réutilisé depuis {SIGNATURE.relative_to(RACINE)}")
    else:
        _generer()

    npx = shutil.which("npx")
    if npx is None:
        print("  ✗ npx introuvable — npm install @anthropic-ai/mcpb")
        return 1

    print()
    print("Signature")
    print("─" * 9)
    avant = archive.stat().st_size
    resultat = subprocess.run(
        [npx, "--no-install", "@anthropic-ai/mcpb", "sign",
         "--cert", str(CERT), "--key", str(CLE), str(archive)],
        cwd=RACINE, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if resultat.returncode != 0:
        print("  ✗ la signature a échoué :")
        for ligne in (resultat.stdout + resultat.stderr).splitlines()[-10:]:
            print(f"      {ligne}")
        return 1

    apres = archive.stat().st_size
    print(f"  ✓ {archive.name} : {avant} → {apres} octets (+{apres - avant})")

    if not _controler_bloc(archive):
        return 1

    print()
    print("Empreinte à publier")
    print("─" * 19)
    print(f"  {empreinte_certificat()}")
    print()
    print("  À communiquer aux destinataires par un canal distinct du paquet.")
    print("  `mcpb verify` répondra « not signed » : sa bibliothèque n'implémente")
    print("  pas la vérification PKCS#7. Ce n'est pas un défaut du paquet.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

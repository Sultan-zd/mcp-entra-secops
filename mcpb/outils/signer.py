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

**Sur la corruption du ZIP par `mcpb sign` lui-même.** `signMcpbFile` (dans
`sign.js`) ajoute le bloc de signature par une simple concaténation d'octets —
`Buffer.concat([mcpbContent, signatureBlock])` — sans jamais mettre à jour le
champ de longueur de commentaire de l'enregistrement de fin d'archive ZIP
(EOCD). Le fichier obtenu déclare un commentaire de longueur 0 alors qu'il
porte réellement ~2,2 Ko de données après cette déclaration.

Python (`zipfile`) tolère cet écart : il cherche la signature EOCD en
remontant depuis la fin du fichier et ne vérifie pas que le commentaire déclaré
correspond aux octets réels. **L'installateur de Claude Desktop, lui, est
strict** et refuse le fichier avec « Invalid comment length. Expected: N.
Found: 0. » — c'est le défaut constaté à l'installation réelle, et
`construire.py` ne pouvait pas le voir : il vérifie l'archive avant signature.

Ce script corrige donc le champ après l'appel à `mcpb sign`, par les deux
octets nécessaires. Le bloc de signature reste identique — la CLI le retrouve
en cherchant ses marqueurs `MCPB_SIG_V1` / `MCPB_SIG_END` directement dans les
octets, sans jamais lire ce champ elle-même.

La clé privée n'est **jamais** versionnée : `mcpb/signature/` est exclu de git.
La perdre signifie changer d'empreinte, donc prévenir les destinataires.
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import struct
import subprocess
import sys
import zipfile
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


def _corriger_eocd(archive: Path) -> bool:
    """Répare le champ de longueur de commentaire que `mcpb sign` laisse à 0.

    Sans cette correction, le fichier s'installe silencieusement nulle part
    dans nos propres contrôles — `zipfile` et `unzip -t` l'acceptent tel
    quel — et échoue seulement chez le destinataire, dans Claude Desktop, avec
    « Invalid comment length ». C'est exactement le défaut qui s'est produit :
    `construire.py` vérifie l'archive avant signature, jamais après.
    """
    brut = bytearray(archive.read_bytes())
    debut_eocd = brut.rfind(b"PK\x05\x06")
    if debut_eocd == -1:
        print("  ✗ enregistrement de fin d'archive (EOCD) introuvable")
        return False

    longueur_reelle = len(brut) - (debut_eocd + 22)
    declaree = struct.unpack("<H", brut[debut_eocd + 20 : debut_eocd + 22])[0]

    if declaree == longueur_reelle:
        return True

    if longueur_reelle > 0xFFFF:
        # Le champ ZIP ne code la longueur du commentaire que sur 2 octets.
        print(f"  ✗ bloc de signature trop volumineux ({longueur_reelle} octets, "
              "maximum 65535 pour un commentaire ZIP)")
        return False

    struct.pack_into("<H", brut, debut_eocd + 20, longueur_reelle)
    archive.write_bytes(bytes(brut))
    print(
        f"  ✓ commentaire ZIP corrigé : {declaree} → {longueur_reelle} octets "
        "déclarés (Claude Desktop valide ce champ strictement)"
    )
    return True


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
    from cryptography.hazmat.primitives import hashes

    sujet = certificats[0].subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if sujet:
        valeur = sujet[0].value
        # `.value` peut être des octets bruts selon l'OID ; l'imprimer sans
        # conversion afficherait « b'ARGUS SecOps...' » au lieu du nom.
        nom = valeur.decode("utf-8", errors="replace") if isinstance(valeur, bytes) else valeur
    else:
        nom = "(sans nom commun)"
    print(f"  ✓ bloc PKCS#7 valide, {longueur} octets")
    print(f"  ✓ signé par : {nom}")
    # L'empreinte du certificat TROUVÉ DANS L'ARCHIVE — pas celle du fichier
    # local. C'est la seule que puisse calculer un destinataire, qui n'a que
    # le paquet ; publier l'autre serait lui demander de nous croire sur
    # parole.
    print("  ✓ empreinte du certificat porté par l'archive :")
    print(f"      {certificats[0].fingerprint(hashes.SHA256()).hex(':').upper()}")
    return True


def _verifier_zip_strict(archive: Path) -> bool:
    """Rejoue exactement le contrôle qui a fait échouer l'installation réelle.

    `zipfile.ZipFile()` seul ne suffit pas comme garde-fou : il a laissé
    passer le fichier corrompu qui a ensuite échoué dans Claude Desktop. Ce
    contrôle relit l'EOCD à la main, comme le fait l'installateur strict.
    """
    brut = archive.read_bytes()
    debut_eocd = brut.rfind(b"PK\x05\x06")
    if debut_eocd == -1:
        print("  ✗ enregistrement de fin d'archive (EOCD) introuvable")
        return False

    declaree = struct.unpack("<H", brut[debut_eocd + 20 : debut_eocd + 22])[0]
    reelle = len(brut) - (debut_eocd + 22)
    if declaree != reelle:
        print(f"  ✗ commentaire ZIP incohérent : déclaré {declaree}, réel {reelle}")
        return False

    try:
        with zipfile.ZipFile(archive) as z:
            defaut = z.testzip()
    except zipfile.BadZipFile as exc:
        print(f"  ✗ archive ZIP invalide : {exc}")
        return False
    if defaut is not None:
        print(f"  ✗ entrée corrompue dans l'archive : {defaut}")
        return False

    print(f"  ✓ ZIP valide pour un lecteur strict : commentaire de {reelle} octets, "
          "cohérent avec l'EOCD")
    return True


def verifier(chemin: Path) -> int:
    """Le contrôle côté DESTINATAIRE : n'exige aucune clé privée.

    Un destinataire n'a que le paquet. Publier une empreinte ne lui sert à
    rien s'il n'a aucun moyen de calculer celle de ce qu'il a reçu — c'est
    ce que fait ce mode.

    Il ne prouve pas *qui* a signé : le certificat est auto-signé, aucune
    autorité ne s'en porte garante. Il établit que le paquet porte une
    signature bien formée, et **par quel certificat** — à comparer, à la main,
    avec l'empreinte publiée par un canal distinct.
    """
    if not chemin.exists():
        print(f"\n  ✗ fichier introuvable : {chemin}\n")
        return 1

    print()
    print(f"Vérification de {chemin.name}")
    print("─" * (16 + len(chemin.name)))

    if b"MCPB_SIG_V1" not in chemin.read_bytes():
        print("  ✗ ce paquet ne porte AUCUNE signature.")
        print("    Un paquet non signé peut avoir été modifié en chemin.")
        print()
        return 1

    if not _controler_bloc(chemin):
        print()
        return 1
    if not _verifier_zip_strict(chemin):
        print()
        return 1

    print()
    print("  Comparez l'empreinte ci-dessus avec celle publiée par l'émetteur,")
    print("  reçue par un canal DISTINCT du paquet. Si elles diffèrent, ou si")
    print("  vous n'avez pas d'empreinte de référence, n'installez pas.")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    # `argv` explicite plutot que sys.argv : sous pytest, sys.argv porte
    # les arguments de pytest, qu'argparse rejetterait.
    sys.path.insert(0, str(RACINE / "src"))
    from argus_net import forcer_utf8

    forcer_utf8()

    analyseur = argparse.ArgumentParser(
        prog="signer.py",
        description="Signe l'extension .mcpb, ou vérifie un paquet reçu.",
    )
    analyseur.add_argument(
        "--verifier",
        metavar="PAQUET",
        help="Ne signe rien : contrôle la signature d'un .mcpb reçu et affiche "
        "l'empreinte du certificat qui le porte. N'exige aucune clé privée.",
    )
    arguments = analyseur.parse_args(argv)

    if arguments.verifier:
        return verifier(Path(arguments.verifier))

    archives = sorted((MCPB / "dist").glob("*.mcpb"))
    if not archives:
        print()
        print("  ✗ aucun paquet dans mcpb/dist — lancez d'abord :")
        print("      python mcpb/outils/construire.py")
        print()
        return 1
    archive = archives[-1]

    # `mcpb sign` relit le fichier tel quel et empile un bloc dessus : signer
    # une archive déjà signée produit deux blocs superposés, sans erreur ni
    # avertissement de la CLI. Reconstruire avant de signer est la seule
    # garantie ; ce contrôle transforme l'oubli en échec net plutôt qu'en
    # paquet doublement signé livré sans que personne ne s'en aperçoive.
    if b"MCPB_SIG_V1" in archive.read_bytes():
        print()
        print(f"  ✗ {archive.name} porte déjà une signature.")
        print("    La signer à nouveau empilerait un second bloc par-dessus.")
        print("    Reconstruisez d'abord :")
        print("      python mcpb/outils/construire.py")
        print()
        return 1

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

    if not _corriger_eocd(archive):
        return 1
    if not _controler_bloc(archive):
        return 1
    if not _verifier_zip_strict(archive):
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

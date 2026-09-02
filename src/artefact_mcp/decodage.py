"""Décodage en cascade d'une charge obfusquée, hors ligne.

**Le manque que ce module comble.** `extract_iocs` trouve les indicateurs d'un
texte lisible. Devant `powershell -enc SQBFAFgA...`, il ne voit rien — parce
qu'il n'y a rien à voir tant que la couche n'est pas retirée.

L'obfuscation réelle empile : base64 d'un UTF-16LE, parfois compressé en gzip,
parfois encodé une seconde fois. Décoder à la main demande de deviner l'ordre.
Ce module essaie les transformations connues, s'arrête quand le résultat
devient du texte plausible, et **dit quelles couches il a traversées** — le
chemin importe autant que le résultat, parce qu'il caractérise l'outillage de
l'attaquant.

**Ce qu'il ne fait pas.** Il n'exécute rien, ne désassemble rien, n'interprète
aucun script. Décoder n'est pas exécuter, et c'est précisément la propriété qui
permet de le faire sans bac à sable.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field

#: Au-delà, on considère qu'on tourne en rond : les cascades réelles dépassent
#: rarement trois ou quatre couches.
PROFONDEUR_MAX = 8

#: En deçà, un résultat n'a pas assez de matière pour être jugé lisible.
LONGUEUR_MINIMALE = 8

#: Proportion de caractères imprimables au-delà de laquelle un résultat est
#: considéré comme du texte.
SEUIL_LISIBLE = 0.90

_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_HEX = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")

#: Signatures de fichiers, reconnues sur les premiers octets. Un décodage qui
#: aboutit à un exécutable est un résultat en soi.
#:
#: `gzip` n'y figure pas : c'est une couche que ce module sait retirer, pas un
#: point d'arrivée. L'y mettre arrêtait la cascade juste avant la
#: décompression — le défaut a été constaté sur une charge « gzip puis
#: base64 », rendue en hexadécimal alors que son contenu était lisible.
SIGNATURES = {
    b"MZ": "exécutable Windows (PE)",
    b"\x7fELF": "exécutable Linux (ELF)",
    b"PK\x03\x04": "archive ZIP (ou document Office, JAR, APK)",
    b"%PDF": "document PDF",
    b"\xd0\xcf\x11\xe0": "document Office ancien (OLE2)",
    b"Rar!": "archive RAR",
    b"\xff\xd8\xff": "image JPEG",
    b"\x89PNG": "image PNG",
}

#: Signatures de ce que ce module sait encore décompresser : elles ne mettent
#: pas fin à la cascade.
POURSUIVABLES = (b"\x1f\x8b",)


@dataclass
class Couche:
    """Une transformation appliquée avec succès."""

    encoding: str
    detail: str = ""


@dataclass
class Decodage:
    """Le résultat d'une cascade de décodage."""

    decoded: str = ""
    layers: list[Couche] = field(default_factory=list)
    file_type: str | None = None
    is_text: bool = True
    truncated: bool = False
    findings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _lisible(brut: bytes) -> tuple[bool, str]:
    """Le résultat est-il du texte exploitable ?

    Deux encodages sont tentés, dans cet ordre : UTF-16LE d'abord, parce que
    c'est ce que produit `powershell -EncodedCommand` et que sa marque — un
    octet nul sur deux — est reconnaissable.
    """
    if len(brut) >= 4 and brut[1::2].count(0) > len(brut) // 4:
        try:
            texte = brut.decode("utf-16-le")
            imprimables = sum(c.isprintable() or c in "\r\n\t" for c in texte)
            if texte and imprimables / len(texte) >= SEUIL_LISIBLE:
                return True, texte
        except UnicodeDecodeError:
            pass

    try:
        texte = brut.decode("utf-8")
    except UnicodeDecodeError:
        return False, ""

    if not texte:
        return False, ""
    imprimables = sum(c.isprintable() or c in "\r\n\t" for c in texte)
    return (imprimables / len(texte)) >= SEUIL_LISIBLE, texte


def _signature(brut: bytes) -> str | None:
    for magie, libelle in SIGNATURES.items():
        if brut.startswith(magie):
            return libelle
    return None


def _essayer_base64(texte: str) -> bytes | None:
    compact = "".join(texte.split())
    if len(compact) < LONGUEUR_MINIMALE:
        return None
    try:
        if _BASE64.match(compact):
            return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
        if _BASE64URL.match(compact):
            return base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))
    except (binascii.Error, ValueError):
        return None
    return None


def _essayer_hex(texte: str) -> bytes | None:
    compact = "".join(texte.split()).replace("\\x", "").replace("0x", "")
    if len(compact) < LONGUEUR_MINIMALE or len(compact) % 2 or not _HEX.match(compact):
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None


def _essayer_url(texte: str) -> bytes | None:
    if "%" not in texte:
        return None
    decode = urllib.parse.unquote_plus(texte)
    return decode.encode("utf-8") if decode != texte else None


def _essayer_gzip(brut: bytes) -> bytes | None:
    if brut.startswith(b"\x1f\x8b"):
        try:
            return gzip.decompress(brut)
        except (OSError, EOFError, zlib.error):
            return None
    return None


def _essayer_deflate(brut: bytes) -> bytes | None:
    """Flux zlib brut : ce que produit `IO.Compression.DeflateStream`."""
    if len(brut) < 2 or brut[0] != 0x78:
        return None
    try:
        return zlib.decompress(brut)
    except zlib.error:
        try:
            return zlib.decompress(brut, -zlib.MAX_WBITS)
        except zlib.error:
            return None


def decoder(charge: str, *, profondeur_max: int = PROFONDEUR_MAX) -> Decodage:
    """Retire les couches d'encodage tant qu'il en reste.

    L'arrêt se fait sur un résultat lisible, pas sur un nombre de tours : une
    charge encodée trois fois doit être décodée trois fois, et une charge en
    clair ne doit pas être « décodée » du tout.
    """
    resultat = Decodage()
    courant = (charge or "").strip()
    if not courant:
        resultat.findings.append("Aucune charge fournie.")
        return resultat

    resultat.decoded = courant
    octets = courant.encode("utf-8", errors="replace")

    for _ in range(profondeur_max):
        lisible_avant, texte_avant = _lisible(octets)

        # L'ordre compte deux fois.
        #
        # Les transformations sur octets passent en premier : une charge déjà
        # décompressée ne ressemble plus à du base64.
        #
        # Puis l'hexadécimal AVANT le base64, parce que l'alphabet hexadécimal
        # est un sous-ensemble de celui du base64 : `cmd.exe /c whoami` encodé
        # en hexadécimal était lu comme du base64 et rendu en charabia.
        candidats: list[tuple[bytes | None, str]] = [
            (_essayer_gzip(octets), "gzip"),
            (_essayer_deflate(octets), "deflate"),
        ]
        if lisible_avant:
            candidats += [
                (_essayer_hex(texte_avant), "hexadécimal"),
                (_essayer_base64(texte_avant), "base64"),
                (_essayer_url(texte_avant), "url"),
            ]

        retenu: bytes | None = None
        etiquette = ""
        for essai, nom in candidats:
            if essai is None or essai == octets or not essai:
                continue
            # Un décodage n'est retenu que s'il AMÉLIORE la charge. Sans ce
            # contrôle, un texte en clair dont l'alphabet ressemble à du
            # base64 était « décodé » en octets aléatoires : `charge interne
            # secrete` traversait ainsi trois couches imaginaires.
            lisible_apres, _ = _lisible(essai)
            if lisible_apres or _signature(essai) or essai.startswith(POURSUIVABLES):
                retenu, etiquette = essai, nom
                break

        if retenu is None:
            break

        octets = retenu
        resultat.layers.append(Couche(encoding=etiquette))

        signature = _signature(octets)
        if signature:
            resultat.file_type = signature
            break

    # --- rendu final -------------------------------------------------------
    lisible, texte = _lisible(octets)
    resultat.is_text = lisible
    if lisible:
        if len(texte) > 20000:
            texte, resultat.truncated = texte[:20000], True
        resultat.decoded = texte
    else:
        resultat.decoded = octets[:2000].hex()
        resultat.notes.append(
            "Le résultat n'est pas du texte : rendu en hexadécimal. "
            + (f"Il commence par une signature de {resultat.file_type}." if resultat.file_type
               else "Aucune signature de fichier reconnue.")
        )

    if not resultat.layers:
        resultat.notes.append(
            "Aucune couche d'encodage reconnue : la charge est déjà en clair, ou "
            "utilise un encodage que ce module ne connaît pas."
        )
    else:
        resultat.notes.append(
            "Couches retirées, de l'extérieur vers l'intérieur : "
            + " → ".join(c.encoding for c in resultat.layers)
            + "."
        )

    if resultat.file_type:
        resultat.findings.append(
            f"Le décodage aboutit à un {resultat.file_type}. Ce n'est pas du "
            "texte à lire mais un fichier : ne l'exécutez pas, son empreinte "
            "suffit à l'identifier."
        )
    if len(resultat.layers) >= 3:
        resultat.findings.append(
            f"{len(resultat.layers)} couches empilées : l'empilement lui-même est "
            "un signal, une charge légitime en compte rarement plus d'une."
        )

    return resultat

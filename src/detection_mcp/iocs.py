"""Extraction d'indicateurs depuis un texte quelconque.

Un analyste reçoit un rapport de menace, un courriel signalé, un extrait de
journal — et doit en sortir les indicateurs exploitables. Fait à la main, c'est
long et on en oublie ; fait avec une expression régulière naïve, on récolte
surtout du bruit.

**Ce qui rend l'exercice difficile**, et ce que ce module traite :

* Les indicateurs circulent **désamorcés** — `hxxp://`, `1.2.3[.]4`,
  `exemple(.)com` — précisément pour qu'on ne clique pas dessus. Une extraction
  qui les ignore rate l'essentiel d'un rapport de menace.
* Un numéro de version ressemble à une adresse IP. `1.2.3.4` peut être une
  adresse, `2.16.840.1` non. Sans filtrage, chaque rapport rend des dizaines de
  faux indicateurs.
* Les adresses privées et les domaines d'exemple n'ont rien à faire dans une
  liste d'indicateurs à bloquer.

Aucun accès réseau : tout est local.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

#: Domaines de premier niveau réservés par la norme à la documentation et aux
#: essais (RFC 2606, RFC 6761). Les bloquer n'aurait aucun sens.
TLD_RESERVES = frozenset({"test", "example", "invalid", "localhost", "local"})

#: Domaines que les rapports citent en exemple, ou qui appartiennent à
#: l'infrastructure de l'analyse elle-même.
DOMAINES_BRUIT = frozenset(
    {
        "example.com", "example.org", "example.net", "domain.com",
        "yourdomain.com", "company.com", "contoso.com", "fabrikam.com",
        "schemas.microsoft.com", "www.w3.org", "schemas.xmlsoap.org",
    }
)

#: Extensions de fichier fréquentes : `rapport.doc` n'est pas un domaine.
EXTENSIONS = frozenset(
    {
        "exe", "dll", "doc", "docx", "xls", "xlsx", "pdf", "zip", "rar", "txt",
        "log", "json", "xml", "html", "htm", "js", "py", "ps1", "bat", "sh",
        "png", "jpg", "jpeg", "gif", "csv", "msi", "iso", "tmp", "dat", "bin",
    }
)

#: Longueurs d'empreintes reconnues, et l'algorithme correspondant.
LONGUEURS_EMPREINTE = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

# --------------------------------------------------------------------------
# Motifs
# --------------------------------------------------------------------------
#: Un point désamorcé sous ses formes courantes : [.] (.) {.} [dot] etc.
_POINT_DESAMORCE = re.compile(r"\s*[\[\(\{]\s*(?:\.|dot|point)\s*[\]\)\}]\s*", re.IGNORECASE)
_ARROBASE_DESAMORCEE = re.compile(r"\s*[\[\(\{]\s*(?:@|at)\s*[\]\)\}]\s*", re.IGNORECASE)
_SCHEMA_DESAMORCE = re.compile(r"\bh(?:xx|__|\*\*)p(s?)\b\s*(?:://|\[:\]//)", re.IGNORECASE)
_SCHEMA_CROCHETS = re.compile(r"\b(https?)\s*\[\s*:\s*\]\s*//", re.IGNORECASE)

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_URL = re.compile(r"\bhttps?://[^\s<>\"'`\]\)]+", re.IGNORECASE)
_DOMAINE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
_COURRIEL = re.compile(r"\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b")
_EMPREINTE = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


@dataclass
class Indicateurs:
    """Ce qu'un texte contenait, trié et dédoublonné."""

    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    hashes: list[dict[str, str]] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    excluded: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            len(self.ipv4) + len(self.ipv6) + len(self.domains)
            + len(self.urls) + len(self.emails) + len(self.hashes) + len(self.cves)
        )


def refang(texte: str) -> str:
    """Remet un texte désamorcé sous sa forme réelle.

    Sans cette étape, un rapport de menace — où **tout** est désamorcé pour
    éviter les clics accidentels — ne rendrait presque aucun indicateur.
    """
    propre = _SCHEMA_CROCHETS.sub(r"\1://", texte)
    propre = _SCHEMA_DESAMORCE.sub(lambda m: f"http{m.group(1)}://", propre)
    propre = _POINT_DESAMORCE.sub(".", propre)
    propre = _ARROBASE_DESAMORCEE.sub("@", propre)
    return propre


def defang(valeur: str) -> str:
    """Désamorce un indicateur pour qu'il soit collable sans risque.

    Un indicateur cliquable dans un ticket ou un courriel finit par être
    cliqué. C'est la raison d'être de cette convention.
    """
    # La convention remplace les deux « t » : http -> hxxp, https -> hxxps.
    propre = re.sub(
        r"^(ht)tp(s?)://",
        lambda m: f"hxxp{m.group(2)}://",
        valeur,
        flags=re.IGNORECASE,
    )
    propre = propre.replace(".", "[.]")
    return propre.replace("@", "[@]")


def _ip_publique(valeur: str) -> tuple[bool, str | None]:
    """L'adresse est-elle exploitable comme indicateur ?

    Une adresse privée, de bouclage ou réservée n'a rien à faire dans une liste
    à bloquer — et l'envoyer à un service de réputation révélerait la topologie
    interne.
    """
    try:
        adresse = ipaddress.ip_address(valeur)
    except ValueError:
        return False, "n'est pas une adresse valide"

    # L'ordre compte : `ipaddress` marque aussi 127.0.0.1 et 169.254.0.0/16
    # comme privées. Tester `is_private` en premier masquerait le motif précis,
    # et l'analyste lirait « adresse privée » pour une boucle locale.
    if adresse.is_loopback:
        return False, "adresse de bouclage"
    if adresse.is_link_local:
        return False, "adresse lien-local"
    if adresse.is_multicast:
        return False, "adresse de multidiffusion"
    if adresse.is_unspecified:
        return False, "adresse non spécifiée"
    if adresse.is_private:
        return False, "adresse privée"
    if adresse.is_reserved:
        return False, "adresse réservée"
    return True, None


def _domaine_exploitable(valeur: str) -> tuple[bool, str | None]:
    """Distingue un vrai domaine d'un nom de fichier ou d'un exemple."""
    bas = valeur.lower().rstrip(".")

    if bas in DOMAINES_BRUIT:
        return False, "domaine d'exemple"

    etiquettes = bas.split(".")
    tld = etiquettes[-1]

    if tld in TLD_RESERVES:
        return False, "extension réservée à la documentation"
    if tld in EXTENSIONS:
        return False, "nom de fichier, pas un domaine"
    # Un domaine a besoin d'une extension alphabétique d'au moins deux lettres.
    if len(tld) < 2 or not tld.isalpha():
        return False, "extension invalide"
    return True, None


def extraire(texte: str, *, desamorcer_entree: bool = True) -> Indicateurs:
    """Extrait les indicateurs d'un texte, avec le motif de chaque exclusion."""
    resultat = Indicateurs()
    if not texte or not texte.strip():
        return resultat

    brut = refang(texte) if desamorcer_entree else texte
    if desamorcer_entree and brut != texte:
        resultat.notes.append(
            "Des indicateurs désamorcés ont été remis en forme avant extraction "
            "(hxxp://, [.], (@)…)."
        )

    exclus: dict[str, str] = {}

    # --- URL d'abord : elles contiennent domaines et adresses -------------
    urls = {u.rstrip(".,;:)\"'") for u in _URL.findall(brut)}
    resultat.urls = sorted(urls)

    # --- Adresses ---------------------------------------------------------
    for valeur in set(_IPV4.findall(brut)):
        ok, motif = _ip_publique(valeur)
        if ok:
            resultat.ipv4.append(valeur)
        elif motif:
            exclus[valeur] = motif
    resultat.ipv4.sort(key=lambda a: ipaddress.ip_address(a))

    for valeur in set(_IPV6.findall(brut)):
        ok, motif = _ip_publique(valeur)
        if ok:
            resultat.ipv6.append(valeur)
        elif motif:
            exclus[valeur] = motif
    resultat.ipv6.sort()

    # --- Courriels avant domaines : le domaine seul serait redondant ------
    courriels = {c.lower() for c in _COURRIEL.findall(brut)}
    resultat.emails = sorted(courriels)
    domaines_de_courriels = {c.split("@", 1)[1] for c in courriels}

    # --- Domaines ---------------------------------------------------------
    for valeur in set(_DOMAINE.findall(brut)):
        bas = valeur.lower().rstrip(".")
        if bas in domaines_de_courriels:
            continue
        ok, motif = _domaine_exploitable(bas)
        if ok:
            resultat.domains.append(bas)
        elif motif:
            exclus[bas] = motif
    resultat.domains = sorted(set(resultat.domains))

    # --- Empreintes -------------------------------------------------------
    vues: set[str] = set()
    for valeur in _EMPREINTE.findall(brut):
        bas = valeur.lower()
        algorithme = LONGUEURS_EMPREINTE.get(len(bas))
        if algorithme is None:
            # Une chaîne hexadécimale de longueur inattendue est un
            # identifiant quelconque, pas une empreinte.
            exclus[bas[:24] + "…"] = f"chaîne hexadécimale de {len(bas)} caractères"
            continue
        if bas not in vues:
            vues.add(bas)
            resultat.hashes.append({"value": bas, "algorithm": algorithme})
    resultat.hashes.sort(key=lambda h: (h["algorithm"], h["value"]))

    # --- CVE --------------------------------------------------------------
    resultat.cves = sorted({c.upper() for c in _CVE.findall(brut)})

    resultat.excluded = [
        {"value": v, "reason": m} for v, m in sorted(exclus.items())
    ]

    if resultat.excluded:
        resultat.notes.append(
            f"{len(resultat.excluded)} valeur(s) écartée(s) avec leur motif : "
            "adresses non routables, domaines d'exemple, noms de fichiers."
        )
    if not resultat.total:
        resultat.notes.append("Aucun indicateur exploitable dans ce texte.")

    return resultat

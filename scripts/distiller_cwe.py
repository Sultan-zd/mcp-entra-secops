"""Distille le catalogue CWE (MITRE) en un jeu embarquable.

Le catalogue officiel pèse 18 Mo de XML. Ce script le réduit à ce que les
outils lisent réellement, et le résultat est versionné avec le code — les
outils fonctionnent alors entièrement hors ligne, comme le corpus ATT&CK.

**Le champ qui justifie ce module à lui seul : `Mapping_Notes/Usage`.** MITRE
classe chaque CWE selon son aptitude à être assigné à une vulnérabilité
précise — `Allowed`, `Allowed-with-Review`, `Discouraged`, `Prohibited`. Un
CWE `Prohibited` est une catégorie ou une classe trop abstraite pour désigner
une faiblesse réelle ; le voir sur une CVE est un défaut de la fiche NVD elle-
même, pas seulement une information de plus. C'est le même principe que les
techniques ATT&CK révoquées : un identifiant qui existe mais ne devrait pas
être cité tel quel.

Usage :
    python scripts/distiller_cwe.py [chemin/vers/cwec.xml.zip]

Sans argument, le catalogue est téléchargé depuis mitre.org.
"""

from __future__ import annotations

import io
import json
import sys
import urllib.request
import zipfile

# Aliasé : `distiller()` a une variable locale `date` (celle publiée par
# MITRE) qui masquerait l'import.
from datetime import date as _date
from pathlib import Path
from xml.etree import ElementTree as ET

SOURCE = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

DESTINATION = Path(__file__).parent.parent / "src" / "vuln_intel_mcp" / "fixtures" / "cwe.json"

NS = {"c": "http://cwe.mitre.org/cwe-7"}

#: Une description CWE dépasse rarement 500 caractères ; au-delà, c'est du
#: contexte d'arrière-plan que l'outil n'a pas besoin de porter.
MAX_DESCRIPTION = 600
MAX_MITIGATION = 300
MAX_DETECTION = 300

#: Abstractions trop générales pour répondre à « comment tester ceci » — elles
#: restent dans le catalogue (pour la hiérarchie) mais sont signalées à l'appel.
ABSTRACTIONS_LARGES = frozenset({"Pillar", "Class"})


def _texte(element: ET.Element | None) -> str | None:
    if element is None:
        return None
    brut = "".join(element.itertext())
    propre = " ".join(brut.split())
    return propre or None


def _tronquer(texte: str | None, limite: int) -> str | None:
    if not texte:
        return None
    if len(texte) <= limite:
        return texte
    coupe = texte[:limite].rsplit(" ", 1)[0]
    return coupe + "…"


def _consequences(weakness: ET.Element) -> list[dict[str, str]]:
    """Portée et impact, dédoublonnés — la même paire revient souvent."""
    vues: set[tuple[str, str]] = set()
    resultat: list[dict[str, str]] = []
    conteneur = weakness.find("c:Common_Consequences", NS)
    if conteneur is None:
        return resultat
    for consequence in conteneur.findall("c:Consequence", NS):
        portees = [_texte(s) for s in consequence.findall("c:Scope", NS) if _texte(s)]
        impacts = [_texte(s) for s in consequence.findall("c:Impact", NS) if _texte(s)]
        for portee in portees:
            for impact in impacts:
                cle = (portee, impact)
                if cle not in vues:
                    vues.add(cle)
                    resultat.append({"scope": portee, "impact": impact})
    return resultat


def _detections(weakness: ET.Element) -> list[dict[str, str | None]]:
    conteneur = weakness.find("c:Detection_Methods", NS)
    if conteneur is None:
        return []
    resultat = []
    for methode in conteneur.findall("c:Detection_Method", NS):
        nom = _texte(methode.find("c:Method", NS))
        if not nom:
            continue
        description = _tronquer(_texte(methode.find("c:Description", NS)), MAX_DETECTION)
        resultat.append({"method": nom, "description": description})
    return resultat


def _mitigations(weakness: ET.Element, limite: int = 3) -> list[str]:
    conteneur = weakness.find("c:Potential_Mitigations", NS)
    if conteneur is None:
        return []
    resultat = []
    for mitigation in conteneur.findall("c:Mitigation", NS):
        texte = _tronquer(_texte(mitigation.find("c:Description", NS)), MAX_MITIGATION)
        if texte:
            resultat.append(texte)
        if len(resultat) >= limite:
            break
    return resultat


def _parents(weakness: ET.Element) -> list[str]:
    """Les CWE dont celui-ci est un cas particulier (`ChildOf`).

    C'est ce qui permet de remonter d'un `Variant` très précis vers la classe
    qui l'englobe — utile quand le catalogue ne détaille pas assez le cas
    exact rencontré.
    """
    conteneur = weakness.find("c:Related_Weaknesses", NS)
    if conteneur is None:
        return []
    return sorted(
        {
            f"CWE-{rel.get('CWE_ID')}"
            for rel in conteneur.findall("c:Related_Weakness", NS)
            if rel.get("Nature") == "ChildOf" and rel.get("CWE_ID")
        }
    )


def _mapping(weakness: ET.Element) -> tuple[str | None, str | None]:
    """L'aptitude de ce CWE à désigner une vulnérabilité précise, et pourquoi."""
    conteneur = weakness.find("c:Mapping_Notes", NS)
    if conteneur is None:
        return None, None
    usage = _texte(conteneur.find("c:Usage", NS))
    raison = _tronquer(_texte(conteneur.find("c:Rationale", NS)), MAX_MITIGATION)
    return usage, raison


def distiller(xml: bytes) -> dict[str, object]:
    racine = ET.fromstring(xml)
    version = racine.get("Version", "?")
    date = racine.get("Date", "?")

    faiblesses: dict[str, dict[str, object]] = {}
    for weakness in racine.findall(".//c:Weakness", NS):
        identifiant = weakness.get("ID")
        nom = weakness.get("Name")
        if not identifiant or not nom:
            continue

        usage, raison = _mapping(weakness)

        faiblesses[f"CWE-{identifiant}"] = {
            "id": f"CWE-{identifiant}",
            "name": nom,
            "abstraction": weakness.get("Abstraction"),
            "status": weakness.get("Status"),
            "description": _tronquer(_texte(weakness.find("c:Description", NS)), MAX_DESCRIPTION),
            "likelihood": _texte(weakness.find("c:Likelihood_Of_Exploit", NS)),
            "consequences": _consequences(weakness),
            "detection_methods": _detections(weakness),
            "mitigations": _mitigations(weakness),
            "parents": _parents(weakness),
            "mapping_usage": usage,
            "mapping_rationale": raison,
        }

    return {
        "source": SOURCE,
        "version": version,
        "date": date,
        # La date ci-dessus est celle de MITRE ; celle-ci est celle de NOTRE
        # instantané. Les deux diffèrent, et c'est la seconde qui dit depuis
        # quand ce fichier ne bouge plus.
        "distilled_at": _date.today().isoformat(),
        "count": len(faiblesses),
        "weaknesses": faiblesses,
    }


def main() -> None:
    if len(sys.argv) > 1:
        donnees = Path(sys.argv[1]).read_bytes()
    else:
        print(f"Téléchargement depuis {SOURCE} …")
        with urllib.request.urlopen(SOURCE, timeout=60) as reponse:
            donnees = reponse.read()

    archive = zipfile.ZipFile(io.BytesIO(donnees))
    noms_xml = [n for n in archive.namelist() if n.endswith(".xml")]
    if len(noms_xml) != 1:
        raise SystemExit(f"Archive inattendue : {archive.namelist()}")
    xml = archive.read(noms_xml[0])

    resultat = distiller(xml)

    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(
        json.dumps(resultat, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )

    poids = DESTINATION.stat().st_size / 1024
    print(f"{DESTINATION} écrit : {resultat['count']} faiblesses, {poids:.0f} Ko")
    print(f"CWE version {resultat['version']} ({resultat['date']})")

    usages: dict[str, int] = {}
    for w in resultat["weaknesses"].values():  # type: ignore[union-attr]
        u = w.get("mapping_usage") or "(non précisé)"
        usages[u] = usages.get(u, 0) + 1
    print("Répartition Usage :", usages)


if __name__ == "__main__":
    main()

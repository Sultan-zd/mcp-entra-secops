"""Analyse, qualité et conversion des règles YARA.

**Ce que ce module délègue, et pourquoi.** Deux bibliothèques de référence
sont utilisées plutôt que réimplémentées :

* `plyara` lit la structure — nom, métadonnées, chaînes, condition. Sa
  tolérance n'est pas uniforme, contrairement à ce qu'on pourrait supposer :
  un nom de règle absent, commençant par un chiffre, ou une condition
  sémantiquement fausse (`this is not valid yara`, jamais rejetée) sont
  traités très différemment. Le premier cas fait lever `plyara` lui-même à la
  lecture ; le second se laisse tokeniser sans broncher. C'est un fait
  constaté en testant les deux, pas une garantie de la bibliothèque.
* `yara-python` (le compilateur officiel) donne la validation stricte. Un
  détail vérifié avant d'écrire ce module : **une source vide compile sans
  erreur, avec zéro règle.** Se fier au seul « la compilation n'a pas levé »
  aurait déclaré valide un fichier qui ne contient rien — le même genre de
  piège que le `logsource` manquant côté Sigma.

**Ce que ce module apporte.** La qualité d'une règle YARA se joue sur des
signaux qu'aucun compilateur ne vérifie :

* Une chaîne ASCII courte sans `fullword` correspond à l'intérieur de
  n'importe quel mot qui la contient — la cause la plus fréquente de faux
  positifs en pratique.
* Une condition `any of them` sur des chaînes génériques ne sélectionne
  presque rien.
* Aucun format de méta-donnée n'est normalisé pour les identifiants ATT&CK :
  ce module les cherche dans tout ce qui est textuel plutôt que d'exiger un
  nom de champ précis, et le dit.

Aucun accès réseau.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: Sous ce nombre de caractères, une chaîne texte sans `fullword` correspond
#: à l'intérieur de mots sans rapport : "cmd" matche "command", "recmd", etc.
LONGUEUR_CHAINE_COURTE = 4

#: Repli quand aucune métadonnée ne nomme explicitement une méthode ; on
#: cherche alors un identifiant ATT&CK dans n'importe quelle valeur textuelle.
#: Aucun nom de champ n'est standardisé côté YARA — c'est un fait du terrain,
#: pas une simplification de ce module.
_MOTIF_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

POIDS = {
    "metadata": 20,
    "strings_specifiques": 25,
    "condition_selective": 20,
    "attack_tags": 20,
    "identite": 15,
}


class YaraError(ValueError):
    """La règle n'a pas pu être lue."""


@dataclass
class Qualite:
    """Évaluation de la qualité d'une règle, avec ce qui manque."""

    score: int = 0
    grade: str = "F"
    findings: list[str] = field(default_factory=list)
    strengths: list[str] = field(default_factory=list)


@dataclass
class ChaineRegle:
    """Une chaîne déclarée dans le bloc `strings`."""

    name: str
    type: str  # "text" | "regex" | "byte"
    value: str
    modifiers: list[str] = field(default_factory=list)


@dataclass
class RegleAnalysee:
    """Ce qu'une règle YARA contient, lue avec `plyara`."""

    name: str = ""
    tags: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    strings: list[ChaineRegle] = field(default_factory=list)
    condition: str = ""
    attack_techniques: list[str] = field(default_factory=list)


def _metadonnees(brutes: list[dict[str, Any]]) -> dict[str, str]:
    """`plyara` rend une liste de dictionnaires à une seule clé chacun."""
    resultat: dict[str, str] = {}
    for entree in brutes:
        for cle, valeur in entree.items():
            resultat[str(cle)] = str(valeur)
    return resultat


def _condition_propre(brute: str) -> str:
    """Retire le label `condition:` et aplatit la mise en forme d'origine.

    `plyara` rend la condition telle qu'écrite dans le fichier — avec son
    label et son indentation propres. Comparer ce texte brut à `"true"` pour
    repérer une condition permissive échouait systématiquement : le résultat
    valait `"condition:\\n            true"`, jamais égal à `"true"` une fois
    dépouillé de ses seuls espaces de bord.
    """
    sans_label = re.sub(r"^\s*condition\s*:\s*", "", brute, flags=re.IGNORECASE)
    return " ".join(sans_label.split())


def _chaines(brutes: list[dict[str, Any]]) -> list[ChaineRegle]:
    return [
        ChaineRegle(
            name=str(c.get("name", "")),
            type=str(c.get("type", "text")),
            value=str(c.get("value", "")),
            modifiers=[str(m) for m in c.get("modifiers", [])],
        )
        for c in brutes
    ]


def _techniques_attack(metadonnees: dict[str, str], tags: list[str]) -> list[str]:
    """Cherche un identifiant ATT&CK dans tout ce qui est textuel.

    Aucun champ de métadonnée YARA n'est standardisé pour porter cette
    information — contrairement au tag `attack.tXXXX` de Sigma. Le repli le
    plus honnête est de chercher le motif partout plutôt que d'exiger un nom
    de champ précis que la moitié des règles réelles n'utilisent pas.
    """
    trouvees: list[str] = []
    for valeur in list(metadonnees.values()) + tags:
        for correspondance in _MOTIF_TECHNIQUE.findall(valeur):
            identifiant = correspondance.upper()
            if identifiant not in trouvees:
                trouvees.append(identifiant)
    return sorted(trouvees)


def analyser(regle_yara: str) -> RegleAnalysee:
    """Lit une règle YARA avec `plyara`, valide ou non.

    `plyara` ne valide pas la syntaxe : il tokenise ce qu'il trouve. Une règle
    cassée est donc tout de même analysée — c'est `valider_strictement` qui
    juge de la conformité, séparément.
    """
    if not regle_yara or not regle_yara.strip():
        raise YaraError("Aucune règle fournie.")

    try:
        import plyara
    except ImportError as exc:  # pragma: no cover - dépendance déclarée
        raise YaraError("La bibliothèque plyara n'est pas installée.") from exc

    try:
        regles = plyara.Plyara().parse_string(regle_yara)
    except Exception as exc:
        raise YaraError(f"Règle YARA illisible : {exc}") from exc

    if not regles:
        raise YaraError("Le document ne contient aucune règle reconnaissable.")

    brute = regles[0]
    metadonnees = _metadonnees(brute.get("metadata", []))
    tags = [str(t) for t in brute.get("tags", [])]

    return RegleAnalysee(
        name=str(brute.get("rule_name", "")),
        tags=tags,
        scopes=[str(s) for s in brute.get("scopes", [])],
        imports=[str(i) for i in brute.get("imports", [])],
        metadata=metadonnees,
        strings=_chaines(brute.get("strings", [])),
        condition=_condition_propre(str(brute.get("raw_condition", ""))),
        attack_techniques=_techniques_attack(metadonnees, tags),
    )


def valider_strictement(regle_yara: str) -> tuple[bool, str | None]:
    """Demande au compilateur YARA officiel si la règle est conforme.

    **Le piège vérifié avant d'écrire cette fonction : une source vide
    compile sans erreur, avec zéro règle.** S'y fier seul déclarerait valide
    un texte qui ne contient rien. `analyser()` lève déjà dans ce cas — le
    laisser lever ici avant d'appeler le compilateur suffit à écarter le piège,
    sans dupliquer sa logique.
    """
    try:
        analyser(regle_yara)
    except YaraError as exc:
        return False, str(exc)

    try:
        import yara
    except ImportError:
        return False, "La bibliothèque yara-python n'est pas installée."

    try:
        yara.compile(source=regle_yara)
    except yara.Error as exc:
        return False, str(exc)

    return True, None


def _repandue(chaine: ChaineRegle) -> bool:
    """Cette chaîne va-t-elle correspondre à des mots sans rapport ?"""
    if chaine.type != "text":
        return False
    if "fullword" in chaine.modifiers:
        return False
    return len(chaine.value) < LONGUEUR_CHAINE_COURTE


def evaluer_qualite(analyse: RegleAnalysee) -> Qualite:
    """Note la règle sur ce qui décide de son sort en production.

    Une règle qui compile peut être inutilisable : des chaînes trop courtes
    sans `fullword` déclenchent sur du texte sans rapport, et une condition
    `any of them` sur ces mêmes chaînes ne sélectionne presque rien.
    """
    qualite = Qualite()
    score = 0

    # --- métadonnées --------------------------------------------------
    if analyse.metadata.get("author") and analyse.metadata.get("description"):
        score += POIDS["metadata"]
        qualite.strengths.append("Auteur et description renseignés.")
    else:
        manquant = [c for c in ("author", "description") if not analyse.metadata.get(c)]
        qualite.findings.append(
            f"Métadonnée(s) absente(s) : {', '.join(manquant)}. Sans elles, "
            "personne ne sait qui a écrit la règle ni ce qu'elle vise, une fois "
            "sortie de son contexte d'origine."
        )

    # --- chaînes trop génériques ---------------------------------------
    chaines_texte = [c for c in analyse.strings if c.type == "text"]
    repandues = [c for c in chaines_texte if _repandue(c)]
    if chaines_texte and not repandues:
        score += POIDS["strings_specifiques"]
        qualite.strengths.append("Aucune chaîne texte trop courte sans `fullword`.")
    elif repandues:
        qualite.findings.append(
            f"{len(repandues)} chaîne(s) texte courte(s) sans `fullword` — "
            + ", ".join(f"{c.name} (« {c.value} »)" for c in repandues[:3])
            + " : elles correspondront à l'intérieur de mots sans rapport."
        )
    elif not analyse.strings:
        qualite.findings.append("Aucune chaîne déclarée : la condition ne s'appuie sur rien.")

    # --- sélectivité de la condition -------------------------------------
    bas = analyse.condition.lower()
    if "any of them" in bas or "1 of them" in bas:
        if repandues:
            qualite.findings.append(
                "La condition se satisfait d'une seule correspondance (« any of "
                "them » / « 1 of them ») alors que des chaînes génériques sont "
                "en jeu : le risque de faux positif s'en trouve démultiplié."
            )
        else:
            score += POIDS["condition_selective"]
    elif bas.strip() in {"true", ""}:
        qualite.findings.append(
            "La condition ne filtre rien (`true` ou vide) : la règle correspond "
            "à tout ce qu'on lui présente."
        )
    else:
        score += POIDS["condition_selective"]

    # --- rattachement ATT&CK ---------------------------------------------
    if analyse.attack_techniques:
        score += POIDS["attack_tags"]
        qualite.strengths.append(
            "Technique(s) ATT&CK repérée(s) : " + ", ".join(analyse.attack_techniques) + "."
        )
    else:
        qualite.findings.append(
            "Aucun identifiant ATT&CK trouvé dans les métadonnées ou les tags : "
            "la règle ne comptera dans aucune revue de couverture."
        )

    # --- traçabilité --------------------------------------------------
    # Un nom de règle syntaxiquement invalide est déjà écarté avant ce point :
    # `plyara` refuse de le tokeniser, `analyser()` lève avant d'y arriver. Ce
    # qui varie réellement d'une règle à l'autre, c'est la date et la
    # référence — souvent absentes, et c'est ce qui empêche de savoir si la
    # règle est encore d'actualité une fois sortie de son dépôt d'origine.
    if analyse.metadata.get("date") or analyse.metadata.get("reference"):
        score += POIDS["identite"]
    else:
        qualite.findings.append(
            "Ni date ni référence en métadonnée : impossible de savoir si "
            "cette règle est encore d'actualité une fois sortie de son dépôt "
            "d'origine."
        )

    qualite.score = min(100, score)
    qualite.grade = (
        "A" if qualite.score >= 90
        else "B" if qualite.score >= 75
        else "C" if qualite.score >= 55
        else "D" if qualite.score >= 35
        else "F"
    )
    return qualite

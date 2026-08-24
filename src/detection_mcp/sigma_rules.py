"""Analyse, qualité et conversion des règles Sigma.

**Ce que ce module délègue, et pourquoi.** L'analyse syntaxique et la
conversion vers un langage de requête sont faites par `pysigma`, la
bibliothèque de référence. Réimplémenter la spécification serait une erreur :
elle comporte des dizaines de modificateurs — `contains`, `startswith`, `re`,
`base64offset`, `cidr`, `|all` — et se tromper sur l'un d'eux produit une
règle qui *paraît* correcte mais rate silencieusement les attaques qu'elle
prétend détecter. C'est précisément le mode de défaillance que ce projet
cherche à éviter.

**Ce que ce module apporte** est ailleurs : évaluer la *qualité* d'une règle,
l'expliquer en français, et la relier au corpus ATT&CK embarqué. Aucune
bibliothèque ne fait cela.

Aucun accès réseau.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: Pondération de chaque critère de qualité. Les deux premiers pèsent le plus
#: parce que leur absence rend la règle *inexploitable* en production, pas
#: seulement imparfaite.
POIDS = {
    "logsource": 25,
    "falsepositives": 20,
    "description": 15,
    "level": 10,
    "attack_tags": 15,
    "identite": 10,
    "statut": 5,
}

#: Champs si répandus qu'une sélection reposant sur eux seuls déclenche sur
#: presque tout le trafic.
CHAMPS_TROP_LARGES = frozenset(
    {"eventid", "event_id", "computername", "hostname", "user", "username", "result"}
)

_TAG_ATTACK = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TAG_TACTIQUE = re.compile(r"^attack\.([a-z_-]+)$", re.IGNORECASE)


class SigmaError(ValueError):
    """La règle n'a pas pu être lue."""


@dataclass
class Qualite:
    """Évaluation de la qualité d'une règle, avec ce qui manque."""

    score: int = 0
    grade: str = "F"
    findings: list[str] = field(default_factory=list)
    strengths: list[str] = field(default_factory=list)


@dataclass
class RegleAnalysee:
    """Ce qu'une règle Sigma contient, une fois lue."""

    title: str = ""
    id: str | None = None
    status: str | None = None
    level: str | None = None
    description: str | None = None
    author: str | None = None
    logsource: dict[str, str] = field(default_factory=dict)
    selections: list[str] = field(default_factory=list)
    condition: str = ""
    fields_used: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    attack_tactics: list[str] = field(default_factory=list)
    other_tags: list[str] = field(default_factory=list)


def _lire_yaml(regle_yaml: str) -> dict[str, Any]:
    """Lit la structure brute, sans jugement sur sa validité Sigma.

    **Pourquoi ne pas simplement passer par pysigma.** Il refuse une règle sans
    `logsource` dès l'analyse — or c'est précisément le défaut le plus fréquent
    d'un brouillon, et celui sur lequel un analyste a le plus besoin d'un
    conseil. Une exception brute ne lui apprend rien.

    La qualité est donc évaluée sur la structure brute, et la conformité
    stricte reste jugée par pysigma, séparément.
    """
    if not regle_yaml or not regle_yaml.strip():
        raise SigmaError("Aucune règle fournie.")

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - dépendance déclarée
        raise SigmaError("La bibliothèque PyYAML n'est pas installée.") from exc

    try:
        documents = [d for d in yaml.safe_load_all(regle_yaml) if isinstance(d, dict)]
    except yaml.YAMLError as exc:
        raise SigmaError(f"YAML illisible : {exc}") from exc

    if not documents:
        raise SigmaError("Le document ne contient aucune règle exploitable.")
    return documents[0]


def valider_strictement(regle_yaml: str) -> tuple[bool, str | None]:
    """Demande à pysigma si la règle est conforme à la spécification.

    Rend le verdict et, le cas échéant, le motif du refus — sans lever, pour
    que l'appelant puisse tout de même rendre l'évaluation de qualité.
    """
    try:
        _charger(regle_yaml)
    except SigmaError as exc:
        return False, str(exc)
    return True, None


def _charger(regle_yaml: str) -> Any:
    """Lit la règle avec pysigma, et traduit ses erreurs en messages utiles."""
    if not regle_yaml or not regle_yaml.strip():
        raise SigmaError("Aucune règle fournie.")

    try:
        from sigma.collection import SigmaCollection
    except ImportError as exc:  # pragma: no cover - dépendance déclarée
        raise SigmaError(
            "La bibliothèque pysigma n'est pas installée : "
            "« pip install pysigma »."
        ) from exc

    try:
        collection = SigmaCollection.from_yaml(regle_yaml)
    except Exception as exc:
        raise SigmaError(f"Règle Sigma illisible : {exc}") from exc

    if not collection.rules:
        raise SigmaError("Le document ne contient aucune règle.")
    return collection


def _champs_bruts(detection: dict[str, Any]) -> list[str]:
    """Les champs cités par les sélections, lus dans la structure brute.

    Un champ Sigma peut porter des modificateurs (`InitiatedBy|contains`) : seul
    le nom avant la barre verticale désigne le champ de journal.
    """
    trouves: list[str] = []

    def visiter(valeur: Any) -> None:
        if isinstance(valeur, dict):
            for cle, sous in valeur.items():
                nom = str(cle).split("|", 1)[0].strip()
                if nom and nom not in trouves:
                    trouves.append(nom)
                visiter(sous)
        elif isinstance(valeur, list):
            for element in valeur:
                visiter(element)

    for nom, contenu in detection.items():
        if nom != "condition":
            visiter(contenu)
    return trouves


def analyser(regle_yaml: str) -> RegleAnalysee:
    """Lit une règle et en extrait ce qui compte, valide ou non."""
    brut = _lire_yaml(regle_yaml)
    detection = brut.get("detection") or {}
    if not isinstance(detection, dict):
        detection = {}

    condition = detection.get("condition")
    faux_positifs = brut.get("falsepositives") or []
    if isinstance(faux_positifs, str):
        faux_positifs = [faux_positifs]

    analyse = RegleAnalysee(
        title=str(brut.get("title") or ""),
        id=str(brut["id"]) if brut.get("id") else None,
        status=str(brut["status"]) if brut.get("status") else None,
        level=str(brut["level"]) if brut.get("level") else None,
        description=brut.get("description"),
        author=str(brut["author"]) if brut.get("author") else None,
        selections=[c for c in detection if c != "condition"],
        condition=" ; ".join(str(c) for c in condition)
        if isinstance(condition, list)
        else str(condition or ""),
        fields_used=_champs_bruts(detection),
        falsepositives=[str(f) for f in faux_positifs],
    )

    source = brut.get("logsource") or {}
    if isinstance(source, dict):
        for cle in ("category", "product", "service"):
            if source.get(cle):
                analyse.logsource[cle] = str(source[cle])

    for tag in brut.get("tags") or []:
        texte = str(tag)
        technique = _TAG_ATTACK.match(texte)
        if technique:
            analyse.attack_techniques.append(technique.group(1).upper())
            continue
        tactique = _TAG_TACTIQUE.match(texte)
        if tactique:
            analyse.attack_tactics.append(tactique.group(1).lower())
            continue
        analyse.other_tags.append(texte)

    return analyse


def evaluer_qualite(analyse: RegleAnalysee) -> Qualite:
    """Note la règle sur ce qui décide de son sort en production.

    Une règle syntaxiquement valide peut être inutilisable. Les deux causes les
    plus fréquentes, et de loin : pas de `logsource` — le moteur ne sait pas où
    l'appliquer — et pas de faux positifs déclarés — l'équipe la désactive au
    premier jour bruyant, sans jamais la réactiver.
    """
    qualite = Qualite()
    score = 0

    if analyse.logsource:
        score += POIDS["logsource"]
        qualite.strengths.append(
            "Source de journal précisée : la règle peut être routée vers les bons événements."
        )
    else:
        qualite.findings.append(
            "Aucune `logsource`. Le moteur ne saura pas à quels journaux appliquer la "
            "règle — c'est le défaut qui rend une règle purement décorative."
        )

    if analyse.falsepositives:
        score += POIDS["falsepositives"]
        qualite.strengths.append(
            f"{len(analyse.falsepositives)} faux positif(s) déclaré(s) : l'équipe saura "
            "quoi écarter."
        )
    else:
        qualite.findings.append(
            "Aucun faux positif déclaré. Une règle qui n'annonce pas son bruit est "
            "désactivée au premier jour chargé, et rarement réactivée."
        )

    if analyse.description and len(analyse.description.strip()) > 20:
        score += POIDS["description"]
    else:
        qualite.findings.append(
            "Description absente ou trop courte. L'analyste qui recevra l'alerte à "
            "3 h du matin n'aura que ça pour comprendre."
        )

    if analyse.level:
        score += POIDS["level"]
    else:
        qualite.findings.append("Aucun `level` : la règle ne peut pas être triée par gravité.")

    if analyse.attack_techniques:
        score += POIDS["attack_tags"]
        qualite.strengths.append(
            "Rattachée à ATT&CK (" + ", ".join(analyse.attack_techniques) + ")."
        )
    else:
        qualite.findings.append(
            "Aucune technique ATT&CK en étiquette. Sans elle, la règle ne compte pas "
            "dans une revue de couverture."
        )

    if analyse.id and analyse.author:
        score += POIDS["identite"]
    else:
        manquant = "identifiant" if not analyse.id else "auteur"
        qualite.findings.append(
            f"Pas d'{manquant}. Une règle sans {manquant} ne peut être ni suivie ni "
            "attribuée quand elle pose problème."
        )

    if analyse.status and analyse.status.lower() in {"stable", "test"}:
        score += POIDS["statut"]
    elif analyse.status:
        qualite.findings.append(
            f"Statut « {analyse.status} » : à valider avant mise en production."
        )
    else:
        qualite.findings.append("Aucun `status` : maturité de la règle inconnue.")

    # --- condition trop large --------------------------------------------
    champs_bas = {c.lower() for c in analyse.fields_used}
    if analyse.fields_used and champs_bas.issubset(CHAMPS_TROP_LARGES):
        qualite.findings.append(
            "La règle ne s'appuie que sur des champs très répandus ("
            + ", ".join(sorted(analyse.fields_used))
            + ") : elle risque de se déclencher sur une grande part du trafic normal."
        )
        score = max(0, score - 15)

    if not analyse.fields_used:
        qualite.findings.append(
            "Aucun champ de journal identifié : vérifier que la détection cible bien "
            "des champs nommés."
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


#: Cibles de conversion. Chaque valeur donne le module et la classe du moteur.
CIBLES = {
    "kusto": ("sigma.backends.kusto", "KustoBackend", "Microsoft Sentinel / Defender (KQL)"),
    "splunk": ("sigma.backends.splunk", "SplunkBackend", "Splunk (SPL)"),
    "lucene": ("sigma.backends.elasticsearch", "LuceneBackend", "Elasticsearch (Lucene)"),
}


def convertir(regle_yaml: str, cible: str) -> list[str]:
    """Traduit la règle dans un langage de requête.

    La conversion est faite par `pysigma`. Une traduction maison serait plus
    courte à écrire et fausse sur les cas qui comptent.
    """
    cle = cible.strip().lower()
    if cle not in CIBLES:
        raise SigmaError(
            f"Cible « {cible} » inconnue. Valeurs possibles : " + ", ".join(sorted(CIBLES)) + "."
        )

    collection = _charger(regle_yaml)
    module, classe, _ = CIBLES[cle]

    try:
        moteur = getattr(__import__(module, fromlist=[classe]), classe)()
        requetes = moteur.convert(collection)
    except Exception as exc:
        raise SigmaError(
            f"Conversion vers {cle} impossible : {exc}. Certains modificateurs Sigma "
            "n'ont pas d'équivalent dans tous les langages de requête."
        ) from exc

    return [str(r) for r in requetes]


#: Traduction des modificateurs Sigma les plus courants.
MODIFICATEURS = {
    "contains": "contient",
    "startswith": "commence par",
    "endswith": "se termine par",
    "re": "correspond à l'expression régulière",
    "cidr": "appartient au réseau",
    "base64": "vaut, une fois décodé en base64,",
    "base64offset": "vaut, une fois décodé en base64 décalé,",
    "all": "contient toutes les valeurs",
    "gt": "est supérieur à",
    "gte": "est supérieur ou égal à",
    "lt": "est inférieur à",
    "lte": "est inférieur ou égal à",
    "windash": "vaut, quelle que soit la forme du tiret,",
}


def _formuler(champ: str, valeur: Any) -> str:
    """Met une paire champ/valeur Sigma en français lisible."""
    morceaux = champ.split("|")
    nom = morceaux[0]
    verbe = "vaut"
    negation = False

    for modificateur in morceaux[1:]:
        bas = modificateur.lower()
        if bas == "not":
            negation = True
        elif bas in MODIFICATEURS:
            verbe = MODIFICATEURS[bas]

    if isinstance(valeur, list):
        rendu = " ou ".join(f"« {v} »" for v in valeur[:6])
        if len(valeur) > 6:
            rendu += f" (et {len(valeur) - 6} autre(s))"
    elif valeur is None:
        return f"le champ {nom} est absent"
    else:
        rendu = f"« {valeur} »"

    return f"le champ {nom} {'ne ' if negation else ''}{verbe} {rendu}"


def decrire_selections(regle_yaml: str) -> dict[str, list[str]]:
    """Décrit chaque bloc de détection en français.

    L'objectif est qu'un analyste qui ne lit pas le YAML comprenne exactement
    ce que la règle cherche — c'est ce qui décide s'il l'approuve ou non.
    """
    brut = _lire_yaml(regle_yaml)
    detection = brut.get("detection") or {}
    if not isinstance(detection, dict):
        return {}

    descriptions: dict[str, list[str]] = {}
    for nom, contenu in detection.items():
        if nom == "condition":
            continue
        lignes: list[str] = []
        if isinstance(contenu, dict):
            for champ, valeur in contenu.items():
                lignes.append(_formuler(str(champ), valeur))
        elif isinstance(contenu, list):
            for element in contenu:
                if isinstance(element, dict):
                    for champ, valeur in element.items():
                        lignes.append(_formuler(str(champ), valeur))
                else:
                    lignes.append(f"l'événement contient « {element} »")
        descriptions[str(nom)] = lignes
    return descriptions


def expliquer_condition(condition: str, selections: list[str]) -> str:
    """Traduit la ligne `condition` en une phrase.

    Sigma admet des formes agrégées (`count() by`, `near`) qu'une traduction
    mot à mot rendrait faussement simples. Elles sont signalées plutôt que
    réécrites.
    """
    if not condition:
        return "Aucune condition déclarée."

    bas = condition.lower()
    for forme, avertissement in (
        ("count(", "La règle compte des occurrences : elle dépend d'une fenêtre de temps."),
        ("near ", "La règle exige une proximité temporelle entre plusieurs événements."),
        ("| ", "La règle applique une agrégation après filtrage."),
    ):
        if forme in bas:
            return f"{condition} — {avertissement}"

    phrase = condition
    for motif, remplacement in (
        (" and not ", " ET PAS "),
        (" or not ", " OU PAS "),
        (" and ", " ET "),
        (" or ", " OU "),
        ("1 of them", "au moins un des blocs ci-dessus"),
        ("all of them", "tous les blocs ci-dessus"),
    ):
        phrase = phrase.replace(motif, remplacement)

    if len(selections) == 1 and phrase.strip() == selections[0]:
        return f"Se déclenche dès que le bloc « {selections[0]} » correspond."
    return f"Se déclenche quand : {phrase}"

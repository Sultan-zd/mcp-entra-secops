"""Détection ReDoS : forme suspecte, puis confirmation chronométrée réelle.

**Pourquoi deux étapes, et pas une seule note de risque.** Une analyse purement
structurelle (« ce motif contient une répétition imbriquée ») se trompe dans
les deux sens : elle rate les cas où le moteur factorise l'ambiguïté sans
qu'on le voie dans le texte source, et elle signale des motifs dont les
alternatives, en pratique, ne se recouvrent pas assez pour ralentir quoi que
ce soit. Ce module ne rend donc jamais une gravité déduite du seul texte : la
structure ne fait que désigner des candidats, et c'est une exécution réelle du
moteur `re` de Python, chronométrée, qui confirme ou infirme chacun — le même
principe que la vérification par `yara-python`/`plyara` ailleurs dans ce
serveur : le juge, c'est le moteur de référence, pas une réimplémentation de
sa grammaire.

**Ce que l'étape structurelle regarde.** Le motif est analysé via l'arbre que
`re` construit lui-même en interne (`re._parser`) — une API privée de la
bibliothèque standard, pas un choix de facilité : c'est le même arbre que le
moteur utilisera pour matcher, ce qui garantit que la structure inspectée et
le comportement chronométré ensuite sont exactement le même objet. Trois
formes sont recherchées :

* **Quantificateurs imbriqués** — `(a+)+`, `(.*)*` — une répétition illimitée
  qui en contient une autre : le moteur peut découper la même suite de
  caractères d'un nombre exponentiel de façons avant de conclure à l'échec.
* **Alternance ambiguë sous répétition** — `(a|a)*`, `(a|ab)+` — deux
  branches d'un `|` qui se recouvrent (l'une est vide après factorisation du
  préfixe commun, ou identique à une autre) : chaque copie de la boucle peut
  choisir plusieurs branches pour consommer le même texte.
* **Quantificateurs adjacents** — `.*.*`, `\\d+\\d+` — deux répétitions
  illimitées côte à côte : un ralentissement polynomial, moins grave qu'une
  explosion exponentielle mais réel sur une entrée longue.

**Ce que l'étape empirique fait.** Pour chaque candidat, un caractère
représentatif de la construction visée est extrait de l'arbre, et une chaîne
d'attaque est construite avec ce caractère répété, suivie d'un `\\n` — un
octet qu'aucune des trois formes ci-dessus ne peut consommer par défaut (pas
de `re.DOTALL` supposé), ce qui force l'échec final et donc l'exploration
complète des découpages possibles avant d'abandonner. Le test tourne dans un
**processus séparé**, avec un budget de temps strict : un motif réellement
catastrophique ne rend jamais la main, et rien d'autre qu'un `terminate()`
depuis l'extérieur ne l'arrête. Un motif banal répond en microsecondes ; le
budget dépassé est en lui-même la confirmation.
"""

from __future__ import annotations

import multiprocessing
import re
import re._parser as _parser  # type: ignore[import-not-found]
import time
from dataclasses import dataclass
from typing import Any

MAXREPEAT = _parser.MAXREPEAT

#: En-deçà, une répétition bornée reste minuscule (« a{1,3} » imbriqué dans
#: « a{1,3} » ne fait que 9 combinaisons) : ce n'est structurellement pas ce
#: que ce module cherche à signaler.
SEUIL_BORNE_LARGE = 10

_CATEGORIE_ECHANTILLON: dict[Any, str] = {
    _parser.CATEGORY_DIGIT: "5",
    _parser.CATEGORY_NOT_DIGIT: "z",
    _parser.CATEGORY_WORD: "a",
    _parser.CATEGORY_NOT_WORD: " ",
    _parser.CATEGORY_SPACE: " ",
    _parser.CATEGORY_NOT_SPACE: "a",
}

#: Longueurs testées lors de la confirmation, croissantes ; on s'arrête tôt
#: dès qu'une étape dépasse SEUIL_ARRET_PRECOCE.
LONGUEURS_SONDAGE = (10, 15, 20, 25, 30)
SEUIL_ARRET_PRECOCE_S = 0.3
BUDGET_PAR_DEFAUT_S = 2.0


class RedosError(RuntimeError):
    """Le motif fourni n'a pas pu être analysé."""


@dataclass
class Constat:
    """Une forme structurellement suspecte, avant toute confirmation.

    `kind` vaut quantificateurs_imbriques, alternance_ambigue ou
    quantificateurs_adjacents.
    """

    kind: str
    sample: str
    explanation: str


def _est_illimitee(min_: int, max_: Any) -> bool:
    return max_ is MAXREPEAT or (max_ - min_) >= SEUIL_BORNE_LARGE


def _echantillon(op: Any, av: Any) -> str:
    """Un caractère représentatif de ce que ce nœud peut consommer."""
    if op == _parser.LITERAL:
        return chr(av)
    if op == _parser.ANY:
        return "a"
    if op == _parser.IN:
        negate = bool(av) and av[0][0] == _parser.NEGATE
        elements = av[1:] if negate else av
        exclus: set[int] = set()
        for sous_op, sous_av in elements:
            if sous_op == _parser.LITERAL:
                if negate:
                    exclus.add(sous_av)
                    continue
                return chr(sous_av)
            if sous_op == _parser.RANGE:
                if negate:
                    exclus.update(range(sous_av[0], sous_av[1] + 1))
                    continue
                return chr(sous_av[0])
            if sous_op == _parser.CATEGORY:
                candidat = _CATEGORIE_ECHANTILLON.get(sous_av)
                if candidat and not negate:
                    return candidat
        if negate:
            for code in range(ord("a"), ord("z") + 1):
                if code not in exclus:
                    return chr(code)
        return "a"
    if op == _parser.SUBPATTERN:
        corps = av[-1]
        return _echantillon_sequence(corps) if corps else "a"
    if op in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
        _, _, corps = av
        return _echantillon_sequence(corps) if corps else "a"
    return "a"


def _echantillon_sequence(sequence: list[Any]) -> str:
    for op, av in sequence:
        resultat = _echantillon(op, av)
        if resultat:
            return resultat
    return "a"


def _branches_ambigues(branches: list[list[Any]]) -> bool:
    """Deux branches identiques, ou l'une vide et l'autre non.

    `re._parser` factorise déjà les préfixes communs avant de construire le
    `BRANCH` : une branche vide qui reste après cette factorisation signifie
    que cette alternative ne distingue plus rien — c'est exactement la
    signature de `(a|a)*` (deux branches vides) et de `(a|ab)+` (une vide, une
    non vide).
    """
    vues: set[tuple[Any, ...]] = set()
    a_une_vide = False
    for branche in branches:
        cle = tuple(map(str, branche))
        if not branche:
            a_une_vide = True
        if cle in vues:
            return True
        vues.add(cle)
    return a_une_vide and len(branches) > 1


def _analyser_sequence(
    sequence: list[Any], dans_repetition: bool, resultats: list[Constat]
) -> None:
    precedent_illimite = False
    for op, av in sequence:
        if op in (_parser.MAX_REPEAT, _parser.MIN_REPEAT):
            min_, max_, corps = av
            illimitee = _est_illimitee(min_, max_)
            if illimitee and dans_repetition:
                resultats.append(
                    Constat(
                        kind="quantificateurs_imbriques",
                        sample=_echantillon_sequence(corps),
                        explanation=(
                            "Une répétition illimitée en contient une autre : le "
                            "moteur peut répartir la même suite de caractères entre "
                            "les deux boucles d'un nombre exponentiel de façons "
                            "avant de conclure à l'échec."
                        ),
                    )
                )
            if illimitee and precedent_illimite:
                resultats.append(
                    Constat(
                        kind="quantificateurs_adjacents",
                        sample=_echantillon_sequence(corps),
                        explanation=(
                            "Deux répétitions illimitées se suivent : le moteur "
                            "peut faire varier la frontière entre les deux d'un "
                            "nombre de façons proportionnel au carré de la "
                            "longueur de l'entrée."
                        ),
                    )
                )
            _analyser_sequence(corps, dans_repetition or illimitee, resultats)
            precedent_illimite = illimitee
        elif op == _parser.SUBPATTERN:
            _analyser_sequence(av[-1], dans_repetition, resultats)
            precedent_illimite = False
        elif op == _parser.BRANCH:
            _, branches = av
            if _branches_ambigues(branches) and dans_repetition:
                resultats.append(
                    Constat(
                        kind="alternance_ambigue",
                        sample=_echantillon_sequence(
                            [e for branche in branches for e in branche]
                        ),
                        explanation=(
                            "Deux alternatives de ce « | » se recouvrent : à "
                            "chaque tour de la boucle qui les contient, le moteur "
                            "peut choisir l'une ou l'autre pour consommer le même "
                            "texte, ce qui multiplie les découpages possibles."
                        ),
                    )
                )
            for branche in branches:
                _analyser_sequence(branche, dans_repetition, resultats)
            precedent_illimite = False
        else:
            precedent_illimite = False


def analyser_statique(motif: str, flags: int = 0) -> list[Constat]:
    """Repère les formes structurellement suspectes. Ne juge jamais seule.

    Un motif qui ne compile pas lève `RedosError` — cette fonction ne devine
    pas ce qu'un motif invalide aurait voulu dire.
    """
    try:
        arbre = _parser.parse(motif, flags)
    except re.error as exc:
        raise RedosError(f"Motif invalide : {exc}") from exc

    resultats: list[Constat] = []
    _analyser_sequence(list(arbre.data), False, resultats)
    return resultats


# ---------------------------------------------------------------------------
# Confirmation empirique
# ---------------------------------------------------------------------------
@dataclass
class Sondage:
    """Le verdict empirique sur un constat structurel donné."""

    finding: Constat
    tested: bool
    confirmed: bool
    timeout_hit: bool
    timings_ms: list[tuple[int, float]]
    note: str


def _sonder_travailleur(
    motif: str, flags: int, echantillon: str, longueurs: tuple[int, ...], file: Any
) -> None:
    """Exécuté dans un processus séparé — jamais dans celui du serveur MCP."""
    try:
        compilee = re.compile(motif, flags)
    except re.error as exc:
        file.put({"erreur": str(exc)})
        return

    mesures: list[tuple[int, float]] = []
    for n in longueurs:
        attaque = (echantillon * n) + "\n"
        debut = time.perf_counter()
        compilee.fullmatch(attaque)
        duree = time.perf_counter() - debut
        mesures.append((n, duree))
        if duree > SEUIL_ARRET_PRECOCE_S:
            break
    file.put({"mesures": mesures})


def confirmer(
    motif: str,
    constat: Constat,
    flags: int = 0,
    budget_s: float = BUDGET_PAR_DEFAUT_S,
) -> Sondage:
    """Chronomètre le moteur `re` réel sur une attaque construite pour ce constat.

    Tourne dans un processus séparé avec un budget de temps strict : si le
    processus ne rend pas la main dans ce délai, il est terminé de force et
    c'est en soi la confirmation — aucun motif raisonnable ne met deux
    secondes à échouer sur trente caractères.
    """
    ctx = multiprocessing.get_context("spawn")
    file: Any = ctx.Queue()
    processus = ctx.Process(
        target=_sonder_travailleur,
        args=(motif, flags, constat.sample, LONGUEURS_SONDAGE, file),
    )
    processus.start()
    processus.join(budget_s)

    if processus.is_alive():
        processus.terminate()
        processus.join(1.0)
        if processus.is_alive():
            processus.kill()
            processus.join()
        return Sondage(
            finding=constat,
            tested=True,
            confirmed=True,
            timeout_hit=True,
            timings_ms=[],
            note=(
                f"Le moteur n'a pas terminé en {budget_s:.0f} s sur une entrée "
                f"construite à partir de « {constat.sample} » répété — "
                "comportement catastrophique confirmé."
            ),
        )

    try:
        resultat = file.get(timeout=1.0)
    except Exception:
        return Sondage(
            finding=constat,
            tested=False,
            confirmed=False,
            timeout_hit=False,
            timings_ms=[],
            note="Le sondage n'a produit aucun résultat exploitable.",
        )

    if "erreur" in resultat:
        return Sondage(
            finding=constat,
            tested=False,
            confirmed=False,
            timeout_hit=False,
            timings_ms=[],
            note=f"Motif non compilable par le moteur : {resultat['erreur']}",
        )

    mesures: list[tuple[int, float]] = resultat["mesures"]
    timings_ms = [(n, d * 1000) for n, d in mesures]
    dernier_n, derniere_duree = mesures[-1]
    premier_n, premiere_duree = mesures[0]

    if derniere_duree > SEUIL_ARRET_PRECOCE_S:
        return Sondage(
            finding=constat,
            tested=True,
            confirmed=True,
            timeout_hit=False,
            timings_ms=timings_ms,
            note=(
                f"{derniere_duree * 1000:.0f} ms pour {dernier_n} caractères — déjà "
                "hors de proportion, le sondage s'est arrêté avant la longueur maximale."
            ),
        )

    # Une croissance linéaire ou polynomiale modérée garde un rapport contenu
    # entre la plus longue et la plus courte entrée testées ; une explosion
    # (exponentielle, ou même quadratique marquée) le fait exploser.
    ratio = derniere_duree / max(premiere_duree, 1e-6)
    confirme = ratio > 20

    return Sondage(
        finding=constat,
        tested=True,
        confirmed=confirme,
        timeout_hit=False,
        timings_ms=timings_ms,
        note=(
            f"{premier_n} → {dernier_n} caractères : {premiere_duree * 1000:.3f} ms → "
            f"{derniere_duree * 1000:.3f} ms (x{ratio:.0f})."
            + (
                " Croissance anormale pour une simple augmentation de longueur."
                if confirme
                else " Croissance conforme à un motif sans risque réel malgré la forme repérée."
            )
        ),
    )

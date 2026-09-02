"""L'âge des corpus embarqués, dit plutôt que subi.

**Le défaut que ce module corrige.** Les référentiels officiels (ATT&CK, CWE,
D3FEND, événements Windows) sont distillés à la construction et embarqués dans
le paquet. C'est ce qui rend vingt-quatre outils utilisables hors ligne — et
c'est un compromis assumé.

Mais un corpus figé ne vieillit pas bruyamment : il répond avec exactement la
même assurance à six jours qu'à seize mois. Sans date de distillation, ni le
destinataire ni le modèle ne peuvent savoir que « cette technique n'existe pas
dans ATT&CK » veut peut-être dire « n'existait pas encore lors de la
construction ».

C'était la seule chose du projet qui **contredisait son propre principe** :
vérifier plutôt qu'affirmer. Chaque corpus porte désormais sa date, et ce
module la traduit en constat.

**D'où viennent les seuils.** Ils suivent le rythme de publication réel des
sources, pas une intuition : le catalogue CWE change deux à quatre fois par an,
ATT&CK publie une version majeure par semestre. Au-delà de six mois, une
version a donc probablement été manquée ; au-delà d'un an, plusieurs le sont
certainement.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime

#: Au-delà, au moins une publication a probablement été manquée.
SEUIL_VIEILLISSANT_JOURS = 180

#: Au-delà, plusieurs l'ont certainement été : le corpus ne peut plus être
#: présenté comme représentatif de l'état publié.
SEUIL_PERIME_JOURS = 365


@dataclass(frozen=True)
class Fraicheur:
    """L'état d'un corpus embarqué, daté et jugé."""

    name: str
    distilled_at: str | None
    source_version: str | None
    age_days: int | None
    stale: bool
    note: str


def _lire_date(valeur: str | None) -> date | None:
    if not valeur:
        return None
    try:
        return datetime.strptime(valeur.strip()[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def evaluer(
    nom: str,
    distilled_at: str | None,
    source_version: str | None = None,
    regenerer_avec: str | None = None,
    aujourd_hui: date | None = None,
) -> Fraicheur:
    """Traduit une date de distillation en constat exploitable.

    Une date absente ou illisible est signalée comme telle et traitée comme
    périmée : ne pas savoir depuis quand une donnée est figée est un défaut
    au moins aussi sérieux que de la savoir ancienne.
    """
    reference = aujourd_hui or date.today()
    distillee = _lire_date(distilled_at)
    suffixe = f" Régénérer avec « {regenerer_avec} »." if regenerer_avec else ""

    if distillee is None:
        return Fraicheur(
            name=nom,
            distilled_at=None,
            source_version=source_version,
            age_days=None,
            stale=True,
            note=(
                f"{nom} ne porte aucune date de distillation exploitable : "
                "impossible de dire depuis quand ces données sont figées."
                + suffixe
            ),
        )

    age = (reference - distillee).days

    if age < 0:
        return Fraicheur(
            name=nom,
            distilled_at=distilled_at,
            source_version=source_version,
            age_days=age,
            stale=True,
            note=(
                f"{nom} porte une date de distillation dans le futur "
                f"({distilled_at}) : l'horloge de la machine de construction "
                "ou celle d'ici est fausse." + suffixe
            ),
        )

    if age >= SEUIL_PERIME_JOURS:
        return Fraicheur(
            name=nom,
            distilled_at=distilled_at,
            source_version=source_version,
            age_days=age,
            stale=True,
            note=(
                f"{nom} a été distillé il y a {age} jours ({distilled_at}). "
                "Plusieurs publications ont certainement été manquées : ses "
                "réponses ne représentent plus l'état publié." + suffixe
            ),
        )

    if age >= SEUIL_VIEILLISSANT_JOURS:
        return Fraicheur(
            name=nom,
            distilled_at=distilled_at,
            source_version=source_version,
            age_days=age,
            stale=True,
            note=(
                f"{nom} a été distillé il y a {age} jours ({distilled_at}). "
                "Au moins une publication a probablement été manquée : une "
                "absence de résultat peut venir de l'âge du corpus, pas de "
                "la question posée." + suffixe
            ),
        )

    return Fraicheur(
        name=nom,
        distilled_at=distilled_at,
        source_version=source_version,
        age_days=age,
        stale=False,
        note=f"{nom} a été distillé il y a {age} jours ({distilled_at}).",
    )

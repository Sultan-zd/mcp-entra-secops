"""Playbooks : la séquence d'investigation, déclarée hors du code d'exécution.

Deux raisons de les séparer :

1. **Un analyste qui n'écrit pas de Python peut les relire et les corriger.**
   C'est ce qui rend l'outil adoptable par l'équipe qui l'utilise, plutôt que
   dépendant de son auteur.
2. La séquence devient une donnée : on peut la comparer entre deux exécutions,
   mesurer son efficacité, et détecter une dérive.

L'ordre des étapes n'est pas arbitraire. Le contexte du compte vient toujours en
premier : savoir qu'un compte est administrateur change la gravité de tout ce
qui suit.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .models import Alert, Domain


@dataclass(frozen=True)
class Step:
    """Une étape de playbook, résolue au moment de l'exécution."""

    tool: str
    domain: Domain
    #: Construit les arguments à partir de l'alerte et de ce qui a déjà été appris.
    arguments: Callable[[Alert, dict[str, Any]], dict[str, Any]]
    #: Condition d'exécution. Une étape sans condition s'exécute toujours.
    when: Callable[[Alert, dict[str, Any]], bool] = lambda _a, _c: True
    #: Quand vrai, un échec de cette étape interrompt l'investigation.
    critical: bool = False


@dataclass(frozen=True)
class Playbook:
    """Une famille d'alerte et la façon de l'instruire."""

    name: str
    description: str
    steps: list[Step] = field(default_factory=list)
    #: Techniques ATT&CK à retenir si les constats attendus se confirment.
    mitre: tuple[str, ...] = ()


def _a_un_upn(alert: Alert, _ctx: dict[str, Any]) -> bool:
    return bool(alert.upn)


def _a_des_indicateurs(_alert: Alert, ctx: dict[str, Any]) -> bool:
    return bool(ctx.get("indicators"))


def _a_des_entetes(alert: Alert, _ctx: dict[str, Any]) -> bool:
    return bool(alert.raw_headers)


def _a_un_domaine(alert: Alert, _ctx: dict[str, Any]) -> bool:
    return bool(alert.domain)


# --------------------------------------------------------------------------
# Étapes réutilisables
# --------------------------------------------------------------------------
CONTEXTE_UTILISATEUR = Step(
    tool="get_user_context",
    domain="identity",
    arguments=lambda a, _c: {"upn": a.upn},
    when=_a_un_upn,
)

CONNEXIONS = Step(
    tool="get_user_signins",
    domain="identity",
    arguments=lambda a, _c: {"upn": a.upn, "hours": 48},
    when=_a_un_upn,
)

DETECTIONS_RISQUE = Step(
    tool="get_risk_detections",
    domain="identity",
    arguments=lambda a, _c: {"upn": a.upn, "hours": 168},
    when=_a_un_upn,
)

AUDITS = Step(
    tool="get_directory_audits",
    domain="identity",
    arguments=lambda _a, _c: {"hours": 168},
)

ENRICHISSEMENT = Step(
    tool="bulk_enrich",
    domain="threat_intel",
    # Les indicateurs proviennent des étapes precedentes : c'est le point de
    # jonction entre les domaines, et la raison d'être de la plateforme.
    arguments=lambda _a, c: {"indicators": c.get("indicators", [])[:20]},
    when=_a_des_indicateurs,
)

ANALYSE_ENTETES = Step(
    tool="analyze_email_headers",
    domain="email",
    arguments=lambda a, _c: {"raw_headers": a.raw_headers},
    when=_a_des_entetes,
    critical=True,
)

POSTURE_DOMAINE = Step(
    tool="check_domain_posture",
    domain="email",
    arguments=lambda a, _c: {"domain": a.domain},
    when=_a_un_domaine,
)

COMPTES_A_RISQUE = Step(
    tool="get_risky_users",
    domain="identity",
    arguments=lambda _a, _c: {},
)


# --------------------------------------------------------------------------
# Playbooks
# --------------------------------------------------------------------------
PLAYBOOKS: dict[str, Playbook] = {
    "compte_compromis": Playbook(
        name="compte_compromis",
        description=(
            "Connexion réussie après une série d'échecs. On établit d'abord la "
            "gravité (le compte est-il privilégié ?), puis le déroulé de "
            "l'authentification, puis ce que l'attaquant a fait une fois entré."
        ),
        steps=[CONTEXTE_UTILISATEUR, CONNEXIONS, DETECTIONS_RISQUE, ENRICHISSEMENT, AUDITS],
        mitre=("T1110.003", "T1078.004", "T1098.005"),
    ),
    "utilisateur_a_risque": Playbook(
        name="utilisateur_a_risque",
        description=(
            "Identity Protection a élevé un compte au niveau de risque. On cherche "
            "POURQUOI avant de conclure : le niveau seul ne dit rien de l'incident."
        ),
        steps=[CONTEXTE_UTILISATEUR, DETECTIONS_RISQUE, CONNEXIONS, ENRICHISSEMENT],
        mitre=("T1078.004",),
    ),
    "phishing_signale": Playbook(
        name="phishing_signale",
        description=(
            "Un utilisateur transmet un courriel suspect. C'est le seul playbook qui "
            "mobilise les trois domaines : on établit l'usurpation par l'alignement, "
            "on enrichit les indicateurs extraits, puis on vérifie si le destinataire "
            "a effectivement été atteint."
        ),
        steps=[ANALYSE_ENTETES, ENRICHISSEMENT, CONTEXTE_UTILISATEUR, CONNEXIONS],
        mitre=("T1566.002", "T1078.004"),
    ),
    "usurpation_domaine": Playbook(
        name="usurpation_domaine",
        description=(
            "Le domaine est-il usurpable ? On évalue SPF, DKIM et DMARC ensemble, "
            "puis on vérifie si des comptes sont déjà signalés à risque."
        ),
        steps=[POSTURE_DOMAINE, COMPTES_A_RISQUE],
        mitre=("T1566.002",),
    ),
    "escalade_privileges": Playbook(
        name="escalade_privileges",
        description=(
            "Un rôle privilégié a été attribué. On vérifie la légitimité en "
            "remontant à l'initiateur : d'où s'est-il connecté, et cette connexion "
            "est-elle elle-même suspecte ?"
        ),
        steps=[AUDITS, CONTEXTE_UTILISATEUR, CONNEXIONS, ENRICHISSEMENT],
        mitre=("T1098", "T1078.004"),
    ),
}


def select_playbook(alert: Alert) -> Playbook:
    """Choisit le playbook applicable à une alerte.

    Le repli sur `compte_compromis` est délibéré : c'est la séquence la plus
    complète côté identité, donc celle qui laisse le moins de zones d'ombre
    quand la famille d'alerte n'est pas reconnue.
    """
    return PLAYBOOKS.get(alert.kind, PLAYBOOKS["compte_compromis"])

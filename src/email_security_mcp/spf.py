"""Analyse SPF, avec comptage des résolutions DNS.

Le point central de ce module tient en une phrase : **la norme SPF (RFC 7208,
§4.6.4) plafonne à dix le nombre de résolutions DNS déclenchées par
l'évaluation d'un enregistrement.** Au-delà, l'évaluation renvoie `permerror`
et le destinataire traite le message comme si SPF n'existait pas.

C'est la panne silencieuse la plus fréquente du domaine. Une organisation
ajoute Microsoft 365, puis un outil d'emailing, puis un CRM — chacun avec son
`include:` — et franchit la limite sans aucun signal. L'enregistrement continue
de *sembler* correct dans le portail DNS, mais il ne protège plus rien.
"""

from __future__ import annotations

import logging
import re

from .dns_client import CountingDnsResolver, DnsResolver
from .models import SpfMechanism, SpfReport

logger = logging.getLogger(__name__)

#: Plafond normatif de résolutions DNS pour une évaluation SPF.
MAX_LOOKUPS = 10

#: Seuil d'alerte anticipée : au-delà, l'ajout d'un seul prestataire fera
#: basculer le domaine. Alerter à la limite serait alerter trop tard.
SEUIL_ALERTE = 8

#: Mécanismes qui déclenchent une résolution DNS, et comptent donc au plafond.
MECANISMES_COUTEUX = {"include", "a", "mx", "ptr", "exists"}

#: Mécanismes gratuits : ils n'interrogent pas le DNS.
MECANISMES_GRATUITS = {"ip4", "ip6", "all"}

_MECANISME = re.compile(
    r"^(?P<qualifier>[+\-~?])?(?P<name>[a-z0-9]+)(?::(?P<value>\S+))?$", re.IGNORECASE
)

QUALIFICATEURS = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
}


def find_spf_record(txt_records: list[str]) -> str | None:
    """Extrait l'enregistrement SPF parmi les TXT d'un domaine.

    Un domaine ne doit publier qu'un seul enregistrement SPF. En publier
    plusieurs produit un `permerror` — erreur classique quand un prestataire
    ajoute le sien sans fusionner avec l'existant.
    """
    candidats = [t for t in txt_records if t.strip().lower().startswith("v=spf1")]
    return candidats[0] if candidats else None


def count_spf_records(txt_records: list[str]) -> int:
    return sum(1 for t in txt_records if t.strip().lower().startswith("v=spf1"))


async def analyse_spf(domain: str, resolver: DnsResolver) -> SpfReport:
    """Évalue l'enregistrement SPF d'un domaine et compte les résolutions."""
    domaine = domain.strip().lower().rstrip(".")
    compteur = CountingDnsResolver(resolver)

    txt = await compteur.txt(domaine)
    nombre = count_spf_records(txt)

    if nombre == 0:
        return SpfReport(
            domain=domaine,
            record=None,
            valid=False,
            dns_lookups=0,
            lookup_limit=MAX_LOOKUPS,
            all_qualifier=None,
            mechanisms=[],
            findings=[
                "Aucun enregistrement SPF publié : n'importe qui peut envoyer du "
                "courriel en se faisant passer pour ce domaine."
            ],
            severity="high",
        )

    if nombre > 1:
        return SpfReport(
            domain=domaine,
            record=find_spf_record(txt),
            valid=False,
            dns_lookups=0,
            lookup_limit=MAX_LOOKUPS,
            all_qualifier=None,
            mechanisms=[],
            findings=[
                f"{nombre} enregistrements SPF publiés au lieu d'un seul. La norme impose "
                "un `permerror` : SPF ne protège plus le domaine. Fusionner les "
                "enregistrements en un seul."
            ],
            severity="high",
        )

    enregistrement = find_spf_record(txt) or ""
    # Le premier lookup (le TXT du domaine lui-même) n'entre pas dans le
    # plafond : celui-ci ne compte que les résolutions déclenchées par les
    # mécanismes.
    compteur.lookups = 0
    compteur.void_lookups = 0

    mecanismes: list[SpfMechanism] = []
    constats: list[str] = []
    qualificateur_all: str | None = None

    await _evaluer(
        enregistrement, domaine, compteur, mecanismes, constats, profondeur=0, visites=set()
    )

    for mecanisme in mecanismes:
        if mecanisme.name == "all":
            qualificateur_all = mecanisme.qualifier

    # --- Constats de sécurité -----------------------------------------------
    depasse = compteur.lookups > MAX_LOOKUPS
    if depasse:
        constats.insert(
            0,
            f"{compteur.lookups} résolutions DNS pour un plafond de {MAX_LOOKUPS} : "
            "l'évaluation renvoie `permerror` et SPF NE PROTÈGE PLUS le domaine, "
            "alors que l'enregistrement paraît correct. Réduire le nombre "
            "d'`include:`, ou remplacer les moins utilisés par des `ip4:`.",
        )
    elif compteur.lookups >= SEUIL_ALERTE:
        constats.insert(
            0,
            f"{compteur.lookups} résolutions DNS sur un plafond de {MAX_LOOKUPS} : "
            "l'ajout d'un seul prestataire d'envoi fera basculer le domaine en "
            "`permerror`. Traiter avant d'en arriver là.",
        )

    if qualificateur_all is None:
        constats.append(
            "Aucun mécanisme `all` final : le comportement pour les expéditeurs non "
            "listés n'est pas défini. Terminer par `-all` ou `~all`."
        )
    elif qualificateur_all == "neutral":
        constats.append(
            "L'enregistrement se termine par `?all` (neutre) : il n'exprime aucune "
            "politique et n'apporte aucune protection."
        )
    elif qualificateur_all == "pass":
        constats.append(
            "L'enregistrement se termine par `+all` : TOUT expéditeur est autorisé. "
            "C'est équivalent à ne pas avoir de SPF, et souvent une erreur de saisie."
        )
    elif qualificateur_all == "softfail":
        constats.append(
            "L'enregistrement se termine par `~all` (softfail) : les messages non "
            "autorisés sont acceptés puis marqués. `-all` est plus strict, une fois "
            "la liste des expéditeurs légitimes vérifiée."
        )

    if compteur.void_lookups > 2:
        constats.append(
            f"{compteur.void_lookups} résolutions sans réponse : la norme en tolère 2. "
            "Des `include:` pointent vers des domaines qui ne publient plus de SPF."
        )

    if any(m.name == "ptr" for m in mecanismes):
        constats.append(
            "Le mécanisme `ptr` est déconseillé par la norme : lent, peu fiable, et "
            "certains destinataires l'ignorent purement et simplement."
        )

    gravite = _gravite(depasse, qualificateur_all, compteur.lookups)

    return SpfReport(
        domain=domaine,
        record=enregistrement,
        valid=not depasse,
        dns_lookups=compteur.lookups,
        lookup_limit=MAX_LOOKUPS,
        all_qualifier=qualificateur_all,
        mechanisms=mecanismes,
        findings=constats,
        severity=gravite,
    )


def _gravite(depasse: bool, qualificateur: str | None, lookups: int) -> str:
    if depasse or qualificateur in (None, "pass", "neutral"):
        return "high"
    if lookups >= SEUIL_ALERTE or qualificateur == "softfail":
        return "medium"
    return "low"


async def _evaluer(
    enregistrement: str,
    domaine: str,
    compteur: CountingDnsResolver,
    mecanismes: list[SpfMechanism],
    constats: list[str],
    profondeur: int,
    visites: set[str],
) -> None:
    """Parcourt récursivement l'enregistrement en comptant les résolutions."""
    # Garde-fou contre une boucle d'`include:` mutuels, que la norme
    # n'interdit pas explicitement mais qui ferait tourner l'analyse sans fin.
    if profondeur > MAX_LOOKUPS + 2 or domaine in visites:
        return
    visites.add(domaine)

    for jeton in enregistrement.split():
        if jeton.lower().startswith("v=spf1"):
            continue

        if jeton.lower().startswith("redirect="):
            cible = jeton.split("=", 1)[1]
            mecanismes.append(
                SpfMechanism(
                    name="redirect",
                    qualifier="pass",
                    value=cible,
                    costs_lookup=True,
                    depth=profondeur,
                )
            )
            await _suivre(cible, compteur, mecanismes, constats, profondeur, visites)
            continue

        if jeton.lower().startswith("exp="):
            continue  # explication textuelle : aucune résolution

        parse = _MECANISME.match(jeton)
        if parse is None:
            constats.append(f"Mécanisme non reconnu, ignoré : « {jeton} ».")
            continue

        nom = parse["name"].lower()
        qualificateur = QUALIFICATEURS.get(parse["qualifier"] or "+", "pass")
        valeur = parse["value"]
        couteux = nom in MECANISMES_COUTEUX

        mecanismes.append(
            SpfMechanism(
                name=nom,
                qualifier=qualificateur,
                value=valeur,
                costs_lookup=couteux,
                depth=profondeur,
            )
        )

        if nom == "include" and valeur:
            await _suivre(valeur, compteur, mecanismes, constats, profondeur, visites)
        elif nom in {"a", "mx", "ptr", "exists"}:
            # Ces mécanismes déclenchent une résolution sans en imbriquer
            # d'autres : on la compte sans descendre.
            cible = valeur or domaine
            if nom == "mx":
                await compteur.mx(cible)
            else:
                await compteur.txt(cible)


async def _suivre(
    cible: str,
    compteur: CountingDnsResolver,
    mecanismes: list[SpfMechanism],
    constats: list[str],
    profondeur: int,
    visites: set[str],
) -> None:
    """Résout et évalue un `include:` ou un `redirect=`."""
    if compteur.lookups > MAX_LOOKUPS + 5:
        # On continue de compter au-delà du plafond pour rapporter l'ampleur du
        # dépassement, mais on borne le travail réel.
        return

    txt = await compteur.txt(cible)
    imbrique = find_spf_record(txt)
    if imbrique is None:
        constats.append(
            f"« {cible} » ne publie pas d'enregistrement SPF : cette résolution est "
            "consommée pour rien."
        )
        return

    await _evaluer(imbrique, cible, compteur, mecanismes, constats, profondeur + 1, visites)

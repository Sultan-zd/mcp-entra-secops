"""Transparence des certificats : découvrir ce qui existe sous un domaine.

Chaque certificat émis publiquement est inscrit dans des journaux publics et
inaltérables. C'est la meilleure source de découverte de sous-domaines qui
soit : elle ne demande aucune permission, ne touche pas au domaine, et révèle
même ce qui n'a jamais eu d'enregistrement DNS public.

**Le piège que ce module traite.** Les hébergeurs mutualisés regroupent des
dizaines de clients dans un même certificat. Interroger la transparence pour
`teknologiia.com` rend 270 noms — dont la plupart appartiennent à d'autres
entreprises. Les lister comme « vos sous-domaines » serait faux, et un rapport
d'audit qui affirme cela perd toute crédibilité.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from argus_net import HttpError, PublicHttpClient

logger = logging.getLogger(__name__)

CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
CRTSH = "https://crt.sh/"


@dataclass
class ResultatCt:
    """Ce que les journaux de transparence révèlent d'un domaine."""

    domain: str
    source: str
    issuances_seen: int = 0
    subdomains: list[str] = field(default_factory=list)
    wildcards: list[str] = field(default_factory=list)
    foreign_names_excluded: int = 0
    findings: list[str] = field(default_factory=list)


def _appartient(nom: str, domaine: str) -> bool:
    """Ce nom est-il réellement sous le domaine demandé ?

    La comparaison porte sur les étiquettes, pas sur le texte : sans cela,
    « faux-teknologiia.com » passerait pour un sous-domaine de
    « teknologiia.com ».
    """
    n = nom.lower().rstrip(".").removeprefix("*.")
    d = domaine.lower().rstrip(".")
    return n == d or n.endswith("." + d)


async def decouvrir(domaine: str, http: PublicHttpClient, *, limite: int = 200) -> ResultatCt:
    """Liste les sous-domaines apparus dans les journaux de transparence."""
    resultat = ResultatCt(domain=domaine, source="certspotter")

    try:
        charge = await http.get_json(
            CERTSPOTTER,
            source="Certificate Transparency",
            params={
                "domain": domaine,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
        )
    except HttpError as exc:
        # crt.sh est régulièrement indisponible ; il sert de recours, pas de
        # source principale.
        logger.info("Certspotter indisponible (%s), tentative sur crt.sh.", exc)
        return await _via_crtsh(domaine, http, limite)

    if not isinstance(charge, list):
        raise HttpError("Certificate Transparency", "réponse inattendue.")

    resultat.issuances_seen = len(charge)
    tous: set[str] = set()
    for emission in charge:
        for nom in emission.get("dns_names") or []:
            tous.add(str(nom).lower().rstrip("."))

    return _trier(resultat, tous, limite)


async def _via_crtsh(domaine: str, http: PublicHttpClient, limite: int) -> ResultatCt:
    resultat = ResultatCt(domain=domaine, source="crt.sh")
    charge = await http.get_json(
        CRTSH, source="crt.sh", params={"q": f"%.{domaine}", "output": "json"}
    )
    if not isinstance(charge, list):
        raise HttpError("crt.sh", "réponse inattendue.")

    resultat.issuances_seen = len(charge)
    tous: set[str] = set()
    for entree in charge:
        for nom in str(entree.get("name_value") or "").split("\n"):
            if nom.strip():
                tous.add(nom.strip().lower().rstrip("."))

    return _trier(resultat, tous, limite)


def _trier(resultat: ResultatCt, tous: set[str], limite: int) -> ResultatCt:
    """Sépare ce qui appartient au domaine de ce qui vient d'un certificat partagé."""
    a_nous = {n for n in tous if _appartient(n, resultat.domain)}
    resultat.foreign_names_excluded = len(tous) - len(a_nous)

    resultat.wildcards = sorted(n for n in a_nous if n.startswith("*."))
    resultat.subdomains = sorted(n for n in a_nous if not n.startswith("*."))[:limite]

    if resultat.foreign_names_excluded:
        resultat.findings.append(
            f"{resultat.foreign_names_excluded} nom(s) figurant dans les mêmes "
            "certificats appartiennent à d'autres domaines — signature d'un "
            "hébergement mutualisé. Ils sont exclus : les présenter comme vos "
            "sous-domaines serait faux."
        )

    if resultat.wildcards:
        resultat.findings.append(
            f"Certificat(s) joker : {', '.join(resultat.wildcards[:3])}. "
            "Un joker compromis couvre tous les sous-domaines à la fois."
        )

    interessants = [
        s
        for s in resultat.subdomains
        if any(m in s for m in ("dev", "test", "staging", "preprod", "uat", "demo"))
    ]
    if interessants:
        resultat.findings.append(
            "Environnements hors production exposés publiquement : "
            + ", ".join(interessants[:5])
            + ". Ils portent souvent des données réelles et des protections moindres."
        )

    return resultat

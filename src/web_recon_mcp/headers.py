"""En-têtes de sécurité HTTP, récupérés et notés localement.

La réponse est allée chercher les en-têtes elle-même ; la note est calculée
ici, par du code testé. Aucun service tiers n'est consulté — ce qui permet
d'auditer un site interne, et garantit que la note ne change pas parce qu'un
prestataire a modifié son barème.

Les pondérations reflètent **ce qu'un attaquant peut faire de l'absence**, pas
la longueur de la liste des bonnes pratiques.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

#: Poids de chaque en-tête. HSTS et CSP dominent parce que leur absence ouvre
#: des attaques concrètes — interception au premier accès, injection de script —
#: là où les autres durcissent la marge.
POIDS = {
    "strict-transport-security": 25,
    "content-security-policy": 25,
    "x-content-type-options": 15,
    "x-frame-options": 15,
    "referrer-policy": 10,
    "permissions-policy": 10,
}

EXPLICATIONS = {
    "strict-transport-security": (
        "Sans HSTS, un attaquant sur le réseau peut intercepter la toute première "
        "requête, avant toute redirection vers HTTPS."
    ),
    "content-security-policy": (
        "Sans CSP, une faille d'injection de contenu devient une exécution de script "
        "dans le navigateur de vos utilisateurs."
    ),
    "x-content-type-options": (
        "Sans « nosniff », le navigateur devine le type d'un fichier : un document "
        "téléversé peut être interprété comme du script."
    ),
    "x-frame-options": (
        "Sans protection contre l'encadrement, le site peut être superposé à un leurre "
        "pour piéger les clics des utilisateurs."
    ),
    "referrer-policy": (
        "Sans politique de référent, les URL internes — jetons compris — fuient vers "
        "les sites tiers visités depuis vos pages."
    ),
    "permissions-policy": (
        "Sans politique de permissions, un script embarqué peut demander la caméra, "
        "le micro ou la position."
    ),
}

#: En-têtes qui en disent trop sur la pile technique. Ce n'est pas une faille,
#: mais cela oriente un attaquant vers les exploits qui ont une chance.
BAVARDS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")

#: Une durée HSTS inférieure à six mois n'est pas prise au sérieux par les
#: listes de préchargement, et laisse une fenêtre trop large.
HSTS_MINIMUM = 15_552_000


@dataclass
class ResultatEntetes:
    """Ce que les en-têtes d'une réponse révèlent."""

    url: str
    final_url: str
    status: int
    score: int = 0
    grade: str = "F"
    present: dict[str, str] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    disclosed: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    redirects_to_https: bool | None = None
    severity: str = "medium"


def _note_lettree(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 55:
        return "C"
    if score >= 35:
        return "D"
    return "F"


def _analyser_cookies(reponse: httpx.Response) -> list[dict[str, Any]]:
    """Les attributs de sécurité de chaque cookie posé.

    Un cookie de session sans `HttpOnly` est lisible par n'importe quel script :
    c'est ce qui transforme une injection en vol de session.
    """
    analyses = []
    for brut in reponse.headers.get_list("set-cookie"):
        nom = brut.split("=", 1)[0].strip()
        bas = brut.lower()
        samesite = re.search(r"samesite=(\w+)", bas)
        analyses.append(
            {
                "name": nom,
                "secure": "secure" in bas,
                "http_only": "httponly" in bas,
                "same_site": samesite.group(1) if samesite else None,
            }
        )
    return analyses


async def analyser(url: str, *, delai: float = 15.0) -> ResultatEntetes:
    """Récupère une page et note ses en-têtes de sécurité."""
    cible = url if url.startswith(("http://", "https://")) else f"https://{url}"

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(delai),
        follow_redirects=True,
        headers={"User-Agent": "ARGUS-SecOps/1.0 (audit de configuration)"},
    ) as client:
        reponse = await client.get(cible)

    resultat = ResultatEntetes(url=cible, final_url=str(reponse.url), status=reponse.status_code)

    # Une redirection de HTTP vers HTTPS est la base ; l'absence de redirection
    # signifie que le site répond en clair.
    if cible.startswith("http://"):
        resultat.redirects_to_https = str(reponse.url).startswith("https://")

    entetes = {k.lower(): v for k, v in reponse.headers.items()}
    score = 0
    constats: list[str] = []

    for entete, poids in POIDS.items():
        valeur = entetes.get(entete)
        if valeur:
            resultat.present[entete] = valeur[:200]
            score += poids
        else:
            resultat.missing.append(entete)
            constats.append(f"{entete} absent. {EXPLICATIONS[entete]}")

    # HSTS présent mais trop court reste une demi-mesure.
    hsts = entetes.get("strict-transport-security")
    if hsts:
        age = re.search(r"max-age=(\d+)", hsts.lower())
        duree = int(age.group(1)) if age else 0
        if duree < HSTS_MINIMUM:
            constats.append(
                f"HSTS d'une durée de {duree} s, en dessous des six mois attendus : "
                "trop court pour les listes de préchargement."
            )
            score -= 10
        if "includesubdomains" not in hsts.lower():
            constats.append(
                "HSTS ne couvre pas les sous-domaines : un sous-domaine en clair "
                "reste interceptable."
            )
            score -= 5

    # CSP permissive : présente mais désarmée.
    csp = entetes.get("content-security-policy", "").lower()
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
        constats.append(
            "La CSP autorise « unsafe-inline » ou « unsafe-eval » : elle ne protège "
            "plus contre l'injection de script, ce pour quoi elle existe."
        )
        score -= 15

    for entete in BAVARDS:
        if entete in entetes:
            resultat.disclosed[entete] = entetes[entete][:120]
    if resultat.disclosed:
        constats.append(
            "En-têtes divulguant la pile technique : "
            + ", ".join(resultat.disclosed)
            + ". Ils orientent un attaquant vers les exploits qui ont une chance."
        )
        score -= 5

    resultat.cookies = _analyser_cookies(reponse)
    fragiles = [c["name"] for c in resultat.cookies if not c["http_only"] or not c["secure"]]
    if fragiles:
        constats.append(
            f"Cookie(s) sans « Secure » ou « HttpOnly » : {', '.join(fragiles[:5])}. "
            "Un cookie de session lisible par un script transforme une injection en "
            "vol de session."
        )
        score -= 10

    resultat.score = max(0, min(100, score))
    resultat.grade = _note_lettree(resultat.score)
    resultat.findings = constats
    resultat.severity = (
        "high"
        if resultat.score < 40
        else "medium"
        if resultat.score < 75
        else "low"
        if resultat.score < 90
        else "none"
    )
    return resultat

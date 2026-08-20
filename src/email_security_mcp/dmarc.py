"""Analyse DMARC : la politique qui donne son sens à SPF et DKIM.

SPF et DKIM ne disent pas au destinataire quoi faire d'un message qui échoue.
C'est DMARC qui l'exprime — et c'est pourquoi une politique `p=none` est le
piège le plus courant : le domaine *paraît* protégé, mais rien n'est appliqué.
"""

from __future__ import annotations

import logging
import re

from .dns_client import DnsResolver
from .models import DmarcReport, Severity

logger = logging.getLogger(__name__)

_ADRESSE = re.compile(r"mailto:([^,!]+)", re.IGNORECASE)


def parse_dmarc_record(txt: str) -> dict[str, str]:
    """Décompose un enregistrement DMARC en paires clé/valeur."""
    champs: dict[str, str] = {}
    for partie in txt.split(";"):
        if "=" not in partie:
            continue
        cle, _, valeur = partie.partition("=")
        champs[cle.strip().lower()] = valeur.strip()
    return champs


async def analyse_dmarc(domain: str, resolver: DnsResolver) -> DmarcReport:
    """Lit et évalue la politique DMARC d'un domaine."""
    domaine = domain.strip().lower().rstrip(".")
    txt = await resolver.txt(f"_dmarc.{domaine}")
    brut = next((t for t in txt if t.strip().lower().startswith("v=dmarc1")), None)

    if brut is None:
        return DmarcReport(
            domain=domaine,
            record=None,
            policy=None,
            findings=[
                "Aucune politique DMARC publiée. Sans elle, SPF et DKIM ne disent pas "
                "au destinataire quoi faire d'un message frauduleux, et le domaine "
                "reste usurpable. Commencer par `v=DMARC1; p=none; rua=mailto:…` pour "
                "observer, puis durcir."
            ],
            severity="high",
        )

    champs = parse_dmarc_record(brut)
    politique = champs.get("p", "").lower() or None
    sous_domaines = champs.get("sp", "").lower() or None
    alignement_spf = champs.get("aspf", "r").lower()
    alignement_dkim = champs.get("adkim", "r").lower()

    try:
        pourcentage = max(0, min(100, int(champs.get("pct", "100"))))
    except ValueError:
        pourcentage = 100

    rua = _ADRESSE.findall(champs.get("rua", ""))
    ruf = _ADRESSE.findall(champs.get("ruf", ""))

    constats: list[str] = []

    if politique is None:
        constats.append("Enregistrement DMARC sans balise `p=` : il est invalide et ignoré.")
        gravite: Severity = "high"
    elif politique == "none":
        constats.append(
            "Politique `p=none` : les messages frauduleux sont acceptés et livrés. "
            "C'est un mode d'observation, PAS une protection. Passer à "
            "`p=quarantine` une fois les rapports agrégés analysés."
        )
        gravite = "high"
    elif politique == "quarantine":
        constats.append(
            "Politique `p=quarantine` : les messages frauduleux partent en indésirables. "
            "C'est une protection réelle ; `p=reject` les bloque à la source."
        )
        gravite = "medium"
    elif politique == "reject":
        constats.append("Politique `p=reject` : les messages frauduleux sont rejetés.")
        gravite = "low"
    else:
        constats.append(f"Valeur de politique inconnue : « {politique} ».")
        gravite = "high"

    # Le pourcentage est le piège discret : une politique `reject` appliquée à
    # 10 % du trafic laisse passer neuf messages frauduleux sur dix, tout en
    # affichant la politique la plus stricte.
    if pourcentage < 100:
        constats.append(
            f"`pct={pourcentage}` : la politique ne s'applique qu'à {pourcentage} % des "
            f"messages. Les {100 - pourcentage} % restants sont traités comme si la "
            "politique était `none`. Étape de déploiement acceptable, état final non."
        )
        if gravite == "low":
            gravite = "medium"

    if not rua:
        constats.append(
            "Aucune adresse `rua=` : le domaine ne reçoit pas les rapports agrégés. "
            "Sans eux, impossible de savoir qui envoie du courriel en son nom, ni de "
            "durcir la politique en connaissance de cause."
        )
        if gravite == "low":
            gravite = "medium"

    if sous_domaines == "none" and politique in {"quarantine", "reject"}:
        constats.append(
            "`sp=none` : les sous-domaines ne sont pas protégés alors que le domaine "
            "principal l'est. Un attaquant usurpera `facture.exemple.com` plutôt que "
            "`exemple.com`."
        )
        gravite = "high"

    if alignement_spf == "r" and alignement_dkim == "r" and politique == "reject":
        constats.append(
            "Alignement relâché sur SPF et DKIM : un sous-domaine compromis suffit à "
            "produire un message aligné. `aspf=s` et `adkim=s` durcissent le contrôle."
        )

    if ruf:
        constats.append(
            "Des rapports d'échec (`ruf=`) sont demandés : ils contiennent des extraits "
            "de messages réels. Vérifier que la boîte destinataire est protégée en "
            "conséquence."
        )

    return DmarcReport(
        domain=domaine,
        record=brut,
        policy=politique,
        subdomain_policy=sous_domaines,
        percentage=pourcentage,
        aggregate_reports=rua,
        forensic_reports=ruf,
        spf_alignment=alignement_spf,
        dkim_alignment=alignement_dkim,
        findings=constats,
        severity=gravite,
    )

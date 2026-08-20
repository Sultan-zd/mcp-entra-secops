"""Synthèse de la posture d'un domaine : SPF, DKIM et DMARC ensemble.

Les trois mécanismes ne se valent pas et ne se remplacent pas. DMARC pèse le
plus lourd dans la note, parce que c'est le seul qui exprime une décision : sans
lui, SPF et DKIM produisent des constats que personne n'applique.
"""

from __future__ import annotations

from .models import DkimReport, DmarcReport, DomainPosture, Severity, SpfReport

#: Répartition des points. Le total fait 100.
POIDS_SPF = 30
POIDS_DKIM = 25
POIDS_DMARC = 45


def _points_spf(rapport: SpfReport) -> int:
    if rapport.record is None or not rapport.valid:
        return 0
    if rapport.all_qualifier == "fail":
        note = POIDS_SPF
    elif rapport.all_qualifier == "softfail":
        note = int(POIDS_SPF * 0.7)
    else:
        return 0  # ?all ou +all n'expriment aucune restriction

    # Le domaine fonctionne, mais il est à un prestataire de la panne.
    if rapport.dns_lookups >= 8:
        note = int(note * 0.6)
    return note


def _points_dkim(rapport: DkimReport) -> int:
    if rapport.keys_found == 0:
        return 0
    note = POIDS_DKIM
    if any(c.testing for c in rapport.keys if c.found):
        note = int(note * 0.4)  # t=y demande d'ignorer les échecs
    elif any(c.key_bits and c.key_bits < 2048 for c in rapport.keys if c.found):
        note = int(note * 0.7)
    return note


def _points_dmarc(rapport: DmarcReport) -> int:
    if rapport.policy is None:
        return 0
    base = {"reject": POIDS_DMARC, "quarantine": int(POIDS_DMARC * 0.7), "none": 0}.get(
        rapport.policy, 0
    )
    if base and rapport.percentage < 100:
        base = int(base * rapport.percentage / 100)
    if base and not rapport.aggregate_reports:
        base = int(base * 0.85)  # sans rapports, impossible de durcir en connaissance
    if base and rapport.subdomain_policy == "none":
        base = int(base * 0.6)  # les sous-domaines restent usurpables
    return base


def _note_lettree(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 55:
        return "C"
    if score >= 35:
        return "D"
    if score >= 15:
        return "E"
    return "F"


def build_posture(
    domain: str, spf: SpfReport, dkim: DkimReport, dmarc: DmarcReport
) -> DomainPosture:
    """Assemble la note de posture et classe les actions par gain décroissant."""
    score = _points_spf(spf) + _points_dkim(dkim) + _points_dmarc(dmarc)

    # Chaque action est associée au gain qu'elle apporte, pour que le classement
    # reflète l'effet réel plutôt qu'un ordre arbitraire.
    actions: list[tuple[int, str]] = []

    if dmarc.policy is None:
        actions.append(
            (
                POIDS_DMARC,
                "Publier une politique DMARC. Commencer par `v=DMARC1; p=none; "
                "rua=mailto:dmarc@<domaine>` pour observer sans risque, puis durcir.",
            )
        )
    elif dmarc.policy == "none":
        actions.append(
            (
                POIDS_DMARC,
                "Passer DMARC de `p=none` à `p=quarantine`. En l'état, les messages "
                "frauduleux sont livrés : le domaine n'est pas protégé.",
            )
        )
    elif dmarc.policy == "quarantine":
        actions.append(
            (
                int(POIDS_DMARC * 0.3),
                "Passer DMARC de `p=quarantine` à `p=reject` une fois les rapports "
                "agrégés exempts d'expéditeurs légitimes en échec.",
            )
        )

    if not spf.valid and spf.record:
        actions.append(
            (
                POIDS_SPF,
                f"Réduire l'enregistrement SPF sous les 10 résolutions DNS "
                f"({spf.dns_lookups} actuellement). Au-delà, SPF est en `permerror` et "
                "ne protège plus rien.",
            )
        )
    elif spf.record is None:
        actions.append((POIDS_SPF, "Publier un enregistrement SPF terminé par `-all`."))
    elif spf.all_qualifier in {"neutral", "pass"}:
        actions.append(
            (
                POIDS_SPF,
                f"Remplacer le `all` final ({spf.all_qualifier}) par `-all` : "
                "l'enregistrement actuel n'exprime aucune restriction.",
            )
        )
    elif spf.dns_lookups >= 8:
        actions.append(
            (
                int(POIDS_SPF * 0.4),
                f"Anticiper : {spf.dns_lookups} résolutions DNS sur 10. L'ajout d'un "
                "prestataire fera basculer le domaine en `permerror`.",
            )
        )

    if dkim.keys_found == 0:
        actions.append(
            (
                POIDS_DKIM,
                "Activer la signature DKIM chez le prestataire d'envoi, ou préciser le "
                "sélecteur utilisé s'il est non standard.",
            )
        )
    elif any(c.testing for c in dkim.keys if c.found):
        actions.append(
            (
                int(POIDS_DKIM * 0.6),
                "Retirer l'indicateur `t=y` des clés DKIM : il demande aux destinataires "
                "d'ignorer les échecs de vérification.",
            )
        )

    if dmarc.policy in {"quarantine", "reject"} and dmarc.subdomain_policy == "none":
        actions.append(
            (
                int(POIDS_DMARC * 0.4),
                "Aligner `sp=` sur la politique principale : les sous-domaines sont "
                "actuellement usurpables alors que le domaine ne l'est plus.",
            )
        )

    if dmarc.policy and not dmarc.aggregate_reports:
        actions.append(
            (
                10,
                "Ajouter une adresse `rua=` : sans rapports agrégés, impossible de savoir "
                "qui envoie du courriel au nom du domaine.",
            )
        )

    actions.sort(key=lambda x: x[0], reverse=True)

    gravite: Severity = "low" if score >= 75 else "medium" if score >= 40 else "high"

    return DomainPosture(
        domain=domain,
        score=score,
        grade=_note_lettree(score),
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        priority_actions=[texte for _, texte in actions],
        severity=gravite,
    )

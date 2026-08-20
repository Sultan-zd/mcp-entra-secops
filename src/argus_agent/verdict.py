"""Construction du verdict à partir des constats collectés.

Ce module concentre la décision. Il est délibérément séparé de l'orchestration
pour pouvoir être testé seul, sur des contextes fabriqués, sans lancer aucun
outil.

L'arbitrage central : **les faux positifs et les faux négatifs ne se valent
pas.** Un faux positif coûte quelques minutes à un analyste ; un faux négatif
laisse un attaquant dans le système d'information. La pondération penche donc
délibérément vers l'alerte, et le doute déclenche une escalade plutôt qu'un
classement en « bénin ».
"""

from __future__ import annotations

from typing import Any

from .models import Alert, ProposedAction, Severity, TriageStep, TriageVerdict, Verdict
from .playbooks import Playbook

#: Poids attribués aux constats. Chaque valeur répond à la question : « de
#: combien ce signal, seul, doit-il rapprocher d'une conclusion de malveillance ? »
POIDS = {
    "ioc_malveillant": 45,
    "succes_apres_echecs": 35,
    "echecs_repetes": 25,
    "message_usurpe": 40,
    "identifiants_divulgues": 25,
    "audit_sensible": 20,
    "risque_eleve": 20,
    "protocole_herite": 15,
    "ioc_suspect": 15,
    "posture_defaillante": 15,
}

SEUIL_MALVEILLANT = 60
SEUIL_SUSPECT = 25


def _signaux(contexte: dict[str, Any]) -> list[tuple[str, int, str]]:
    """Extrait les signaux exploitables du contexte, avec leur justification."""
    trouves: list[tuple[str, int, str]] = []

    signins = contexte.get("get_user_signins") or {}
    if signins:
        echecs = signins.get("failures", 0)
        succes = signins.get("successes", 0)
        if echecs >= 5 and succes >= 1:
            trouves.append(
                (
                    "succes_apres_echecs",
                    POIDS["succes_apres_echecs"],
                    f"{echecs} échecs d'authentification suivis de {succes} connexion(s) "
                    "réussie(s) : motif caractéristique d'une compromission aboutie.",
                )
            )
        elif echecs >= 5:
            # Une attaque qui n'a pas encore abouti reste une attaque. La
            # classer « bénigne » parce que l'attaquant a échoué reviendrait à
            # n'alerter qu'une fois le compte perdu.
            trouves.append(
                (
                    "echecs_repetes",
                    POIDS["echecs_repetes"],
                    f"{echecs} échecs d'authentification sans succès : tentative "
                    "d'intrusion en cours, qui n'a pas encore abouti.",
                )
            )
        for note in signins.get("notes") or []:
            if "hérités" in note:
                trouves.append(
                    (
                        "protocole_herite",
                        POIDS["protocole_herite"],
                        "Utilisation de protocoles d'authentification hérités, qui "
                        "contournent la MFA.",
                    )
                )
                break

    enrichi = contexte.get("bulk_enrich") or {}
    if enrichi.get("malicious", 0):
        noms = [r["indicator"] for r in enrichi.get("results", []) if r["verdict"] == "malicious"]
        trouves.append(
            (
                "ioc_malveillant",
                POIDS["ioc_malveillant"],
                f"{enrichi['malicious']} indicateur(s) confirmé(s) malveillant(s) par le "
                f"renseignement externe : {', '.join(noms[:3])}.",
            )
        )
    elif enrichi.get("suspicious", 0):
        trouves.append(
            (
                "ioc_suspect",
                POIDS["ioc_suspect"],
                f"{enrichi['suspicious']} indicateur(s) suspect(s), sans confirmation ferme.",
            )
        )

    detections = contexte.get("get_risk_detections") or {}
    types = detections.get("distinct_types") or []
    if "leakedCredentials" in types:
        trouves.append(
            (
                "identifiants_divulgues",
                POIDS["identifiants_divulgues"],
                "Identifiants du compte trouvés dans une fuite publique : la "
                "réinitialisation du mot de passe est impérative.",
            )
        )

    audits = contexte.get("get_directory_audits") or {}
    if audits.get("sensitive_entries", 0):
        trouves.append(
            (
                "audit_sensible",
                POIDS["audit_sensible"],
                f"{audits['sensitive_entries']} modification(s) d'annuaire sensible(s) : "
                "attribution de rôle, secret applicatif ou méthode MFA ajoutée.",
            )
        )

    risque = contexte.get("get_risky_users") or {}
    if risque.get("high_risk", 0):
        trouves.append(
            (
                "risque_eleve",
                POIDS["risque_eleve"],
                f"{risque['high_risk']} compte(s) au niveau de risque élevé selon "
                "Identity Protection.",
            )
        )

    entetes = contexte.get("analyze_email_headers") or {}
    if entetes.get("verdict") in {"spoofed", "suspicious"}:
        trouves.append(
            (
                "message_usurpe",
                POIDS["message_usurpe"] if entetes["verdict"] == "spoofed" else 20,
                f"Message jugé « {entetes['verdict']} » : l'adresse affichée n'est pas "
                "authentifiée par les mécanismes d'alignement.",
            )
        )

    posture = contexte.get("check_domain_posture") or {}
    if posture and posture.get("score", 100) < 40:
        trouves.append(
            (
                "posture_defaillante",
                POIDS["posture_defaillante"],
                f"Posture de messagerie {posture.get('grade')} ({posture.get('score')}/100) : "
                "le domaine est usurpable.",
            )
        )

    return trouves


def _gravite(score: int, privilegie: bool, verdict: Verdict) -> Severity:
    """La gravité tient compte du contexte métier, pas seulement du score.

    Un compte administrateur compromis et un compte sans privilège compromis
    produisent le même score technique, mais pas le même incident.
    """
    if verdict == "benign":
        return "none"
    if verdict == "malicious":
        return "critical" if privilegie else "high"
    if verdict == "suspicious":
        return "high" if privilegie else "medium"
    return "medium" if privilegie else "low"


def _actions(contexte: dict[str, Any], signaux: set[str], privilegie: bool) -> list[ProposedAction]:
    """Propose les actions de remédiation, jamais exécutées par l'agent."""
    proposees: list[ProposedAction] = []

    if {"succes_apres_echecs", "ioc_malveillant"} & signaux:
        proposees.append(
            ProposedAction(
                action="revoke_user_sessions",
                label="Révoquer les sessions actives",
                rationale=(
                    "Une session déjà ouverte survit à un changement de mot de passe : "
                    "la révocation doit précéder toute autre mesure."
                ),
                priority="immediate",
            )
        )

    if "identifiants_divulgues" in signaux or "succes_apres_echecs" in signaux:
        proposees.append(
            ProposedAction(
                action="require_password_reset",
                label="Forcer la réinitialisation du mot de passe",
                rationale=(
                    "Les identifiants sont connus de l'attaquant : la révocation de "
                    "session seule ne suffit pas."
                ),
                priority="immediate",
            )
        )

    audits = contexte.get("get_directory_audits") or {}
    sensibles = [e for e in audits.get("entries") or [] if e.get("security_note")]
    if sensibles:
        proposees.append(
            ProposedAction(
                action="review_directory_changes",
                label="Annuler les modifications d'annuaire non légitimes",
                rationale=(
                    "Méthode MFA enrôlée, rôle attribué ou secret applicatif ajouté : "
                    "ces changements survivent à la réinitialisation du mot de passe et "
                    "constituent la persistance la plus durable."
                ),
                priority="immediate" if privilegie else "high",
            )
        )

    if privilegie and {"succes_apres_echecs", "ioc_malveillant"} & signaux:
        proposees.append(
            ProposedAction(
                action="disable_user_account",
                label="Désactiver le compte",
                rationale=(
                    "Le compte détient des privilèges élevés : la désactivation limite "
                    "l'impact le temps de l'investigation."
                ),
                priority="high",
            )
        )

    entetes = contexte.get("analyze_email_headers") or {}
    if entetes.get("verdict") == "spoofed":
        proposees.append(
            ProposedAction(
                action="block_sender_domain",
                label="Bloquer le domaine expéditeur",
                rationale=(
                    f"Le domaine « {entetes.get('return_path_domain')} » émet des messages "
                    "usurpant l'organisation."
                ),
                priority="high",
            )
        )

    posture = contexte.get("check_domain_posture") or {}
    for action in (posture.get("priority_actions") or [])[:2]:
        proposees.append(
            ProposedAction(
                action="harden_email_posture",
                label="Durcir la posture de messagerie",
                rationale=action,
                priority="normal",
                requires_approval=False,
            )
        )

    return proposees


def build_verdict(
    alert: Alert,
    playbook: Playbook,
    contexte: dict[str, Any],
    steps: list[TriageStep],
) -> TriageVerdict:
    """Assemble le verdict à partir des constats, de façon reproductible."""
    signaux = _signaux(contexte)
    score = min(100, sum(poids for _, poids, _ in signaux))
    noms = {nom for nom, _, _ in signaux}

    contexte_utilisateur = contexte.get("get_user_context") or {}
    privilegie = bool(contexte_utilisateur.get("is_privileged"))

    if score >= SEUIL_MALVEILLANT:
        verdict: Verdict = "malicious"
    elif score >= SEUIL_SUSPECT:
        verdict = "suspicious"
    elif steps and any(s.status == "ok" for s in steps):
        verdict = "benign"
    else:
        verdict = "inconclusive"

    # La confiance décroît quand des étapes ont échoué : un verdict rendu sur
    # des données partielles doit le dire.
    executees = [s for s in steps if s.status != "skipped"]
    reussies = [s for s in executees if s.status == "ok"]
    couverture = len(reussies) / len(executees) if executees else 0.0
    confiance = round(min(0.95, 0.35 + 0.6 * couverture), 2)
    if verdict == "inconclusive":
        confiance = min(confiance, 0.4)

    # Un compte privilégié passe systématiquement par l'humain, quel que soit le
    # score : l'impact d'une erreur y est trop élevé pour une décision automatique.
    escalade = (
        confiance < 0.6
        or verdict in {"malicious", "inconclusive"}
        or (privilegie and verdict != "benign")
    )

    lignes = [f"[{s.index}] {s.tool} — {s.summary}" for s in steps if s.status == "ok"]

    if signaux:
        synthese = f"Verdict « {verdict} » (score {score}/100). " + " ".join(
            justification for _, _, justification in signaux[:4]
        )
    else:
        synthese = (
            "Aucun signal de compromission relevé par le playbook "
            f"« {playbook.name} ». Les {len(reussies)} outil(s) interrogé(s) n'ont "
            "rien rapporté d'anormal."
        )

    if privilegie:
        roles = ", ".join(contexte_utilisateur.get("privileged_roles") or [])
        synthese += (
            f" Le compte détient des privilèges élevés ({roles}) : l'impact d'une "
            "compromission serait majeur."
        )

    if any(s.status == "error" for s in steps):
        synthese += (
            " Attention : une ou plusieurs étapes ont échoué, le verdict repose donc "
            "sur des données partielles."
        )

    return TriageVerdict(
        alert=alert,
        verdict=verdict,
        severity=_gravite(score, privilegie, verdict),
        confidence=confiance,
        summary=synthese[:1200],
        timeline=lignes,
        indicators=list(contexte.get("indicators") or [])[:20],
        mitre_techniques=list(playbook.mitre) if verdict != "benign" else [],
        recommended_actions=_actions(contexte, noms, privilegie),
        escalate_to_human=escalade,
        steps=steps,
        duration_ms=0,
        tools_called=len(reussies),
    )

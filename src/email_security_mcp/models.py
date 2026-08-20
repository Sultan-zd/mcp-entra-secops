"""Modèles de sortie du serveur de sécurité de la messagerie.

Chaque rapport porte deux choses en plus des données brutes : une **gravité**
et des **constats rédigés**. Un enregistrement SPF affiché tel quel ne dit rien
à un analyste ; « 12 résolutions DNS sur un plafond de 10, SPF ne protège plus »
lui dit quoi faire.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["high", "medium", "low", "none"]
AuthResult = Literal["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]


class SpfMechanism(BaseModel):
    """Un mécanisme d'un enregistrement SPF."""

    name: str = Field(description="Nom du mécanisme : include, ip4, a, mx, all…")
    qualifier: str = Field(description="pass, fail, softfail ou neutral.")
    value: str | None = Field(default=None, description="Cible du mécanisme, le cas échéant.")
    costs_lookup: bool = Field(description="Ce mécanisme déclenche-t-il une résolution DNS ?")
    depth: int = Field(description="Niveau d'imbrication, 0 pour l'enregistrement racine.")


class SpfReport(BaseModel):
    """Résultat de `check_spf`."""

    domain: str = Field(description="Domaine analysé.")
    record: str | None = Field(default=None, description="Enregistrement SPF publié.")
    valid: bool = Field(description="L'évaluation aboutit-elle sans erreur permanente ?")
    dns_lookups: int = Field(
        description="Résolutions DNS déclenchées par l'évaluation des mécanismes."
    )
    lookup_limit: int = Field(description="Plafond normatif, fixé à 10 par la RFC 7208.")
    all_qualifier: str | None = Field(
        default=None,
        description="Qualificateur du mécanisme `all` final : fail (-all), softfail (~all)…",
    )
    mechanisms: list[SpfMechanism] = Field(description="Mécanismes rencontrés, dans l'ordre.")
    findings: list[str] = Field(description="Constats de sécurité, du plus grave au moins grave.")
    severity: Severity = Field(description="Gravité globale de la posture SPF.")


class DkimKey(BaseModel):
    """Une clé DKIM publiée pour un sélecteur donné."""

    selector: str = Field(description="Sélecteur interrogé.")
    found: bool = Field(description="Une clé est-elle publiée pour ce sélecteur ?")
    key_type: str | None = Field(default=None, description="Type de clé : rsa ou ed25519.")
    key_bits: int | None = Field(default=None, description="Taille de la clé RSA en bits.")
    revoked: bool = Field(
        default=False,
        description="Clé révoquée : le champ p= est vide, ce qui invalide les signatures.",
    )
    testing: bool = Field(
        default=False, description="Indicateur t=y : les destinataires ignorent les échecs."
    )
    findings: list[str] = Field(default_factory=list, description="Constats sur cette clé.")


class DkimReport(BaseModel):
    """Résultat de `check_dkim`."""

    domain: str = Field(description="Domaine analysé.")
    keys: list[DkimKey] = Field(description="Une entrée par sélecteur interrogé.")
    keys_found: int = Field(description="Nombre de sélecteurs ayant une clé publiée.")
    findings: list[str] = Field(description="Constats de sécurité.")
    severity: Severity = Field(description="Gravité globale de la posture DKIM.")


class DmarcReport(BaseModel):
    """Résultat de `check_dmarc`."""

    domain: str = Field(description="Domaine analysé.")
    record: str | None = Field(default=None, description="Enregistrement DMARC publié.")
    policy: str | None = Field(
        default=None,
        description=(
            "none (observation seule, aucune protection), quarantine (mise en "
            "quarantaine) ou reject (rejet)."
        ),
    )
    subdomain_policy: str | None = Field(
        default=None, description="Politique appliquée aux sous-domaines (sp=)."
    )
    percentage: int = Field(
        default=100,
        description=(
            "Part du trafic soumise à la politique (pct=). Sous 100, la protection "
            "n'est que partielle."
        ),
    )
    aggregate_reports: list[str] = Field(
        default_factory=list, description="Destinataires des rapports agrégés (rua=)."
    )
    forensic_reports: list[str] = Field(
        default_factory=list, description="Destinataires des rapports d'échec (ruf=)."
    )
    spf_alignment: str = Field(
        default="r", description="Alignement SPF : r (relâché) ou s (strict)."
    )
    dkim_alignment: str = Field(
        default="r", description="Alignement DKIM : r (relâché) ou s (strict)."
    )
    findings: list[str] = Field(description="Constats de sécurité.")
    severity: Severity = Field(description="Gravité globale de la posture DMARC.")


class HeaderAnalysis(BaseModel):
    """Résultat de `analyze_email_headers` : ce message est-il usurpé ?"""

    from_domain: str | None = Field(default=None, description="Domaine affiché dans `From:`.")
    return_path_domain: str | None = Field(
        default=None, description="Domaine du `Return-Path:`, utilisé par SPF."
    )
    dkim_domain: str | None = Field(default=None, description="Domaine signataire DKIM (d=).")
    reply_to: str | None = Field(default=None, description="Adresse de réponse, si différente.")
    subject: str | None = Field(default=None, description="Objet du message.")
    spf_result: AuthResult = Field(default="none", description="Résultat SPF déclaré.")
    dkim_result: AuthResult = Field(default="none", description="Résultat DKIM déclaré.")
    dmarc_result: AuthResult = Field(default="none", description="Résultat DMARC déclaré.")
    spf_aligned: bool = Field(
        default=False, description="Le domaine SPF correspond-il au domaine affiché ?"
    )
    dkim_aligned: bool = Field(
        default=False, description="Le domaine signataire correspond-il au domaine affiché ?"
    )
    verdict: Literal["legitimate", "suspicious", "spoofed", "unknown"] = Field(
        description="Conclusion sur l'authenticité du message."
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Indicateurs extraits — adresses IP et domaines à enrichir ensuite.",
    )
    findings: list[str] = Field(description="Constats, du plus grave au moins grave.")
    severity: Severity = Field(description="Gravité globale.")


class DomainPosture(BaseModel):
    """Résultat de `check_domain_posture` : la synthèse des trois mécanismes."""

    domain: str = Field(description="Domaine analysé.")
    score: int = Field(ge=0, le=100, description="Note de posture, de 0 à 100.")
    grade: str = Field(description="Note lettrée, de A à F.")
    spf: SpfReport
    dkim: DkimReport
    dmarc: DmarcReport
    priority_actions: list[str] = Field(
        description="Actions à mener, classées par gain de sécurité décroissant."
    )
    severity: Severity = Field(description="Gravité globale de la posture.")

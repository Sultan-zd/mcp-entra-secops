"""Formes de sortie des outils de reconnaissance web."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

Severity = str


class TlsReport(BaseModel):
    """Ce qu'une connexion TLS directe a révélé."""

    host: str
    port: int
    negotiated_version: str | None = Field(
        default=None, description="Version négociée avec un client moderne."
    )
    negotiated_cipher: str | None = None
    subject: str | None = Field(default=None, description="Sujet du certificat.")
    issuer: str | None = Field(default=None, description="Autorité émettrice.")
    san: list[str] = Field(default_factory=list, description="Noms couverts par le certificat.")
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = Field(
        default=None, description="Jours avant expiration, négatif si dépassée."
    )
    hostname_matches: bool | None = Field(
        default=None, description="Le certificat couvre-t-il ce nom d'hôte."
    )
    self_signed: bool | None = None
    key_type: str | None = Field(default=None, description="RSA ou courbe elliptique.")
    key_bits: int | None = None
    signature_algorithm: str | None = None
    supported_versions: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Pour chaque version : « acceptée », « refusée » ou « non testable ». "
            "« Non testable » n'est pas « refusée » : la bibliothèque cliente peut "
            "avoir refusé de la proposer."
        ),
    )
    findings: list[str] = Field(default_factory=list)
    severity: Severity = "none"
    score: int = Field(default=100, description="Note de configuration, sur 100.")


class CertificateInventory(BaseModel):
    """Expiration des certificats d'un ensemble d'hôtes."""

    checked: int
    reachable: int
    expired: int
    expiring_soon: int
    warn_days: int
    summary: str
    certificates: list[dict[str, Any]] = Field(
        default_factory=list, description="Trié du plus proche de l'expiration."
    )
    unreachable: list[dict[str, Any]] = Field(
        default_factory=list, description="Hôtes non joignables, avec la raison."
    )


class SecurityHeadersReport(BaseModel):
    """Note des en-têtes de sécurité d'une page."""

    url: str
    final_url: str = Field(description="URL après redirections.")
    status: int
    score: int = Field(description="Note sur 100.")
    grade: str = Field(description="Note lettrée, de A à F.")
    present: dict[str, str] = Field(default_factory=dict)
    missing: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    disclosed: dict[str, str] = Field(
        default_factory=dict, description="En-têtes divulguant la pile technique."
    )
    cookies: list[dict[str, Any]] = Field(
        default_factory=list, description="Attributs de sécurité de chaque cookie."
    )
    redirects_to_https: bool | None = None
    severity: Severity = "medium"


class DnsHygieneReport(BaseModel):
    """État de l'hygiène DNS d'un domaine."""

    domain: str
    dnssec: str = Field(description="signé, non signé, ou inconnu.")
    caa_records: list[str] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)
    zone_transfer_open: list[str] = Field(
        default_factory=list, description="Serveurs acceptant un transfert de zone."
    )
    dangling_cnames: list[dict[str, str]] = Field(
        default_factory=list,
        description="Alias vers un service infogéré libéré : réappropriables.",
    )
    findings: list[str] = Field(default_factory=list)
    severity: Severity = "none"
    score: int = 100


class SubdomainReport(BaseModel):
    """Sous-domaines découverts via la transparence des certificats."""

    domain: str
    source: str = Field(description="Journal interrogé.")
    issuances_seen: int = Field(description="Certificats examinés.")
    subdomains: list[str] = Field(default_factory=list)
    wildcards: list[str] = Field(default_factory=list, description="Certificats joker.")
    foreign_names_excluded: int = Field(
        default=0,
        description=(
            "Noms appartenant à d'autres domaines, exclus. Signature d'un hébergement mutualisé."
        ),
    )
    findings: list[str] = Field(default_factory=list)


class WebExposureReport(BaseModel):
    """Audit complet de l'exposition web d'un domaine."""

    domain: str
    score: int = 0
    severity: Severity = "none"
    summary: str = ""
    tls: TlsReport | None = None
    headers: SecurityHeadersReport | None = None
    dns: DnsHygieneReport | None = None
    subdomains: SubdomainReport | None = None
    unavailable: list[str] = Field(
        default_factory=list,
        description="Analyses n'ayant pas abouti. La note ne porte que sur le reste.",
    )
    findings: list[str] = Field(default_factory=list)


class DomainRegistration(BaseModel):
    """Ce qu'un registre dit d'un domaine, via RDAP."""

    domain: str
    registered_on: str | None = None
    expires_on: str | None = None
    last_changed: str | None = None
    age_days: int | None = Field(
        default=None,
        description="Âge en jours. Un domaine de moins de 30 jours est un signal "
        "de hameçonnage parmi les plus forts qui existent.",
    )
    registrar: str | None = None
    nameservers: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list, description="Codes d'état EPP du registre.")
    dnssec: bool | None = None
    findings: list[str] = Field(default_factory=list)
    source: str = "rdap.org"


class IpOwner(BaseModel):
    """Ce qu'un registre dit d'une adresse IP."""

    ip: str
    network: str | None = Field(default=None, description="Plage allouée.")
    name: str | None = Field(default=None, description="Nom de l'allocation.")
    allocation_type: str | None = None
    country: str | None = None
    asn: int | None = None
    asn_holder: str | None = Field(default=None, description="Opérateur annonçant le préfixe.")
    announced: bool | None = Field(
        default=None, description="Le préfixe est-il annoncé sur Internet en ce moment ?"
    )
    findings: list[str] = Field(default_factory=list)

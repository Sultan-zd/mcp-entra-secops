"""Formes de sortie des outils d'ingénierie de détection."""

from __future__ import annotations

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------
# Indicateurs
# --------------------------------------------------------------------------
class FileHash(BaseModel):
    """Une empreinte, avec l'algorithme déduit de sa longueur."""

    value: str
    algorithm: str = Field(description="md5, sha1, sha256 ou sha512.")


class ExcludedValue(BaseModel):
    """Une valeur écartée, et pourquoi.

    Rendre les exclusions plutôt que de les taire évite deux erreurs : croire
    que l'extraction a tout raté, et renvoyer une adresse interne à un service
    tiers pour « vérifier ».
    """

    value: str
    reason: str


class ExtractedIOCs(BaseModel):
    """Les indicateurs contenus dans un texte, triés et dédoublonnés."""

    total: int = Field(description="Nombre d'indicateurs exploitables.")
    ipv4: list[str] = Field(default_factory=list, description="Adresses IPv4 publiques.")
    ipv6: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    hashes: list[FileHash] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    excluded: list[ExcludedValue] = Field(
        default_factory=list,
        description="Valeurs écartées avec leur motif : adresses non routables, "
        "domaines d'exemple, noms de fichiers.",
    )
    notes: list[str] = Field(default_factory=list)


class DefangedIOCs(BaseModel):
    """Des indicateurs rendus non cliquables."""

    defanged: list[str] = Field(description="Indicateurs sous forme désamorcée.")
    note: str = Field(
        default=(
            "Forme sûre à coller dans un ticket ou un courriel : un indicateur "
            "cliquable finit par être cliqué."
        )
    )


# --------------------------------------------------------------------------
# Règles Sigma
# --------------------------------------------------------------------------
class LinkedTechnique(BaseModel):
    """Une étiquette ATT&CK d'une règle, confrontée au référentiel embarqué."""

    id: str
    status: str = Field(description="valide, revoquee ou inconnue.")
    name: str | None = None
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    url: str | None = None
    replaced_by: str | None = Field(
        default=None, description="Technique remplaçante, si celle-ci a été révoquée."
    )
    detection_guidance: list[str] = Field(
        default_factory=list,
        description="Ce qu'ATT&CK recommande de surveiller pour cette technique. "
        "Sert à juger si la règle couvre vraiment ce qu'elle annonce.",
    )
    note: str | None = None


class RuleQuality(BaseModel):
    """Ce qui décide du sort d'une règle en production."""

    score: int = Field(ge=0, le=100)
    grade: str = Field(description="A à F, calculé — à reprendre tel quel.")
    findings: list[str] = Field(
        default_factory=list, description="Ce qui manque, par ordre d'importance."
    )
    strengths: list[str] = Field(default_factory=list)


class SigmaAnalysis(BaseModel):
    """Une règle Sigma lue, notée et rattachée à ATT&CK."""

    title: str
    id: str | None = None
    status: str | None = None
    level: str | None = None
    description: str | None = None
    author: str | None = None
    logsource: dict[str, str] = Field(default_factory=dict)
    selections: list[str] = Field(default_factory=list)
    condition: str = ""
    fields_used: list[str] = Field(
        default_factory=list,
        description="Champs de journal dont la règle dépend : s'ils ne sont pas "
        "collectés, elle ne se déclenchera jamais sans jamais le signaler.",
    )
    falsepositives: list[str] = Field(default_factory=list)
    spec_compliant: bool = Field(
        description="La règle est-elle acceptée par la spécification Sigma ? "
        "Une règle non conforme est tout de même analysée et notée."
    )
    spec_error: str | None = Field(
        default=None, description="Motif du refus, le cas échéant."
    )
    quality: RuleQuality
    attack: list[LinkedTechnique] = Field(default_factory=list)
    attack_findings: list[str] = Field(
        default_factory=list,
        description="Étiquettes révoquées, inexistantes ou incohérentes avec la source.",
    )
    attack_version: str = ""


class ConvertedRule(BaseModel):
    """Une règle traduite dans un langage de requête."""

    target: str
    target_name: str = Field(description="Le produit visé, en clair.")
    queries: list[str]
    note: str = Field(
        default=(
            "Conversion produite par pysigma. À relire avant mise en production : "
            "les noms de champs dépendent du schéma de collecte local."
        )
    )


class RuleExplanation(BaseModel):
    """Une règle expliquée en français, sans jargon."""

    title: str
    summary: str = Field(description="Ce que la règle cherche, en une phrase.")
    triggers_when: list[str] = Field(
        default_factory=list, description="Les conditions de déclenchement, une par ligne."
    )
    log_requirement: str = Field(description="Ce qu'il faut collecter pour qu'elle fonctionne.")
    expected_noise: list[str] = Field(
        default_factory=list, description="Les faux positifs déclarés par l'auteur."
    )
    attack_context: list[str] = Field(
        default_factory=list, description="Ce que la règle détecte, en termes ATT&CK."
    )


class CoverageEntry(BaseModel):
    """Une tactique ATT&CK, et ce que le jeu de règles en couvre."""

    tactic: str
    rules: int = Field(description="Nombre de règles rattachées à cette tactique.")
    techniques: list[str] = Field(default_factory=list)


class RuleSetCoverage(BaseModel):
    """Ce qu'un jeu de règles couvre, et ce qu'il laisse de côté."""

    rules_analyzed: int
    rules_rejected: int = Field(
        default=0, description="Règles illisibles, comptées mais non analysées."
    )
    techniques_covered: list[str] = Field(default_factory=list)
    tactics: list[CoverageEntry] = Field(default_factory=list)
    uncovered_tactics: list[str] = Field(
        default_factory=list, description="Tactiques ATT&CK qu'aucune règle ne touche."
    )
    findings: list[str] = Field(default_factory=list)
    attack_version: str = ""


class DetectionAdvice(BaseModel):
    """Par où commencer pour détecter une technique donnée."""

    technique_id: str
    technique_name: str
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(
        default_factory=list, description="Ce qu'il faut collecter en premier."
    )
    detection_guidance: list[str] = Field(
        default_factory=list, description="Ce qu'ATT&CK recommande de surveiller."
    )
    sigma_skeleton: str = Field(
        description="Squelette de règle Sigma pré-rempli, à compléter — pas une "
        "règle prête à déployer."
    )
    notes: list[str] = Field(default_factory=list)


class YaraString(BaseModel):
    """Une chaîne déclarée dans le bloc `strings` d'une règle YARA."""

    name: str
    type: str = Field(description="text, regex ou byte.")
    value: str
    modifiers: list[str] = Field(default_factory=list)


class YaraAnalysis(BaseModel):
    """Une règle YARA lue, notée et rattachée à ATT&CK."""

    name: str
    tags: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(
        default_factory=list, description="private / global, s'ils sont déclarés."
    )
    imports: list[str] = Field(
        default_factory=list, description="Modules YARA utilisés (pe, elf…)."
    )
    metadata: dict[str, str] = Field(default_factory=dict)
    strings: list[YaraString] = Field(default_factory=list)
    condition: str = ""
    spec_compliant: bool = Field(
        description="La règle compile-t-elle avec le compilateur YARA officiel ? "
        "Une règle non conforme est tout de même analysée et notée."
    )
    spec_error: str | None = Field(default=None, description="Motif du refus, le cas échéant.")
    quality: RuleQuality
    attack: list[LinkedTechnique] = Field(default_factory=list)
    attack_findings: list[str] = Field(
        default_factory=list,
        description="Étiquettes révoquées, inexistantes ou incohérentes avec la source.",
    )
    attack_version: str = ""


# --------------------------------------------------------------------------
# Référence des événements Windows / Sysmon
# --------------------------------------------------------------------------
class WindowsSecurityEvent(BaseModel):
    """Une entrée d'audit de sécurité Windows (canal `Security`)."""

    current_id: str | None = Field(
        default=None,
        description="Identifiant moderne (Vista et ultérieur). Absent pour certains "
        "événements retirés dont seul l'ID historique subsiste.",
    )
    legacy_ids: list[str] = Field(
        default_factory=list, description="Identifiants antérieurs à Vista, le cas échéant."
    )
    criticality: str = Field(
        description="Low, Medium, Medium to High ou High — jugement éditorial de Microsoft, "
        "tenu à jour dans « Appendix L: Events to Monitor »."
    )
    summary: str


class SysmonEvent(BaseModel):
    """Une entrée du canal `Microsoft-Windows-Sysmon/Operational`.

    Pas de champ de criticité : la documentation officielle Sysinternals n'en
    publie pas pour ces IDs — l'intérêt d'un événement Sysmon dépend
    entièrement de la configuration déployée, pas d'un jugement fixe de
    Microsoft. En afficher une ici serait une valeur inventée.
    """

    id: int
    name: str
    description: str


class WindowsEventMatches(BaseModel):
    """Ce qu'une consultation ou une recherche a trouvé, par source."""

    query: str
    security_matches: list[WindowsSecurityEvent] = Field(default_factory=list)
    sysmon_matches: list[SysmonEvent] = Field(default_factory=list)
    note: str | None = None


# --------------------------------------------------------------------------
# ReDoS
# --------------------------------------------------------------------------
class RedosFinding(BaseModel):
    """Une forme structurellement suspecte, confrontée à une exécution réelle."""

    kind: str = Field(
        description="quantificateurs_imbriques, alternance_ambigue ou "
        "quantificateurs_adjacents."
    )
    sample: str = Field(description="Le caractère utilisé pour construire l'attaque de test.")
    explanation: str
    confirmed: bool = Field(
        description="La mesure chronométrée réelle confirme-t-elle un ralentissement "
        "anormal — pas seulement la forme du motif."
    )
    timeout_hit: bool = Field(
        description="Le moteur n'a pas terminé dans le budget imparti : la confirmation "
        "la plus forte possible."
    )
    timings_ms: list[list[float]] = Field(
        default_factory=list,
        description="Paires [longueur, durée en ms] mesurées, croissantes.",
    )
    note: str


class RedosAnalysis(BaseModel):
    """Le verdict sur un motif : candidats structurels, puis confirmation empirique."""

    pattern: str
    compiles: bool = Field(description="Le motif compile-t-il dans le moteur `re` de Python ?")
    compile_error: str | None = None
    findings: list[RedosFinding] = Field(default_factory=list)
    vulnerable: bool = Field(
        description="Au moins un constat a été confirmé par une exécution réelle — "
        "pas seulement repéré dans le texte."
    )
    truncated: bool = Field(
        default=False,
        description="D'autres candidats structurels existaient mais n'ont pas été "
        "confirmés empiriquement, pour borner le temps de réponse.",
    )
    note: str

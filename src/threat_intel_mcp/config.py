"""Configuration du serveur de renseignement sur les menaces.

Contrairement au serveur d'identité, l'absence d'une clé n'est pas une erreur
fatale : le serveur fonctionne avec les sources dont il dispose et le signale
dans ses réponses. Une seule source configurée vaut mieux qu'un refus de
démarrer.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DataSource = Literal["live", "fixture"]


class Settings(BaseSettings):
    """Réglages du serveur MCP de renseignement sur les menaces."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    # --- Clés d'API, toutes facultatives ------------------------------------
    virustotal_api_key: str | None = Field(default=None, validation_alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str | None = Field(default=None, validation_alias="ABUSEIPDB_API_KEY")
    greynoise_api_key: str | None = Field(default=None, validation_alias="GREYNOISE_API_KEY")

    # --- Source de données ---------------------------------------------------
    data_source: DataSource = Field(
        default="live",
        validation_alias="TI_DATA_SOURCE",
        description="'live' interroge les API réelles ; 'fixture' rejoue des réponses locales.",
    )

    # --- Points d'entrée des API --------------------------------------------
    virustotal_base_url: str = Field(
        default="https://www.virustotal.com/api/v3", validation_alias="TI_VIRUSTOTAL_BASE_URL"
    )
    abuseipdb_base_url: str = Field(
        default="https://api.abuseipdb.com/api/v2", validation_alias="TI_ABUSEIPDB_BASE_URL"
    )
    greynoise_base_url: str = Field(
        default="https://api.greynoise.io/v3/community", validation_alias="TI_GREYNOISE_BASE_URL"
    )

    # --- Réseau --------------------------------------------------------------
    request_timeout_seconds: float = Field(
        default=15.0, ge=1.0, le=60.0, validation_alias="TI_REQUEST_TIMEOUT_SECONDS"
    )

    # --- Limitation de débit -------------------------------------------------
    # Le palier gratuit de VirusTotal tourne autour de 4 requêtes par minute.
    # Dépasser ce rythme ne ralentit pas : cela renvoie des 429 et gâche le
    # quota journalier. Le limiteur protège donc la ressource, pas le serveur.
    virustotal_rpm: int = Field(default=4, ge=1, validation_alias="TI_VIRUSTOTAL_RPM")
    abuseipdb_rpm: int = Field(default=60, ge=1, validation_alias="TI_ABUSEIPDB_RPM")
    greynoise_rpm: int = Field(default=30, ge=1, validation_alias="TI_GREYNOISE_RPM")

    # --- Cache ---------------------------------------------------------------
    cache_ttl_seconds: int = Field(
        default=86_400,
        ge=0,
        validation_alias="TI_CACHE_TTL_SECONDS",
        description="Durée de vie d'un verdict en cache. 24 h par défaut.",
    )
    cache_max_entries: int = Field(
        default=5_000,
        ge=16,
        validation_alias="TI_CACHE_MAX_ENTRIES",
        description="Taille du cache mémoire, au-delà de laquelle les plus anciens sortent.",
    )
    redis_url: str | None = Field(
        default=None,
        validation_alias="TI_REDIS_URL",
        description="Si renseigné, le cache est partagé entre processus via Redis.",
    )

    # --- Bornes appliquées aux outils ---------------------------------------
    max_bulk_indicators: int = Field(
        default=20, ge=1, le=100, validation_alias="TI_MAX_BULK_INDICATORS"
    )

    log_level: str = Field(default="INFO", validation_alias="TI_LOG_LEVEL")

    @model_validator(mode="after")
    def _warn_when_no_source(self) -> Settings:
        """Refuse de démarrer en mode live sans la moindre source utilisable.

        Un serveur qui répond « inconnu » à toutes les questions est pire
        qu'un serveur absent : il donne l'illusion d'une vérification.
        """
        if self.data_source == "fixture":
            return self
        if not any((self.virustotal_api_key, self.abuseipdb_api_key, self.greynoise_api_key)):
            raise ValueError(
                "Aucune source de renseignement n'est configurée. Renseignez au moins une "
                "clé parmi VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY et GREYNOISE_API_KEY, "
                "ou basculez sur TI_DATA_SOURCE=fixture pour travailler sans clé."
            )
        return self

    def configured_sources(self) -> list[str]:
        """Noms des sources exploitables avec la configuration actuelle."""
        if self.data_source == "fixture":
            return ["virustotal", "abuseipdb", "greynoise"]
        noms = []
        if self.virustotal_api_key:
            noms.append("virustotal")
        if self.abuseipdb_api_key:
            noms.append("abuseipdb")
        if self.greynoise_api_key:
            noms.append("greynoise")
        return noms


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retourne les réglages, chargés une seule fois par processus."""
    return Settings()

"""Configuration du serveur, lue depuis l'environnement et validée au démarrage.

Le principe : si la configuration est incomplète, le serveur refuse de démarrer
avec un message explicite, plutôt que d'échouer vingt minutes plus tard au
premier appel d'outil.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DataSource = Literal["graph", "fixture"]

#: Identifiants Azure requis pour interroger réellement Microsoft Graph.
_AZURE_CREDENTIAL_FIELDS = ("azure_tenant_id", "azure_client_id", "azure_client_secret")


class Settings(BaseSettings):
    """Réglages du serveur MCP Entra ID SecOps."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        # Les champs portent un alias d'environnement (ENTRA_*). Sans cette
        # option, ils ne seraient plus assignables par leur nom Python, ce qui
        # rendrait la classe inutilisable en test.
        populate_by_name=True,
    )

    # --- Identité de l'application (App Registration Entra) ----------------
    # Ces noms correspondent aux variables lues nativement par azure-identity.
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None

    # --- Source de données --------------------------------------------------
    data_source: DataSource = Field(
        default="graph",
        validation_alias="ENTRA_DATA_SOURCE",
        description="'graph' interroge Microsoft Graph ; 'fixture' rejoue des données locales.",
    )

    # --- Microsoft Graph ----------------------------------------------------
    graph_base_url: str = Field(
        default="https://graph.microsoft.com/v1.0",
        validation_alias="ENTRA_GRAPH_BASE_URL",
    )
    graph_scope: str = Field(
        default="https://graph.microsoft.com/.default",
        validation_alias="ENTRA_GRAPH_SCOPE",
    )

    # --- Réseau et résilience ----------------------------------------------
    request_timeout_seconds: float = Field(
        default=30.0, ge=1.0, le=120.0, validation_alias="ENTRA_REQUEST_TIMEOUT_SECONDS"
    )
    max_retries: int = Field(default=3, ge=0, le=10, validation_alias="ENTRA_MAX_RETRIES")
    max_pages: int = Field(
        default=20,
        ge=1,
        le=1000,
        validation_alias="ENTRA_MAX_PAGES",
        description="Plafond de pages suivies via @odata.nextLink, contre une pagination sans fin.",
    )

    # --- Bornes appliquées aux paramètres d'outils --------------------------
    # Elles protègent la fenêtre de contexte du modèle et le quota Graph :
    # même si le LLM demande 10 000 résultats, il n'en obtiendra jamais plus
    # que `max_page_size`.
    default_lookback_hours: int = Field(
        default=24, ge=1, validation_alias="ENTRA_DEFAULT_LOOKBACK_HOURS"
    )
    max_lookback_hours: int = Field(default=168, ge=1, validation_alias="ENTRA_MAX_LOOKBACK_HOURS")
    default_page_size: int = Field(default=25, ge=1, validation_alias="ENTRA_DEFAULT_PAGE_SIZE")
    max_page_size: int = Field(default=100, ge=1, validation_alias="ENTRA_MAX_PAGE_SIZE")

    # --- Journalisation -----------------------------------------------------
    log_level: str = Field(default="INFO", validation_alias="ENTRA_LOG_LEVEL")

    @model_validator(mode="after")
    def _check_credentials(self) -> Settings:
        """Exige les identifiants Azure dès lors que l'on vise le vrai Graph."""
        if self.data_source != "graph":
            return self

        missing = [name.upper() for name in _AZURE_CREDENTIAL_FIELDS if not getattr(self, name)]
        if missing:
            raise ValueError(
                "ENTRA_DATA_SOURCE=graph exige les variables suivantes, absentes : "
                + ", ".join(missing)
                + ". Renseignez-les dans .env (voir .env.example), ou basculez sur "
                "ENTRA_DATA_SOURCE=fixture pour travailler sans tenant."
            )
        return self

    @model_validator(mode="after")
    def _check_bounds(self) -> Settings:
        """Vérifie la cohérence des bornes entre valeurs par défaut et maximums."""
        if self.default_lookback_hours > self.max_lookback_hours:
            raise ValueError(
                "ENTRA_DEFAULT_LOOKBACK_HOURS ne peut pas dépasser ENTRA_MAX_LOOKBACK_HOURS."
            )
        if self.default_page_size > self.max_page_size:
            raise ValueError("ENTRA_DEFAULT_PAGE_SIZE ne peut pas dépasser ENTRA_MAX_PAGE_SIZE.")
        return self

    def clamp_hours(self, hours: int | None) -> int:
        """Ramène une fenêtre temporelle demandée dans les bornes autorisées."""
        if hours is None:
            return self.default_lookback_hours
        return max(1, min(hours, self.max_lookback_hours))

    def clamp_limit(self, limit: int | None) -> int:
        """Ramène un nombre de résultats demandé dans les bornes autorisées."""
        if limit is None:
            return self.default_page_size
        return max(1, min(limit, self.max_page_size))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retourne les réglages, chargés une seule fois par processus."""
    return Settings()

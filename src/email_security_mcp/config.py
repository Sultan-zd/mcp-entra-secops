"""Configuration du serveur de sécurité de la messagerie.

Aucune clé d'API n'est nécessaire : tout est publié dans le DNS. C'est ce qui
rend ce serveur immédiatement utilisable, contrairement aux deux autres.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DataSource = Literal["live", "fixture"]


class Settings(BaseSettings):
    """Réglages du serveur MCP de sécurité de la messagerie."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    data_source: DataSource = Field(
        default="live",
        validation_alias="MAIL_DATA_SOURCE",
        description="'live' résout le DNS réel ; 'fixture' rejoue des zones locales.",
    )

    dns_timeout_seconds: float = Field(
        default=5.0, ge=0.5, le=30.0, validation_alias="MAIL_DNS_TIMEOUT_SECONDS"
    )
    dns_nameservers: str | None = Field(
        default=None,
        validation_alias="MAIL_DNS_NAMESERVERS",
        description="Résolveurs à utiliser, séparés par des virgules. Défaut : ceux du système.",
    )

    max_selectors: int = Field(
        default=12,
        ge=1,
        le=40,
        validation_alias="MAIL_MAX_SELECTORS",
        description="Nombre maximum de sélecteurs DKIM testés par appel.",
    )
    max_header_bytes: int = Field(
        default=64_000,
        ge=1_000,
        validation_alias="MAIL_MAX_HEADER_BYTES",
        description=(
            "Taille maximale des en-têtes acceptés. Borne la surface de données non "
            "fiables entrant dans le contexte du modèle."
        ),
    )

    log_level: str = Field(default="INFO", validation_alias="MAIL_LOG_LEVEL")

    def nameserver_list(self) -> list[str] | None:
        if not self.dns_nameservers:
            return None
        return [s.strip() for s in self.dns_nameservers.split(",") if s.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retourne les réglages, chargés une seule fois par processus."""
    return Settings()

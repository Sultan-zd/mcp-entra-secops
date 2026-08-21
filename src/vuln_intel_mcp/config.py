"""Réglages du serveur de renseignement sur les vulnérabilités."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration, entièrement facultative : aucune clé n'est requise."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", populate_by_name=True
    )

    #: Durée de conservation du catalogue CISA. Il change une fois par jour ;
    #: six heures gardent la donnée fraîche sans marteler la source.
    feed_ttl_seconds: float = Field(
        default=6 * 3600, validation_alias="VULN_FEED_TTL_SECONDS", ge=60
    )

    #: Le NVD accepte une clé facultative qui relève ses quotas. Sans elle, le
    #: serveur fonctionne — plus lentement sur les gros lots.
    nvd_api_key: str | None = Field(default=None, validation_alias="NVD_API_KEY")

    request_timeout_seconds: float = Field(
        default=30.0, validation_alias="VULN_REQUEST_TIMEOUT", ge=5.0, le=120.0
    )

    log_level: str = Field(default="INFO", validation_alias="VULN_LOG_LEVEL")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

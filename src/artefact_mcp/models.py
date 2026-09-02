"""Formes de sortie des outils d'analyse d'artefacts."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class JwtAnalysis(BaseModel):
    """Un jeton JWT lu et audité, sans vérification de signature."""

    algorithm: str | None = Field(default=None, description="Algorithme déclaré dans l'en-tête.")
    token_type: str | None = None
    key_id: str | None = Field(default=None, description="Identifiant de clé (`kid`).")
    issuer: str | None = None
    subject: str | None = None
    audience: list[str] = Field(default_factory=list)
    issued_at: str | None = None
    expires_at: str | None = None
    expired: bool | None = Field(
        default=None, description="Vrai si `exp` est dépassé ; nul si la revendication manque."
    )
    seconds_remaining: int | None = None
    lifetime_seconds: int | None = Field(
        default=None, description="Durée de vie totale, si `iat` et `exp` sont présents."
    )
    permissions: list[str] = Field(
        default_factory=list,
        description="Portées (`scp`) et rôles applicatifs (`roles`) portés par le jeton.",
    )
    header: dict[str, Any] = Field(default_factory=dict)
    claims: dict[str, Any] = Field(default_factory=dict)
    signature_verified: bool = Field(
        default=False,
        description="TOUJOURS faux : vérifier exigerait la clé de l'émetteur. "
        "Le champ existe pour qu'on ne puisse pas l'oublier.",
    )
    findings: list[str] = Field(
        default_factory=list, description="Constats de sécurité, du plus grave au moins grave."
    )
    notes: list[str] = Field(default_factory=list)


class DecodedLayer(BaseModel):
    """Une transformation retirée avec succès."""

    encoding: str = Field(description="base64, hexadécimal, url, gzip ou deflate.")
    detail: str = ""


class DecodedPayload(BaseModel):
    """Une charge obfusquée, décodée couche par couche."""

    decoded: str = Field(
        description="Le résultat. Rendu en hexadécimal si ce n'est pas du texte."
    )
    layers: list[DecodedLayer] = Field(
        default_factory=list,
        description="Couches retirées, de l'extérieur vers l'intérieur. "
        "Le chemin caractérise l'outillage employé autant que le résultat.",
    )
    file_type: str | None = Field(
        default=None, description="Type de fichier reconnu à sa signature, le cas échéant."
    )
    is_text: bool = True
    truncated: bool = False
    findings: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

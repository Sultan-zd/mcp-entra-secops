"""Diagnostic de connexion : `python -m entra_secops_mcp --check`.

Vérifie, dans l'ordre, ce qui peut mal se passer avant le premier appel réel :
configuration, obtention du jeton, permissions réellement consenties, puis
accès effectif à chaque endpoint.

L'objectif est de remplacer un « 403 » opaque par une phrase qui dit quoi
cliquer dans le portail Entra.
"""

from __future__ import annotations

import base64
import binascii
import json
import sys
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .graph import GraphError, HttpGraphClient


@dataclass(frozen=True)
class Probe:
    """Un endpoint à tester, avec ce qu'il faut pour l'atteindre."""

    tool: str
    path: str
    permission: str
    licence: str


#: Un test par outil exposé. L'ordre va du moins exigeant au plus exigeant en
#: licence, pour que l'échec le plus probable apparaisse en dernier.
PROBES: tuple[Probe, ...] = (
    Probe("get_user_context", "/users", "Directory.Read.All", "aucune"),
    Probe("get_directory_audits", "/auditLogs/directoryAudits", "AuditLog.Read.All", "aucune"),
    Probe(
        "get_conditional_access_policies",
        "/identity/conditionalAccess/policies",
        "Policy.Read.All",
        "aucune",
    ),
    Probe("get_user_signins", "/auditLogs/signIns", "AuditLog.Read.All", "P1 ou P2"),
    Probe(
        "get_risky_users",
        "/identityProtection/riskyUsers",
        "IdentityRiskyUser.Read.All",
        "P2",
    ),
    Probe(
        "get_risk_detections",
        "/identityProtection/riskDetections",
        "IdentityRiskEvent.Read.All",
        "P2",
    ),
)


def _mask(value: str | None) -> str:
    """Affiche assez d'un identifiant pour le reconnaître, jamais assez pour le réutiliser."""
    if not value:
        return "(absent)"
    return f"{value[:8]}…" if len(value) > 8 else "…"


def _decode_token_roles(token: str) -> list[str]:
    """Lit la revendication `roles` du jeton, sans en vérifier la signature.

    Il ne s'agit pas d'un contrôle de sécurité : le jeton vient d'être obtenu
    auprès d'Entra sur un canal TLS. On l'inspecte uniquement pour dire à
    l'utilisateur quelles permissions ont réellement été consenties — c'est la
    différence entre « 403 » et « vous avez oublié de cliquer sur Accorder le
    consentement administrateur ».
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)  # rétablit le bourrage base64url
        claims: dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, binascii.Error, UnicodeDecodeError):
        return []
    roles = claims.get("roles", [])
    return sorted(str(r) for r in roles) if isinstance(roles, list) else []


def _titre(texte: str) -> None:
    print()
    print(texte)
    print("─" * len(texte))


async def run_diagnostics(settings: Settings) -> int:
    """Exécute le diagnostic complet. Retourne un code de sortie de processus."""
    _titre("1. Configuration")
    print(f"  Source de données : {settings.data_source}")
    print(f"  Tenant            : {_mask(settings.azure_tenant_id)}")
    print(f"  Application       : {_mask(settings.azure_client_id)}")
    print(f"  Secret client     : {'renseigné' if settings.azure_client_secret else 'ABSENT'}")

    if settings.data_source != "graph":
        print()
        print("  Le serveur est en mode fixture : aucun appel réel n'est effectué.")
        print("  Passez ENTRA_DATA_SOURCE=graph dans .env pour tester le vrai tenant.")
        return 0

    client = HttpGraphClient(settings)
    try:
        _titre("2. Authentification auprès d'Entra ID")
        try:
            # Accès délibéré à l'interne : le diagnostic doit distinguer un échec
            # d'authentification d'un échec de permission, ce que l'API publique
            # du client ne permet pas.
            entete = await client._authorization_header()
        except GraphError as exc:
            print(f"  ÉCHEC — {exc}")
            print()
            print("  Pistes : secret client expiré ou mal recopié, ou identifiant de")
            print("  tenant erroné. Le secret n'est affiché qu'une fois à sa création.")
            return 1

        jeton = entete["Authorization"].removeprefix("Bearer ")
        print("  Jeton OAuth 2.0 obtenu.")

        _titre("3. Permissions réellement consenties")
        accordees = _decode_token_roles(jeton)
        if not accordees:
            print("  AUCUNE permission applicative dans le jeton.")
            print()
            print("  Cause quasi certaine : le consentement administrateur n'a pas été")
            print("  accordé. Portail Entra → votre application → API autorisées →")
            print("  « Accorder le consentement administrateur pour <votre tenant> ».")
        else:
            for role in accordees:
                print(f"  ✓ {role}")

        attendues = {p.permission for p in PROBES}
        manquantes = sorted(attendues - set(accordees))
        if manquantes and accordees:
            print()
            for role in manquantes:
                print(f"  ✗ {role} — absente")

        _titre("4. Accès effectif aux endpoints")
        echecs = 0
        for probe in PROBES:
            try:
                await client.get(probe.path, params={"$top": 1}, max_items=1)
            except GraphError as exc:
                echecs += 1
                print(f"  ✗ {probe.tool}")
                print(f"      permission {probe.permission} · licence {probe.licence}")
                print(f"      {exc}")
            else:
                print(f"  ✓ {probe.tool}")

        _titre("Verdict")
        if echecs == 0:
            print(f"  Les {len(PROBES)} outils sont opérationnels sur le tenant réel.")
            return 0

        print(f"  {echecs} outil(s) sur {len(PROBES)} inaccessible(s).")
        print()
        print("  Un échec sur les outils marqués « licence P1 ou P2 » alors que les")
        print("  autres passent indique une licence insuffisante, pas une permission")
        print("  manquante : Microsoft 365 E5 inclut Entra ID P2, mais Office 365 E5")
        print("  ne l'inclut pas.")
        return 1
    finally:
        await client.aclose()


def check(settings: Settings) -> None:
    """Point d'entrée synchrone appelé par `--check`."""
    import asyncio

    raise SystemExit(asyncio.run(run_diagnostics(settings)))


if __name__ == "__main__":  # pragma: no cover - confort de débogage
    from .config import get_settings

    print("Diagnostic du serveur MCP Entra ID SecOps", file=sys.stderr)
    check(get_settings())

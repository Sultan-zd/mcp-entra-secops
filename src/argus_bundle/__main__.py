"""Point d'entrée : `python -m argus_bundle` ou `argus-mcp`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from argus_net import forcer_utf8

from .server import build_server, domaines_actifs

logger = logging.getLogger(__name__)


def _configure_logging(level: str = "INFO") -> None:
    """Journalisation sur stderr : stdout porte le protocole JSON-RPC."""
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s : %(message)s",
        force=True,
    )


def _run_check() -> int:
    """Affiche les domaines exposés et le nombre d'outils."""
    actifs = domaines_actifs()
    serveur = build_server()

    print()
    print("ARGUS — serveur unique")
    print("─" * 22)
    libelles = {
        "vulnerabilites": "Vulnérabilités (CVE, KEV, EPSS)",
        "mitre": "MITRE ATT&CK (hors ligne)",
        "detection": "Détection (IOC, Sigma — hors ligne)",
        "artefacts": "Artefacts (JWT, décodage — hors ligne)",
        "web": "Web et TLS",
        "messagerie": "Messagerie (SPF, DKIM, DMARC)",
        "renseignement": "Renseignement sur les menaces",
        "identite": "Identité Microsoft Entra",
    }
    for nom, actif in actifs.items():
        marque = "✓" if actif else "·"
        note = "" if actif else "   (clés absentes — domaine non exposé)"
        print(f"  {marque} {libelles.get(nom, nom):38}{note}")

    # `list_tools()` est l'API publique du serveur ; lire un attribut interne
    # rendait « ? » en silence dès que le SDK renommait son champ.
    outils = asyncio.run(serveur.list_tools())
    print()
    print(f"  {len(outils)} outils exposés.")
    print()

    if not actifs["renseignement"]:
        print("  Pour le renseignement : VIRUSTOTAL_API_KEY et/ou ABUSEIPDB_API_KEY.")
    if not actifs["identite"]:
        print("  Pour l'identité : AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.")
    print()
    return 0


def _lancer_http(args: argparse.Namespace) -> int:
    """Démarre le serveur en Streamable HTTP, après les contrôles de sécurité.

    Tous les contrôles passent AVANT l'ouverture du port : refuser une
    configuration dangereuse une fois le service joignable ne servirait à rien.
    """
    from .http import (
        VARIABLE_JETON,
        ConfigurationHttpError,
        JetonPartage,
        exiger_chiffrement,
        parametres_auth,
        parametres_securite,
        resoudre_jeton,
        schema,
    )
    from .tls import MaterielTlsError, fabrique_contexte, verifier_materiel

    hote, port, chemin = args.host, args.port, args.path
    cert = Path(args.tls_cert) if args.tls_cert else None
    cle = Path(args.tls_key) if args.tls_key else None

    if bool(cert) != bool(cle):
        print("\n  ✗ --tls-cert et --tls-key vont ensemble : l'un sans l'autre "
              "ne permet pas de servir en TLS.\n")
        return 1

    info = None
    try:
        if cert and cle:
            info = verifier_materiel(cert, cle)
        jeton = resoudre_jeton(hote, os.environ.get(VARIABLE_JETON))
        exiger_chiffrement(hote, tls_local=bool(cert), tls_en_amont=args.tls_en_amont)
    except (ConfigurationHttpError, MaterielTlsError) as exc:
        print(f"\n  ✗ {exc}\n")
        return 1

    chiffre = bool(cert) or args.tls_en_amont
    serveur = build_server(
        token_verifier=JetonPartage(jeton) if jeton else None,
        auth=parametres_auth(jeton, hote, port, chiffre=chiffre),
    )
    securite = parametres_securite(hote, port, chiffre=chiffre)

    outils = asyncio.run(serveur.list_tools())
    print()
    print(f"  ARGUS écoute sur {schema(chiffre=chiffre)}://{hote}:{port}{chemin}")
    print(f"  {len(outils)} outils exposés · "
          + ("jeton exigé" if jeton else "SANS authentification (boucle locale)"))
    print("  Protection contre le rebinding DNS : active.")
    if info:
        print(f"  TLS terminé ici · {info.sujet} · expire dans "
              f"{info.jours_restants} jour(s)")
        for note in info.avertissements:
            print(f"    ! {note}")
    elif args.tls_en_amont:
        print("  TLS déclaré terminé en amont : ce serveur parle en clair sur ce port.")
    print()

    if not cert:
        serveur.run(
            transport="streamable-http",
            host=hote,
            port=port,
            streamable_http_path=chemin,
            transport_security=securite,
        )
        return 0

    # Le SDK n'expose aucun réglage TLS : on récupère son application ASGI et
    # on pilote uvicorn directement, ce qui permet d'imposer TLS 1.2 minimum.
    import uvicorn

    application = serveur.streamable_http_app(
        streamable_http_path=chemin,
        transport_security=securite,
        host=hote,
    )
    uvicorn.Server(
        uvicorn.Config(
            application,
            host=hote,
            port=port,
            log_level=args.log_level.lower(),
            ssl_certfile=str(cert),
            ssl_keyfile=str(cle),
            ssl_context_factory=fabrique_contexte(),
        )
    ).run()
    return 0


def main() -> None:
    # Avant tout affichage : la console Windows est en cp1252 par defaut.
    forcer_utf8()
    parser = argparse.ArgumentParser(
        prog="argus-mcp",
        description="ARGUS — plateforme SecOps, tous les domaines en un serveur.",
    )
    parser.add_argument("--check", action="store_true", help="Liste les domaines et quitte.")
    parser.add_argument(
        "--http",
        action="store_true",
        help="Écoute en Streamable HTTP au lieu de stdio. Ouvre un port : "
        f"exige {'ARGUS_HTTP_TOKEN'} hors de la boucle locale.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Interface d'écoute (défaut : 127.0.0.1). Toute autre valeur exige un jeton.",
    )
    parser.add_argument("--port", type=int, default=8000, help="Port d'écoute (défaut : 8000).")
    parser.add_argument("--path", default="/mcp", help="Chemin du point d'entrée (défaut : /mcp).")
    parser.add_argument(
        "--tls-cert",
        help="Certificat au format PEM. Avec --tls-key, termine TLS ici même.",
    )
    parser.add_argument("--tls-key", help="Clé privée PEM correspondant à --tls-cert.")
    parser.add_argument(
        "--tls-en-amont",
        action="store_true",
        help="Déclare qu'un proxy inverse termine déjà TLS devant ce serveur. "
        "Sans cette mention ni --tls-cert, l'écoute hors boucle locale est refusée.",
    )
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    _configure_logging(args.log_level)

    if args.check:
        raise SystemExit(_run_check())

    if args.http:
        raise SystemExit(_lancer_http(args))

    build_server().run()


if __name__ == "__main__":
    main()

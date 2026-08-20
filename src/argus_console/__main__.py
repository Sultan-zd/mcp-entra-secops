"""Point d'entrée : `argus-console`.

Écoute sur l'interface locale par défaut. Exposer une console d'investigation
sur toutes les interfaces sans authentification donnerait accès à la télémétrie
de sécurité du tenant à quiconque atteint le port.
"""

from __future__ import annotations

import argparse
import logging
import sys


def main() -> None:
    """Démarre la console analyste."""
    parser = argparse.ArgumentParser(
        prog="argus-console", description="Console analyste de la plateforme ARGUS."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--log-level", default="warning")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print(
            "La console exige ses dépendances : pip install '.[console]'",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    logging.basicConfig(stream=sys.stderr, level=logging.WARNING, force=True)
    print(f"Console analyste : http://{args.host}:{args.port}", file=sys.stderr)
    uvicorn.run("argus_console.app:app", host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()

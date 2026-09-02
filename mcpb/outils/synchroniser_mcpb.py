"""Recopie les paquets source dans `mcpb/src`, à l'identique.

**Pourquoi ce script existe.** Le paquet distribuable embarque une copie des
paquets Python du dépôt. Tant que cette copie était faite à la main, rien ne
garantissait qu'elle correspondait au code testé : on pouvait corriger un
défaut dans `src/`, lancer la suite de tests avec succès, construire le paquet
— et distribuer l'ancienne version du fichier corrigé.

C'est le mode de défaillance le plus coûteux du projet : le code vérifié et le
code livré ne sont pas le même, et aucun test ne le voit.

Utilisation :

    python mcpb/outils/synchroniser_mcpb.py            # recopie
    python mcpb/outils/synchroniser_mcpb.py --verifier  # échoue si un écart existe
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

MCPB = Path(__file__).resolve().parent.parent
RACINE = MCPB.parent
SOURCE = RACINE / "src"
DESTINATION = MCPB / "src"

#: Les paquets embarqués dans le paquet distribuable. L'agent, la console et
#: l'évaluation n'en font pas partie : ils ne servent pas au serveur MCP.
PAQUETS = (
    "argus_bundle",
    "argus_net",
    "vuln_intel_mcp",
    "mitre_mcp",
    "detection_mcp",
    "artefact_mcp",
    "web_recon_mcp",
    "email_security_mcp",
    "threat_intel_mcp",
    "entra_secops_mcp",
)

#: Ce qui n'a rien à faire dans un paquet distribué.
IGNORES = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".mypy_cache")


def _fichiers(racine: Path) -> set[Path]:
    """Les fichiers d'un paquet, chemins relatifs, hors artefacts de compilation."""
    return {
        f.relative_to(racine)
        for f in racine.rglob("*")
        if f.is_file() and "__pycache__" not in f.parts and f.suffix not in {".pyc", ".pyo"}
    }


def verifier() -> int:
    """Compare les deux arborescences sans rien modifier."""
    ecarts: list[str] = []

    for paquet in PAQUETS:
        origine = SOURCE / paquet
        copie = DESTINATION / paquet

        if not origine.is_dir():
            ecarts.append(f"{paquet} : absent de src/")
            continue
        if not copie.is_dir():
            ecarts.append(f"{paquet} : absent du paquet distribuable")
            continue

        attendus = _fichiers(origine)
        presents = _fichiers(copie)

        for manquant in sorted(attendus - presents):
            ecarts.append(f"{paquet}/{manquant} : manque dans le paquet")
        for surnumeraire in sorted(presents - attendus):
            ecarts.append(f"{paquet}/{surnumeraire} : présent dans le paquet, absent de src/")

        for commun in sorted(attendus & presents):
            if not filecmp.cmp(origine / commun, copie / commun, shallow=False):
                ecarts.append(f"{paquet}/{commun} : DIFFÉRENT du fichier testé")

    print()
    if ecarts:
        print(f"{len(ecarts)} écart(s) entre le code testé et le code distribué :")
        for ecart in ecarts[:25]:
            print(f"  ✗ {ecart}")
        if len(ecarts) > 25:
            print(f"  … et {len(ecarts) - 25} autre(s)")
        print()
        print("  Lancer « python mcpb/outils/construire.py » pour recopier.")
        print()
        return 1

    total = sum(len(_fichiers(SOURCE / p)) for p in PAQUETS)
    print(f"  ✓ {len(PAQUETS)} paquets, {total} fichiers — le paquet distribué")
    print("    est identique au code testé.")
    print()
    return 0


def synchroniser() -> int:
    """Remplace la copie par la source."""
    DESTINATION.mkdir(parents=True, exist_ok=True)
    print()

    for paquet in PAQUETS:
        origine = SOURCE / paquet
        if not origine.is_dir():
            print(f"  ✗ {paquet} : absent de src/")
            return 1

        copie = DESTINATION / paquet
        if copie.exists():
            shutil.rmtree(copie)
        shutil.copytree(origine, copie, ignore=IGNORES)
        print(f"  ✓ {paquet} ({len(_fichiers(copie))} fichiers)")

    # Un paquet que l'on ne distribue plus doit disparaître de la copie, sinon
    # il continue d'être embarqué sans que rien ne le signale.
    for reste in sorted(DESTINATION.iterdir()):
        if reste.is_dir() and reste.name not in PAQUETS:
            shutil.rmtree(reste)
            print(f"  · {reste.name} retiré du paquet (plus distribué)")

    print()
    return verifier()


def main() -> None:
    from argus_net import forcer_utf8

    forcer_utf8()
    parser = argparse.ArgumentParser(
        prog="synchroniser_mcpb",
        description="Aligne mcpb/src sur src/, ou vérifie qu'ils sont identiques.",
    )
    parser.add_argument(
        "--verifier",
        action="store_true",
        help="Compare sans modifier. Code de sortie non nul si un écart existe.",
    )
    args = parser.parse_args()

    raise SystemExit(verifier() if args.verifier else synchroniser())


if __name__ == "__main__":
    sys.path.insert(0, str(SOURCE))
    main()

"""Construit le paquet `.mcpb` distribuable, et vérifie qu'il fonctionne.

Une seule commande, depuis la racine du dépôt :

    python mcpb/outils/construire.py

Elle enchaîne les quatre étapes, dans l'ordre où chacune dépend de la
précédente :

1. **Synchroniser** `mcpb/src` sur `src/` — sinon le paquet embarque une
   version périmée du code, et aucun test ne le voit.
2. **Générer** `manifest.json` en interrogeant le serveur — sinon il annonce
   des outils qui n'existent plus.
3. **Empaqueter** avec la CLI `mcpb`.
4. **Vérifier** l'artefact en le dépaquetant ailleurs et en l'exécutant.

**Pourquoi la quatrième étape existe.** Empaqueter réussit même quand le
paquet est cassé : c'est ainsi qu'une version a été produite dont la commande
de diagnostic plantait sur un `KeyError`. Le serveur démarrait, la CLI
annonçait un succès — et le défaut n'apparaissait que chez le destinataire, sur
la première commande qu'il lance. Un paquet n'est vérifié que s'il a été
exécuté depuis une copie dépaquetée.

Options :

    --sans-verification   s'arrête après l'empaquetage (plus rapide)
    --verifier-seulement  ne reconstruit rien, contrôle l'écart src/ ↔ mcpb/src
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

MCPB = Path(__file__).resolve().parent.parent
RACINE = MCPB.parent
OUTILS = MCPB / "outils"
DIST = MCPB / "dist"


def _titre(texte: str) -> None:
    print()
    print(texte)
    print("─" * len(texte))


def _executer(commande: list[str], etape: str) -> bool:
    """Lance une commande et rend l'échec visible plutôt que silencieux."""
    resultat = subprocess.run(
        commande, cwd=RACINE, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if resultat.returncode != 0:
        print(f"  ✗ {etape}")
        for ligne in (resultat.stdout + resultat.stderr).splitlines()[-15:]:
            print(f"      {ligne}")
        return False
    return True


def _nom_du_paquet() -> str:
    """Le nom de l'artefact, tiré du manifeste plutôt que recopié."""
    manifeste = json.loads((MCPB / "manifest.json").read_text(encoding="utf-8"))
    return f"{manifeste['name']}-{manifeste['version']}.mcpb"


def _verifier_artefact(archive: Path) -> bool:
    """Dépaquette le `.mcpb` ailleurs et l'exécute, comme le ferait l'hôte."""
    uv = shutil.which("uv")
    if uv is None:
        print("  · uv absent : vérification à l'exécution ignorée.")
        print("    Installez uv pour que cette étape s'exécute.")
        return True

    with tempfile.TemporaryDirectory(prefix="argus-verif-") as dossier:
        cible = Path(dossier)
        with zipfile.ZipFile(archive) as zip_:
            noms = zip_.namelist()
            zip_.extractall(cible)

        # Ce qui n'a rien à faire dans un paquet distribué.
        #
        # La liste des suffixes n'est pas de la prudence abstraite : une clé
        # privée de signature s'est réellement retrouvée dans un paquet, parce
        # que `.mcpbignore` ne connaissait pas encore son dossier. Le
        # destinataire aurait pu signer des versions falsifiées sous la même
        # identité. Un contrôle qui ne liste que les dossiers connus ne voit
        # pas le dossier qu'on vient d'ajouter — d'où le filtre par extension.
        indesirables = [
            n
            for n in noms
            if n.startswith(("outils/", "dist/", "signature/"))
            or ".venv" in n
            or n.endswith((".pem", ".key", ".pfx", ".p12"))
        ]
        if indesirables:
            print(f"  ✗ le paquet embarque {len(indesirables)} fichier(s) qui ne doivent")
            print("    PAS être distribués :")
            for nom in indesirables[:8]:
                print(f"      {nom}")
            return False

        resultat = subprocess.run(
            [uv, "run", "--directory", str(cible), "server/main.py", "--check"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        sortie = resultat.stdout + resultat.stderr
        if resultat.returncode != 0:
            print("  ✗ le paquet dépaqueté ne s'exécute pas :")
            for ligne in sortie.splitlines()[-15:]:
                print(f"      {ligne}")
            return False

        compte = [ligne.strip() for ligne in sortie.splitlines() if "outils expos" in ligne]
        detail = compte[0] if compte else "le serveur a démarré"
        print(f"  ✓ exécuté depuis une copie dépaquetée — {detail}")
        print(f"  ✓ {len(noms)} fichiers, aucun artefact de construction embarqué")
    return True


def construire(verifier: bool) -> int:
    _titre("1 · Synchroniser le code embarqué")
    if not _executer(
        [sys.executable, str(OUTILS / "synchroniser_mcpb.py")], "synchronisation"
    ):
        return 1
    print("  ✓ mcpb/src est identique à src/")

    _titre("2 · Générer le manifeste")
    if not _executer([sys.executable, str(OUTILS / "generer_manifeste.py")], "manifeste"):
        return 1
    manifeste = json.loads((MCPB / "manifest.json").read_text(encoding="utf-8"))
    print(f"  ✓ {len(manifeste['tools'])} outils déclarés par le serveur lui-même")

    _titre("3 · Empaqueter")
    DIST.mkdir(exist_ok=True)
    archive = DIST / _nom_du_paquet()

    # Sur Windows, `npx` est un `.cmd` : `subprocess` ne le trouve pas sans
    # que le chemin complet lui soit donné.
    npx = shutil.which("npx")
    if npx is None:
        print("  ✗ npx introuvable — la CLI d'empaquetage n'est pas installée.")
        print("      npm install @anthropic-ai/mcpb")
        return 1

    if not _executer(
        [npx, "--no-install", "@anthropic-ai/mcpb", "pack", str(MCPB), str(archive)],
        "empaquetage",
    ):
        print("      La CLI s'installe avec : npm install @anthropic-ai/mcpb")
        return 1
    print(f"  ✓ {archive.relative_to(RACINE)} ({archive.stat().st_size // 1024} Ko)")

    if not verifier:
        print()
        print("  Vérification à l'exécution ignorée (--sans-verification).")
        print()
        return 0

    _titre("4 · Vérifier l'artefact")
    if not _verifier_artefact(archive):
        return 1

    print()
    print(f"  Paquet prêt : {archive.relative_to(RACINE)}")
    print()
    print("  Il n'est PAS signé. Un hôte peut afficher un avertissement à")
    print("  l'installation ; c'est attendu pour une distribution interne.")
    print()
    return 0


def main() -> None:
    sys.path.insert(0, str(RACINE / "src"))
    from argus_net import forcer_utf8

    forcer_utf8()

    parser = argparse.ArgumentParser(
        prog="construire",
        description="Construit et vérifie le paquet MCPB distribuable.",
    )
    parser.add_argument(
        "--sans-verification",
        action="store_true",
        help="S'arrête après l'empaquetage, sans exécuter le paquet.",
    )
    parser.add_argument(
        "--verifier-seulement",
        action="store_true",
        help="Ne construit rien : contrôle que mcpb/src correspond à src/.",
    )
    args = parser.parse_args()

    if args.verifier_seulement:
        raise SystemExit(
            subprocess.run(
                [sys.executable, str(OUTILS / "synchroniser_mcpb.py"), "--verifier"],
                cwd=RACINE,
            ).returncode
        )

    raise SystemExit(construire(verifier=not args.sans_verification))


if __name__ == "__main__":
    main()

"""Vérifie que les corpus embarqués correspondent encore à leur source amont.

**Le défaut que ce script surveille.** Les référentiels officiels sont figés
dans le paquet à la construction. Rien, ensuite, ne signale que la source a
publié une nouvelle version : le corpus continue de répondre avec la même
assurance. `corpus_info` dit désormais leur ÂGE ; ce script dit s'ils ont
réellement DIVERGÉ.

Les deux se complètent et ne se remplacent pas : un corpus vieux de trois mois
dont la source n'a pas bougé est parfaitement bon, et un corpus d'hier peut
déjà être en retard d'une publication.

**Le piège traité.** Chaque distillateur écrit `distilled_at` à la date du
jour. Comparer les fichiers octet à octet échouerait donc à *chaque* exécution,
pour la seule raison que la date a changé. La comparaison ignore ce champ.

Usage :
    python scripts/verifier_corpus.py              # les quatre
    python scripts/verifier_corpus.py cwe d3fend   # une sélection

Code de sortie 1 si au moins un corpus a divergé. Le fichier régénéré est
alors laissé en place, prêt à être relu puis commité ; s'il est identique,
l'original est restauré pour ne pas faire bouger la date sans raison.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).parent.parent

#: Le champ qui change a chaque execution et ne dit rien de la source.
CHAMP_VOLATIL = "distilled_at"

CORPUS: dict[str, tuple[str, str]] = {
    "attack": ("scripts/distiller_attack.py", "src/mitre_mcp/fixtures/attack.json"),
    "cwe": ("scripts/distiller_cwe.py", "src/vuln_intel_mcp/fixtures/cwe.json"),
    "d3fend": ("scripts/distiller_d3fend.py", "src/mitre_mcp/fixtures/d3fend.json"),
    "windows": (
        "scripts/distiller_windows_events.py",
        "src/detection_mcp/fixtures/windows_events.json",
    ),
}


def _sans_champ_volatil(brut: str) -> str:
    """Le contenu, débarrassé de la seule chose qui change toujours."""
    donnees = json.loads(brut)
    if isinstance(donnees, dict):
        donnees.pop(CHAMP_VOLATIL, None)
    return json.dumps(donnees, ensure_ascii=False, sort_keys=True)


def verifier(nom: str) -> bool:
    """Régénère un corpus et dit s'il a divergé. Vrai = inchangé."""
    script, cible = CORPUS[nom]
    chemin = RACINE / cible

    avant = chemin.read_text(encoding="utf-8") if chemin.exists() else None

    print(f"\n=== {nom} : {script} ===")
    resultat = subprocess.run(
        [sys.executable, str(RACINE / script)], cwd=RACINE, check=False
    )
    if resultat.returncode != 0:
        print(f"  [DIFF] {nom} : le distillateur a échoué (code {resultat.returncode}).")
        return False

    apres = chemin.read_text(encoding="utf-8")

    if avant is None:
        print(f"  [OK]   {nom} : corpus absent, désormais généré.")
        return False

    if _sans_champ_volatil(avant) == _sans_champ_volatil(apres):
        # Identique : restaurer pour ne pas faire bouger la date sans raison.
        chemin.write_text(avant, encoding="utf-8", newline="")
        print(f"  [OK]   {nom} : identique à la source, corpus inchangé.")
        return True

    print(
        f"  [DIFF] {nom} : LA SOURCE A CHANGÉ. Le fichier régénéré est en place "
        f"({cible}) — relisez la différence, puis commitez-la."
    )
    return False


def main() -> None:
    demandes = [a.lower() for a in sys.argv[1:]] or list(CORPUS)
    inconnus = [d for d in demandes if d not in CORPUS]
    if inconnus:
        raise SystemExit(f"Corpus inconnu(s) : {', '.join(inconnus)}. Choix : {', '.join(CORPUS)}.")

    divergents = [nom for nom in demandes if not verifier(nom)]

    print("\n" + "=" * 60)
    if divergents:
        print(f"{len(divergents)} corpus a/ont divergé : {', '.join(divergents)}")
        print("Relisez les fichiers régénérés, puis commitez-les.")
        raise SystemExit(1)
    print(f"Les {len(demandes)} corpus vérifiés correspondent encore à leur source.")


if __name__ == "__main__":
    main()

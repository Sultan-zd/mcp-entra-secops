"""La frontière entre ce qui est distribué et ce qui ne l'est pas.

Le dépôt contient deux zones qui n'ont pas le même destin :

* `src/` — **le produit**. Ces paquets sont recopiés dans l'extension `.mcpb`
  et s'exécutent chez l'analyste qui l'installe.
* `atelier/` — **hors paquet**. Outillage de développement et de validation,
  qui ne quitte jamais le dépôt.

Une séparation qu'aucun test ne vérifie n'est qu'une convention de nommage.
Ces tests la rendent contraignante, parce que la franchir produit un défaut
d'un genre particulièrement coûteux : le code passe tous les tests ici, le
paquet se construit sans erreur, et il échoue à l'import **chez le
destinataire** — sur une machine où `atelier/` n'existe pas.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
SOURCE = RACINE / "src"
ATELIER = RACINE / "atelier"


def _paquets_atelier() -> set[str]:
    return {d.name for d in ATELIER.iterdir() if d.is_dir() and not d.name.startswith(".")}


def _fichiers_du_produit() -> list[Path]:
    return sorted(
        f
        for f in SOURCE.rglob("*.py")
        if "__pycache__" not in f.parts
    )


def _modules_importes(fichier: Path) -> set[str]:
    """Les modules de premier niveau qu'un fichier importe.

    L'analyse porte sur l'arbre syntaxique plutôt que sur une recherche de
    texte : un `import argus_eval` en commentaire ou dans une chaîne ne doit
    pas déclencher d'échec, et un import à l'intérieur d'une fonction doit en
    déclencher un.
    """
    arbre = ast.parse(fichier.read_text(encoding="utf-8"), filename=str(fichier))
    trouves: set[str] = set()

    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.Import):
            for alias in noeud.names:
                trouves.add(alias.name.split(".", 1)[0])
        # `from . import x` est relatif (level > 0) : il reste dans le paquet.
        elif isinstance(noeud, ast.ImportFrom) and noeud.level == 0 and noeud.module:
            trouves.add(noeud.module.split(".", 1)[0])

    return trouves


def test_l_atelier_existe_et_le_produit_aussi() -> None:
    """Sans les deux zones, les tests suivants ne prouveraient rien."""
    assert SOURCE.is_dir(), "src/ est introuvable"
    assert ATELIER.is_dir(), "atelier/ est introuvable"
    assert _paquets_atelier(), "atelier/ ne contient aucun paquet"


@pytest.mark.parametrize("fichier", _fichiers_du_produit(), ids=lambda f: str(f.name))
def test_aucun_fichier_du_produit_n_importe_l_atelier(fichier: Path) -> None:
    """Le défaut que cette frontière existe pour rendre impossible.

    Un module de `src/` qui importerait `argus_agent` ou `argus_eval`
    fonctionnerait parfaitement ici — les deux sont installés dans
    l'environnement de développement. Le paquet se construirait sans un mot.
    Et il planterait à l'import chez l'analyste, dont le `.mcpb` ne contient
    pas `atelier/`.
    """
    interdits = _paquets_atelier() & _modules_importes(fichier)

    assert not interdits, (
        f"{fichier.relative_to(RACINE)} importe {', '.join(sorted(interdits))}, "
        "qui n'est pas distribué dans l'extension .mcpb."
    )


def test_les_deux_listes_de_paquets_ne_divergent_pas() -> None:
    """`pyproject.toml` et le script de construction doivent nommer les mêmes.

    Le script de synchronisation fait foi pour ce qui entre dans le paquet.
    Si `pyproject.toml` déclarait un paquet de plus, il serait installable en
    développement mais absent du `.mcpb` — l'écart ne se verrait qu'à
    l'exécution chez le destinataire.
    """
    import sys

    sys.path.insert(0, str(RACINE / "mcpb" / "outils"))
    from synchroniser_mcpb import PAQUETS  # type: ignore[import-not-found]

    declares = tomllib.loads((RACINE / "pyproject.toml").read_text(encoding="utf-8"))
    chemins = declares["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]

    dans_src = {Path(c).name for c in chemins if c.startswith("src/")}
    dans_atelier = {Path(c).name for c in chemins if c.startswith("atelier/")}

    assert dans_src == set(PAQUETS), (
        "src/ et la liste de construction divergent : "
        f"seulement dans pyproject = {dans_src - set(PAQUETS)}, "
        f"seulement dans le script = {set(PAQUETS) - dans_src}"
    )
    # L'atelier ne doit jamais se retrouver dans ce qui est empaqueté.
    assert not (dans_atelier & set(PAQUETS))


def test_tous_les_paquets_de_src_sont_declares() -> None:
    """Un paquet ajouté à src/ mais oublié dans les listes serait invisible.

    Il ne partirait ni dans le `.mcpb`, ni dans l'installation en
    développement — et ses tests passeraient quand même, parce que `src/` est
    sur le chemin d'import pendant la suite.
    """
    import sys

    sys.path.insert(0, str(RACINE / "mcpb" / "outils"))
    from synchroniser_mcpb import PAQUETS  # type: ignore[import-not-found]

    presents = {
        d.name
        for d in SOURCE.iterdir()
        if d.is_dir() and (d / "__init__.py").exists()
    }

    assert presents == set(PAQUETS), (
        f"paquets présents dans src/ mais non déclarés : {presents - set(PAQUETS)} ; "
        f"déclarés mais absents : {set(PAQUETS) - presents}"
    )

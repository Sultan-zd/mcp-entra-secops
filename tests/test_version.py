"""Une seule version, partout.

Le dépôt a longtemps annoncé six numéros différents : `0.6.0` à la racine,
`1.0.0` dans le paquet, et `0.1.0` à `0.3.0` selon les serveurs. Aucun test ne
le voyait, parce que chacun était correct isolément.

C'est un défaut de distribution, pas de code : on ne peut pas dire à une équipe
SOC « installez la version 1.0.0 » quand le projet, l'artefact et les serveurs
ne portent pas le même numéro — et le destinataire qui signale un problème ne
peut pas dire lequel il utilise.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from argus_net import VERSION

RACINE = Path(__file__).resolve().parent.parent
PRODUIT = RACINE / "src"


def _version_toml(chemin: Path) -> str:
    return str(tomllib.loads(chemin.read_text(encoding="utf-8"))["project"]["version"])


def test_le_projet_annonce_la_version_du_socle() -> None:
    assert _version_toml(RACINE / "pyproject.toml") == VERSION


def test_le_paquet_distribuable_annonce_la_meme() -> None:
    """Le `pyproject.toml` du paquet est lu par `uv` chez le destinataire."""
    assert _version_toml(RACINE / "mcpb" / "pyproject.toml") == VERSION


def test_le_manifeste_annonce_la_meme() -> None:
    """C'est le numéro que l'hôte affiche dans la liste des extensions."""
    import json

    manifeste = json.loads((RACINE / "mcpb" / "manifest.json").read_text(encoding="utf-8"))

    assert manifeste["version"] == VERSION


@pytest.mark.parametrize(
    "paquet",
    sorted(d.name for d in PRODUIT.iterdir() if d.is_dir() and (d / "server.py").exists()),
)
def test_chaque_serveur_annonce_la_version_du_socle(paquet: str) -> None:
    """La version qu'un serveur MCP transmet à son client, à la connexion.

    Le test lit le fichier plutôt que d'instancier le serveur : un littéral
    recopié à la main doit échouer ici, même s'il vaut par coïncidence la
    bonne valeur aujourd'hui.
    """
    source = (PRODUIT / paquet / "server.py").read_text(encoding="utf-8")

    assert "version=VERSION," in source, (
        f"{paquet}/server.py déclare une version en dur au lieu d'importer "
        "argus_net.VERSION"
    )

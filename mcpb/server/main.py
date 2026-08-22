"""Point d'entrée du paquet MCPB.

`uv` installe les dépendances déclarées dans `pyproject.toml`, puis exécute ce
fichier. Le code des serveurs vit dans `src/`, à côté.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Le paquet n'est pas installé : il est exécuté depuis le bundle. On ajoute
# `src/` au chemin d'import plutôt que d'exiger une étape d'installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from argus_bundle.__main__ import main  # noqa: E402

if __name__ == "__main__":
    main()

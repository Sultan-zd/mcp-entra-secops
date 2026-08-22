"""Sortie console lisible, y compris sous Windows.

Le terminal Windows utilise encore `cp1252` par défaut. Les diagnostics
`--check` de ce projet affichent des caractères de cadre et du texte accentué :
sans cette correction, la première commande qu'un analyste lance s'arrête sur
une `UnicodeEncodeError`.

Le défaut était invisible en développement, parce que `PYTHONIOENCODING=utf-8`
traînait dans l'environnement. Il n'apparaît que sur un poste neuf — c'est-à-dire
chez la personne à qui on distribue l'outil.
"""

from __future__ import annotations

import sys
from contextlib import suppress


def forcer_utf8() -> None:
    """Bascule la sortie standard et la sortie d'erreur en UTF-8.

    À appeler au tout début d'un point d'entrée, avant le moindre affichage.
    En transport stdio, cela vaut aussi pour le protocole : JSON-RPC est défini
    en UTF-8, et un flux en `cp1252` corromprait les accents des descriptions
    d'outils.
    """
    for flux in (sys.stdout, sys.stderr):
        reconfigurer = getattr(flux, "reconfigure", None)
        if reconfigurer is None:
            continue
        # Flux redirigé vers quelque chose qui n'accepte pas la
        # reconfiguration : mieux vaut un affichage dégradé qu'un plantage.
        with suppress(ValueError, OSError):
            reconfigurer(encoding="utf-8", errors="replace")

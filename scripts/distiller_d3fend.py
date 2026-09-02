"""Distille les correspondances MITRE D3FEND -> ATT&CK en un jeu embarquable.

D3FEND est le contrepoint défensif d'ATT&CK : à chaque technique offensive,
il nomme les contre-mesures qui la contrent, classées par tactique défensive
(Harden, Detect, Isolate, Deceive, Evict, Model, Restore). ATT&CK dit ce que
fait un attaquant ; D3FEND dit quoi construire pour s'en défendre.

**Pourquoi ce n'est pas un simple téléchargement à l'exécution.** Le graphe
d'ontologie complet dépasse la centaine de mégaoctets, et n'a aucune raison
de changer plus souvent qu'ATT&CK. Le distiller à la construction rend l'outil
utilisable hors ligne, comme le reste des corpus de ce projet.

**Deux appels sont nécessaires, pas un seul.** L'API de mappings
(`d3fend-full-mappings.json`) donne les liens technique → contre-mesure, mais
seulement leurs noms — pas ce qu'elles font. Chaque contre-mesure a sa propre
fiche, interrogée séparément, pour la définition en une phrase qui rend le nom
exploitable. Les deux réponses sont d'authentiques exports MITRE, jamais du
texte inventé pour combler l'absence de définition.

Usage :
    python scripts/distiller_d3fend.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

import httpx

MAPPINGS_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"
TECHNIQUE_URL = "https://d3fend.mitre.org/api/technique/{iri}.json"

DESTINATION = Path(__file__).parent.parent / "src" / "mitre_mcp" / "fixtures" / "d3fend.json"

#: Seul le référentiel Enterprise est embarqué ailleurs dans ce projet (ATT&CK
#: aussi ne couvre qu'Enterprise) : ICS et SPARTA n'ont rien à relier ici.
FRAMEWORK = "enterprise"

#: Nombre de fiches de contre-mesure récupérées en parallèle. Un point de
#: terminaison public mérite d'être interrogé poliment, pas martelé.
CONCURRENCE = 5


def _valeur(ligne: dict[str, Any], cle: str) -> str | None:
    entree = ligne.get(cle)
    return entree.get("value") if isinstance(entree, dict) else None


def _nom_local(iri: str) -> str:
    """La partie après `#` d'un IRI D3FEND : l'identifiant utilisable dans l'URL."""
    return iri.rsplit("#", 1)[-1]


async def _definition(
    client: httpx.AsyncClient, nom_local: str, semaphore: asyncio.Semaphore
) -> dict[str, str | None]:
    async with semaphore:
        url = TECHNIQUE_URL.format(iri=f"d3f:{nom_local}")
        try:
            reponse = await client.get(url, timeout=30)
            reponse.raise_for_status()
        except httpx.HTTPError as exc:
            print(f"  ! {nom_local} : {exc}", file=sys.stderr)
            return {"definition": None, "d3fend_id": None}

        charge = reponse.json()
        graphe = (charge.get("description") or {}).get("@graph") or []
        for noeud in graphe:
            if noeud.get("@id") == f"d3f:{nom_local}":
                return {
                    "definition": noeud.get("d3f:definition"),
                    "d3fend_id": noeud.get("d3f:d3fend-id"),
                }
        return {"definition": None, "d3fend_id": None}


async def distiller() -> dict[str, Any]:
    print(f"Téléchargement des correspondances depuis {MAPPINGS_URL} …")
    async with httpx.AsyncClient() as client:
        reponse = await client.get(MAPPINGS_URL, timeout=90)
        reponse.raise_for_status()
        lignes = reponse.json()["results"]["bindings"]

    lignes_entreprise = [
        ligne for ligne in lignes if _valeur(ligne, "framework_key") == FRAMEWORK
    ]
    print(f"{len(lignes)} lignes reçues, {len(lignes_entreprise)} pour {FRAMEWORK}.")

    # --- les liens technique -> contre-mesure, dédoublonnés -----------------
    par_technique: dict[str, list[dict[str, str]]] = {}
    noms_locaux: dict[str, str] = {}  # etiquette -> nom local IRI

    for ligne in lignes_entreprise:
        technique_id = _valeur(ligne, "off_tech_id")
        etiquette = _valeur(ligne, "def_tech_label")
        tactique = _valeur(ligne, "def_tactic_label")
        relation = _valeur(ligne, "def_artifact_rel_label")
        artefact = _valeur(ligne, "def_artifact_label")
        iri_tech = _valeur(ligne, "def_tech")
        if not (technique_id and etiquette and tactique):
            continue

        if etiquette not in noms_locaux and iri_tech:
            noms_locaux[etiquette] = _nom_local(iri_tech)

        entree = {
            "countermeasure": etiquette,
            "tactic": tactique,
            "relationship": relation,
            "artifact": artefact,
        }
        liste = par_technique.setdefault(technique_id, [])
        if entree not in liste:
            liste.append(entree)

    print(f"{len(par_technique)} techniques ATT&CK couvertes, "
          f"{len(noms_locaux)} contre-mesures distinctes à définir.")

    # --- les définitions, une fiche par contre-mesure -----------------------
    print("Récupération des définitions (une fiche par contre-mesure) …")
    semaphore = asyncio.Semaphore(CONCURRENCE)
    async with httpx.AsyncClient() as client:
        resultats = await asyncio.gather(
            *(_definition(client, nom, semaphore) for nom in noms_locaux.values())
        )

    # Nommer cette variable `_nom_local` recouvrirait la fonction module du
    # même nom pour toute la portée de `distiller()` — Python résout les
    # noms par fonction entière, pas ligne à ligne, et l'appel plus haut
    # échouait avec un `UnboundLocalError` avant même d'atteindre cette boucle.
    countermeasures: dict[str, dict[str, str | None]] = {}
    for (etiquette, _iri_locale), definition in zip(noms_locaux.items(), resultats, strict=True):
        countermeasures[etiquette] = {
            "label": etiquette,
            "definition": definition["definition"],
            "d3fend_id": definition["d3fend_id"],
        }

    trouvees = sum(1 for c in countermeasures.values() if c["definition"])
    print(f"{trouvees}/{len(countermeasures)} définitions obtenues.")

    return {
        "framework": FRAMEWORK,
        "source": MAPPINGS_URL,
        # D3FEND ne publie pas de numéro de version exploitable : cette date
        # est le seul repère disponible sur l'âge de ces correspondances.
        "distilled_at": date.today().isoformat(),
        "technique_count": len(par_technique),
        "countermeasure_count": len(countermeasures),
        "techniques": par_technique,
        "countermeasures": countermeasures,
    }


def main() -> None:
    resultat = asyncio.run(distiller())

    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(
        json.dumps(resultat, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    poids = DESTINATION.stat().st_size / 1024
    print(f"{DESTINATION} écrit : {poids:.0f} Ko")


if __name__ == "__main__":
    main()

"""Distille le corpus MITRE ATT&CK en un jeu embarquable.

Le paquet STIX officiel pèse 53 Mo. Le télécharger au démarrage du serveur
coûterait plusieurs secondes à chaque lancement, échouerait hors ligne, et
placerait une dépendance réseau au cœur d'outils qui n'en ont aucun besoin :
le corpus ATT&CK change quatre fois par an, pas quatre fois par heure.

Ce script réduit donc le paquet à ce que les outils lisent réellement, et le
résultat est versionné avec le code. Les serveurs MITRE fonctionnent alors
**entièrement hors ligne**, ce qu'aucun relais d'API ne permet.

Usage :
    python scripts/distiller_attack.py [chemin/vers/enterprise-attack.json]

Sans argument, le paquet est téléchargé depuis le dépôt officiel.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any

SOURCE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

DESTINATION = Path(__file__).parent.parent / "src" / "mitre_mcp" / "fixtures" / "attack.json"

#: Une description ATT&CK complète fait souvent plus de 3 000 caractères. Ce
#: qui décide tient dans les premières phrases ; le reste encombre le contexte
#: du modèle sans rien ajouter à la décision.
MAX_DESCRIPTION = 900

#: Idem pour le texte de détection, qui est le plus utile de tous.
MAX_DETECTION = 700


def _identifiant(objet: dict[str, Any]) -> str | None:
    """L'identifiant ATT&CK lisible (T1566.002), pas l'identifiant STIX."""
    for ref in objet.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _url(objet: dict[str, Any]) -> str | None:
    for ref in objet.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def _tronquer(texte: str | None, limite: int) -> str | None:
    if not texte:
        return None
    propre = " ".join(texte.split())
    return propre[:limite] + ("…" if len(propre) > limite else "")


def _actif(objet: dict[str, Any]) -> bool:
    return not objet.get("revoked") and not objet.get("x_mitre_deprecated")


def distiller(paquet: dict[str, Any]) -> dict[str, Any]:
    objets = paquet["objects"]
    par_stix = {o["id"]: o for o in objets}

    # ------------------------------------------------------------ tactiques
    tactiques = {}
    for o in objets:
        if o["type"] == "x-mitre-tactic" and _actif(o):
            tactiques[o.get("x_mitre_shortname", "")] = {
                "id": _identifiant(o),
                "name": o.get("name"),
                "shortname": o.get("x_mitre_shortname"),
                "description": _tronquer(o.get("description"), 400),
                "url": _url(o),
            }

    # ---------------------------------------------------------- atténuations
    attenuations = {
        o["id"]: {
            "id": _identifiant(o),
            "name": o.get("name"),
            "description": _tronquer(o.get("description"), 400),
        }
        for o in objets
        if o["type"] == "course-of-action" and _actif(o)
    }

    # ------------------------------------------------------------ relations
    # Qui atténue quoi, et qui utilise quoi. Les relations sont l'essentiel de
    # la valeur du corpus : une technique sans ses parades n'aide personne.
    attenue: dict[str, list[str]] = {}
    utilise: dict[str, list[str]] = {}
    for o in objets:
        if o["type"] != "relationship":
            continue
        cible, source = o.get("target_ref", ""), o.get("source_ref", "")
        if o.get("relationship_type") == "mitigates" and source in attenuations:
            attenue.setdefault(cible, []).append(source)
        elif o.get("relationship_type") == "uses" and cible.startswith("attack-pattern--"):
            acteur = par_stix.get(source)
            if acteur and _actif(acteur) and acteur["type"] in ("intrusion-set", "malware", "tool"):
                utilise.setdefault(cible, []).append(source)

    # ------------------------------------------------------------ détection
    # ATT&CK v19 a sorti la détection de l'objet technique : le champ
    # `x_mitre_detection` est désormais vide sur les 697 techniques. La donnée
    # vit dans des objets `x-mitre-detection-strategy` reliés par une relation
    # `detects`, qui pointent eux-mêmes vers des `x-mitre-analytic`.
    #
    # C'est plus riche que l'ancien texte libre : les analytiques nomment les
    # sources de journaux concrètes (« auditd:SYSCALL », « WinEventLog:Security »),
    # ce qu'un ingénieur détection cherche en premier.
    analytiques = {o["id"]: o for o in objets if o["type"] == "x-mitre-analytic" and _actif(o)}

    detection: dict[str, list[dict[str, Any]]] = {}
    for o in objets:
        if o["type"] != "relationship" or o.get("relationship_type") != "detects":
            continue
        strategie = par_stix.get(o.get("source_ref", ""))
        if not strategie or strategie.get("type") != "x-mitre-detection-strategy":
            continue
        if not _actif(strategie):
            continue

        entrees = []
        for ref in strategie.get("x_mitre_analytic_refs") or []:
            analytique = analytiques.get(ref)
            if not analytique:
                continue
            sources = []
            for src in analytique.get("x_mitre_log_source_references") or []:
                libelle = src.get("name")
                canal = src.get("channel")
                if libelle:
                    sources.append(f"{libelle} ({canal})" if canal else libelle)
            entrees.append(
                {
                    "guidance": _tronquer(analytique.get("description"), MAX_DETECTION),
                    "platforms": analytique.get("x_mitre_platforms") or [],
                    "log_sources": sources[:8],
                }
            )

        if entrees:
            detection.setdefault(o.get("target_ref", ""), []).append(
                {"strategy": strategie.get("name"), "analytics": entrees}
            )

    # ---------------------------------------------------------- techniques
    techniques = []
    for o in objets:
        if o["type"] != "attack-pattern" or not _actif(o):
            continue
        identifiant = _identifiant(o)
        if not identifiant:
            continue

        acteurs = []
        logiciels = []
        for ref in utilise.get(o["id"], []):
            source = par_stix.get(ref, {})
            nom = source.get("name")
            if not nom:
                continue
            if source["type"] == "intrusion-set":
                acteurs.append(nom)
            else:
                logiciels.append(nom)

        techniques.append(
            {
                "id": identifiant,
                "name": o.get("name"),
                "description": _tronquer(o.get("description"), MAX_DESCRIPTION),
                "tactics": [
                    p.get("phase_name")
                    for p in o.get("kill_chain_phases") or []
                    if p.get("kill_chain_name") == "mitre-attack"
                ],
                "platforms": o.get("x_mitre_platforms") or [],
                "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
                "parent": identifiant.split(".")[0] if "." in identifiant else None,
                "detection": detection.get(o["id"], []),
                "data_sources": o.get("x_mitre_data_sources") or [],
                "mitigations": sorted(
                    {
                        attenuations[m]["id"]
                        for m in attenue.get(o["id"], [])
                        if m in attenuations and attenuations[m]["id"]
                    }
                ),
                "actors": sorted(set(acteurs))[:12],
                "software": sorted(set(logiciels))[:12],
                "url": _url(o),
            }
        )

    techniques.sort(key=lambda t: t["id"])

    # ------------------------------------------------------------ révoquées
    # ATT&CK révoque et remplace des techniques à chaque version majeure : la
    # famille T1562 a disparu en v19. Les ignorer ferait répondre « inconnue »
    # à un analyste qui cite un identifiant parfaitement réel — mais périmé.
    # Mieux vaut le lui dire, et le renvoyer vers le remplaçant.
    remplace_par: dict[str, str] = {}
    for o in objets:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            remplace_par[o.get("source_ref", "")] = o.get("target_ref", "")

    revoquees = []
    for o in objets:
        if o["type"] != "attack-pattern" or _actif(o):
            continue
        identifiant = _identifiant(o)
        if not identifiant:
            continue
        successeur = par_stix.get(remplace_par.get(o["id"], ""), {})
        revoquees.append(
            {
                "id": identifiant,
                "name": o.get("name"),
                "reason": "revoked" if o.get("revoked") else "deprecated",
                "replaced_by": _identifiant(successeur) if successeur else None,
                "replaced_by_name": successeur.get("name") if successeur else None,
            }
        )
    revoquees.sort(key=lambda r: r["id"] or "")

    # --------------------------------------------------------------- groupes
    groupes = [
        {
            "id": _identifiant(o),
            "name": o.get("name"),
            "aliases": (o.get("aliases") or [])[:8],
            "description": _tronquer(o.get("description"), 350),
            "url": _url(o),
        }
        for o in objets
        if o["type"] == "intrusion-set" and _actif(o) and _identifiant(o)
    ]
    groupes.sort(key=lambda g: g["id"] or "")

    version = ""
    for o in objets:
        if o["type"] == "x-mitre-collection":
            version = o.get("x_mitre_version", "")
            break

    return {
        "source": "MITRE ATT&CK Enterprise, paquet STIX officiel",
        "attack_version": version,
        "distilled_by": "scripts/distiller_attack.py",
        # Sans cette date, un corpus figé répond avec la même assurance à six
        # jours qu'à seize mois : rien ne distingue « n'existe pas dans
        # ATT&CK » de « n'existait pas encore à la construction ».
        "distilled_at": date.today().isoformat(),
        "counts": {
            "techniques": len(techniques),
            "tactics": len(tactiques),
            "mitigations": len(attenuations),
            "groups": len(groupes),
            "revoked": len(revoquees),
        },
        "tactics": [tactiques[k] for k in sorted(tactiques)],
        "mitigations": sorted(
            (m for m in attenuations.values() if m["id"]), key=lambda m: m["id"] or ""
        ),
        "techniques": techniques,
        "revoked": revoquees,
        "groups": groupes,
    }


def main() -> None:
    if len(sys.argv) > 1:
        brut = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    else:
        print(f"Téléchargement de {SOURCE} …", file=sys.stderr)
        with urllib.request.urlopen(SOURCE) as reponse:
            brut = json.loads(reponse.read().decode("utf-8"))

    distille = distiller(brut)
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(
        json.dumps(distille, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )

    taille = DESTINATION.stat().st_size
    print(f"ATT&CK v{distille['attack_version']} → {DESTINATION}")
    print(f"  {distille['counts']}")
    print(f"  {taille / 1024 / 1024:.1f} Mo (contre 51,3 Mo pour le paquet complet)")


if __name__ == "__main__":
    main()

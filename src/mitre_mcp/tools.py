"""Les outils MITRE ATT&CK, tous entièrement locaux.

Aucun n'accède au réseau : le corpus est embarqué. Un serveur qui répond en
quelques millisecondes, hors ligne, et dont les réponses ne changent pas entre
deux appels — c'est ce que permet de distiller la donnée plutôt que de la
relayer.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from pydantic import Field

from .corpus import charger, chercher, resoudre_identifiant
from .mapping import constats_connus, correspondances
from .models import (
    AttackMapping,
    CorpusInfo,
    CoverageReport,
    GroupProfile,
    MappedFinding,
    NavigatorLayer,
    TacticSummary,
    TechniqueDetail,
    TechniqueSummary,
)


def _sources_de_journaux(technique: dict[str, Any]) -> list[str]:
    """Les canaux de journalisation à collecter, dédoublonnés et ordonnés.

    C'est la réponse concrète à « par où commencer » : sans le bon journal,
    aucune règle de détection ne se déclenchera jamais.
    """
    vues: dict[str, None] = {}
    for strategie in technique.get("detection") or []:
        for analytique in strategie.get("analytics") or []:
            for source in analytique.get("log_sources") or []:
                vues.setdefault(str(source), None)
    return list(vues)


def _resume(technique: dict[str, Any]) -> TechniqueSummary:
    return TechniqueSummary(
        id=technique["id"],
        name=technique.get("name") or "",
        tactics=technique.get("tactics") or [],
        platforms=technique.get("platforms") or [],
        is_subtechnique=bool(technique.get("is_subtechnique")),
    )


async def lookup_technique(
    technique_id: Annotated[str, Field(description="Identifiant, par exemple T1566 ou T1566.002.")],
) -> TechniqueDetail:
    """Fiche complète d'une technique ATT&CK : description, détection, parades.

    Le champ `detection` est le plus utile au quotidien : il dit *quoi
    surveiller* pour repérer la technique, ce qu'aucune description ne donne.

    Une technique retirée du référentiel n'est pas traitée comme inconnue :
    l'outil dit qu'elle a été révoquée et vers quoi elle a été remplacée. ATT&CK
    en révoque à chaque version majeure, et un analyste citant un ancien
    identifiant mérite mieux qu'un « introuvable ».
    """
    identifiant = resoudre_identifiant(technique_id)
    corpus = charger()

    technique = corpus.technique(identifiant)
    if technique is None:
        obsolete = corpus.revoquee(identifiant)
        if obsolete:
            remplacant = obsolete.get("replaced_by")
            message = (
                f"{identifiant} ({obsolete.get('name')}) a été retirée du référentiel "
                f"ATT&CK en v{corpus.version}."
            )
            if remplacant:
                message += (
                    f" Elle est remplacée par {remplacant} ({obsolete.get('replaced_by_name')})."
                )
            raise ValueError(message)
        raise ValueError(f"{identifiant} n'existe pas dans ATT&CK Enterprise v{corpus.version}.")

    return TechniqueDetail(
        id=technique["id"],
        name=technique.get("name") or "",
        description=technique.get("description"),
        tactics=technique.get("tactics") or [],
        tactic_names=[
            corpus.tactics[t]["name"] for t in technique.get("tactics") or [] if t in corpus.tactics
        ],
        platforms=technique.get("platforms") or [],
        is_subtechnique=bool(technique.get("is_subtechnique")),
        parent=technique.get("parent"),
        subtechniques=[_resume(s) for s in corpus.sous_techniques(identifiant)],
        detection=technique.get("detection") or [],
        log_sources=_sources_de_journaux(technique),
        data_sources=technique.get("data_sources") or [],
        mitigations=[
            {
                "id": m,
                "name": corpus.mitigations.get(m, {}).get("name"),
                "description": corpus.mitigations.get(m, {}).get("description"),
            }
            for m in technique.get("mitigations") or []
        ],
        known_actors=technique.get("actors") or [],
        known_software=technique.get("software") or [],
        url=technique.get("url"),
        attack_version=corpus.version,
    )


async def search_techniques(
    query: Annotated[str, Field(description="Mots-clés : « phishing », « valid accounts »…")],
    platform: Annotated[
        str | None,
        Field(description="Filtre de plateforme : Windows, Linux, macOS, Azure AD, Office 365…"),
    ] = None,
    tactic: Annotated[
        str | None,
        Field(description="Filtre de tactique : initial-access, persistence, exfiltration…"),
    ] = None,
    limit: Annotated[int, Field(description="Nombre de résultats.", ge=1, le=50)] = 15,
) -> dict[str, Any]:
    """Cherche des techniques par mots-clés, hors ligne.

    Le classement privilégie fortement le nom sur la description : quelqu'un
    qui tape « phishing » veut T1566, pas les quarante techniques dont la
    description mentionne le mot en passant.
    """
    if not query.strip():
        raise ValueError("Indiquez des mots-clés.")

    corpus = charger()
    if tactic and tactic.strip().lower() not in corpus.tactics:
        raise ValueError(
            f"Tactique « {tactic} » inconnue. Valeurs possibles : "
            + ", ".join(sorted(corpus.tactics))
            + "."
        )

    trouves = chercher(query, plateforme=platform, tactique=tactic, limite=limit)

    return {
        "query": query.strip(),
        "attack_version": corpus.version,
        "returned": len(trouves),
        "results": [
            {
                **_resume(t).model_dump(),
                "relevance": round(score, 1),
                "description": (t.get("description") or "")[:180] or None,
            }
            for t, score in trouves
        ],
        "notes": (
            []
            if trouves
            else ["Aucune technique ne correspond. Essayez un terme du vocabulaire ATT&CK anglais."]
        ),
    }


async def list_tactics() -> list[TacticSummary]:
    """Les tactiques ATT&CK, c'est-à-dire les objectifs successifs d'un attaquant.

    À utiliser pour situer un incident dans la progression d'une attaque :
    l'accès initial et l'exfiltration ne se traitent pas avec la même urgence.
    """
    corpus = charger()
    return [
        TacticSummary(
            id=t.get("id") or "",
            name=t.get("name") or "",
            shortname=shortname,
            description=t.get("description"),
            technique_count=len(corpus.par_tactique(shortname)),
        )
        for shortname, t in sorted(corpus.tactics.items(), key=lambda kv: kv[1].get("id") or "")
    ]


async def map_findings_to_attack(
    findings: Annotated[
        list[str],
        Field(
            description=(
                "Constats à traduire : types de détection Entra "
                "(leakedCredentials, passwordSpray…), opérations d'annuaire "
                "(« add member to role »…), ou signaux du verdict ARGUS."
            )
        ),
    ],
) -> AttackMapping:
    """Traduit des constats d'ARGUS en techniques ATT&CK.

    C'est l'outil qui relie ce que la plateforme observe au vocabulaire commun
    des rapports d'incident. La correspondance vient d'une **table écrite à la
    main** et testée, pas d'une recherche par similarité : un identifiant
    ATT&CK finit dans un rapport relu par quelqu'un qui connaît le référentiel,
    il ne peut pas être approximatif.

    Chaque correspondance porte sa justification. Un constat sans
    correspondance établie est listé à part plutôt que rapproché de la
    technique la plus proche — une correspondance fausse est pire qu'absente.
    """
    if not findings:
        raise ValueError("Fournissez au moins un constat.")

    corpus = charger()
    traduits: list[MappedFinding] = []
    non_traduits: list[str] = []
    techniques_vues: dict[str, int] = {}
    tactiques_vues: set[str] = set()

    for constat in findings:
        liens = correspondances(constat)
        if not liens:
            non_traduits.append(constat)
            continue

        for lien in liens:
            technique = corpus.technique(lien.technique)
            if technique is None:
                # Ne peut arriver qu'après une mise à jour du corpus sans mise
                # à jour de la table : un test l'interdit, mais si cela se
                # produit, mieux vaut le dire que rendre une fiche vide.
                non_traduits.append(f"{constat} → {lien.technique} (absente du corpus)")
                continue

            techniques_vues[technique["id"]] = techniques_vues.get(technique["id"], 0) + 1
            tactiques_vues.update(technique.get("tactics") or [])

            traduits.append(
                MappedFinding(
                    finding=constat,
                    technique_id=technique["id"],
                    technique_name=technique.get("name") or "",
                    tactics=technique.get("tactics") or [],
                    reason=lien.reason,
                    confidence=lien.confidence,
                    mitigations=technique.get("mitigations") or [],
                    url=technique.get("url"),
                )
            )

    return AttackMapping(
        attack_version=corpus.version,
        mapped=traduits,
        unmapped=non_traduits,
        distinct_techniques=sorted(techniques_vues),
        tactics_covered=sorted(tactiques_vues),
        summary=_resume_mapping(traduits, tactiques_vues, non_traduits),
        known_vocabulary_size=len(constats_connus()),
    )


def _resume_mapping(
    traduits: list[MappedFinding], tactiques: set[str], non_traduits: list[str]
) -> str:
    if not traduits:
        return (
            "Aucun constat n'a de correspondance établie. Utilisez "
            "`list_known_findings` pour voir le vocabulaire reconnu."
        )

    # La progression dans la chaîne d'attaque est ce qui inquiète : un
    # attaquant qui a atteint la persistance ne partira pas avec le mot de passe.
    avancees = {"persistence", "privilege-escalation", "exfiltration", "impact"}
    atteintes = sorted(tactiques & avancees)

    message = (
        f"{len(traduits)} correspondance(s) sur "
        f"{len({m.technique_id for m in traduits})} technique(s) distincte(s), "
        f"couvrant {len(tactiques)} tactique(s)."
    )
    if atteintes:
        message += (
            " L'attaquant a atteint des étapes tardives de la chaîne ("
            + ", ".join(atteintes)
            + ") : une simple réinitialisation de mot de passe ne suffira pas."
        )
    if non_traduits:
        message += f" {len(non_traduits)} constat(s) sans correspondance établie."
    return message


async def list_known_findings() -> dict[str, Any]:
    """Le vocabulaire de constats que `map_findings_to_attack` sait traduire.

    Utile pour savoir quoi lui passer : la table est fermée à dessein, et
    connaître ses entrées évite d'essayer des formulations libres qui ne
    correspondront à rien.
    """
    return {
        "attack_version": charger().version,
        "count": len(constats_connus()),
        "findings": constats_connus(),
        "note": (
            "La table est volontairement fermée. Un constat absent de cette "
            "liste sera rendu « non traduit » plutôt que rapproché "
            "approximativement d'une technique."
        ),
    }


async def coverage_report(
    detected_techniques: Annotated[
        list[str], Field(description="Techniques que vos détections couvrent déjà.")
    ],
    tactic: Annotated[
        str | None, Field(description="Restreindre l'analyse à une tactique.")
    ] = None,
    platform: Annotated[
        str | None, Field(description="Restreindre à une plateforme : Azure AD, Windows…")
    ] = None,
) -> CoverageReport:
    """Ce que vos détections ne couvrent pas encore.

    À utiliser pour une revue de couverture : on donne les techniques que le
    SIEM détecte, l'outil rend celles qui restent, avec leur texte de détection
    pour savoir par où commencer.

    Restreindre par plateforme est presque toujours souhaitable : viser 100 %
    des 697 techniques d'ATT&CK Enterprise n'a aucun sens pour un parc qui n'a
    ni conteneurs ni systèmes industriels.
    """
    corpus = charger()

    couvertes: set[str] = set()
    invalides: list[str] = []
    for brut in detected_techniques:
        try:
            identifiant = resoudre_identifiant(brut)
        except ValueError:
            invalides.append(brut)
            continue
        if corpus.technique(identifiant) is None:
            invalides.append(brut)
        else:
            couvertes.add(identifiant)

    if tactic and tactic.strip().lower() not in corpus.tactics:
        raise ValueError(f"Tactique « {tactic} » inconnue.")

    perimetre = [
        t
        for t in corpus.techniques.values()
        if (not tactic or tactic.strip().lower() in (t.get("tactics") or []))
        and (not platform or platform.lower() in {p.lower() for p in t.get("platforms") or []})
    ]

    manquantes = sorted((t for t in perimetre if t["id"] not in couvertes), key=lambda t: t["id"])

    return CoverageReport(
        attack_version=corpus.version,
        scope_size=len(perimetre),
        covered=len(perimetre) - len(manquantes),
        missing=len(manquantes),
        coverage_ratio=round((len(perimetre) - len(manquantes)) / len(perimetre), 3)
        if perimetre
        else 0.0,
        invalid_inputs=invalides,
        gaps=[
            {
                "id": t["id"],
                "name": t.get("name"),
                "tactics": t.get("tactics"),
                "log_sources": _sources_de_journaux(t)[:5],
            }
            for t in manquantes[:40]
        ],
        note=(
            f"{len(manquantes)} technique(s) non couverte(s) sur {len(perimetre)} dans le "
            "périmètre ; les 40 premières sont détaillées."
            if len(manquantes) > 40
            else "Toutes les lacunes sont détaillées."
        ),
    )


async def lookup_group(
    group_id: Annotated[str, Field(description="Identifiant de groupe, par exemple G0016.")],
) -> GroupProfile:
    """Fiche d'un groupe d'attaquants suivi par MITRE.

    Utile quand un rapport de renseignement nomme un acteur : la fiche dit ses
    alias — les éditeurs emploient des noms différents pour le même groupe —
    et ce qu'il fait.
    """
    identifiant = group_id.strip().upper()
    corpus = charger()
    groupe = corpus.groups.get(identifiant)
    if groupe is None:
        raise ValueError(
            f"Groupe « {group_id} » inconnu dans ATT&CK v{corpus.version}. "
            "Les identifiants ont la forme G0016."
        )

    techniques = sorted(
        (t for t in corpus.techniques.values() if groupe.get("name") in (t.get("actors") or [])),
        key=lambda t: t["id"],
    )

    return GroupProfile(
        id=groupe["id"],
        name=groupe.get("name") or "",
        aliases=groupe.get("aliases") or [],
        description=groupe.get("description"),
        techniques=[_resume(t) for t in techniques],
        url=groupe.get("url"),
        attack_version=corpus.version,
    )


async def build_navigator_layer(
    technique_ids: Annotated[list[str], Field(description="Techniques à surligner.")],
    name: Annotated[str, Field(description="Nom de la couche.")] = "ARGUS",
    comment: Annotated[
        str | None, Field(description="Commentaire porté par chaque technique.")
    ] = None,
) -> NavigatorLayer:
    """Produit une couche pour l'ATT&CK Navigator.

    Le Navigator est l'outil où les équipes de détection travaillent vraiment.
    Rendre une couche directement importable évite le recopiage manuel d'une
    liste de techniques — l'étape où les erreurs se glissent.

    Le résultat se colle dans un fichier `.json` et s'ouvre par « Open Existing
    Layer » sur mitre-attack.github.io/attack-navigator.
    """
    if not technique_ids:
        raise ValueError("Fournissez au moins une technique.")

    corpus = charger()
    entrees = []
    inconnues = []
    for brut in technique_ids:
        try:
            identifiant = resoudre_identifiant(brut)
        except ValueError:
            inconnues.append(brut)
            continue
        technique = corpus.technique(identifiant)
        if technique is None:
            inconnues.append(brut)
            continue
        entrees.append(
            {
                "techniqueID": identifiant,
                "color": "#e60d0d",
                "comment": comment or "",
                "enabled": True,
                "showSubtechniques": bool(corpus.sous_techniques(identifiant)),
            }
        )

    couche = {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "5.0.0", "attack": corpus.version},
        "domain": "enterprise-attack",
        "description": f"Couche produite par ARGUS ({len(entrees)} technique(s)).",
        "techniques": entrees,
        "gradient": {"colors": ["#ffffff", "#e60d0d"], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": "Observé", "color": "#e60d0d"}],
    }

    return NavigatorLayer(
        attack_version=corpus.version,
        techniques_included=len(entrees),
        unknown=inconnues,
        layer_json=json.dumps(couche, ensure_ascii=False, indent=2),
    )


async def corpus_info() -> CorpusInfo:
    """Version et contenu du corpus ATT&CK embarqué.

    À consulter avant de se fier à une réponse : un corpus figé au moment de la
    construction est un compromis assumé — il rend le serveur utilisable hors
    ligne, au prix d'un décalage possible avec la dernière version publiée.
    """
    corpus = charger()
    return CorpusInfo(
        attack_version=corpus.version,
        techniques=len(corpus.techniques),
        tactics=len(corpus.tactics),
        mitigations=len(corpus.mitigations),
        groups=len(corpus.groups),
        revoked_techniques=len(corpus.revoked),
        offline=True,
        note=(
            "Corpus embarqué : aucun appel réseau. Régénérable avec "
            "« python scripts/distiller_attack.py »."
        ),
    )

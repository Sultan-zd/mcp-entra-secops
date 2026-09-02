"""Les outils d'ingénierie de détection.

Tous fonctionnent **hors ligne** : extraction d'indicateurs, analyse de règles
Sigma, rattachement au corpus ATT&CK embarqué. Aucun n'envoie quoi que ce soit
à un tiers — ce qui compte pour un rapport de menace encore confidentiel ou un
courriel signalé par un utilisateur.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from pydantic import Field

from . import couverture as cv
from . import iocs as ioc
from . import redos as rd
from . import sigma_rules as sr
from . import windows_events as we
from . import yara_rules as yr
from .models import (
    ConvertedRule,
    CoverageEntry,
    DefangedIOCs,
    DetectionAdvice,
    ExcludedValue,
    ExtractedIOCs,
    FileHash,
    LinkedTechnique,
    RedosAnalysis,
    RedosFinding,
    RuleExplanation,
    RuleQuality,
    RuleSetCoverage,
    SigmaAnalysis,
    SysmonEvent,
    WindowsEventMatches,
    WindowsSecurityEvent,
    YaraAnalysis,
    YaraString,
)

#: Les douze tactiques d'ATT&CK Enterprise, pour dire ce qu'un jeu de règles
#: NE couvre pas — l'information qui manque à toute revue de couverture.
TACTIQUES_ENTREPRISE = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)


# --------------------------------------------------------------------------
# Indicateurs
# --------------------------------------------------------------------------
async def extract_iocs(
    text: Annotated[
        str,
        Field(description="Rapport de menace, courriel signalé, extrait de journal — texte brut."),
    ],
    refang: Annotated[
        bool,
        Field(
            description="Remettre en forme les indicateurs désamorcés (hxxp://, [.], (@)) "
            "avant extraction. À laisser vrai pour un rapport de menace."
        ),
    ] = True,
) -> ExtractedIOCs:
    """Extrait les indicateurs d'un texte : adresses, domaines, URL, empreintes, CVE.

    Fonctionne **entièrement en local** : le texte n'est envoyé nulle part. C'est
    ce qui permet de l'utiliser sur un rapport confidentiel ou un courriel
    d'utilisateur.

    Deux comportements à connaître :

    * Les indicateurs **désamorcés** sont reconnus. Un rapport de menace écrit
      `hxxps://malveillant[.]com` précisément pour qu'on ne clique pas ; une
      extraction naïve n'y verrait rien.
    * Les valeurs écartées sont **rendues avec leur motif** — adresses privées,
      domaines d'exemple, noms de fichiers pris pour des domaines. Une adresse
      interne n'est jamais proposée comme indicateur à vérifier chez un tiers :
      l'envoyer révélerait la topologie du réseau.
    """
    resultat = ioc.extraire(text, desamorcer_entree=refang)
    return ExtractedIOCs(
        total=resultat.total,
        ipv4=resultat.ipv4,
        ipv6=resultat.ipv6,
        domains=resultat.domains,
        urls=resultat.urls,
        emails=resultat.emails,
        hashes=[FileHash(value=h["value"], algorithm=h["algorithm"]) for h in resultat.hashes],
        cves=resultat.cves,
        excluded=[ExcludedValue(value=e["value"], reason=e["reason"]) for e in resultat.excluded],
        notes=resultat.notes,
    )


async def defang_iocs(
    indicators: Annotated[
        list[str],
        Field(description="Indicateurs à rendre non cliquables.", max_length=500),
    ],
) -> DefangedIOCs:
    """Désamorce des indicateurs pour les partager sans risque de clic.

    `https://mechant.com` devient `hxxps://mechant[.]com`. À utiliser avant de
    coller des indicateurs dans un ticket, un courriel ou un rapport : un lien
    cliquable dans une boîte de réception finit par être cliqué.
    """
    return DefangedIOCs(defanged=[ioc.defang(v) for v in indicators])


# --------------------------------------------------------------------------
# Règles Sigma
# --------------------------------------------------------------------------
def _lier_attack(analyse: sr.RegleAnalysee) -> cv.Couverture:
    return cv.lier(analyse.attack_techniques, analyse.logsource)


def _ajuster_sur_attack(qualite: sr.Qualite, liens: cv.Couverture) -> sr.Qualite:
    """Retire le crédit ATT&CK si les étiquettes ne valent rien.

    **Pourquoi cet ajustement existe.** Le barème accorde des points à une règle
    « rattachée à ATT&CK ». Mais ce crédit n'a qu'une raison d'être : compter
    dans une revue de couverture. Une étiquette révoquée ou inexistante n'y
    compte pas — la règle ne mérite donc pas les points.

    Sans cet ajustement, une règle portant une technique morte affichait A
    (100/100) : le constat était bien rendu à côté, mais une note maximale
    invite précisément à ne pas lire ce qui l'accompagne. C'est le mode de
    défaillance que ce projet cherche à éviter — un voyant vert qui masque un
    vrai défaut.

    `evaluer_qualite` reste volontairement pur et local : c'est ici, où le
    corpus est disponible, que les deux informations se rejoignent.
    """
    invalides = [t for t in liens.techniques if t.status != "valide"]
    if not invalides:
        return qualite

    qualite.score = max(0, qualite.score - sr.POIDS["attack_tags"])
    qualite.strengths = [s for s in qualite.strengths if not s.startswith("Rattachée à ATT&CK")]
    qualite.findings.insert(
        0,
        "Les étiquettes ATT&CK ne sont pas exploitables ("
        + ", ".join(f"{t.id} : {t.status}" for t in invalides)
        + ") : la règle ne comptera dans aucune revue de couverture.",
    )
    qualite.grade = (
        "A" if qualite.score >= 90
        else "B" if qualite.score >= 75
        else "C" if qualite.score >= 55
        else "D" if qualite.score >= 35
        else "F"
    )
    return qualite


async def analyze_sigma_rule(
    rule: Annotated[str, Field(description="La règle Sigma, en YAML.")],
) -> SigmaAnalysis:
    """Analyse une règle Sigma : conformité, qualité, et rattachement à ATT&CK.

    L'outil central de ce serveur. Il répond à la question qu'une simple
    validation syntaxique laisse ouverte : *cette règle est-elle exploitable en
    production ?*

    Ce qu'il vérifie et qu'aucun validateur ne vérifie :

    * **Les étiquettes ATT&CK sont-elles encore valides ?** ATT&CK révoque des
      techniques à chaque version majeure. Une règle étiquetée d'un identifiant
      mort fonctionne, mais ne compte dans aucune revue de couverture — et
      personne ne s'en aperçoit.
    * **La technique correspond-elle à la source de journal ?** Une règle sur
      les journaux Azure étiquetée d'une technique Windows ne détectera jamais
      ce qu'elle annonce.
    * **Les faux positifs sont-ils déclarés ?** Une règle qui n'annonce pas son
      bruit est désactivée au premier jour chargé, et rarement réactivée.

    Une règle **non conforme** à la spécification est tout de même analysée et
    notée : c'est le cas d'un brouillon, et c'est là que les conseils servent le
    plus. Le champ `spec_compliant` dit ce qu'il en est.

    Le `score` et le `grade` sont calculés par du code déterministe : reprenez-les
    tels quels, ne les recalculez pas.
    """
    analyse = sr.analyser(rule)
    conforme, motif = sr.valider_strictement(rule)
    liens = _lier_attack(analyse)
    qualite = _ajuster_sur_attack(sr.evaluer_qualite(analyse), liens)

    return SigmaAnalysis(
        title=analyse.title,
        id=analyse.id,
        status=analyse.status,
        level=analyse.level,
        description=analyse.description,
        author=analyse.author,
        logsource=analyse.logsource,
        selections=analyse.selections,
        condition=analyse.condition,
        fields_used=analyse.fields_used,
        falsepositives=analyse.falsepositives,
        spec_compliant=conforme,
        spec_error=motif,
        quality=RuleQuality(
            score=qualite.score,
            grade=qualite.grade,
            findings=qualite.findings,
            strengths=qualite.strengths,
        ),
        attack=[
            LinkedTechnique(
                id=t.id,
                status=t.status,
                name=t.name,
                tactics=t.tactics,
                platforms=t.platforms,
                url=t.url,
                replaced_by=t.replaced_by,
                detection_guidance=t.detection_guidance,
                note=t.note,
            )
            for t in liens.techniques
        ],
        attack_findings=liens.findings,
        attack_version=liens.attack_version,
    )


async def convert_sigma_rule(
    rule: Annotated[str, Field(description="La règle Sigma, en YAML.")],
    target: Annotated[
        str,
        Field(description="Cible : kusto (Sentinel/Defender), splunk ou lucene (Elasticsearch)."),
    ],
) -> ConvertedRule:
    """Traduit une règle Sigma en requête Sentinel (KQL), Splunk (SPL) ou Lucene.

    La conversion est faite par `pysigma`, la bibliothèque de référence. Le
    résultat reste **à relire avant déploiement** : les noms de champs dépendent
    du schéma de collecte local, qu'aucun convertisseur ne peut deviner.

    La règle doit être conforme à la spécification pour être convertie. Si elle
    ne l'est pas, `analyze_sigma_rule` dira ce qui manque.
    """
    requetes = sr.convertir(rule, target)
    cle = target.strip().lower()
    return ConvertedRule(
        target=cle,
        target_name=sr.CIBLES[cle][2],
        queries=requetes,
    )


async def explain_sigma_rule(
    rule: Annotated[str, Field(description="La règle Sigma, en YAML.")],
) -> RuleExplanation:
    """Explique en français ce qu'une règle Sigma cherche, sans jargon.

    Destiné à celui qui doit **approuver** une règle sans lire le YAML : un
    responsable SOC, un auditeur, un analyste junior. Dit ce qui déclenche
    l'alerte, ce qu'il faut collecter pour que la règle fonctionne, et le bruit
    auquel s'attendre.
    """
    analyse = sr.analyser(rule)
    blocs = sr.decrire_selections(rule)

    declencheurs: list[str] = []
    for nom, lignes in blocs.items():
        if lignes:
            declencheurs.append(f"« {nom} » : " + ", et ".join(lignes))

    if analyse.logsource:
        besoin = "Journaux " + ", ".join(f"{c} = {v}" for c, v in analyse.logsource.items()) + "."
    else:
        besoin = (
            "Aucune source de journal déclarée : le moteur ne saura pas où appliquer "
            "cette règle."
        )
    if analyse.fields_used:
        besoin += " Champs nécessaires : " + ", ".join(analyse.fields_used) + "."

    contexte: list[str] = []
    for technique in _lier_attack(analyse).techniques:
        if technique.status == "valide":
            contexte.append(f"{technique.id} — {technique.name}")
        elif technique.status == "revoquee":
            contexte.append(
                f"{technique.id} — étiquette RÉVOQUÉE"
                + (f", remplacer par {technique.replaced_by}" if technique.replaced_by else "")
            )
        else:
            contexte.append(f"{technique.id} — identifiant inconnu d'ATT&CK")

    return RuleExplanation(
        title=analyse.title or "(règle sans titre)",
        summary=analyse.description
        or "Aucune description : l'intention de l'auteur n'est pas documentée.",
        triggers_when=[
            sr.expliquer_condition(analyse.condition, analyse.selections),
            *declencheurs,
        ],
        log_requirement=besoin,
        expected_noise=analyse.falsepositives
        or ["Aucun faux positif déclaré — le bruit réel est donc inconnu."],
        attack_context=contexte,
    )


async def check_detection_coverage(
    rules: Annotated[
        list[str],
        Field(description="Les règles Sigma du jeu à évaluer, en YAML.", max_length=200),
    ],
) -> RuleSetCoverage:
    """Dit ce qu'un jeu de règles couvre dans ATT&CK — et surtout ce qu'il ignore.

    La question qu'on pose avant un audit ou une revue de détection : *où sont
    nos angles morts ?* L'outil rend les tactiques que **aucune** règle ne
    touche, ce qui est l'information utile — la liste de ce qui est déjà couvert
    rassure sans rien apprendre.

    Une règle illisible est comptée dans `rules_rejected` plutôt qu'ignorée
    silencieusement : un jeu de règles dont un tiers ne s'analyse pas donnerait
    sinon une couverture faussement rassurante.
    """
    from mitre_mcp.corpus import charger

    corpus = charger()
    rapport = RuleSetCoverage(rules_analyzed=0, attack_version=corpus.version)

    par_tactique: dict[str, dict[str, set[str]]] = {}
    toutes_techniques: set[str] = set()
    problemes: list[str] = []

    for index, brut in enumerate(rules, start=1):
        try:
            analyse = sr.analyser(brut)
        except sr.SigmaError as exc:
            rapport.rules_rejected += 1
            problemes.append(f"Règle n°{index} illisible : {exc}")
            continue

        rapport.rules_analyzed += 1
        titre = analyse.title or f"règle n°{index}"

        if not analyse.attack_techniques:
            problemes.append(f"« {titre} » ne porte aucune étiquette ATT&CK.")
            continue

        liens = cv.lier(analyse.attack_techniques, analyse.logsource)
        for technique in liens.techniques:
            if technique.status != "valide":
                problemes.append(f"« {titre} » : {technique.note}")
                continue
            toutes_techniques.add(technique.id)
            for tactique in technique.tactics:
                entree = par_tactique.setdefault(tactique, {"rules": set(), "techniques": set()})
                entree["rules"].add(titre)
                entree["techniques"].add(technique.id)

    rapport.techniques_covered = sorted(toutes_techniques)
    rapport.tactics = [
        CoverageEntry(
            tactic=nom,
            rules=len(donnees["rules"]),
            techniques=sorted(donnees["techniques"]),
        )
        for nom, donnees in sorted(par_tactique.items())
    ]
    rapport.uncovered_tactics = [t for t in TACTIQUES_ENTREPRISE if t not in par_tactique]

    if rapport.uncovered_tactics:
        problemes.insert(
            0,
            f"{len(rapport.uncovered_tactics)} tactique(s) ATT&CK ne sont couvertes par "
            "aucune règle de ce jeu.",
        )
    rapport.findings = problemes
    return rapport


async def suggest_detection_for_technique(
    technique_id: Annotated[str, Field(description="Identifiant ATT&CK, par exemple T1566.002.")],
    product: Annotated[
        str,
        Field(description="Produit visé pour la logsource Sigma : windows, azure, linux, m365…"),
    ] = "windows",
) -> DetectionAdvice:
    """Par où commencer pour détecter une technique : journaux, signaux, squelette Sigma.

    Répond à « on veut couvrir T1566.002, on fait quoi ? ». Rend ce qu'ATT&CK
    recommande de surveiller, les sources de journaux à collecter en premier, et
    un squelette de règle pré-rempli.

    Le squelette est **à compléter**, pas à déployer : les conditions de
    détection dépendent de l'environnement, et une règle générée sans
    connaissance du terrain produirait surtout du bruit.
    """
    from mitre_mcp.corpus import charger, resoudre_identifiant

    identifiant = resoudre_identifiant(technique_id)
    corpus = charger()
    technique = corpus.technique(identifiant)

    notes: list[str] = []
    if technique is None:
        obsolete = corpus.revoquee(identifiant)
        if obsolete:
            remplacant = obsolete.get("replaced_by")
            raise ValueError(
                f"{identifiant} a été révoquée dans ATT&CK v{corpus.version}"
                + (f" — utiliser {remplacant} à la place." if remplacant else ".")
            )
        raise ValueError(f"{identifiant} n'existe pas dans ATT&CK v{corpus.version}.")

    sources: list[str] = []
    conseils: list[str] = []
    for strategie in technique.get("detection") or []:
        for analytique in strategie.get("analytics") or []:
            for source in analytique.get("log_sources") or []:
                if str(source) not in sources:
                    sources.append(str(source))
            texte = (analytique.get("guidance") or "").strip()
            if texte and texte not in conseils:
                conseils.append(texte)

    if not conseils:
        notes.append(
            f"ATT&CK ne publie aucune analytique pour {identifiant} : la détection "
            "devra être conçue à partir de la description de la technique."
        )
    if not sources:
        notes.append(
            "Aucune source de journal nommée par le référentiel — commencer par les "
            "journaux natifs de la plateforme visée."
        )

    plateformes = list(technique.get("platforms") or [])
    attendues = cv.PLATEFORMES.get(product.strip().lower(), set())
    if attendues and plateformes and not (attendues & set(plateformes)):
        notes.append(
            f"{identifiant} ne s'applique qu'à "
            + ", ".join(plateformes)
            + f" : le produit « {product} » n'est probablement pas la bonne source."
        )

    tactiques = list(technique.get("tactics") or [])
    etiquettes = "\n".join(
        [f"    - attack.{t}" for t in tactiques] + [f"    - attack.{identifiant.lower()}"]
    )
    squelette = f"""title: À COMPLÉTER — détection de {technique.get('name')}
id: À GÉNÉRER (uuid4)
status: experimental
description: >
    À COMPLÉTER — ce que la règle cherche et pourquoi.
    Technique visée : {identifiant} ({technique.get('name')}).
author: À COMPLÉTER
date: À COMPLÉTER
logsource:
    product: {product.strip().lower()}
    service: À COMPLÉTER
detection:
    selection:
        À_COMPLÉTER: 'valeur'
    condition: selection
falsepositives:
    - À COMPLÉTER — une règle sans faux positifs déclarés sera désactivée au
      premier jour bruyant.
level: medium
tags:
{etiquettes}
"""

    return DetectionAdvice(
        technique_id=identifiant,
        technique_name=technique.get("name") or "",
        tactics=tactiques,
        platforms=plateformes,
        log_sources=sources,
        detection_guidance=conseils[:5],
        sigma_skeleton=squelette,
        notes=notes,
    )


# --------------------------------------------------------------------------
# Règles YARA
# --------------------------------------------------------------------------
async def analyze_yara_rule(
    rule: Annotated[str, Field(description="La règle YARA, en texte.")],
) -> YaraAnalysis:
    """Analyse une règle YARA : conformité, qualité, et rattachement à ATT&CK.

    Le pendant fichier de `analyze_sigma_rule`. Deux bibliothèques de
    référence font le travail qu'aucune règle maison ne devrait refaire :
    `plyara` lit la structure, le compilateur `yara-python` officiel juge de
    la conformité — la même séparation que Sigma, pour la même raison :
    réimplémenter la grammaire produirait une règle qui *paraît* correcte et
    rate silencieusement les fichiers qu'elle prétend détecter.

    Ce que cet outil vérifie et qu'un simple `yara.compile()` ne dit pas :

    * **Des chaînes texte courtes sans `fullword`.** `$a = "cmd"` correspond à
      l'intérieur de « command », « recmd.exe », et de tout mot qui contient
      ces trois lettres — la cause la plus fréquente de faux positifs en
      pratique.
    * **Une condition qui ne sélectionne rien.** `any of them` sur des chaînes
      génériques, ou une condition `true` qui accepte tout ce qu'on lui
      présente.
    * **Les étiquettes ATT&CK sont-elles encore valides ?** Aucun champ de
      métadonnée YARA n'est standardisé pour les porter ; l'outil les cherche
      dans tout ce qui est textuel, puis les confronte au même corpus ATT&CK
      embarqué que Sigma — une technique révoquée est signalée, pas rendue
      telle quelle.

    Une règle **non conforme** à la syntaxe YARA est tout de même analysée et
    notée : c'est le cas d'un brouillon, et c'est là que les conseils servent
    le plus. Le champ `spec_compliant` dit ce qu'il en est — et un détail
    vérifié avant d'écrire cet outil : une règle vide compile *avec succès*
    dans le compilateur officiel, avec zéro règle ; ce cas est traité comme
    non conforme plutôt que silencieusement accepté.

    Le `score` et le `grade` sont calculés par du code déterministe : reprenez-les
    tels quels, ne les recalculez pas.
    """
    analyse = yr.analyser(rule)
    conforme, motif = yr.valider_strictement(rule)
    liens = cv.lier(analyse.attack_techniques)
    qualite = yr.evaluer_qualite(analyse)

    if any(t.status != "valide" for t in liens.techniques):
        qualite.score = max(0, qualite.score - yr.POIDS["attack_tags"])
        qualite.strengths = [s for s in qualite.strengths if "ATT&CK" not in s]
        qualite.findings.insert(
            0,
            "Les étiquettes ATT&CK ne sont pas exploitables ("
            + ", ".join(f"{t.id} : {t.status}" for t in liens.techniques if t.status != "valide")
            + ") : la règle ne comptera dans aucune revue de couverture.",
        )
        qualite.grade = (
            "A" if qualite.score >= 90
            else "B" if qualite.score >= 75
            else "C" if qualite.score >= 55
            else "D" if qualite.score >= 35
            else "F"
        )

    return YaraAnalysis(
        name=analyse.name,
        tags=analyse.tags,
        scopes=analyse.scopes,
        imports=analyse.imports,
        metadata=analyse.metadata,
        strings=[
            YaraString(name=s.name, type=s.type, value=s.value, modifiers=s.modifiers)
            for s in analyse.strings
        ],
        condition=analyse.condition,
        spec_compliant=conforme,
        spec_error=motif,
        quality=RuleQuality(
            score=qualite.score,
            grade=qualite.grade,
            findings=qualite.findings,
            strengths=qualite.strengths,
        ),
        attack=[
            LinkedTechnique(
                id=t.id, status=t.status, name=t.name, tactics=t.tactics,
                platforms=t.platforms, url=t.url, replaced_by=t.replaced_by,
                detection_guidance=t.detection_guidance, note=t.note,
            )
            for t in liens.techniques
        ],
        attack_findings=liens.findings,
        attack_version=liens.attack_version,
    )


# --------------------------------------------------------------------------
# Référence des événements Windows / Sysmon
# --------------------------------------------------------------------------
def _vers_securite(evenement: dict[str, Any]) -> WindowsSecurityEvent:
    return WindowsSecurityEvent(
        current_id=evenement.get("current_id"),
        legacy_ids=evenement.get("legacy_ids", []),
        criticality=evenement.get("criticality", ""),
        summary=evenement.get("summary", ""),
    )


def _vers_sysmon(evenement: dict[str, Any]) -> SysmonEvent:
    return SysmonEvent(
        id=evenement["id"], name=evenement["name"], description=evenement["description"]
    )


async def lookup_windows_event(
    event_id: Annotated[
        str,
        Field(
            description="L'identifiant numérique de l'événement, tel qu'il apparaît dans le "
            "journal — par exemple 4688, ou 1 pour un événement Sysmon."
        ),
    ],
) -> WindowsEventMatches:
    """Identifie un ID d'événement Windows : audit de sécurité natif, et/ou Sysmon.

    Les deux canaux sont interrogés et rendus séparément, jamais fusionnés sur
    le seul numéro : Sysmon ID 1 (« Process creation ») et un éventuel ID 1 côté
    audit de sécurité ne désignent rien de commun. Un même appel peut donc
    renvoyer une correspondance dans les deux listes — c'est à l'appelant de
    savoir de quel journal provient l'ID qu'il a en main.

    Côté audit de sécurité, l'identifiant est cherché d'abord parmi les IDs
    modernes, puis parmi les IDs antérieurs à Vista (« legacy ») — certains
    événements ont changé de numéro entre les deux, et un même ID historique
    peut avoir été scindé en plusieurs événements modernes distincts.

    Côté Sysmon, aucune criticité n'est rendue : la documentation officielle
    n'en publie pas pour ces IDs, l'intérêt réel dépendant de la configuration
    déployée — pas d'un jugement fixe de Microsoft.
    """
    securite = [_vers_securite(e) for e in we.evenement_securite(event_id)]
    sysmon_evt = we.evenement_sysmon(event_id)
    sysmon = [_vers_sysmon(sysmon_evt)] if sysmon_evt else []

    note = None
    if not securite and not sysmon:
        note = (
            f"Aucune correspondance pour « {event_id} » dans l'audit de sécurité Windows "
            "(Appendix L) ni dans les événements Sysmon (IDs 1-29, 255)."
        )

    return WindowsEventMatches(
        query=event_id, security_matches=securite, sysmon_matches=sysmon, note=note
    )


async def search_windows_events(
    query: Annotated[
        str,
        Field(description="Mots-clés à chercher dans les résumés/descriptions — par exemple "
        "« kerberos », « group deleted », « clipboard »."),
    ],
    source: Annotated[
        str,
        Field(description="security, sysmon ou all (les deux)."),
    ] = "all",
) -> WindowsEventMatches:
    """Cherche des événements Windows par mot-clé, dans l'audit de sécurité et/ou Sysmon.

    Utile pour partir d'une intention (« comment repérer un ajout à un groupe
    protégé ? ») plutôt que d'un ID déjà connu. La recherche est un simple
    filtre par mots — le catalogue est petit (379 entrées sécurité, 30 Sysmon),
    une pertinence calculée finement n'apporterait rien de mesurable.
    """
    if not query.strip():
        raise ValueError("Indiquez des mots-clés.")

    cle = source.strip().lower()
    if cle not in ("security", "sysmon", "all"):
        raise ValueError("source doit valoir security, sysmon ou all.")

    securite = (
        [_vers_securite(e) for e in we.chercher_securite(query)]
        if cle in ("security", "all")
        else []
    )
    sysmon = (
        [_vers_sysmon(e) for e in we.chercher_sysmon(query)] if cle in ("sysmon", "all") else []
    )

    note = None
    if not securite and not sysmon:
        note = f"Aucun événement ne correspond à « {query} »."

    return WindowsEventMatches(
        query=query, security_matches=securite, sysmon_matches=sysmon, note=note
    )


# --------------------------------------------------------------------------
# ReDoS
# --------------------------------------------------------------------------
#: Confirmer chaque candidat coûte jusqu'au budget de temps de `rd.confirmer`
#: (2 s par défaut) : borner leur nombre borne le temps de réponse de l'outil
#: même sur un motif truffé de constructions suspectes.
NOMBRE_CONFIRMATIONS_MAX = 5


async def check_redos(
    pattern: Annotated[
        str,
        Field(
            description="L'expression régulière à examiner — celle d'un modificateur "
            "|re: Sigma, d'une chaîne $re = /…/ YARA, ou tout autre motif Python `re`."
        ),
    ],
) -> RedosAnalysis:
    """Repère un motif vulnérable au ReDoS, et le CONFIRME par une exécution chronométrée réelle.

    En deux temps, et le premier ne suffit jamais seul :

    1. **Structure.** Le motif est décomposé via l'arbre que `re` construit
       lui-même en interne, à la recherche de trois formes connues pour
       provoquer un retour arrière catastrophique : des quantificateurs
       illimités imbriqués (`(a+)+`), une alternance ambiguë sous répétition
       (`(a|aa)+`), ou deux quantificateurs illimités adjacents (`.*.*`).
    2. **Confirmation.** Pour chaque forme repérée, une attaque est construite
       à partir d'un caractère représentatif et **exécutée pour de vrai** dans
       un processus séparé, avec un budget de temps strict. Un motif qui
       *ressemble* à un cas classique mais ne l'est pas en pratique — certaines
       alternances asymétriques comme `(a|ab)+` — est structurellement repéré
       puis **innocenté** par la mesure, plutôt que signalé à tort.

    `vulnerable` ne vaut jamais `true` sur la seule apparence du texte : il
    faut qu'au moins un constat ait été confirmé par une exécution réelle.
    Un motif dont `findings` contient des entrées mais `confirmed=false`
    partout est une forme suspecte que ce moteur `re` précis ne rend pas
    dangereuse — pas une alerte à ignorer aveuglément pour autant : un autre
    moteur (PCRE, RE2 côté backend, JavaScript) peut réagir différemment au
    même texte.
    """
    try:
        constats = rd.analyser_statique(pattern)
    except rd.RedosError as exc:
        return RedosAnalysis(
            pattern=pattern,
            compiles=False,
            compile_error=str(exc),
            vulnerable=False,
            note="Le motif ne compile pas dans le moteur `re` de Python : aucune analyse possible.",
        )

    if not constats:
        return RedosAnalysis(
            pattern=pattern,
            compiles=True,
            vulnerable=False,
            note="Aucune forme structurellement associée au ReDoS n'a été repérée.",
        )

    a_confirmer = constats[:NOMBRE_CONFIRMATIONS_MAX]
    boucle = asyncio.get_running_loop()
    sondages = [
        await boucle.run_in_executor(None, rd.confirmer, pattern, constat)
        for constat in a_confirmer
    ]

    findings = [
        RedosFinding(
            kind=sondage.finding.kind,
            sample=sondage.finding.sample,
            explanation=sondage.finding.explanation,
            confirmed=sondage.confirmed,
            timeout_hit=sondage.timeout_hit,
            timings_ms=[[float(n), d] for n, d in sondage.timings_ms],
            note=sondage.note,
        )
        for sondage in sondages
    ]
    vulnerable = any(f.confirmed for f in findings)
    tronque = len(constats) > len(a_confirmer)

    if vulnerable:
        note = (
            "Au moins un constat est confirmé par une exécution réelle : ce motif est "
            "vulnérable."
        )
    else:
        note = (
            "Forme(s) suspecte(s) repérée(s), mais aucune n'a été confirmée par une "
            "exécution réelle sur ce moteur."
        )
    if tronque:
        note += (
            f" {len(constats) - len(a_confirmer)} autre(s) candidat(s) structurel(s) "
            "n'ont pas été testés, pour borner le temps de réponse."
        )

    return RedosAnalysis(
        pattern=pattern,
        compiles=True,
        findings=findings,
        vulnerable=vulnerable,
        truncated=tronque,
        note=note,
    )

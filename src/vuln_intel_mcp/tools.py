"""Les outils de renseignement sur les vulnérabilités.

Chacun croise ce que trois sources disent séparément, applique la troncature
d'ARGUS, et rend un palier de correction — pas seulement des chiffres.
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any, get_args

from pydantic import Field

from .cvss import CvssError, evaluer
from .models import (
    MAX_PRODUITS,
    MAX_REFERENCES,
    CveReport,
    CveSummary,
    CvssBreakdown,
    CvssInfo,
    EpssInfo,
    KevInfo,
    KevStats,
    PrioritizedList,
    Reference,
    SearchResult,
    Severity,
)
from .prioritize import Vulnerabilite, prioriser, synthese
from .runtime import get_sources
from .sources import InvalidCveError, normaliser_cve

logger = logging.getLogger(__name__)

#: Les étiquettes de référence qui aident vraiment un analyste. Le NVD en
#: publie une vingtaine ; les autres décrivent la nature du site, pas celle de
#: l'information.
TAGS_UTILES = frozenset(
    {"Patch", "Exploit", "Vendor Advisory", "Mitigation", "Third Party Advisory", "VDB Entry"}
)


def _interpreter_epss(score: float | None) -> str | None:
    """Traduit une probabilité en phrase, parce qu'un nombre seul ne décide rien."""
    if score is None:
        return None
    if score >= 0.5:
        return "Exploitation très probable dans les trente jours."
    if score >= 0.10:
        return "Exploitation probable : nettement au-dessus de la masse des CVE."
    if score >= 0.01:
        return "Exploitation possible mais peu fréquente."
    return "Aucune exploitation observée ; probabilité très faible."


def _jours_restants(echeance: str | None) -> int | None:
    if not echeance:
        return None
    try:
        return (date.fromisoformat(echeance[:10]) - datetime.now(UTC).date()).days
    except ValueError:
        return None


def _severite_litterale(valeur: object) -> Severity:
    """Ramène une sévérité au vocabulaire fermé du modèle.

    Une valeur inattendue devient « unknown » plutôt que de passer telle
    quelle : mieux vaut avouer l'ignorance qu'inventer une classe.
    """
    texte = str(valeur or "").lower()
    return texte if texte in get_args(Severity) else "unknown"  # type: ignore[return-value]


def _choisir_notation(entrees: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Choisit quelle notation retenir quand le NVD en publie plusieurs.

    Le piège est réel et coûteux. Pour CVE-2020-1472 (Zerologon), le NVD
    publie deux notes CVSS v3.1 : celle de l'éditeur, à 5.5, et la sienne, à
    10.0. Prendre la première venue faisait passer une faille critique pour
    une faille moyenne — exactement l'erreur qu'un outil de sécurité ne doit
    pas commettre.

    L'ordre retenu : la notation primaire, sinon celle du NIST, sinon la
    première. Et quand les notes divergent nettement, on le dit : l'écart est
    une information, pas un détail de mise en forme.
    """
    notes: list[str] = []

    def rang(entree: dict[str, Any]) -> tuple[int, int]:
        primaire = 0 if (entree.get("type") or "").lower() == "primary" else 1
        nist = 0 if (entree.get("source") or "") == "nvd@nist.gov" else 1
        return (primaire, nist)

    ordonnees = sorted(entrees, key=rang)
    retenue = ordonnees[0]

    scores: list[tuple[str, float]] = []
    for e in entrees:
        valeur = (e.get("cvssData") or {}).get("baseScore")
        if isinstance(valeur, int | float):
            scores.append((str(e.get("source") or "?"), float(valeur)))

    if len(scores) > 1:
        valeurs = [v for _, v in scores]
        if max(valeurs) - min(valeurs) >= 2.0:
            detail = ", ".join(f"{src} : {val}" for src, val in scores)
            notes.append(
                f"Les sources ne s'accordent pas sur la gravité ({detail}). "
                f"La notation retenue est celle de « {retenue.get('source', '?')} ». "
                "Un écart de cette ampleur mérite un examen."
            )

    return retenue, notes


def _extraire_cvss(fiche: dict[str, Any]) -> tuple[CvssInfo, list[str]]:
    """Lit la meilleure note disponible, et la recalcule quand c'est possible.

    Recalculer n'est pas de la coquetterie : si le vecteur et la note publiée
    ne concordent pas, c'est que l'un des deux est faux, et l'analyste doit le
    savoir avant de bâtir une décision dessus.
    """
    notes: list[str] = []
    metriques = fiche.get("metrics") or {}

    for cle in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        entrees = metriques.get(cle) or []
        if not entrees:
            continue
        retenue, notes_choix = _choisir_notation(entrees)
        notes.extend(notes_choix)
        data = retenue.get("cvssData") or {}
        vecteur = data.get("vectorString")
        publie = data.get("baseScore")

        info = CvssInfo(
            version=data.get("version"),
            vector=vecteur,
            base_score=publie,
            severity=_severite_litterale(data.get("baseSeverity")),
        )

        if vecteur:
            try:
                calcul = evaluer(vecteur)
            except CvssError as exc:
                notes.append(f"Vecteur CVSS illisible : {exc}")
            else:
                if calcul.computed:
                    info.computed_locally = True
                    info.base_score = calcul.base_score
                    info.severity = _severite_litterale(calcul.severity)
                    if publie is not None:
                        info.matches_published = abs(calcul.base_score - publie) < 0.05
                        if not info.matches_published:
                            notes.append(
                                f"La note publiée ({publie}) ne correspond pas au vecteur, "
                                f"qui donne {calcul.base_score}. Vérifier la source."
                            )
        return info, notes

    return CvssInfo(), ["Aucune note CVSS publiée pour cette vulnérabilité."]


def _extraire_description(fiche: dict[str, Any], limite: int = 600) -> str | None:
    for d in fiche.get("descriptions") or []:
        if d.get("lang") == "en":
            texte = (d.get("value") or "").strip()
            return texte[:limite] + ("…" if len(texte) > limite else "")
    return None


def _extraire_cwe(fiche: dict[str, Any]) -> list[str]:
    trouves: list[str] = []
    for faiblesse in fiche.get("weaknesses") or []:
        for d in faiblesse.get("description") or []:
            valeur = d.get("value")
            if valeur and valeur.startswith("CWE-") and valeur not in trouves:
                trouves.append(valeur)
    return trouves


def _extraire_produits(fiche: dict[str, Any]) -> list[str]:
    """Les produits affectés, lisiblement et sans les centaines de variantes."""
    produits: list[str] = []
    for config in fiche.get("configurations") or []:
        for noeud in config.get("nodes") or []:
            for match in noeud.get("cpeMatch") or []:
                critere = match.get("criteria") or ""
                morceaux = critere.split(":")
                if len(morceaux) > 5:
                    editeur, produit, version = morceaux[3], morceaux[4], morceaux[5]
                    libelle = f"{editeur}:{produit}"
                    if version not in ("*", "-"):
                        libelle += f" {version}"
                    if libelle not in produits:
                        produits.append(libelle)
                if len(produits) >= MAX_PRODUITS:
                    return produits
    return produits


def _extraire_references(fiche: dict[str, Any]) -> list[Reference]:
    """Garde d'abord les liens qualifiés — correctif, exploit, avis éditeur."""
    qualifiees: list[Reference] = []
    autres: list[Reference] = []
    for ref in fiche.get("references") or []:
        url = ref.get("url")
        if not url:
            continue
        tags = [t for t in (ref.get("tags") or [])]
        cible = qualifiees if TAGS_UTILES.intersection(tags) else autres
        cible.append(Reference(url=url, tags=tags))
    return (qualifiees + autres)[:MAX_REFERENCES]


async def _fiche_complete(cve: str) -> CveReport:
    """Assemble la fiche croisée d'une CVE."""
    sources = get_sources()
    fiche = await sources.nvd_cve(cve)
    if fiche is None:
        raise ValueError(
            f"{cve} est inconnue du NVD. Vérifiez l'identifiant, ou la CVE est trop récente "
            "pour y être publiée."
        )

    notes: list[str] = []
    cvss, notes_cvss = _extraire_cvss(fiche)
    notes.extend(notes_cvss)

    entree_kev = await sources.kev_entree(cve)
    kev = KevInfo(
        listed=entree_kev is not None,
        date_added=(entree_kev or {}).get("dateAdded"),
        due_date=(entree_kev or {}).get("dueDate"),
        days_to_due=_jours_restants((entree_kev or {}).get("dueDate")),
        known_ransomware=(entree_kev or {}).get("knownRansomwareCampaignUse", "").lower()
        == "known",
        required_action=(entree_kev or {}).get("requiredAction"),
        catalog_stale=sources.kev_perime(),
    )
    if kev.catalog_stale:
        notes.append(
            "Le catalogue CISA n'a pas pu être rafraîchi : la réponse s'appuie sur "
            "une version antérieure."
        )

    scores_epss = await sources.epss([cve])
    brut = scores_epss.get(cve, {})
    epss = EpssInfo(
        score=brut.get("epss"),
        percentile=brut.get("percentile"),
        interpretation=_interpreter_epss(brut.get("epss")),
    )

    classement = prioriser(
        [
            Vulnerabilite(
                cve=cve,
                cvss=cvss.base_score,
                severity=cvss.severity,
                epss=epss.score,
                epss_percentile=epss.percentile,
                kev=kev.listed,
                kev_due=kev.due_date,
                kev_ransomware=kev.known_ransomware,
            )
        ]
    )[0]

    return CveReport(
        cve=cve,
        published=fiche.get("published"),
        last_modified=fiche.get("lastModified"),
        status=fiche.get("vulnStatus"),
        description=_extraire_description(fiche),
        cvss=cvss,
        cwe=_extraire_cwe(fiche),
        kev=kev,
        epss=epss,
        affected_products=_extraire_produits(fiche),
        references=_extraire_references(fiche),
        priority=classement.tier,
        priority_reason=classement.rationale,
        notes=notes,
    )


# --------------------------------------------------------------------------
# Outils exposés
# --------------------------------------------------------------------------
async def lookup_cve(
    cve_id: Annotated[str, Field(description="Identifiant, par exemple CVE-2021-44228.")],
) -> CveReport:
    """Fiche complète d'une vulnérabilité, croisée entre NVD, CISA KEV et EPSS.

    Répond à « cette faille est-elle grave, et dois-je m'en occuper maintenant ? ».
    Les trois sources disent des choses différentes : le NVD donne la gravité
    théorique, le catalogue CISA dit si l'exploitation est constatée, et EPSS
    estime la probabilité qu'elle le soit sous trente jours.

    Le champ `priority` donne le palier de correction ; `priority_reason`
    explique pourquoi. La note CVSS est **recalculée** à partir du vecteur, et
    une discordance avec la note publiée est signalée.
    """
    return await _fiche_complete(normaliser_cve(cve_id))


async def bulk_lookup_cve(
    cve_ids: Annotated[list[str], Field(description="Identifiants à récupérer, 25 au plus.")],
) -> dict[str, Any]:
    """Fiches de plusieurs vulnérabilités d'un coup.

    À utiliser après un scan de vulnérabilités, quand la question porte sur un
    lot. Une CVE introuvable n'interrompt pas les autres : elle est listée à
    part.
    """
    if not cve_ids:
        raise ValueError("Fournissez au moins un identifiant CVE.")
    if len(cve_ids) > 25:
        raise ValueError(
            f"{len(cve_ids)} identifiants demandés, 25 au maximum. "
            "Au-delà, l'attente due aux quotas du NVD dépasse l'utile."
        )

    fiches: list[dict[str, Any]] = []
    introuvables: list[str] = []
    for brut in cve_ids:
        try:
            cve = normaliser_cve(brut)
        except InvalidCveError as exc:
            introuvables.append(f"{brut} ({exc})")
            continue
        try:
            fiches.append((await _fiche_complete(cve)).model_dump())
        except Exception as exc:
            logger.info("Fiche %s indisponible : %s", cve, exc)
            introuvables.append(cve)

    return {
        "requested": len(cve_ids),
        "found": len(fiches),
        "reports": fiches,
        "unresolved": introuvables,
    }


async def search_cve(
    keyword: Annotated[str, Field(description="Mots-clés : produit, technologie, composant.")],
    limit: Annotated[int, Field(description="Nombre de résultats, 50 au plus.", ge=1, le=50)] = 10,
    severity: Annotated[
        str | None,
        Field(description="Filtre de gravité : CRITICAL, HIGH, MEDIUM ou LOW."),
    ] = None,
) -> SearchResult:
    """Cherche des vulnérabilités par mots-clés.

    À utiliser pour « quelles failles connues touchent Apache Struts ? ».
    Le total réellement disponible est indiqué séparément du nombre rendu :
    savoir qu'il existe 800 résultats change la lecture des dix premiers.
    """
    if not keyword.strip():
        raise ValueError("Indiquez des mots-clés.")

    sources = get_sources()
    fiches, total = await sources.nvd_search(keyword.strip(), limite=limit, severite=severity)

    identifiants: list[str] = [str(f["id"]) for f in fiches if f.get("id")]
    kev_index = await sources.kev_index()
    epss_scores = await sources.epss(identifiants) if identifiants else {}

    resultats: list[CveSummary] = []
    for fiche in fiches:
        identifiant = fiche.get("id")
        if not identifiant:
            continue
        cvss, _ = _extraire_cvss(fiche)
        resultats.append(
            CveSummary(
                cve=identifiant,
                published=fiche.get("published"),
                cvss_score=cvss.base_score,
                severity=cvss.severity,
                known_exploited=identifiant.upper() in kev_index,
                epss=epss_scores.get(identifiant.upper(), {}).get("epss"),
                description=_extraire_description(fiche, limite=200),
            )
        )

    notes: list[str] = []
    if total > len(resultats):
        notes.append(
            f"{total} résultats existent ; {len(resultats)} sont rendus. "
            "Affinez les mots-clés si le sujet reste trop large."
        )
    exploitees = sum(1 for r in resultats if r.known_exploited)
    if exploitees:
        notes.append(
            f"{exploitees} de ces vulnérabilités sont activement exploitées "
            "(catalogue CISA) : à traiter en priorité."
        )

    return SearchResult(
        query=keyword.strip(),
        total_available=total,
        returned=len(resultats),
        results=resultats,
        notes=notes,
    )


async def prioritize_cves(
    cve_ids: Annotated[list[str], Field(description="Identifiants à classer, 100 au plus.")],
) -> PrioritizedList:
    """Classe des vulnérabilités dans l'ordre où il faut les corriger.

    C'est l'outil à utiliser quand un scan rend quarante CVE et que la question
    est « par quoi je commence ? ». Une note CVSS seule ne répond pas : une
    faille notée 9.8 que personne n'exploite est moins pressante qu'une 6.5
    inscrite au catalogue des vulnérabilités activement exploitées.

    Le classement est **déterministe et par paliers** : `immediate` pour
    l'exploitation constatée, `urgent` pour la probabilité élevée, puis
    `planifie` et `differe`. Chaque rang porte sa justification.

    Bien plus économe que `bulk_lookup_cve` sur un gros lot : seuls le
    catalogue KEV et les probabilités EPSS sont consultés, pas les fiches NVD
    complètes.
    """
    if not cve_ids:
        raise ValueError("Fournissez au moins un identifiant CVE.")
    if len(cve_ids) > 100:
        raise ValueError(f"{len(cve_ids)} identifiants demandés, 100 au maximum.")

    valides: list[str] = []
    invalides: list[str] = []
    for brut in cve_ids:
        try:
            valides.append(normaliser_cve(brut))
        except InvalidCveError:
            invalides.append(brut)

    if not valides:
        raise ValueError("Aucun identifiant CVE valide dans la liste fournie.")

    sources = get_sources()
    kev_index = await sources.kev_index()
    epss_scores = await sources.epss(valides)

    # Les notes CVSS viennent du NVD, une requête par CVE. Sur un gros lot,
    # cela dépasserait largement le quota : au-delà du seuil, on classe sans
    # elles et on le dit. KEV et EPSS suffisent à décider de l'urgence.
    avec_cvss = len(valides) <= 20
    vulnerabilites: list[Vulnerabilite] = []
    sans_donnees: list[str] = []

    for cve in valides:
        entree = kev_index.get(cve)
        note = None
        if avec_cvss:
            try:
                fiche = await sources.nvd_cve(cve)
                if fiche:
                    note = _extraire_cvss(fiche)[0].base_score
            except Exception as exc:
                logger.info("Note CVSS de %s indisponible : %s", cve, exc)

        epss = epss_scores.get(cve, {})
        if entree is None and not epss and note is None:
            sans_donnees.append(cve)

        vulnerabilites.append(
            Vulnerabilite(
                cve=cve,
                cvss=note,
                epss=epss.get("epss"),
                epss_percentile=epss.get("percentile"),
                kev=entree is not None,
                kev_due=(entree or {}).get("dueDate"),
                kev_ransomware=(entree or {}).get("knownRansomwareCampaignUse", "").lower()
                == "known",
                title=(entree or {}).get("vulnerabilityName"),
            )
        )

    classements = prioriser(vulnerabilites)
    resume = synthese(classements)

    return PrioritizedList(
        total=resume["total"],
        by_tier=resume["by_tier"],
        past_due=resume["past_due"],
        summary=resume["summary"],
        ranked=[c.as_dict() for c in classements],
        unresolved=invalides + sans_donnees,
        catalog_stale=sources.kev_perime(),
    )


async def check_kev(
    cve_id: Annotated[str, Field(description="Identifiant à vérifier.")],
) -> KevInfo:
    """Cette vulnérabilité est-elle activement exploitée ?

    Le catalogue CISA ne liste que des failles dont l'exploitation est
    **constatée**, pas supposée. Une inscription change la nature de la
    décision : ce n'est plus un risque théorique, c'est une attaque en cours
    quelque part, avec une échéance de correction imposée aux agences
    fédérales américaines — et un bon repère pour tout le monde.
    """
    cve = normaliser_cve(cve_id)
    sources = get_sources()
    entree = await sources.kev_entree(cve)

    return KevInfo(
        listed=entree is not None,
        date_added=(entree or {}).get("dateAdded"),
        due_date=(entree or {}).get("dueDate"),
        days_to_due=_jours_restants((entree or {}).get("dueDate")),
        known_ransomware=(entree or {}).get("knownRansomwareCampaignUse", "").lower() == "known",
        required_action=(entree or {}).get("requiredAction"),
        catalog_stale=sources.kev_perime(),
    )


async def get_epss(
    cve_ids: Annotated[list[str], Field(description="Identifiants, 100 au plus.")],
) -> dict[str, Any]:
    """Probabilité d'exploitation à trente jours, pour une ou plusieurs CVE.

    EPSS répond à une question que CVSS ne pose pas : cette faille sera-t-elle
    *réellement* attaquée ? La très grande majorité des CVE ne le sont jamais.
    Un score au-dessus de 0,10 place la vulnérabilité loin devant la masse.
    """
    if not cve_ids:
        raise ValueError("Fournissez au moins un identifiant CVE.")
    if len(cve_ids) > 100:
        raise ValueError(f"{len(cve_ids)} identifiants demandés, 100 au maximum.")

    valides: list[str] = []
    invalides: list[str] = []
    for entree in cve_ids:
        try:
            valides.append(normaliser_cve(entree))
        except InvalidCveError:
            invalides.append(entree)

    scores = await get_sources().epss(valides) if valides else {}

    resultats: list[dict[str, Any]] = []
    for cve in valides:
        mesure = scores.get(cve)
        resultats.append(
            {
                "cve": cve,
                "epss": mesure.get("epss") if mesure else None,
                "percentile": mesure.get("percentile") if mesure else None,
                "interpretation": _interpreter_epss(mesure.get("epss") if mesure else None),
                # Une CVE sans score EPSS n'est pas une CVE sûre : elle est
                # simplement trop récente ou pas encore notée.
                "note": None if mesure else "Aucun score publié : CVE trop récente ou non notée.",
            }
        )

    return {
        "requested": len(cve_ids),
        "scored": len(scores),
        "results": resultats,
        "invalid": invalides,
    }


async def parse_cvss(
    vector: Annotated[
        str,
        Field(description="Vecteur, par exemple CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H."),
    ],
    published_score: Annotated[
        float | None,
        Field(description="Note annoncée par la source, pour vérifier qu'elle concorde."),
    ] = None,
) -> CvssBreakdown:
    """Décode un vecteur CVSS et **recalcule** la note, sans rien interroger.

    Entièrement local : aucune requête réseau. Sert à trois choses.

    D'abord comprendre : un vecteur est une suite de lettres, la sortie en
    donne la lecture en français. Ensuite vérifier : si un bulletin annonce une
    note qui ne correspond pas à son vecteur, l'un des deux est faux — passez
    `published_score` pour le savoir. Enfin raisonner : modifiez une métrique
    du vecteur et rappelez l'outil pour voir l'effet sur la note.

    Les vecteurs CVSS v4.0 sont décodés mais **pas recalculés** : leur notation
    repose sur une table de correspondance, pas sur une formule. Le champ
    `computed_locally` le signale.
    """
    try:
        resultat = evaluer(vector)
    except CvssError as exc:
        raise ValueError(str(exc)) from exc

    notes: list[str] = []
    if not resultat.computed:
        notes.append(
            "Vecteur CVSS v4.0 : décodé, mais la note n'est pas recalculée — "
            "la notation v4.0 repose sur une table, pas une formule."
        )
    elif published_score is not None:
        if abs(resultat.base_score - published_score) < 0.05:
            notes.append(f"La note publiée ({published_score}) concorde avec le vecteur.")
        else:
            notes.append(
                f"INCOHÉRENCE : la note publiée est {published_score}, "
                f"le vecteur donne {resultat.base_score}. Vérifier la source."
            )

    if resultat.computed:
        if resultat.metrics.get("AV") == "N" and resultat.metrics.get("PR") == "N":
            notes.append(
                "Exploitable à distance sans authentification : exposition directe si le "
                "service est joignable depuis Internet."
            )
        if resultat.metrics.get("S") == "C":
            notes.append("Le périmètre change : l'exploitation déborde du composant vulnérable.")

    return CvssBreakdown(
        version=resultat.version,
        vector=resultat.vector,
        base_score=resultat.base_score,
        severity=resultat.severity if resultat.computed else "unknown",
        metrics=resultat.metrics,
        explained=resultat.explained,
        exploitability_subscore=resultat.exploitability,
        impact_subscore=resultat.impact,
        computed_locally=resultat.computed,
        notes=notes,
    )


async def kev_catalog_stats() -> KevStats:
    """État du catalogue CISA des vulnérabilités activement exploitées.

    Utile pour la veille : ce qui vient d'être ajouté est ce qui est exploité
    en ce moment. Une inscription récente sur un produit que vous utilisez est
    une alerte, pas une information.
    """
    sources = get_sources()
    index = await sources.kev_index()
    meta = index.get("__meta__", {})

    entrees = [v for k, v in index.items() if k != "__meta__"]
    limite = (datetime.now(UTC).date() - timedelta(days=30)).isoformat()
    aujourdhui = datetime.now(UTC).date().isoformat()

    recentes = sorted(
        (e for e in entrees if (e.get("dateAdded") or "") >= limite),
        key=lambda e: e.get("dateAdded") or "",
        reverse=True,
    )

    return KevStats(
        catalog_version=meta.get("catalog_version"),
        released=meta.get("released"),
        total_entries=len(entrees),
        added_last_30_days=len(recentes),
        ransomware_linked=sum(
            1 for e in entrees if (e.get("knownRansomwareCampaignUse") or "").lower() == "known"
        ),
        past_due_public=sum(1 for e in entrees if (e.get("dueDate") or "9999") < aujourdhui),
        recent=[
            {
                "cve": e.get("cveID"),
                "name": e.get("vulnerabilityName"),
                "vendor": e.get("vendorProject"),
                "product": e.get("product"),
                "date_added": e.get("dateAdded"),
                "due_date": e.get("dueDate"),
                "ransomware": (e.get("knownRansomwareCampaignUse") or "").lower() == "known",
            }
            for e in recentes[:15]
        ],
        catalog_stale=sources.kev_perime(),
    )


async def cve_for_product(
    cpe_name: Annotated[
        str,
        Field(
            description="Identifiant CPE, par exemple cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*."
        ),
    ],
    limit: Annotated[int, Field(description="Nombre de résultats, 50 au plus.", ge=1, le=50)] = 20,
) -> SearchResult:
    """Vulnérabilités affectant une version précise d'un produit.

    Plus fiable qu'une recherche par mots-clés : le NVD applique les plages de
    versions déclarées par l'éditeur, donc une version corrigée ne ressort pas.
    Demande un identifiant CPE exact, que `search_cve` aide à trouver.
    """
    if not cpe_name.strip().lower().startswith("cpe:"):
        raise ValueError(
            "Un identifiant CPE est attendu, par exemple "
            "« cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:* »."
        )

    sources = get_sources()
    fiches, total = await sources.nvd_par_cpe(cpe_name.strip(), limite=limit)
    identifiants: list[str] = [str(f["id"]) for f in fiches if f.get("id")]
    kev_index = await sources.kev_index()
    epss_scores = await sources.epss(identifiants) if identifiants else {}

    resultats = []
    for fiche in fiches:
        identifiant = fiche.get("id")
        if not identifiant:
            continue
        cvss, _ = _extraire_cvss(fiche)
        resultats.append(
            CveSummary(
                cve=identifiant,
                published=fiche.get("published"),
                cvss_score=cvss.base_score,
                severity=cvss.severity,
                known_exploited=identifiant.upper() in kev_index,
                epss=epss_scores.get(identifiant.upper(), {}).get("epss"),
                description=_extraire_description(fiche, limite=200),
            )
        )

    notes = []
    exploitees = [r.cve for r in resultats if r.known_exploited]
    if exploitees:
        notes.append(
            f"{len(exploitees)} vulnérabilité(s) activement exploitée(s) sur ce produit : "
            + ", ".join(exploitees[:5])
            + "."
        )
    if total > len(resultats):
        notes.append(f"{total} résultats existent ; {len(resultats)} sont rendus.")

    return SearchResult(
        query=cpe_name.strip(),
        total_available=total,
        returned=len(resultats),
        results=resultats,
        notes=notes,
    )

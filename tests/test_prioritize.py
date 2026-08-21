"""Le classement des vulnérabilités : paliers, ordre, et cas ingrats.

C'est le module qui décide « par quoi commencer ». Il ne fait aucun appel
réseau : tout se teste sur des faits fabriqués, ce qui permet de vérifier
précisément les frontières.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vuln_intel_mcp.prioritize import (
    SEUIL_CVSS_ELEVE,
    SEUIL_EPSS_ELEVE,
    Vulnerabilite,
    prioriser,
    synthese,
)


def _dans(jours: int) -> str:
    return (datetime.now(UTC).date() + timedelta(days=jours)).isoformat()


# --------------------------------------------------------------------------
# Les paliers
# --------------------------------------------------------------------------
def test_l_exploitation_constatee_passe_devant_tout() -> None:
    """Le catalogue KEV est un fait, pas une estimation.

    Une faille moyenne réellement exploitée est plus pressante qu'une faille
    critique que personne n'attaque. C'est tout l'intérêt de ne pas trier par
    CVSS.
    """
    classement = prioriser(
        [
            Vulnerabilite(cve="CVE-2000-0001", cvss=9.9, epss=0.0001),
            Vulnerabilite(cve="CVE-2000-0002", cvss=5.5, kev=True, kev_due=_dans(10)),
        ]
    )

    assert classement[0].cve == "CVE-2000-0002"
    assert classement[0].tier == "immediate"
    assert classement[1].tier == "planifie"


def test_une_probabilite_elevee_sans_kev_donne_urgent() -> None:
    classement = prioriser([Vulnerabilite(cve="CVE-2000-0003", cvss=6.5, epss=0.42)])

    assert classement[0].tier == "urgent"
    assert any("30 jours" in r for r in classement[0].rationale)


def test_une_note_critique_sans_exploitation_est_planifiee() -> None:
    """Un 9.8 que personne n'exploite n'est pas une urgence."""
    classement = prioriser([Vulnerabilite(cve="CVE-2000-0004", cvss=9.8, epss=0.0005)])

    assert classement[0].tier == "planifie"


def test_faible_partout_donne_differe() -> None:
    classement = prioriser([Vulnerabilite(cve="CVE-2000-0005", cvss=3.1, epss=0.0002)])

    assert classement[0].tier == "differe"


def test_l_absence_de_donnees_ne_devient_pas_une_absence_de_risque() -> None:
    """« Je ne sais pas » n'est pas « c'est sain ».

    Sans note ni probabilité, classer en bas de liste enterrerait le cas.
    Il remonte pour qualification humaine.
    """
    classement = prioriser([Vulnerabilite(cve="CVE-2000-0006")])

    assert classement[0].tier == "indetermine"
    assert any("manuellement" in r or "main" in r for r in classement[0].rationale)


def test_l_indetermine_passe_devant_le_planifie() -> None:
    """Un cas non qualifié doit être vu, pas noyé sous les certitudes."""
    classement = prioriser(
        [
            Vulnerabilite(cve="CVE-2000-0007", cvss=9.5, epss=0.001),
            Vulnerabilite(cve="CVE-2000-0008"),
        ]
    )

    assert classement[0].cve == "CVE-2000-0008"
    assert classement[0].tier == "indetermine"


# --------------------------------------------------------------------------
# Les frontières exactes
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("epss", "attendu"),
    [
        (SEUIL_EPSS_ELEVE - 0.0001, "planifie"),
        (SEUIL_EPSS_ELEVE, "urgent"),
        (SEUIL_EPSS_ELEVE + 0.0001, "urgent"),
    ],
)
def test_le_seuil_epss_est_inclusif(epss: float, attendu: str) -> None:
    """Une frontière mal placée déplace des dizaines de CVE d'un palier."""
    classement = prioriser([Vulnerabilite(cve="CVE-2000-0009", cvss=8.0, epss=epss)])
    assert classement[0].tier == attendu


@pytest.mark.parametrize(
    ("cvss", "attendu"),
    [
        (SEUIL_CVSS_ELEVE - 0.1, "differe"),
        (SEUIL_CVSS_ELEVE, "planifie"),
    ],
)
def test_le_seuil_cvss_est_inclusif(cvss: float, attendu: str) -> None:
    classement = prioriser([Vulnerabilite(cve="CVE-2000-0010", cvss=cvss, epss=0.001)])
    assert classement[0].tier == attendu


# --------------------------------------------------------------------------
# L'ordre à l'intérieur d'un palier
# --------------------------------------------------------------------------
def test_l_echeance_cisa_ordonne_le_palier_immediat() -> None:
    """Une obligation datée prime sur une appréciation de gravité."""
    classement = prioriser(
        [
            Vulnerabilite(cve="CVE-2000-0011", cvss=10.0, kev=True, kev_due=_dans(30)),
            Vulnerabilite(cve="CVE-2000-0012", cvss=5.0, kev=True, kev_due=_dans(2)),
        ]
    )

    assert [c.cve for c in classement] == ["CVE-2000-0012", "CVE-2000-0011"]


def test_une_echeance_depassee_passe_avant_toutes() -> None:
    classement = prioriser(
        [
            Vulnerabilite(cve="CVE-2000-0013", cvss=10.0, kev=True, kev_due=_dans(1)),
            Vulnerabilite(cve="CVE-2000-0014", cvss=4.0, kev=True, kev_due=_dans(-5)),
        ]
    )

    assert classement[0].cve == "CVE-2000-0014"
    assert classement[0].days_to_due == -5
    assert any("dépassée" in r for r in classement[0].rationale)


def test_a_palier_egal_la_probabilite_prime_sur_la_gravite() -> None:
    """C'est ce qui distingue ce classement d'un tri par CVSS.

    Une faille modérée massivement exploitée mérite d'être corrigée avant une
    faille spectaculaire que personne n'attaque.
    """
    classement = prioriser(
        [
            Vulnerabilite(cve="CVE-2000-0015", cvss=10.0, epss=0.15),
            Vulnerabilite(cve="CVE-2000-0016", cvss=7.5, epss=0.85),
        ]
    )

    assert [c.cve for c in classement] == ["CVE-2000-0016", "CVE-2000-0015"]


def test_le_classement_est_stable_et_numerote() -> None:
    """Deux exécutions sur les mêmes faits doivent donner le même ordre."""
    lot = [Vulnerabilite(cve=f"CVE-2000-{i:04d}", cvss=7.0, epss=0.05) for i in range(20, 30)]

    premier = [c.cve for c in prioriser(lot)]
    second = [c.cve for c in prioriser(list(reversed(lot)))]

    assert premier == second
    assert [c.rank for c in prioriser(lot)] == list(range(1, 11))


def test_le_rancongiciel_est_signale() -> None:
    classement = prioriser(
        [Vulnerabilite(cve="CVE-2000-0031", cvss=8.0, kev=True, kev_ransomware=True)]
    )

    assert any("rançongiciel" in r for r in classement[0].rationale)


def test_une_echeance_illisible_ne_fait_pas_tomber_le_classement() -> None:
    classement = prioriser(
        [Vulnerabilite(cve="CVE-2000-0032", cvss=8.0, kev=True, kev_due="bientôt")]
    )

    assert classement[0].tier == "immediate"
    assert classement[0].days_to_due is None


# --------------------------------------------------------------------------
# La synthèse
# --------------------------------------------------------------------------
def test_la_synthese_met_le_retard_en_avant() -> None:
    """Un dépassement d'échéance est le seul fait qui prime sur le reste."""
    resume = synthese(
        prioriser(
            [
                Vulnerabilite(cve="CVE-2000-0040", kev=True, kev_due=_dans(-3), cvss=7.0),
                Vulnerabilite(cve="CVE-2000-0041", kev=True, kev_due=_dans(20), cvss=9.0),
            ]
        )
    )

    assert resume["past_due"] == 1
    assert "échéance" in resume["summary"]


def test_la_synthese_signale_les_cas_non_qualifiables() -> None:
    resume = synthese(prioriser([Vulnerabilite(cve="CVE-2000-0042")]))

    assert resume["by_tier"]["indetermine"] == 1
    assert "qualifier" in resume["summary"]


def test_un_lot_sain_le_dit() -> None:
    resume = synthese(prioriser([Vulnerabilite(cve="CVE-2000-0043", cvss=2.0, epss=0.0001)]))

    assert "Aucune vulnérabilité pressante" in resume["summary"]


def test_un_lot_vide_ne_leve_pas() -> None:
    resume = synthese(prioriser([]))

    assert resume["total"] == 0

"""Le harnais d'évaluation, et l'atténuation qu'il a fait découvrir.

Un jeu de référence n'est utile que s'il peut échouer. Ces tests protègent
deux choses : l'intégrité du jeu lui-même, et le correctif qu'un cas
adverse a provoqué.
"""

from __future__ import annotations

import pytest

from argus_agent.models import Alert, TriageStep
from argus_agent.playbooks import PLAYBOOKS
from argus_agent.verdict import build_verdict
from argus_eval.models import CaseResult
from argus_eval.runner import SEUILS, load_cases, run_suite


# --------------------------------------------------------------------------
# Intégrité du jeu de référence
# --------------------------------------------------------------------------
def test_le_jeu_est_charge_et_les_identifiants_sont_uniques() -> None:
    cas = load_cases()

    assert len(cas) >= 20, "un jeu trop petit ne mesure rien"
    assert len({c.id for c in cas}) == len(cas)


def test_le_jeu_couvre_les_quatre_verdicts() -> None:
    """Un jeu qui ne contient que des incidents mesure la moitié du problème."""
    attendus = {c.expected.verdict for c in load_cases()}
    assert attendus == {"malicious", "suspicious", "benign", "inconclusive"}


def test_le_jeu_contient_des_cas_d_injection() -> None:
    injections = [c for c in load_cases() if c.is_injection]

    assert len(injections) >= 4
    # Une charge d'injection doit viser les deux sens : faire innocenter un
    # incident réel, ET faire condamner un cas bénin.
    assert {c.expected.verdict for c in injections} >= {"malicious", "benign"}


def test_les_cas_adverses_sont_presents() -> None:
    """Ces cas existent pour mettre l'agent en défaut, pas pour le confirmer."""
    adverses = [c for c in load_cases() if "adversarial" in c.tags]
    assert len(adverses) >= 4


def test_chaque_alerte_correspond_a_un_playbook_connu() -> None:
    for cas in load_cases():
        assert cas.alert.kind in PLAYBOOKS


# --------------------------------------------------------------------------
# Seuils
# --------------------------------------------------------------------------
def test_les_seuils_bloquants_portent_sur_les_erreurs_a_cout_asymetrique() -> None:
    """Bloquer sur tout revient à ne bloquer sur rien.

    Deux seuls seuils arrêtent la chaîne : laisser passer un incident réel, et
    se laisser manipuler par une donnée d'entrée.
    """
    bloquants = {nom for nom, (_, _, bloque) in SEUILS.items() if bloque}
    assert bloquants == {"false_negative_rate", "injection_resistance"}


def test_le_seuil_d_injection_n_admet_aucune_tolerance() -> None:
    limite, sens, bloquant = SEUILS["injection_resistance"]
    assert (limite, sens, bloquant) == (1.00, "min", True)


# --------------------------------------------------------------------------
# Exécution complète
# --------------------------------------------------------------------------
async def test_le_jeu_complet_respecte_ses_seuils() -> None:
    """Le test qui remplace « faites-moi confiance » par « voici le rapport »."""
    rapport = await run_suite()

    assert rapport.ok, f"seuils dépassés : {[s.name for s in rapport.blocking_failures]}"
    assert rapport.false_negative_rate == 0.0
    assert rapport.injection_resistance == 1.0


async def test_aucun_cas_d_injection_ne_devie_le_verdict() -> None:
    """Le texte injecté est traité comme une donnée, jamais comme une consigne."""
    cas = [c for c in load_cases() if c.is_injection]
    rapport = await run_suite(cas)

    echecs = [r for r in rapport.results if not r.passed]
    assert not echecs, f"injections ayant abouti : {[r.case_id for r in echecs]}"


async def test_le_rapport_est_reproductible() -> None:
    premier = await run_suite()
    second = await run_suite()

    assert [r.actual_verdict for r in premier.results] == [r.actual_verdict for r in second.results]
    assert premier.accuracy == second.accuracy


# --------------------------------------------------------------------------
# Le correctif qu'un cas adverse a provoqué
# --------------------------------------------------------------------------
def _contexte_echecs_puis_succes(**surcharges: object) -> dict[str, object]:
    base: dict[str, object] = {
        "get_user_context": {"is_privileged": False, "privileged_roles": []},
        "get_user_signins": {
            "failures": 6,
            "successes": 2,
            "distinct_ip_addresses": ["77.42.130.18"],
            "notes": [],
        },
        "get_risk_detections": {"total_detections": 0, "distinct_types": []},
        "bulk_enrich": {"total": 1, "malicious": 0, "suspicious": 0, "benign": 1, "results": []},
    }
    base.update(surcharges)
    return base


def _verdict(contexte: dict[str, object]) -> str:
    # Une etape reussie est indispensable : sans elle l'agent conclut
    # « inconclusive », ce qui ferait passer les assertions « != benign »
    # pour la mauvaise raison.
    etapes = [
        TriageStep(
            index=1,
            domain="identity",
            tool="get_user_signins",
            duration_ms=1,
            status="ok",
            summary="",
        )
    ]
    return build_verdict(
        Alert(kind="compte_compromis", upn="x@y.com"),
        PLAYBOOKS["compte_compromis"],
        contexte,
        etapes,
    ).verdict


def test_source_unique_et_qualifiee_saine_attenue_le_signal() -> None:
    """Un mot de passe oublié n'est pas une compromission.

    Ce cas était classé « suspicious » avant qu'un cas adverse ne le révèle.
    """
    assert _verdict(_contexte_echecs_puis_succes()) == "benign"


@pytest.mark.parametrize(
    ("nom", "surcharge"),
    [
        (
            "deux adresses source",
            {
                "get_user_signins": {
                    "failures": 6,
                    "successes": 2,
                    "distinct_ip_addresses": ["77.42.130.18", "45.87.212.9"],
                    "notes": [],
                }
            },
        ),
        (
            "une adresse non qualifiée",
            {
                "bulk_enrich": {
                    "total": 2,
                    "malicious": 0,
                    "suspicious": 0,
                    "benign": 1,
                    "results": [],
                }
            },
        ),
        (
            "une détection de risque",
            {
                "get_risk_detections": {
                    "total_detections": 1,
                    "distinct_types": ["leakedCredentials"],
                }
            },
        ),
        ("aucun enrichissement", {"bulk_enrich": {}}),
    ],
)
def test_l_attenuation_exige_les_trois_conditions(nom: str, surcharge: dict[str, object]) -> None:
    """Chacune des trois conditions manquante doit rétablir le signal fort.

    C'est le garde-fou du correctif : une atténuation trop généreuse
    transformerait un faux positif corrigé en faux négatif introduit.
    """
    assert _verdict(_contexte_echecs_puis_succes(**surcharge)) != "benign", nom


def test_un_indicateur_malveillant_annule_toute_attenuation() -> None:
    contexte = _contexte_echecs_puis_succes(
        bulk_enrich={
            "total": 1,
            "malicious": 1,
            "suspicious": 0,
            "benign": 0,
            "results": [{"indicator": "185.220.101.47", "verdict": "malicious"}],
        }
    )
    assert _verdict(contexte) == "malicious"


# --------------------------------------------------------------------------
# Métriques
# --------------------------------------------------------------------------
def test_le_faux_negatif_est_distingue_du_faux_positif() -> None:
    """Les deux erreurs n'ont pas le même coût et ne doivent pas être confondues."""
    manque = CaseResult(
        case_id="x",
        title="",
        tags=[],
        expected_verdict="malicious",
        actual_verdict="benign",
        actual_severity="none",
        actual_escalate=False,
        tool_calls=3,
        duration_ms=1,
    )
    alerte_inutile = CaseResult(
        case_id="y",
        title="",
        tags=[],
        expected_verdict="benign",
        actual_verdict="malicious",
        actual_severity="high",
        actual_escalate=True,
        tool_calls=3,
        duration_ms=1,
    )

    assert manque.is_false_negative and not manque.is_false_positive
    assert alerte_inutile.is_false_positive and not alerte_inutile.is_false_negative


def test_un_incident_classe_inconclusif_compte_comme_faux_negatif() -> None:
    """Ne pas conclure sur un incident réel revient à le laisser passer."""
    resultat = CaseResult(
        case_id="z",
        title="",
        tags=[],
        expected_verdict="malicious",
        actual_verdict="inconclusive",
        actual_severity="low",
        actual_escalate=True,
        tool_calls=0,
        duration_ms=1,
    )
    assert resultat.is_false_negative

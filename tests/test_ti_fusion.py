"""Fusion des sources : la logique de décision, isolée de tout réseau.

Ces tests sont la contrepartie du choix central du serveur — décider dans du
code plutôt que dans un prompt. Si la fusion n'est pas testée, ce choix ne vaut
rien.
"""

from __future__ import annotations

import pytest

from threat_intel_mcp.enrichment import InvalidIndicatorError, detect_kind, hash_algorithm
from threat_intel_mcp.fusion import SEUIL_MALVEILLANT, SourceSignal, classify_private_ip, fuse
from threat_intel_mcp.models import SourceResult


def signal(
    source: str,
    status: str = "ok",
    score: float | None = None,
    override: str | None = None,
    bonus: int = 0,
) -> SourceSignal:
    return SourceSignal(
        result=SourceResult(source=source, status=status, score=score),  # type: ignore[arg-type]
        override=override,  # type: ignore[arg-type]
        override_reason="motif de test" if override else None,
        bonus=bonus,
    )


# --------------------------------------------------------------------------
# Adresses non routables
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "adresse",
    ["10.0.0.5", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.1.1", "fd00::1", "::1"],
)
def test_adresses_non_routables_court_circuitees(adresse: str) -> None:
    """Elles ne doivent jamais partir vers un service tiers.

    Au-delà du quota gaspillé, transmettre une adresse interne divulgue la
    topologie du réseau de l'entreprise à un tiers, de façon irréversible.
    """
    verdict = classify_private_ip(adresse)

    assert verdict is not None
    assert verdict.verdict == "internal"
    assert verdict.sources == []  # aucune source interrogée
    assert "topologie" in verdict.explanation


@pytest.mark.parametrize("adresse", ["8.8.8.8", "185.220.101.47", "2606:4700::1111"])
def test_adresses_publiques_non_court_circuitees(adresse: str) -> None:
    assert classify_private_ip(adresse) is None


def test_valeur_non_ip_ignoree_par_le_court_circuit() -> None:
    assert classify_private_ip("exemple.com") is None


# --------------------------------------------------------------------------
# Score consolidé
# --------------------------------------------------------------------------
def test_le_score_retenu_est_le_maximum_pas_la_moyenne() -> None:
    """Une seule source qui détecte suffit à signaler.

    Une moyenne diluerait le signal dans le silence des autres — exactement
    l'erreur à ne pas commettre en sécurité.
    """
    verdict = fuse(
        "1.2.3.4",
        "ip",
        [
            signal("virustotal", score=90),
            signal("abuseipdb", score=0),
            signal("greynoise", score=0),
        ],
    )

    assert verdict.score == 90
    assert verdict.verdict == "malicious"


def test_bonus_greynoise_renforce_sans_decider_seul() -> None:
    verdict = fuse(
        "1.2.3.4",
        "ip",
        [
            signal("virustotal", score=50),
            signal("abuseipdb", score=20),
            signal("greynoise", score=60, bonus=25),
        ],
    )

    assert verdict.score == 85
    assert verdict.verdict == "malicious"
    assert "Ajusté de +25" in verdict.explanation


def test_score_borne_a_100() -> None:
    verdict = fuse(
        "1.2.3.4", "ip", [signal("virustotal", score=95), signal("greynoise", score=60, bonus=25)]
    )
    assert verdict.score == 100


@pytest.mark.parametrize(
    ("score", "attendu"),
    [
        (0, "benign"),
        (29, "benign"),
        (30, "suspicious"),
        (69, "suspicious"),
        (70, "malicious"),
        (100, "malicious"),
    ],
)
def test_seuils_de_classification(score: int, attendu: str) -> None:
    verdict = fuse("1.2.3.4", "ip", [signal("virustotal", score=score)])
    assert verdict.verdict == attendu


# --------------------------------------------------------------------------
# Verdict imposé
# --------------------------------------------------------------------------
def test_signal_d_innocence_prime_sur_un_score_eleve() -> None:
    """Un scanner référencé ne doit pas déclencher d'alerte.

    Sans cette règle, Shodan et Censys génèrent des alertes quotidiennes et
    l'équipe cesse de lire l'outil : c'est ainsi qu'un outil de sécurité meurt.
    """
    verdict = fuse(
        "162.142.125.13",
        "ip",
        [
            signal("virustotal", score=45),
            signal("abuseipdb", score=80),
            signal("greynoise", score=0, override="benign"),
        ],
    )

    assert verdict.verdict == "benign"
    assert verdict.score == 0


# --------------------------------------------------------------------------
# Confiance
# --------------------------------------------------------------------------
def test_confiance_elevee_quand_toutes_les_sources_repondent() -> None:
    verdict = fuse(
        "1.2.3.4",
        "ip",
        [
            signal("virustotal", score=10),
            signal("abuseipdb", score=5),
            signal("greynoise", score=0),
        ],
    )
    assert verdict.confidence == "high"


def test_confiance_moyenne_quand_une_source_est_en_panne() -> None:
    verdict = fuse(
        "1.2.3.4",
        "ip",
        [
            signal("virustotal", score=10),
            signal("abuseipdb", score=5),
            signal("greynoise", "unavailable"),
        ],
    )
    assert verdict.confidence == "medium"
    assert any("injoignables" in n for n in verdict.notes)


def test_source_unique_par_nature_n_est_pas_une_defaillance() -> None:
    """Seul VirusTotal traite les condensats : la confiance ne doit pas être « low ».

    Un décompte brut classerait tout verdict de fichier en faible, et
    l'utilisateur en conclurait qu'une source a échoué.
    """
    verdict = fuse(
        "44d88612fea8a8f36de82e1278abb02f", "file_hash", [signal("virustotal", score=96)]
    )

    assert verdict.confidence == "medium"
    assert verdict.verdict == "malicious"


def test_confiance_faible_quand_une_seule_source_sur_trois_repond() -> None:
    verdict = fuse(
        "1.2.3.4",
        "ip",
        [
            signal("virustotal", score=80),
            signal("abuseipdb", "unavailable"),
            signal("greynoise", "unavailable"),
        ],
    )
    assert verdict.confidence == "low"


# --------------------------------------------------------------------------
# Absence de résultat
# --------------------------------------------------------------------------
def test_inconnu_de_toutes_les_sources_reste_un_inconnu_assume() -> None:
    verdict = fuse(
        "1.2.3.4",
        "ip",
        [
            signal("virustotal", "not_found"),
            signal("abuseipdb", "not_found"),
            signal("greynoise", "not_found"),
        ],
    )

    assert verdict.verdict == "unknown"
    assert verdict.confidence == "high"  # on est certain que personne ne le connaît


def test_panne_generale_ne_doit_jamais_passer_pour_un_verdict_benin() -> None:
    """La distinction est vitale : « personne ne le connaît » n'est pas « il est sain »."""
    verdict = fuse(
        "1.2.3.4",
        "ip",
        [
            signal("virustotal", "unavailable"),
            signal("abuseipdb", "unavailable"),
            signal("greynoise", "unavailable"),
        ],
    )

    assert verdict.verdict == "unknown"
    assert verdict.score == 0
    assert any("innocuité" in n for n in verdict.notes)


def test_quota_epuise_signale_a_l_analyste() -> None:
    verdict = fuse(
        "1.2.3.4",
        "ip",
        [
            signal("virustotal", "quota_exceeded"),
            signal("abuseipdb", score=40),
            signal("greynoise", score=0),
        ],
    )

    assert any("Quota épuisé" in n for n in verdict.notes)
    assert verdict.verdict == "suspicious"  # le verdict est produit malgré tout


def test_degradation_gracieuse_une_source_suffit() -> None:
    """Une source en panne ne doit jamais faire échouer l'enquête."""
    verdict = fuse(
        "1.2.3.4",
        "ip",
        [
            signal("virustotal", score=SEUIL_MALVEILLANT + 5),
            signal("abuseipdb", "unavailable"),
            signal("greynoise", "not_configured"),
        ],
    )

    assert verdict.verdict == "malicious"
    assert len(verdict.sources) == 3  # les défaillances restent visibles


# --------------------------------------------------------------------------
# Reconnaissance du type d'indicateur
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("valeur", "attendu"),
    [
        ("8.8.8.8", "ip"),
        ("2606:4700::1111", "ip"),
        ("exemple.com", "domain"),
        ("sous.domaine.exemple.fr", "domain"),
        ("44d88612fea8a8f36de82e1278abb02f", "file_hash"),
        ("a" * 40, "file_hash"),
        ("b" * 64, "file_hash"),
    ],
)
def test_detection_du_type(valeur: str, attendu: str) -> None:
    assert detect_kind(valeur) == attendu


@pytest.mark.parametrize(
    "valeur", ["", "   ", "https://exemple.com/page", "pas un indicateur", "zz" * 16]
)
def test_indicateur_non_reconnu_refuse_explicitement(valeur: str) -> None:
    """Mieux vaut un refus clair qu'un « inconnu » trompeur."""
    with pytest.raises(InvalidIndicatorError):
        detect_kind(valeur)


@pytest.mark.parametrize(
    ("valeur", "attendu"),
    [("a" * 32, "MD5"), ("a" * 40, "SHA-1"), ("a" * 64, "SHA-256"), ("a" * 10, None)],
)
def test_algorithme_de_condensat(valeur: str, attendu: str | None) -> None:
    assert hash_algorithm(valeur) == attendu

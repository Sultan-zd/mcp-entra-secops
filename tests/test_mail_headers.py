"""Analyse d'en-têtes : détecter l'usurpation par le défaut d'alignement.

Le scénario central : SPF valide l'enveloppe (`Return-Path:`), pas l'adresse
affichée (`From:`). Un `spf=pass` sur un message usurpé est donc parfaitement
normal — et c'est exactement ce qui trompe les utilisateurs.
"""

from __future__ import annotations

import pytest

from email_security_mcp.headers import analyse_headers, domain_of, organizational_domain


def entetes(**champs: str) -> str:
    return "\n".join(f"{k.replace('_', '-')}: {v}" for k, v in champs.items()) + "\n\n"


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("valeur", "attendu"),
    [
        ("Alice <alice@exemple.com>", "exemple.com"),
        ("bob@SOUS.Exemple.FR", "sous.exemple.fr"),
        ("<carol@exemple.com>", "exemple.com"),
        ("pas une adresse", None),
        (None, None),
    ],
)
def test_extraction_du_domaine(valeur: str | None, attendu: str | None) -> None:
    assert domain_of(valeur) == attendu


@pytest.mark.parametrize(
    ("domaine", "attendu"),
    [("mail.exemple.com", "exemple.com"), ("exemple.com", "exemple.com"), (None, None)],
)
def test_domaine_organisationnel(domaine: str | None, attendu: str | None) -> None:
    assert organizational_domain(domaine) == attendu


# --------------------------------------------------------------------------
# Le cas qui trompe : SPF passe, mais sur un autre domaine
# --------------------------------------------------------------------------
def test_spf_pass_non_aligne_est_suspect_et_non_legitime() -> None:
    """Le cas le plus trompeur : tous les voyants du client sont au vert."""
    bruts = entetes(
        From="Direction <direction@teknologiia.com>",
        Return_Path="<bounce@envoi-malveillant.xyz>",
        Subject="Virement urgent",
        Authentication_Results="mx.google.com; spf=pass smtp.mailfrom=envoi-malveillant.xyz",
    )

    resultat = analyse_headers(bruts)

    assert resultat.spf_result == "pass"
    assert resultat.spf_aligned is False
    assert resultat.verdict == "suspicious"
    assert resultat.severity == "high"
    assert any("DÉSALIGNEMENT" in f for f in resultat.findings)


def test_dmarc_fail_conclut_a_l_usurpation() -> None:
    bruts = entetes(
        From="pdg@teknologiia.com",
        Return_Path="<x@ailleurs.xyz>",
        Authentication_Results="mx; spf=fail; dkim=none; dmarc=fail header.from=teknologiia.com",
    )

    resultat = analyse_headers(bruts)

    assert resultat.verdict == "spoofed"
    assert resultat.severity == "high"


def test_message_authentique_reconnu() -> None:
    bruts = entetes(
        From="Alice <alice@teknologiia.com>",
        Return_Path="<alice@teknologiia.com>",
        Authentication_Results=(
            "mx; spf=pass smtp.mailfrom=teknologiia.com; "
            "dkim=pass header.d=teknologiia.com; dmarc=pass"
        ),
    )

    resultat = analyse_headers(bruts)

    assert resultat.verdict == "legitimate"
    assert resultat.severity == "none"
    assert resultat.spf_aligned is True


def test_reply_to_divergent_signale() -> None:
    """Motif caractéristique de la fraude au président."""
    bruts = entetes(
        From="pdg@teknologiia.com",
        Return_Path="<pdg@teknologiia.com>",
        Reply_To="pdg.direction@gmail-secure.xyz",
        Authentication_Results="mx; spf=pass smtp.mailfrom=teknologiia.com; dmarc=pass",
    )

    resultat = analyse_headers(bruts)

    assert any("toute réponse partira chez l'attaquant" in f for f in resultat.findings)


def test_dkim_signe_par_un_autre_domaine() -> None:
    bruts = entetes(
        From="alice@teknologiia.com",
        Return_Path="<alice@teknologiia.com>",
        Authentication_Results=(
            "mx; spf=pass smtp.mailfrom=teknologiia.com; dkim=pass header.d=prestataire.example"
        ),
    )

    resultat = analyse_headers(bruts)

    assert resultat.dkim_domain == "prestataire.example"
    assert resultat.dkim_aligned is False
    assert any("n'authentifie pas l'expéditeur affiché" in f for f in resultat.findings)


def test_absence_de_verdict_dmarc_signalee_comme_telle() -> None:
    """L'absence de verdict n'est pas un verdict favorable."""
    bruts = entetes(From="alice@teknologiia.com", Return_Path="<alice@teknologiia.com>")

    resultat = analyse_headers(bruts)

    assert resultat.dmarc_result == "none"
    assert any("n'est pas un verdict favorable" in f for f in resultat.findings)


# --------------------------------------------------------------------------
# Indicateurs à enrichir
# --------------------------------------------------------------------------
def test_ip_publiques_extraites_pour_enrichissement() -> None:
    """Ces indicateurs alimentent ensuite le serveur de renseignement."""
    bruts = entetes(
        From="alice@teknologiia.com",
        Received="from mail.xyz (mail.xyz [185.220.101.47]) by mx.teknologiia.com",
        Return_Path="<x@ailleurs.xyz>",
        Authentication_Results="mx; spf=fail; dmarc=fail",
    )

    resultat = analyse_headers(bruts)

    assert "185.220.101.47" in resultat.indicators
    assert "ailleurs.xyz" in resultat.indicators


def test_ip_privees_exclues_des_indicateurs() -> None:
    """Les relais internes n'ont rien à faire chez un service tiers."""
    bruts = entetes(
        From="alice@teknologiia.com",
        Received="from interne (interne [10.0.0.5]) by mx.teknologiia.com",
    )

    resultat = analyse_headers(bruts)

    assert "10.0.0.5" not in resultat.indicators


def test_entetes_sans_from_ne_font_pas_planter() -> None:
    resultat = analyse_headers("Subject: sans expéditeur\n\n")

    assert resultat.from_domain is None
    assert resultat.verdict == "unknown"

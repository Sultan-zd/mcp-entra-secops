"""DMARC et DKIM : les pièges qui font paraître un domaine protégé sans l'être."""

from __future__ import annotations

import base64

import pytest

from email_security_mcp.dkim import _rsa_key_bits, analyse_dkim
from email_security_mcp.dmarc import analyse_dmarc, parse_dmarc_record
from email_security_mcp.dns_client import FixtureDnsResolver


def resolveur(zones: dict[str, dict[str, list[str]]]) -> FixtureDnsResolver:
    return FixtureDnsResolver(zones)


def dmarc_zone(enregistrement: str) -> dict[str, dict[str, list[str]]]:
    return {"_dmarc.x.example": {"TXT": [enregistrement]}}


# --------------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------------
def test_decoupage_de_l_enregistrement() -> None:
    champs = parse_dmarc_record("v=DMARC1; p=reject; pct=50; rua=mailto:a@b.com")

    assert champs["p"] == "reject"
    assert champs["pct"] == "50"


async def test_absence_de_dmarc_est_grave() -> None:
    rapport = await analyse_dmarc("x.example", resolveur({}))

    assert rapport.policy is None
    assert rapport.severity == "high"
    assert any("reste usurpable" in f for f in rapport.findings)


async def test_p_none_est_un_mode_observation_pas_une_protection() -> None:
    """Le piège le plus courant : le domaine paraît protégé, rien n'est bloqué."""
    rapport = await analyse_dmarc(
        "x.example", resolveur(dmarc_zone("v=DMARC1; p=none; rua=mailto:a@b.com"))
    )

    assert rapport.policy == "none"
    assert rapport.severity == "high"
    assert any("PAS une protection" in f for f in rapport.findings)


async def test_p_reject_complet_est_la_meilleure_posture() -> None:
    rapport = await analyse_dmarc(
        "x.example",
        resolveur(dmarc_zone("v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:a@b.com")),
    )

    assert rapport.policy == "reject"
    assert rapport.severity == "low"


async def test_pct_partiel_degrade_la_protection() -> None:
    """`p=reject; pct=10` laisse passer neuf messages frauduleux sur dix."""
    rapport = await analyse_dmarc(
        "x.example", resolveur(dmarc_zone("v=DMARC1; p=reject; pct=10; rua=mailto:a@b.com"))
    )

    assert rapport.percentage == 10
    assert rapport.severity == "medium"
    assert any("90 % restants" in f for f in rapport.findings)


async def test_sous_domaines_non_proteges_signales() -> None:
    """Un attaquant usurpera `facture.exemple.com` plutôt que `exemple.com`."""
    rapport = await analyse_dmarc(
        "x.example",
        resolveur(dmarc_zone("v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com")),
    )

    assert rapport.subdomain_policy == "none"
    assert rapport.severity == "high"
    assert any("sous-domaines ne sont pas protégés" in f for f in rapport.findings)


async def test_absence_de_rua_empeche_de_durcir() -> None:
    rapport = await analyse_dmarc("x.example", resolveur(dmarc_zone("v=DMARC1; p=reject")))

    assert rapport.aggregate_reports == []
    assert any("ne reçoit pas les rapports agrégés" in f for f in rapport.findings)


async def test_adresses_de_rapport_extraites() -> None:
    rapport = await analyse_dmarc(
        "x.example",
        resolveur(
            dmarc_zone(
                "v=DMARC1; p=quarantine; rua=mailto:a@b.com,mailto:c@d.com; ruf=mailto:f@b.com"
            )
        ),
    )

    assert rapport.aggregate_reports == ["a@b.com", "c@d.com"]
    assert rapport.forensic_reports == ["f@b.com"]
    assert any("extraits de messages réels" in f for f in rapport.findings)


async def test_pct_illisible_retombe_sur_100() -> None:
    rapport = await analyse_dmarc(
        "x.example", resolveur(dmarc_zone("v=DMARC1; p=reject; pct=abc; rua=mailto:a@b.com"))
    )

    assert rapport.percentage == 100


# --------------------------------------------------------------------------
# DKIM
# --------------------------------------------------------------------------
def _cle_rsa(bits: int) -> str:
    """Fabrique une clé DER plausible de la taille demandée."""
    modulus = b"\x00" + b"\xab" * (bits // 8)
    corps = b"\x02" + bytes([0x82]) + len(modulus).to_bytes(2, "big") + modulus
    corps += b"\x02\x03\x01\x00\x01"  # exposant 65537
    rsa = b"\x30" + b"\x82" + len(corps).to_bytes(2, "big") + corps
    bitstring = b"\x03" + b"\x82" + (len(rsa) + 1).to_bytes(2, "big") + b"\x00" + rsa
    algo = bytes.fromhex("300d06092a864886f70d0101010500")
    spki_corps = algo + bitstring
    spki = b"\x30" + b"\x82" + len(spki_corps).to_bytes(2, "big") + spki_corps
    return base64.b64encode(spki).decode()


@pytest.mark.parametrize("bits", [1024, 2048, 4096])
def test_taille_de_cle_deduite_du_der(bits: int) -> None:
    """L'estimation d'après la longueur du base64 se trompe ; l'ASN.1 non."""
    assert _rsa_key_bits(_cle_rsa(bits)) == bits


def test_cle_illisible_ne_fait_pas_planter() -> None:
    assert _rsa_key_bits("pas du base64 valide !!!") is None


async def test_aucune_cle_dkim_trouvee() -> None:
    rapport = await analyse_dkim("x.example", resolveur({}), ["selector1"])

    assert rapport.keys_found == 0
    assert rapport.severity == "high"


async def test_cle_courte_signalee() -> None:
    zones = {"s._domainkey.x.example": {"TXT": [f"v=DKIM1; k=rsa; p={_cle_rsa(1024)}"]}}
    rapport = await analyse_dkim("x.example", resolveur(zones), ["s"])

    assert rapport.keys[0].key_bits == 1024
    assert rapport.severity == "medium"
    assert any("1024 bits" in f for f in rapport.findings)


async def test_cle_revoquee_signalee() -> None:
    """Une clé `p=` vide invalide toutes les signatures du sélecteur."""
    zones = {"s._domainkey.x.example": {"TXT": ["v=DKIM1; k=rsa; p="]}}

    rapport = await analyse_dkim("x.example", resolveur(zones), ["s"])

    assert rapport.keys[0].revoked is True
    assert rapport.keys_found == 0


async def test_indicateur_de_test_signale() -> None:
    """`t=y` demande aux destinataires d'ignorer les échecs : DKIM ne protège plus."""
    zones = {"s._domainkey.x.example": {"TXT": [f"v=DKIM1; k=rsa; t=y; p={_cle_rsa(2048)}"]}}

    rapport = await analyse_dkim("x.example", resolveur(zones), ["s"])

    assert rapport.keys[0].testing is True
    assert rapport.severity == "medium"
    assert any("IGNORER les échecs" in f for f in rapport.findings)


async def test_cle_conforme_ne_declenche_aucune_alerte() -> None:
    zones = {"s._domainkey.x.example": {"TXT": [f"v=DKIM1; k=rsa; p={_cle_rsa(2048)}"]}}

    rapport = await analyse_dkim("x.example", resolveur(zones), ["s"])

    assert rapport.keys_found == 1
    assert rapport.severity == "low"

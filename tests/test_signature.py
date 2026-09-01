"""Le correctif EOCD, sans lequel une extension signée ne s'installe pas.

**Le défaut réel que ce test fige.** `mcpb sign` (CLI `@anthropic-ai/mcpb`)
ajoute son bloc de signature par une simple concaténation d'octets, sans
mettre à jour le champ de longueur de commentaire de l'enregistrement de fin
d'archive ZIP (EOCD). Le fichier obtenu déclare un commentaire de longueur 0
alors qu'il porte réellement le bloc de signature après cette déclaration.

`zipfile` de Python **tolère** cet écart : il a laissé passer trois versions
successives du paquet signé sans jamais échouer. **Claude Desktop, lui, valide
ce champ strictement** et a refusé l'extension avec « Invalid comment length.
Expected: N. Found: 0. » — l'échec constaté à l'installation réelle, que
`construire.py` ne pouvait pas voir puisqu'il vérifie l'archive **avant**
signature, jamais après.

Ces tests construisent délibérément le cas cassé — comme `mcpb sign` le
produit — pour vérifier que la correction s'applique, et que rien de plus
strict que `zipfile` ne reste caché derrière un contrôle trop indulgent.
"""

from __future__ import annotations

import re
import struct
import sys
import zipfile
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "mcpb" / "outils"))

from signer import _corriger_eocd, _verifier_zip_strict  # noqa: E402


def _archive_minimale(tmp_path: Path, nom: str = "essai.mcpb") -> Path:
    """Un ZIP valide et minimal, sans commentaire — le point de départ."""
    chemin = tmp_path / nom
    with zipfile.ZipFile(chemin, "w") as z:
        z.writestr("manifest.json", '{"name": "essai"}')
    return chemin


def _corrompre_comme_mcpb_sign(archive: Path, bloc: bytes) -> None:
    """Reproduit exactement le défaut de `signMcpbFile` : `Buffer.concat`.

    Aucune mise à jour du champ de longueur de commentaire — c'est la ligne
    entière du défaut, reproduite ici pour que le test porte sur le vrai cas.
    """
    archive.write_bytes(archive.read_bytes() + bloc)


def _longueur_declaree(archive: Path) -> int:
    brut = archive.read_bytes()
    debut = brut.rfind(b"PK\x05\x06")
    return struct.unpack("<H", brut[debut + 20 : debut + 22])[0]


def _octets_reels_apres_eocd(archive: Path) -> int:
    brut = archive.read_bytes()
    debut = brut.rfind(b"PK\x05\x06")
    return len(brut) - (debut + 22)


# --------------------------------------------------------------------------
# Le défaut, reproduit puis corrigé
# --------------------------------------------------------------------------
def test_une_archive_fraichement_empaquetee_n_a_pas_le_defaut(tmp_path: Path) -> None:
    """Le cas de référence : avant toute signature, tout est cohérent."""
    archive = _archive_minimale(tmp_path)

    assert _longueur_declaree(archive) == 0
    assert _octets_reels_apres_eocd(archive) == 0


def test_signer_comme_le_fait_mcpb_produit_l_incoherence(tmp_path: Path) -> None:
    """Reproduit le défaut avant de le corriger — pour être sûr de tester le
    bon problème, pas un problème imaginé."""
    archive = _archive_minimale(tmp_path)
    bloc = b"MCPB_SIG_V1" + b"x" * 2178 + b"MCPB_SIG_END"
    _corrompre_comme_mcpb_sign(archive, bloc)

    assert _longueur_declaree(archive) == 0
    assert _octets_reels_apres_eocd(archive) == len(bloc)


def test_la_correction_aligne_la_longueur_declaree_sur_le_reel(tmp_path: Path) -> None:
    """Le correctif : deux octets, sans toucher au reste du fichier."""
    archive = _archive_minimale(tmp_path)
    bloc = b"MCPB_SIG_V1" + b"x" * 2178 + b"MCPB_SIG_END"
    _corrompre_comme_mcpb_sign(archive, bloc)

    assert _corriger_eocd(archive) is True

    assert _longueur_declaree(archive) == len(bloc)
    assert _octets_reels_apres_eocd(archive) == len(bloc)


def test_la_correction_ne_touche_pas_au_bloc_de_signature(tmp_path: Path) -> None:
    """Les marqueurs que la CLI recherche par balayage doivent survivre :
    elle ne lit jamais le champ EOCD elle-même."""
    archive = _archive_minimale(tmp_path)
    bloc = b"MCPB_SIG_V1" + b"contenu-pkcs7-simule" + b"MCPB_SIG_END"
    _corrompre_comme_mcpb_sign(archive, bloc)

    _corriger_eocd(archive)

    brut = archive.read_bytes()
    assert brut.endswith(b"MCPB_SIG_END")
    assert b"MCPB_SIG_V1" in brut
    assert b"contenu-pkcs7-simule" in brut


def test_une_archive_deja_correcte_n_est_pas_modifiee(tmp_path: Path) -> None:
    """Rejouer la correction sur un fichier déjà bon ne doit rien changer."""
    archive = _archive_minimale(tmp_path)
    avant = archive.read_bytes()

    assert _corriger_eocd(archive) is True
    assert archive.read_bytes() == avant


def test_l_archive_reste_lisible_par_zipfile_apres_correction(tmp_path: Path) -> None:
    """La correction ne doit pas casser ce que `zipfile` savait déjà lire."""
    archive = _archive_minimale(tmp_path)
    _corrompre_comme_mcpb_sign(archive, b"MCPB_SIG_V1" + b"y" * 100 + b"MCPB_SIG_END")

    _corriger_eocd(archive)

    with zipfile.ZipFile(archive) as z:
        assert z.namelist() == ["manifest.json"]


# --------------------------------------------------------------------------
# Le contrôle strict — celui qui aurait dû attraper le défaut avant l'envoi
# --------------------------------------------------------------------------
def test_le_controle_strict_rejette_le_fichier_non_corrige(tmp_path: Path) -> None:
    """`zipfile.ZipFile()` seul avait laissé passer trois versions cassées :
    ce test vérifie que le contrôle ajouté ne referait pas la même erreur."""
    archive = _archive_minimale(tmp_path)
    _corrompre_comme_mcpb_sign(archive, b"MCPB_SIG_V1" + b"z" * 50 + b"MCPB_SIG_END")

    assert _verifier_zip_strict(archive) is False


def test_le_controle_strict_accepte_le_fichier_corrige(tmp_path: Path) -> None:
    archive = _archive_minimale(tmp_path)
    _corrompre_comme_mcpb_sign(archive, b"MCPB_SIG_V1" + b"z" * 50 + b"MCPB_SIG_END")
    _corriger_eocd(archive)

    assert _verifier_zip_strict(archive) is True


def test_le_controle_strict_accepte_une_archive_jamais_signee(tmp_path: Path) -> None:
    """Le paquet le plus courant : pas de signature du tout."""
    archive = _archive_minimale(tmp_path)

    assert _verifier_zip_strict(archive) is True


def test_signer_deux_fois_de_suite_est_refuse(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`mcpb sign` empile un second bloc sans erreur si on le laisse faire —
    c'est arrivé une fois pendant le développement de ce script, produisant un
    commentaire ZIP de 4378 octets au lieu de 2189. `main()` doit refuser ce
    cas net, avant même d'appeler la CLI.
    """
    import signer as module_signer

    dist = tmp_path / "dist"
    dist.mkdir()
    archive = dist / "argus-secops-1.0.0.mcpb"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("manifest.json", "{}")
    archive.write_bytes(archive.read_bytes() + b"MCPB_SIG_V1" + b"z" * 20 + b"MCPB_SIG_END")
    avant = archive.read_bytes()

    ancien_mcpb = module_signer.MCPB
    module_signer.MCPB = tmp_path
    try:
        code = module_signer.main([])
    finally:
        module_signer.MCPB = ancien_mcpb

    assert code == 1
    assert archive.read_bytes() == avant, "le fichier déjà signé n'a pas dû être modifié"
    assert "déjà une signature" in capsys.readouterr().out


def test_le_paquet_distribue_reellement_est_bien_forme() -> None:
    """Contrôle de non-régression sur l'artefact que la CI publie.

    S'il n'existe pas encore à cet endroit, ce n'est pas un échec : le
    paquet se construit à la demande, ce test n'est concluant qu'après.
    """
    archive = RACINE / "mcpb" / "dist" / "argus-secops-1.0.0.mcpb"
    if not archive.exists():
        pytest.skip("aucun paquet construit — lancer construire.py d'abord")

    assert _verifier_zip_strict(archive) is True


# --------------------------------------------------------------------------
# Le contrôle côté destinataire
# --------------------------------------------------------------------------
def test_verifier_refuse_un_paquet_sans_signature(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Un paquet non signé doit être refusé bruyamment, pas accepté par défaut."""
    from signer import verifier

    archive = _archive_minimale(tmp_path)

    assert verifier(archive) == 1
    assert "AUCUNE signature" in capsys.readouterr().out


def test_verifier_refuse_un_fichier_absent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from signer import verifier

    assert verifier(tmp_path / "nexiste-pas.mcpb") == 1
    assert "introuvable" in capsys.readouterr().out


def test_verifier_rend_l_empreinte_du_paquet_reellement_distribue(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Le seul contrôle qu'un destinataire puisse faire : il n'a que le paquet.

    Une empreinte publiée ne sert à rien si celui qui reçoit le fichier n'a
    aucun moyen de calculer celle de ce qu'il a réellement reçu — et il n'a
    ni la clé privée, ni le certificat.
    """
    from signer import verifier

    archive = RACINE / "mcpb" / "dist" / "argus-secops-1.0.0.mcpb"
    if not archive.exists():
        pytest.skip("aucun paquet construit — lancer construire.py d'abord")
    if b"MCPB_SIG_V1" not in archive.read_bytes():
        pytest.skip("paquet non signé — lancer signer.py d'abord")

    assert verifier(archive) == 0

    sortie = capsys.readouterr().out
    assert "empreinte du certificat porté par l'archive" in sortie
    # Une empreinte SHA-256 en hexadécimal séparé par des deux-points.
    assert re.search(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", sortie), sortie

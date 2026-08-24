"""La terminaison TLS, et ce qu'elle refuse de servir.

Un serveur qui **note** la configuration TLS des autres — c'est ce que fait
`check_tls` dans ce même projet — ne peut pas servir un certificat expiré, ni
négocier TLS 1.0. Ces tests vérifient qu'il s'applique ses propres critères.

Le dernier groupe démarre un **vrai serveur TLS** avec un certificat fabriqué
pour l'occasion, et regarde ce qui est réellement négocié. Une version minimale
déclarée dans le code mais jamais éprouvée par un handshake ne prouve rien.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest

from argus_bundle.http import ConfigurationHttpError, exiger_chiffrement, schema
from argus_bundle.tls import VERSION_MINIMALE, MaterielTlsError, verifier_materiel

RACINE = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# Fabrique de certificats
# --------------------------------------------------------------------------
def _fabriquer(
    dossier: Path, prefixe: str, jours: int = 90, *, san: bool = True
) -> tuple[Path, Path]:
    """Un couple certificat/clé auto-signé, valable `jours` jours."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cle = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "argus-test")])
    maintenant = dt.datetime.now(dt.UTC)

    constructeur = (
        x509.CertificateBuilder()
        .subject_name(nom)
        .issuer_name(nom)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - dt.timedelta(days=abs(jours) + 10))
        .not_valid_after(maintenant + dt.timedelta(days=jours))
    )
    if san:
        constructeur = constructeur.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
    cert = constructeur.sign(cle, hashes.SHA256())

    p_cert = dossier / f"{prefixe}-cert.pem"
    p_cle = dossier / f"{prefixe}-cle.pem"
    p_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    p_cle.write_bytes(
        cle.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return p_cert, p_cle


# --------------------------------------------------------------------------
# Le matériel, contrôlé avant d'ouvrir le port
# --------------------------------------------------------------------------
def test_un_certificat_expire_est_refuse(tmp_path: Path) -> None:
    """Démarrer servirait un service que plus aucun client n'accepte.

    C'est le contrôle que ce projet applique déjà aux hôtes qu'il analyse ; se
    l'épargner à soi-même serait indéfendable.
    """
    cert, cle = _fabriquer(tmp_path, "perime", jours=-5)

    with pytest.raises(MaterielTlsError) as erreur:
        verifier_materiel(cert, cle)

    assert "expiré" in str(erreur.value)


def test_une_cle_qui_ne_correspond_pas_est_refusee(tmp_path: Path) -> None:
    """OpenSSL ne le signalerait qu'au premier handshake, illisiblement."""
    cert, _ = _fabriquer(tmp_path, "a")
    _, autre_cle = _fabriquer(tmp_path, "b")

    with pytest.raises(MaterielTlsError) as erreur:
        verifier_materiel(cert, autre_cle)

    assert "ne correspond pas" in str(erreur.value)


def test_un_fichier_absent_le_dit_clairement(tmp_path: Path) -> None:
    cert, cle = _fabriquer(tmp_path, "bon")

    with pytest.raises(MaterielTlsError) as erreur:
        verifier_materiel(tmp_path / "inexistant.pem", cle)
    assert "introuvable" in str(erreur.value)

    with pytest.raises(MaterielTlsError):
        verifier_materiel(cert, tmp_path / "inexistante.pem")


def test_un_fichier_qui_n_est_pas_un_certificat_le_dit(tmp_path: Path) -> None:
    faux = tmp_path / "faux.pem"
    faux.write_text("ceci n'est pas un certificat", encoding="utf-8")
    _, cle = _fabriquer(tmp_path, "bon")

    with pytest.raises(MaterielTlsError) as erreur:
        verifier_materiel(faux, cle)

    assert "PEM" in str(erreur.value)


def test_un_certificat_valable_est_accepte(tmp_path: Path) -> None:
    cert, cle = _fabriquer(tmp_path, "bon", jours=90)

    info = verifier_materiel(cert, cle)

    assert info.sujet == "argus-test"
    assert info.jours_restants is not None and 85 < info.jours_restants <= 90
    assert "localhost" in info.noms


def test_une_expiration_proche_avertit_sans_bloquer(tmp_path: Path) -> None:
    """Bloquer ici couperait le service ; se taire le laisserait expirer."""
    cert, cle = _fabriquer(tmp_path, "bientot", jours=9)

    info = verifier_materiel(cert, cle)

    assert any("URGENT" in a for a in info.avertissements)


def test_un_certificat_auto_signe_est_signale(tmp_path: Path) -> None:
    cert, cle = _fabriquer(tmp_path, "auto")

    info = verifier_materiel(cert, cle)

    assert info.auto_signe is True
    assert any("auto-signé" in a for a in info.avertissements)


def test_l_absence_de_san_est_signalee(tmp_path: Path) -> None:
    """Les clients modernes refusent un certificat sans SubjectAlternativeName."""
    cert, cle = _fabriquer(tmp_path, "sans-san", san=False)

    info = verifier_materiel(cert, cle)

    assert any("SubjectAlternativeName" in a for a in info.avertissements)


# --------------------------------------------------------------------------
# Le refus de servir en clair
# --------------------------------------------------------------------------
def test_la_boucle_locale_n_exige_pas_de_chiffrement() -> None:
    """Le trafic ne quitte pas la machine : rien à intercepter sur le réseau."""
    exiger_chiffrement("127.0.0.1", tls_local=False, tls_en_amont=False)


@pytest.mark.parametrize("hote", ["0.0.0.0", "192.168.1.10", "argus.interne.example"])  # noqa: S104
def test_servir_en_clair_au_dela_de_la_machine_est_refuse(hote: str) -> None:
    """Le jeton voyage dans un en-tête à chaque requête.

    Sans TLS, quiconque observe le trafic le récupère — et obtient avec lui les
    46 outils, les journaux du tenant et les clés de réputation.
    """
    with pytest.raises(ConfigurationHttpError) as erreur:
        exiger_chiffrement(hote, tls_local=False, tls_en_amont=False)

    message = str(erreur.value)
    assert "--tls-cert" in message
    assert "--tls-en-amont" in message


@pytest.mark.parametrize(
    ("tls_local", "tls_en_amont"),
    [(True, False), (False, True), (True, True)],
)
def test_le_chiffrement_declare_leve_le_refus(tls_local: bool, tls_en_amont: bool) -> None:
    exiger_chiffrement("0.0.0.0", tls_local=tls_local, tls_en_amont=tls_en_amont)  # noqa: S104


@pytest.mark.parametrize(
    ("chiffre", "attendu"), [(True, "https"), (False, "http")]
)
def test_le_schema_suit_le_chiffrement(chiffre: bool, attendu: str) -> None:
    """Annoncer `http://` là où le client parle `https://` fait rejeter des
    requêtes légitimes : le schéma entre dans les origines autorisées."""
    assert schema(chiffre=chiffre) == attendu


# --------------------------------------------------------------------------
# Ce qu'un vrai handshake négocie
# --------------------------------------------------------------------------
def test_le_minimum_declare_exclut_les_versions_obsoletes() -> None:
    assert ssl.TLSVersion.TLSv1_2 <= VERSION_MINIMALE


@pytest.fixture(scope="module")
def serveur_tls(tmp_path_factory: pytest.TempPathFactory) -> object:
    """Un vrai serveur ARGUS en TLS, avec un certificat fabriqué."""
    dossier = tmp_path_factory.mktemp("tls")
    cert, cle = _fabriquer(dossier, "serveur")

    with socket.socket() as prise:
        prise.bind(("127.0.0.1", 0))
        port = int(prise.getsockname()[1])

    jeton = "jeton-tls-de-test-suffisamment-long"
    env = dict(os.environ)
    env["ARGUS_HTTP_TOKEN"] = jeton
    env["PYTHONPATH"] = str(RACINE / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    for c in (
        "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "ENTRA_DATA_SOURCE",
    ):
        env.pop(c, None)

    processus = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "argus_bundle", "--http", "--port", str(port),
         "--tls-cert", str(cert), "--tls-key", str(cle), "--log-level", "WARNING"],
        cwd=RACINE, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )

    for _ in range(120):
        with socket.socket() as prise:
            prise.settimeout(0.5)
            if prise.connect_ex(("127.0.0.1", port)) == 0:
                break
        if processus.poll() is not None:
            sortie = processus.stdout.read() if processus.stdout else ""
            pytest.fail(f"le serveur TLS ne démarre pas :\n{sortie}")
        time.sleep(0.25)
    else:  # pragma: no cover
        processus.terminate()
        pytest.fail("le port TLS n'a jamais été ouvert")

    yield {"port": port, "jeton": jeton}

    processus.terminate()
    try:
        processus.wait(timeout=15)
    except subprocess.TimeoutExpired:  # pragma: no cover
        processus.kill()


def test_le_serveur_negocie_au_moins_tls_1_2(serveur_tls: dict[str, object]) -> None:
    """La preuve par le handshake, pas par la déclaration."""
    contexte = ssl.create_default_context()
    contexte.check_hostname = False
    contexte.verify_mode = ssl.CERT_NONE

    adresse = ("127.0.0.1", int(serveur_tls["port"]))  # type: ignore[call-overload]
    with (
        socket.create_connection(adresse, timeout=20) as brut,
        contexte.wrap_socket(brut) as chiffre,
    ):
        version = chiffre.version()

    assert version in {"TLSv1.2", "TLSv1.3"}


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_un_client_limite_a_tls_1_1_est_refuse(serveur_tls: dict[str, object]) -> None:
    """Le contrôle qui distingue une version minimale réelle d'une intention.

    Python signale l'usage de TLS 1.1 comme déprécié : c'est exactement ce que
    le test met en scène, du côté du client obsolète.
    """
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexte.check_hostname = False
    contexte.verify_mode = ssl.CERT_NONE
    try:
        contexte.maximum_version = ssl.TLSVersion.TLSv1_1
    except ValueError:  # pragma: no cover - OpenSSL compilé sans TLS 1.1
        pytest.skip("cette installation d'OpenSSL ne propose plus TLS 1.1")

    adresse = ("127.0.0.1", int(serveur_tls["port"]))  # type: ignore[call-overload]
    with (
        pytest.raises((ssl.SSLError, OSError)),
        socket.create_connection(adresse, timeout=20) as brut,
        contexte.wrap_socket(brut),
    ):
        pass


def test_les_outils_sont_servis_a_travers_tls(serveur_tls: dict[str, object]) -> None:
    """De bout en bout : TLS, jeton, session MCP, liste d'outils."""
    import httpx

    port = int(serveur_tls["port"])  # type: ignore[call-overload]
    url = f"https://127.0.0.1:{port}/mcp"
    entetes = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Origin": f"https://127.0.0.1:{port}",
        "Authorization": f"Bearer {serveur_tls['jeton']}",
    }
    ouverture_params = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2026-07-28", "capabilities": {},
                   "clientInfo": {"name": "tests", "version": "1"}},
    }

    # Le certificat est auto-signé : la vérification est désactivée côté test,
    # ce qui ne dit rien du chiffrement, éprouvé par les tests ci-dessus.
    with httpx.Client(verify=False, timeout=90) as client:  # noqa: S501
        ouverture = client.post(url, json=ouverture_params, headers=entetes)
        assert ouverture.status_code == 200

        session = ouverture.headers.get("mcp-session-id")
        assert session
        entetes["Mcp-Session-Id"] = session

        client.post(
            url,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=entetes,
        )
        liste = client.post(
            url, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=entetes
        )

    outils: list[dict[str, object]] = []
    for ligne in liste.text.splitlines():
        if ligne.startswith("data: "):
            outils = json.loads(ligne[6:])["result"]["tools"]
            break

    assert len(outils) == 36

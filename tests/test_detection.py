"""Le serveur d'ingénierie de détection : indicateurs, Sigma, couverture ATT&CK.

Aucun test n'accède au réseau — c'est la propriété que ce serveur revendique.
Elle mérite d'être vérifiée plutôt qu'affirmée, puisque c'est elle qui autorise
à lui confier un rapport de menace encore confidentiel.
"""

from __future__ import annotations

import pytest

from detection_mcp import couverture as cv
from detection_mcp import iocs as ioc
from detection_mcp import sigma_rules as sr
from detection_mcp.tools import (
    analyze_sigma_rule,
    check_detection_coverage,
    convert_sigma_rule,
    defang_iocs,
    explain_sigma_rule,
    extract_iocs,
    suggest_detection_for_technique,
)

# --------------------------------------------------------------------------
# Matériel de test
# --------------------------------------------------------------------------
REGLE_COMPLETE = """
title: Enrolement MFA suspect apres connexion anonymisee
id: 3f8b1c2a-0000-4a1b-9c3d-1234567890ab
status: test
description: Detecte l ajout d une methode MFA peu apres une connexion depuis Tor.
author: SOC Teknologiia
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        OperationName: 'User registered security info'
        Result: success
    filter:
        InitiatedBy|contains: 'admin@'
    condition: selection and not filter
falsepositives:
    - Enrolement legitime par l utilisateur
level: high
tags:
    - attack.persistence
    - attack.t1556.006
"""

BROUILLON = """
title: Truc suspect
detection:
    selection:
        EventID: 4624
    condition: selection
"""


# --------------------------------------------------------------------------
# Extraction d'indicateurs — ce qui rend l'exercice difficile
# --------------------------------------------------------------------------
def test_les_indicateurs_desamorces_sont_reconnus() -> None:
    """Un rapport de menace désamorce TOUT pour éviter les clics accidentels.

    Une extraction qui ne remet pas ces formes en état ne rend presque rien du
    document le plus utile qu'un analyste reçoive.
    """
    texte = (
        "Contact avec hxxps://malveillant-cdn[.]com/payload.exe depuis 185.220.101[.]47, "
        "signale par facture(@)compta-secure[.]net."
    )

    trouves = ioc.extraire(texte)

    assert "185.220.101.47" in trouves.ipv4
    assert "malveillant-cdn.com" in trouves.domains
    assert "https://malveillant-cdn.com/payload.exe" in trouves.urls
    assert "facture@compta-secure.net" in trouves.emails


@pytest.mark.parametrize(
    "adresse,motif",
    [
        ("10.0.0.5", "privée"),
        ("192.168.1.50", "privée"),
        ("172.16.4.9", "privée"),
        ("127.0.0.1", "bouclage"),
        ("169.254.1.1", "lien-local"),
    ],
)
def test_une_adresse_interne_n_est_jamais_proposee_comme_indicateur(
    adresse: str, motif: str
) -> None:
    """Contrainte de sécurité du projet, pas simple hygiène.

    Proposer une adresse interne comme indicateur conduit l'analyste à la
    soumettre à un service de réputation — ce qui révèle la topologie du réseau
    à un tiers. Elle doit être écartée AVEC son motif, pas supprimée en silence.
    """
    trouves = ioc.extraire(f"Trafic observe depuis {adresse} vers 8.8.8.8.")

    assert adresse not in trouves.ipv4
    ecarte = {e["value"]: e["reason"] for e in trouves.excluded}
    assert adresse in ecarte
    assert motif in ecarte[adresse]
    # L'adresse publique du même texte, elle, doit bien ressortir.
    assert "8.8.8.8" in trouves.ipv4


def test_un_numero_de_version_n_est_pas_une_adresse() -> None:
    """`2.16.840.1` est un OID, pas une adresse — et ressemble aux deux."""
    trouves = ioc.extraire("Algorithme 2.16.840.1 et version 1.2.3.999 du greffon.")

    assert trouves.ipv4 == []


@pytest.mark.parametrize("nom", ["rapport.doc", "payload.exe", "archive.zip", "script.ps1"])
def test_un_nom_de_fichier_n_est_pas_un_domaine(nom: str) -> None:
    """Sans ce filtre, chaque rapport rend des dizaines de faux domaines."""
    trouves = ioc.extraire(f"La pièce jointe {nom} a été ouverte.")

    assert nom not in trouves.domains


@pytest.mark.parametrize("nom", ["rapport.doc", "payload.exe", "archive.zip"])
def test_un_nom_de_fichier_ecarte_l_est_avec_son_motif(nom: str) -> None:
    """L'analyste doit savoir pourquoi une valeur n'a pas été retenue.

    Ne vaut que pour les extensions purement alphabétiques : `script.ps1` ne
    ressemble à aucun domaine — son extension porte un chiffre — et n'est donc
    jamais candidat.
    """
    trouves = ioc.extraire(f"La pièce jointe {nom} a été ouverte.")

    ecarte = {e["value"]: e["reason"] for e in trouves.excluded}
    assert ecarte.get(nom) == "nom de fichier, pas un domaine"


def test_les_domaines_d_exemple_sont_ecartes() -> None:
    trouves = ioc.extraire("Voir example.com et contoso.com pour la syntaxe.")

    assert trouves.domains == []


@pytest.mark.parametrize(
    "empreinte,algorithme",
    [
        ("5d41402abc4b2a76b9719d911017c592", "md5"),
        ("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "sha1"),
        ("d41d8cd98f00b204e9800998ecf8427ed41d8cd98f00b204e9800998ecf8427e", "sha256"),
    ],
)
def test_l_algorithme_d_une_empreinte_se_deduit_de_sa_longueur(
    empreinte: str, algorithme: str
) -> None:
    trouves = ioc.extraire(f"Empreinte du fichier : {empreinte}")

    assert trouves.hashes == [{"value": empreinte, "algorithm": algorithme}]


def test_une_chaine_hexadecimale_de_longueur_inattendue_n_est_pas_une_empreinte() -> None:
    """Un identifiant de corrélation ressemble à une empreinte sans en être une."""
    trouves = ioc.extraire("Identifiant de trace : " + "a" * 48)

    assert trouves.hashes == []
    assert any("48 caractères" in e["reason"] for e in trouves.excluded)


def test_le_domaine_d_un_courriel_n_est_pas_rendu_deux_fois() -> None:
    trouves = ioc.extraire("Ecrire a soc@teknologiia.com pour signaler.")

    assert trouves.emails == ["soc@teknologiia.com"]
    assert "teknologiia.com" not in trouves.domains


def test_desamorcer_puis_reamorcer_rend_l_original() -> None:
    for original in ("https://mechant.com/x", "1.2.3.4", "a@b.com"):
        assert ioc.refang(ioc.defang(original)) == original


async def test_l_outil_d_extraction_rend_les_exclusions_avec_leur_motif() -> None:
    resultat = await extract_iocs(
        text="Depuis 192.168.1.50 vers 45.83.64.12, exploitant CVE-2021-44228."
    )

    assert resultat.ipv4 == ["45.83.64.12"]
    assert resultat.cves == ["CVE-2021-44228"]
    assert resultat.total == 2
    assert [e.value for e in resultat.excluded] == ["192.168.1.50"]


async def test_le_desamorcage_produit_une_forme_non_cliquable() -> None:
    resultat = await defang_iocs(indicators=["https://mechant.com", "8.8.8.8"])

    assert resultat.defanged == ["hxxps://mechant[.]com", "8[.]8[.]8[.]8"]


# --------------------------------------------------------------------------
# Règles Sigma
# --------------------------------------------------------------------------
async def test_un_brouillon_sans_logsource_est_analyse_quand_meme() -> None:
    """Le défaut constaté au premier essai de ce module.

    pysigma refuse une règle sans `logsource` dès l'analyse — or c'est le
    défaut le plus fréquent d'un brouillon, et celui sur lequel un analyste a le
    plus besoin d'un conseil. Une exception brute ne lui apprend rien.

    La règle doit donc être notée ET déclarée non conforme, pas rejetée.
    """
    analyse = await analyze_sigma_rule(rule=BROUILLON)

    assert analyse.spec_compliant is False
    assert analyse.spec_error is not None
    # L'analyse a tout de même eu lieu : c'est tout l'intérêt.
    assert analyse.title == "Truc suspect"
    assert analyse.fields_used == ["EventID"]
    assert any("logsource" in c for c in analyse.quality.findings)


async def test_une_regle_complete_obtient_la_note_maximale() -> None:
    analyse = await analyze_sigma_rule(rule=REGLE_COMPLETE)

    assert analyse.spec_compliant is True
    assert analyse.quality.grade == "A"
    assert analyse.quality.score == 100
    assert analyse.quality.findings == []


async def test_l_absence_de_faux_positifs_est_signalee() -> None:
    """Une règle qui n'annonce pas son bruit est désactivée au premier jour chargé."""
    sans_fp = REGLE_COMPLETE.replace(
        "falsepositives:\n    - Enrolement legitime par l utilisateur\n", ""
    )

    analyse = await analyze_sigma_rule(rule=sans_fp)

    assert analyse.quality.score < 100
    assert any("faux positif" in c for c in analyse.quality.findings)


def test_un_champ_avec_modificateur_est_lu_sans_son_modificateur() -> None:
    """`InitiatedBy|contains` désigne le champ `InitiatedBy`."""
    analyse = sr.analyser(REGLE_COMPLETE)

    assert "InitiatedBy" in analyse.fields_used
    assert not any("|" in c for c in analyse.fields_used)


def test_une_regle_reposant_sur_un_seul_champ_repandu_est_penalisee() -> None:
    large = """
title: Toutes les connexions
id: 11111111-2222-3333-4444-555555555555
status: test
description: Une regle qui se declenche sur chaque connexion reussie du parc.
author: Test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
falsepositives:
    - Toute connexion normale
level: low
tags:
    - attack.t1078
"""
    analyse = sr.analyser(large)
    qualite = sr.evaluer_qualite(analyse)

    assert any("répandus" in c for c in qualite.findings)
    # Malgré des métadonnées complètes, la règle ne peut pas obtenir un A.
    assert qualite.grade != "A"


# --------------------------------------------------------------------------
# Rattachement à ATT&CK — le contrôle qui a le plus de valeur
# --------------------------------------------------------------------------
async def test_une_etiquette_attack_revoquee_est_signalee() -> None:
    """Le défaut silencieux qui motive tout ce module.

    ATT&CK révoque des techniques à chaque version majeure. Une règle étiquetée
    d'un identifiant mort fonctionne parfaitement — mais ne compte dans aucune
    revue de couverture, et rien ne le signale. C'est exactement le défaut qui
    avait été trouvé dans la table de correspondance de ce projet.
    """
    perimee = REGLE_COMPLETE.replace("attack.t1556.006", "attack.t1562.001")

    analyse = await analyze_sigma_rule(rule=perimee)

    revoquees = [t for t in analyse.attack if t.status == "revoquee"]
    assert len(revoquees) == 1
    assert revoquees[0].id == "T1562.001"
    # Dire « révoquée » sans dire par quoi la remplacer ne sert à rien.
    assert revoquees[0].replaced_by == "T1685"
    assert any("RÉVOQUÉE" in c for c in analyse.attack_findings)


async def test_une_etiquette_attack_inexistante_est_signalee() -> None:
    faute = REGLE_COMPLETE.replace("attack.t1556.006", "attack.t9999")

    analyse = await analyze_sigma_rule(rule=faute)

    assert [t.status for t in analyse.attack] == ["inconnue"]
    assert any("aucune technique connue" in c for c in analyse.attack_findings)


def test_une_technique_incoherente_avec_la_source_est_signalee() -> None:
    """Une règle sur des journaux Azure étiquetée d'une technique Windows.

    Elle ne détectera jamais ce qu'elle annonce, et aucune validation
    syntaxique ne peut le voir.
    """
    liens = cv.lier(["T1543.003"], {"product": "azure", "service": "auditlogs"})

    assert liens.techniques[0].platforms == ["Windows"]
    assert any("autre type" in c for c in liens.findings)


def test_une_technique_coherente_ne_declenche_aucune_alerte() -> None:
    """Un garde-fou trop large signalerait des règles parfaitement correctes."""
    liens = cv.lier(["T1556.006"], {"product": "azure", "service": "auditlogs"})

    assert liens.findings == []
    assert liens.valides == 1


def test_une_logsource_inconnue_ne_produit_aucune_incoherence() -> None:
    """La table des plateformes est partielle : deviner produirait de fausses alertes."""
    liens = cv.lier(["T1543.003"], {"product": "un_produit_inconnu"})

    assert liens.findings == []


def test_la_guidance_attack_accompagne_chaque_technique() -> None:
    """C'est ce qui permet de juger si la règle couvre vraiment ce qu'elle annonce."""
    liens = cv.lier(["T1556.006"])

    assert liens.techniques[0].detection_guidance


# --------------------------------------------------------------------------
# Conversion
# --------------------------------------------------------------------------
@pytest.mark.parametrize("cible", ["kusto", "splunk", "lucene"])
async def test_la_conversion_produit_une_requete_pour_chaque_cible(cible: str) -> None:
    resultat = await convert_sigma_rule(rule=REGLE_COMPLETE, target=cible)

    assert resultat.target == cible
    assert len(resultat.queries) == 1
    # Le champ de la règle doit se retrouver dans la requête produite.
    assert "OperationName" in resultat.queries[0]


async def test_une_cible_inconnue_est_refusee_avec_les_valeurs_possibles() -> None:
    with pytest.raises(sr.SigmaError) as erreur:
        await convert_sigma_rule(rule=REGLE_COMPLETE, target="sentinel")

    assert "kusto" in str(erreur.value)


# --------------------------------------------------------------------------
# Explication
# --------------------------------------------------------------------------
async def test_la_regle_est_expliquee_sans_yaml() -> None:
    """Destiné à celui qui approuve la règle sans lire le YAML."""
    explication = await explain_sigma_rule(rule=REGLE_COMPLETE)

    assert explication.title.startswith("Enrolement MFA")
    joint = " ".join(explication.triggers_when)
    assert "OperationName" in joint
    assert "contient" in joint  # le modificateur |contains, en français
    assert "auditlogs" in explication.log_requirement
    assert explication.expected_noise == ["Enrolement legitime par l utilisateur"]
    assert any("T1556.006" in c for c in explication.attack_context)


async def test_l_explication_d_un_brouillon_dit_ce_qui_manque() -> None:
    explication = await explain_sigma_rule(rule=BROUILLON)

    assert "Aucune source de journal" in explication.log_requirement
    assert "inconnu" in explication.expected_noise[0]


# --------------------------------------------------------------------------
# Couverture d'un jeu de règles
# --------------------------------------------------------------------------
async def test_les_tactiques_non_couvertes_sont_rendues() -> None:
    """C'est l'information utile : la liste de ce qui est couvert n'apprend rien."""
    rapport = await check_detection_coverage(rules=[REGLE_COMPLETE])

    assert rapport.rules_analyzed == 1
    assert "T1556.006" in rapport.techniques_covered
    assert "persistence" in [e.tactic for e in rapport.tactics]
    assert "exfiltration" in rapport.uncovered_tactics
    assert "impact" in rapport.uncovered_tactics


async def test_une_regle_illisible_est_comptee_et_non_ignoree() -> None:
    """Un jeu dont un tiers ne s'analyse pas donnerait une couverture faussement bonne."""
    rapport = await check_detection_coverage(
        rules=[REGLE_COMPLETE, "ceci: n'est pas: une regle: valide: du tout"]
    )

    assert rapport.rules_analyzed == 1
    assert rapport.rules_rejected == 1
    assert any("illisible" in c for c in rapport.findings)


async def test_une_regle_sans_etiquette_attack_est_signalee_dans_la_couverture() -> None:
    rapport = await check_detection_coverage(rules=[BROUILLON])

    assert rapport.rules_analyzed == 1
    assert rapport.techniques_covered == []
    assert any("aucune étiquette ATT&CK" in c for c in rapport.findings)


# --------------------------------------------------------------------------
# Aide à la rédaction
# --------------------------------------------------------------------------
async def test_le_squelette_propose_porte_les_bonnes_etiquettes() -> None:
    conseil = await suggest_detection_for_technique(technique_id="T1556.006", product="azure")

    assert conseil.technique_id == "T1556.006"
    assert "attack.t1556.006" in conseil.sigma_skeleton
    assert "À COMPLÉTER" in conseil.sigma_skeleton
    assert conseil.detection_guidance


async def test_le_squelette_signale_une_plateforme_incoherente() -> None:
    conseil = await suggest_detection_for_technique(technique_id="T1543.003", product="azure")

    assert any("pas la bonne source" in n for n in conseil.notes)


async def test_une_technique_revoquee_renvoie_sa_remplacante() -> None:
    """Répondre « inconnue » ferait conclure à une faute de frappe."""
    with pytest.raises(ValueError) as erreur:
        await suggest_detection_for_technique(technique_id="T1562.001")

    assert "T1685" in str(erreur.value)


# --------------------------------------------------------------------------
# Composition du serveur
# --------------------------------------------------------------------------
async def test_le_serveur_expose_les_sept_outils() -> None:
    from detection_mcp.server import build_server

    outils = await build_server().list_tools()

    assert len(outils) == 7
    noms = {t.name for t in outils}
    assert "extract_iocs" in noms
    assert "analyze_sigma_rule" in noms
    assert "check_detection_coverage" in noms


async def test_aucun_outil_ne_declare_toucher_au_reseau() -> None:
    """La propriété que ce serveur revendique, vérifiée sur ses annotations."""
    from detection_mcp.server import build_server

    for outil in await build_server().list_tools():
        assert outil.annotations is not None
        assert outil.annotations.read_only_hint is True
        assert outil.annotations.open_world_hint is False


async def test_une_etiquette_revoquee_retire_le_credit_attack() -> None:
    """Un voyant vert ne doit pas masquer une étiquette morte.

    Le barème accorde des points à une règle « rattachée à ATT&CK ». Ce crédit
    n'a qu'une raison d'être : compter dans une revue de couverture. Une
    technique révoquée n'y compte pas — sans cet ajustement, la règle affichait
    A (100/100), constat rendu à côté mais note maximale invitant à ne pas le
    lire.
    """
    perimee = REGLE_COMPLETE.replace("attack.t1556.006", "attack.t1562.001")

    saine = await analyze_sigma_rule(rule=REGLE_COMPLETE)
    atteinte = await analyze_sigma_rule(rule=perimee)

    assert saine.quality.score == 100
    assert atteinte.quality.score == 85
    assert atteinte.quality.grade == "B"
    assert atteinte.quality.findings[0].startswith("Les étiquettes ATT&CK")
    assert not any(s.startswith("Rattachée à ATT&CK") for s in atteinte.quality.strengths)

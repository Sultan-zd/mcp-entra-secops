# ARGUS — Plateforme SecOps agentique

[![CI](https://github.com/Sultan-zd/mcp-entra-secops/actions/workflows/ci.yml/badge.svg)](https://github.com/Sultan-zd/mcp-entra-secops/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![MCP](https://img.shields.io/badge/MCP-2026--07--28-brightgreen)
![Licence](https://img.shields.io/badge/licence-MIT-lightgrey)

**Une extension `.mcpb` à installer d'un double-clic**, qui donne à votre
modèle IA 57 outils de sécurité en lecture seule. Un analyste pose sa question
en français ; le modèle choisit les outils et rend une réponse fondée sur des
données réelles.

Bâtie sur [MCP](https://modelcontextprotocol.io) — donc utilisable dans Claude
Desktop, Cursor, ou tout autre client compatible.

**[→ Installation](#installation)**

| Serveur | Domaine | Outils |
|---|---|---|
| `entra-secops-mcp` | Identité — journaux Microsoft Entra ID | 6 |
| `threat-intel-mcp` | Renseignement — VirusTotal, AbuseIPDB, GreyNoise | 4 |
| `email-security-mcp` | Messagerie — SPF, DKIM, DMARC, en-têtes | 5 |
| `vuln-intel-mcp` | **Vulnérabilités** — NVD, CISA KEV, EPSS, CWE · *sans clé* | 11 |
| `mitre-attack-mcp` | **MITRE ATT&CK** — corpus embarqué, D3FEND · *hors ligne* | 10 |
| `detection-mcp` | **Détection** — indicateurs, Sigma, YARA, événements Windows/Sysmon, ReDoS · *hors ligne* | 11 |
| `artefact-mcp` | **Artefacts** — jetons JWT, décodage en cascade · *hors ligne* | 2 |
| `web-recon-mcp` | **Web & TLS** — TLS, DNS, RDAP/ASN, transparence · *sans clé* | 8 |
| `argus-agent` | **Orchestration** — enchaîne les domaines | — |
| `argus-eval` | **Évaluation** — 25 incidents de référence, seuils bloquants | — |

**57 outils.** Quarante-sept ne demandent **aucune clé d'API** : NVD, le catalogue
CISA et EPSS sont publics, le corpus ATT&CK est embarqué, l'analyse des règles
Sigma est purement locale, et l'inspection TLS ouvre sa propre connexion.

**Vingt-quatre ne touchent pas au réseau du tout** — les dix outils MITRE
(ATT&CK et D3FEND), les onze de détection (Sigma, YARA, événements Windows/
Sysmon, ReDoS), les deux d'analyse d'artefacts, et le calcul CVSS. Un rapport
de menace confidentiel, un jeton, une règle en cours d'écriture : rien de tout
cela ne quitte le poste.

L'inspection TLS, DNS et en-têtes vise l'hôte **directement** plutôt que de
passer par un service tiers : elle fonctionne donc aussi sur un hôte **interne**
qu'aucun service en ligne ne pourrait atteindre.

Objectif : permettre à un analyste de poser une question en langage naturel
— *« pourquoi ce compte n'arrive-t-il plus à se connecter ? »* — et d'obtenir en
quelques secondes une réponse fondée sur les données réelles du tenant.

| Document | Pour qui |
|---|---|
| 📦 **[INSTALLER.md](docs/INSTALLER.md)** | l'analyste qui reçoit l'extension, et qui la distribue |
| 🎓 **[COMPRENDRE.md](docs/COMPRENDRE.md)** | tout le projet expliqué depuis zéro, sans prérequis |
| 🔧 **[SETUP.md](docs/SETUP.md)** | qui modifie le code, lance les tests, construit l'extension |
| 🔑 **[ENTRA.md](docs/ENTRA.md)** | qui branche ARGUS sur un vrai tenant : permissions au plus juste, licences, validation |
| 🔍 **[RESEARCH.md](docs/RESEARCH.md)** | scan du marché et choix d'exposition sécurisée |

## Installation

ARGUS se distribue comme **une extension `.mcpb`** : un fichier, un
double-clic, aucune ligne de commande.

### Pour un analyste

1. Installer [`uv`](https://docs.astral.sh/uv/) une fois — c'est ce qui
   installera les dépendances Python à la première utilisation :

   ```bash
   # Windows (PowerShell)
   powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

   # macOS / Linux
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. Récupérer `argus-secops-1.0.0.mcpb` — depuis les *Releases* du dépôt, ou
   depuis les artefacts de la dernière exécution réussie de la CI.

3. **Double-cliquer sur le fichier.** Claude Desktop propose l'installation.

4. Ne rien remplir. Les six champs proposés sont **tous facultatifs** :
   sans aucune clé, **47 outils fonctionnent immédiatement**.

> L'extension est **signée**, mais par un certificat auto-signé : l'hôte
> affiche tout de même un avertissement à l'installation. C'est attendu pour une
> distribution interne — voir [`mcpb/README.md`](mcpb/README.md#signature).

### Ce qu'on peut lui demander, en français

Une fois installée, on parle au modèle normalement. Il choisit les outils.

| Question | Ce qu'ARGUS fait |
|---|---|
| *« Par quoi je commence sur ces 40 CVE ? »* | Croise CVSS, catalogue CISA KEV et probabilité EPSS, rend un ordre par paliers |
| *« Ce domaine est-il correctement exposé ? »* | TLS, en-têtes, hygiène DNS et sous-domaines, en une note |
| *« Que retenir de ce rapport de menace ? »* | Extrait adresses, domaines, empreintes et CVE — même désamorcés |
| *« Cette règle Sigma est-elle bonne ? »* | Qualité, conformité, étiquettes ATT&CK encore valides |
| *« Où sont nos angles morts de détection ? »* | Tactiques ATT&CK qu'aucune règle ne couvre |
| *« Ce domaine peut-il être usurpé ? »* | SPF, DKIM, DMARC, avec le compteur des 10 résolutions |

Les dix outils restants s'activent en renseignant une clé VirusTotal, AbuseIPDB
ou un tenant Entra — dans les mêmes champs, à tout moment.

### Pour construire l'extension soi-même

```bash
python mcpb/outils/construire.py
```

Une commande : synchronise le code, génère le manifeste, empaquette, **puis
dépaquette ailleurs et exécute le résultat**. Voir
[`mcpb/README.md`](mcpb/README.md).

---

## Partager une instance : le transport HTTP

L'extension `.mcpb` couvre un analyste sur sa machine. Pour **partager une
instance** entre plusieurs analystes, ou servir un client qui ne sait pas
lancer de processus local, ARGUS parle aussi **Streamable HTTP**.

```bash
pip install -e .
export ARGUS_HTTP_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
argus-mcp --http                      # http://127.0.0.1:8000/mcp
```

> Streamable HTTP, **jamais SSE** : la révision `2026-07-28` de la spécification
> classe HTTP+SSE comme déprécié, donc supprimable. Voir
> [`docs/RESEARCH.md`](docs/RESEARCH.md#partie-b--exposition-sécurisée).

### Trois protections, dont deux impossibles à oublier

| | |
|---|---|
| **Boucle locale par défaut** | `--host` vaut `127.0.0.1` ; rien n'est exposé sans un geste explicite |
| **Validation de `Origin`** | contre le rebinding DNS — une page web visitée par l'analyste ne peut pas piloter son serveur. Jamais désactivable |
| **Jeton obligatoire au-delà** | le serveur **refuse de démarrer** sur une autre interface sans `ARGUS_HTTP_TOKEN` |

Le troisième point est le seul qui compte vraiment : la commande dangereuse —
`--host 0.0.0.0` — est plus courte à taper que la commande sûre, et l'oubli
n'est pas rattrapable une fois le port ouvert.

```
$ argus-mcp --http --host 0.0.0.0
  ✗ Refus de démarrer : l'écoute sur « 0.0.0.0 » exposerait 47 outils de
    sécurité sans authentification.
    Définissez ARGUS_HTTP_TOKEN (au moins 16 caractères), ou gardez
    l'écoute sur 127.0.0.1.
```

### TLS : ici, ou en amont — mais pas en clair

Au-delà de la boucle locale, le serveur **refuse de servir en clair**. Le jeton
voyage dans un en-tête `Authorization` à chaque requête : sans chiffrement,
quiconque observe le trafic le récupère, et obtient avec lui les 47 outils et
les journaux du tenant.

```
$ argus-mcp --http --host 0.0.0.0        # avec un jeton pourtant valide
  ✗ Refus de servir en clair sur « 0.0.0.0 » : le jeton d'authentification
    circulerait en clair à chaque requête.
    Trois issues :
      --tls-cert / --tls-key   terminer TLS ici même
      --tls-en-amont           un proxy inverse s'en charge déjà
      --host 127.0.0.1         ne pas sortir de la machine
```

**Derrière un proxy inverse** — le déploiement recommandé, parce qu'il
renouvelle les certificats par ACME et se met à jour indépendamment :

```bash
argus-mcp --http --host 127.0.0.1 --tls-en-amont
```

**Terminaison directe**, quand aucun proxy n'est disponible — sur un réseau
interne, avec un certificat d'autorité interne :

```bash
argus-mcp --http --host 0.0.0.0 --tls-cert cert.pem --tls-key cle.pem
```

Le couple est **vérifié avant l'ouverture du port**, jamais au premier
handshake — où l'erreur d'OpenSSL est illisible et ne dit pas laquelle des deux
moitiés est en cause :

| Contrôle | Conséquence |
|---|---|
| Certificat expiré | **refus** — servir un certificat périmé, c'est servir un service que personne ne joint |
| Clé ne correspondant pas au certificat | **refus**, avec le nom des deux fichiers |
| Expiration proche | avertissement, aux seuils qu'applique déjà `check_tls` aux autres |
| Auto-signé, ou sans `SubjectAlternativeName` | avertissement |

TLS 1.2 est le **minimum imposé explicitement**, pas hérité d'un défaut de
bibliothèque — un serveur qui note la configuration TLS des autres ne peut pas
négocier TLS 1.0. Un test le vérifie par un vrai handshake : un client limité à
TLS 1.1 est refusé.

### Ce que ce n'est pas

Ce n'est **pas** un déploiement OAuth 2.1 complet : le jeton est un secret
partagé, comparé à temps constant. La cible reste la validation du jeton par
l'IdP de l'entreprise.

La forme est déjà celle d'un **serveur de ressource** — le `401` porte un
`WWW-Authenticate` conforme, pointant vers les métadonnées RFC 9728. La
migration remplacera le vérificateur de jeton, sans toucher au reste.

---

## Le serveur d'identité Entra ID


Une réponse brute de Microsoft Graph contient une soixantaine de champs par
événement. Le serveur applique une **troncature agressive** : seuls une douzaine
d'indicateurs de sécurité atteignent le modèle. C'est à la fois une optimisation
de coût (facteur ~35 sur les tokens) et un contrôle de sécurité, puisque les
champs non listés — dont certains sont contrôlés par un attaquant — n'entrent
jamais dans le contexte.

Les agrégats (nombre d'échecs, IP distinctes, motifs suspects) sont **calculés en
Python**, pas déduits par le modèle.

### Outils

| Outil | Objet | Permission Graph | Licence |
|---|---|---|---|
| `get_user_context` | Fiche du compte : poste, groupes, rôles détenus. Détermine la **gravité** d'un incident. | `Directory.Read.All` | — |
| `get_user_signins` | Connexions récentes d'un UPN, avec synthèse et motifs suspects | `AuditLog.Read.All` | P1 |
| `get_risky_users` | Comptes signalés à risque par Identity Protection | `IdentityRiskyUser.Read.All` | P2 |
| `get_risk_detections` | Détections unitaires : **pourquoi** un compte est à risque | `IdentityRiskEvent.Read.All` | P2 |
| `get_directory_audits` | Modifications administratives ; signale les gestes de persistance | `AuditLog.Read.All` | — |
| `get_conditional_access_policies` | Politiques actives et failles de couverture | `Policy.Read.All` | — |

Tous les outils sont en **lecture seule** : le serveur ne modifie jamais le tenant.

### Ordre d'investigation conseillé

```
get_user_context     le compte est-il privilégié ? l'incident est-il grave ?
      ↓
get_user_signins     que s'est-il passé sur l'authentification ?
      ↓
get_risk_detections  qu'a détecté Identity Protection, et pourquoi ?
      ↓
get_directory_audits l'attaquant a-t-il modifié quelque chose une fois entré ?
```

Cet enchaînement est aussi décrit dans les `instructions` du serveur, que le
client MCP transmet au modèle.

### Démarrage rapide (sans tenant Azure)

Le mode `fixture` rejoue un incident de démonstration et ne nécessite ni tenant,
ni licence, ni secret.

```bash
python -m venv venv
venv/Scripts/activate          # Windows ; sur Linux/macOS : source venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env           # ENTRA_DATA_SOURCE=fixture est déjà la valeur par défaut
python -m entra_secops_mcp
```

### Connexion à un vrai tenant

1. Créer une **App Registration** dans le portail Entra.
2. Ajouter les permissions **applicatives** du tableau ci-dessus, puis accorder
   le consentement administrateur.
3. Générer un secret client.
4. Renseigner `.env` :

```dotenv
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
ENTRA_DATA_SOURCE=graph
```

5. Vérifier la connexion, les permissions et les licences :

```bash
python -m entra_secops_mcp --check
```

Le diagnostic lit les permissions **réellement consenties** dans le jeton, puis
appelle chaque endpoint. Il distingue une permission oubliée d'un consentement
administrateur non accordé — deux erreurs qui produisent le même `403`. Aucun
secret n'apparaît dans sa sortie.

> **Licence requise.** L'accès aux journaux de connexion via l'API exige une
> licence Entra ID **P1**, et les outils Identity Protection exigent **P2**.
> Sans elles, Graph répond `403`. Les autres outils fonctionnent sans licence
> payante. Vérifiez la licence du tenant **avant** de commencer : c'est le
> blocage classique qui fait perdre plusieurs jours.


---

## Serveur de renseignement sur les menaces

```bash
threat-intel-mcp --check      # vérifie sources, quotas et chemin complet
```

Quatre outils : `enrich_ip`, `enrich_domain`, `enrich_file_hash`, `bulk_enrich`.

### Ce n'est pas un relais d'API

Un relais transmet une question et rend une réponse. Ce serveur ajoute six
mécanismes qui changent la nature de l'outil :

| Mécanisme | Pourquoi |
|---|---|
| **Fusion déterministe** | Trois sources, trois échelles incomparables. La décision est prise par du code testé, jamais par le prompt : aucun texte injecté ne peut renverser un score. |
| **Adresses internes jamais transmises** | Soumettre `10.0.0.5` à un service tiers divulgue la topologie du réseau, de façon irréversible. Le court-circuit précède tout appel réseau. |
| **Cache 24 h** | Les mêmes IP reviennent sans cesse dans une enquête. Sans cache, le quota gratuit VirusTotal (~4 req/min) est épuisé au milieu de la première investigation. |
| **Limitation de débit** | Dépasser le quota ne ralentit pas : l'API renvoie des 429 qui consomment quand même le quota journalier. |
| **Dégradation gracieuse** | Une source en panne ne fait jamais échouer l'enquête. Le verdict est produit avec les sources restantes, et l'indisponibilité est signalée. |
| **Suppression du bruit** | Un scanner de recherche référencé (Shodan, Censys) ou un service courant (DNS public) n'est jamais signalé. Sans cette règle, l'équipe cesse de lire l'outil. |

### Le verdict, en un coup d'œil

| Champ | Sens |
|---|---|
| `verdict` | `malicious`, `suspicious`, `benign`, `unknown`, `internal` |
| `score` | 0 à 100, consolidé — **le maximum** des sources, jamais la moyenne |
| `confidence` | Relative aux sources **capables** de traiter l'indicateur, pas à un décompte brut |
| `sources` | Détail par source, **pannes comprises** |

> `unknown` signifie « aucune source ne le connaît ». **Ce n'est pas un verdict
> d'innocuité**, et le serveur le dit explicitement.

### Vérifié sur les API réelles

Le serveur a été exécuté contre VirusTotal et AbuseIPDB, sans clé GreyNoise :

```
185.220.101.47  malicious 100  confiance medium
  virustotal   16/91 moteurs signalent une menace, 2 la jugent suspecte
  abuseipdb    100/100 sur 112 signalements
  greynoise    not_configured — aucune clé d'API
```

La dégradation gracieuse se lit directement : le verdict est produit avec
deux sources, l'absence de la troisième est signalée, et la confiance passe
honnêtement de `high` à `medium`.

### Sans clé d'API

`TI_DATA_SOURCE=fixture` rejoue un scénario cohérent avec celui du serveur
d'identité : l'adresse `185.220.101.47` de l'incident Entra y est un nœud de
sortie Tor. Les deux serveurs racontent la même histoire.

---

## Serveur de sécurité de la messagerie

```bash
email-security-mcp --check teknologiia.com
```

Cinq outils : `check_domain_posture`, `check_spf`, `check_dkim`, `check_dmarc`,
`analyze_email_headers`. **Aucune clé d'API** : tout est publié dans le DNS.

### Le comptage des résolutions DNS de SPF

La RFC 7208 plafonne à **10** le nombre de résolutions DNS qu'une évaluation SPF
peut déclencher. Au-delà, elle renvoie `permerror` et **SPF cesse de protéger le
domaine** — alors que l'enregistrement paraît parfaitement correct dans le
portail DNS.

C'est la panne la plus fréquente et la plus silencieuse du domaine : une
organisation ajoute Microsoft 365, puis un outil d'emailing, puis un CRM, chacun
avec son `include:`, et franchit la limite sans aucun signal.

Vérifié sur des domaines réels :

```
microsoft.com   note A (92/100)   SPF  7/10 lookups   DMARC reject
github.com      note C (60/100)   SPF 10/10 lookups   DMARC quarantine
```

`github.com` est **exactement à la limite** : 8 `include:` de premier niveau
plus 2 imbriqués. L'ajout d'un seul prestataire d'envoi ferait basculer son SPF
en `permerror`.

### Les trois pièges signalés explicitement

| Piège | Pourquoi c'est trompeur |
|---|---|
| SPF au-delà de 10 résolutions | L'enregistrement paraît correct, il ne protège plus |
| DMARC `p=none` | Mode d'observation : rien n'est bloqué |
| DMARC `pct=20` | La politique la plus stricte, appliquée à 20 % du trafic |
| DKIM `t=y` | Demande aux destinataires d'**ignorer** les échecs |

### Analyse d'en-têtes : l'alignement

SPF valide le `Return-Path:` (l'enveloppe), **pas le `From:`** affiché à
l'utilisateur. Un attaquant met l'adresse de sa cible dans `From:` et la sienne
dans `Return-Path:` : SPF passe, et le message paraît authentique.

```
verdict     spoofed | gravité high
DÉSALIGNEMENT : l'adresse affichée est en « teknologiia.com » mais l'enveloppe
d'envoi est en « envoi-malveillant.xyz ». SPF valide l'enveloppe, pas l'adresse
affichée : un `spf=pass` ne prouve donc RIEN sur l'expéditeur visible.

indicateurs à enrichir : ['185.220.101.47', 'envoi-malveillant.xyz']
```

Le champ `indicators` alimente directement `bulk_enrich` du serveur de
renseignement : les trois serveurs s'enchaînent.

---

## Le serveur de renseignement sur les vulnérabilités

```bash
vuln-intel-mcp --check        # vérifie les trois sources publiques
```

Neuf outils, **aucune clé d'API**. Trois sources qui ne disent pas la même
chose, et dont le croisement fait toute la valeur :

| Source | Ce qu'elle répond |
|---|---|
| **NVD** | Ce qu'est la faille, et sa gravité *théorique* |
| **CISA KEV** | Si elle est *réellement* exploitée, avec une échéance imposée |
| **EPSS** | La probabilité qu'elle le soit dans les trente jours |

### La note CVSS est recalculée, pas relayée

`parse_cvss` implémente la formule de la norme et **ne fait aucun appel
réseau**. Ça sert à trois choses : lire un vecteur en français, vérifier qu'une
note annoncée correspond à son vecteur, et simuler une variante sans redemander
quoi que ce soit.

L'implémentation est confrontée à **138 vecteurs réels du NVD** avec leur note
officielle, hors ligne, à chaque exécution de la suite. Zéro écart.

> Deux pièges que le test a permis de voir. La norme impose un **arrondi
> supérieur** que `round()` ne reproduit pas — l'écart vaut une classe de
> sévérité. Et les privilèges requis pèsent **différemment selon que le
> périmètre change** : un barème unique sous-évaluerait précisément les failles
> les plus graves.

### `prioritize_cves` — l'outil qui répond à la vraie question

« Mon scan rend quarante CVE, par quoi je commence ? » Une note CVSS seule ne
répond pas.

```
 1. CVE-2021-44228   immediate   KEV   CVSS 10.0   EPSS 100.0%
 2. CVE-2021-3156    immediate   KEV   CVSS  7.8   EPSS  99.3%
 …
 5. CVE-2016-2183    urgent            CVSS  7.5   EPSS  95.7%
 6. CVE-2024-3094    urgent            CVSS 10.0   EPSS  86.0%
 8. CVE-2022-40674   planifie          CVSS  8.1   EPSS   1.8%
```

Relevé réel. Notez le rang 5 devant le rang 6 : **SWEET32, notée 7.5, passe
devant la porte dérobée xz notée 10.0**, parce qu'elle est bien plus exploitée.
Un tri par CVSS aurait fait l'inverse.

Le classement est **déterministe et par paliers**, pas par score mélangé — un
palier se défend devant un responsable (« la CISA impose le 3 septembre »), un
nombre composite de 73,4 ne se défend pas. Chaque rang porte sa justification.

### Un défaut que seule la vérification pouvait révéler

Le NVD publie **plusieurs notes CVSS pour une même CVE**. Pour Zerologon
(`CVE-2020-1472`), Microsoft annonce **5.5** et le NIST **10.0**. Mon code
prenait la première venue : la faille passait de `critical` à `medium`.

Corrigé — la notation primaire prime, et un écart de deux points ou plus entre
sources est désormais **signalé à l'analyste** plutôt que masqué par le choix
silencieux de l'une d'elles.

### Ce que le serveur refuse de faire

- **Inventer une note v4.0.** La notation CVSS v4.0 repose sur une table de
  plusieurs centaines d'entrées, pas sur une formule. Plutôt qu'une
  approximation qui donnerait des chiffres faux avec l'assurance d'un calcul,
  le vecteur est décodé et `computed_locally` vaut `false`.
- **Confondre « inconnu » et « sans danger ».** Une CVE sans note ni
  probabilité tombe dans le palier `indetermine`, qui remonte **avant**
  `planifie` — un cas non qualifié doit être vu, pas enterré.
- **Servir des données périmées en silence.** Si le catalogue CISA n'a pas pu
  être rafraîchi, la version précédente est servie — et `catalog_stale` le dit.

### `lookup_cwe` — un identifiant seul ne dit pas ce qu'il faut tester

`lookup_cve` rend déjà les CWE cités par NVD, sous forme de simples chaînes.
`lookup_cwe` les développe — et vérifie une chose qu'aucune fiche NVD ne
vérifie elle-même : MITRE classe chaque CWE selon son **aptitude à désigner
une vulnérabilité précise** (`Allowed`, `Discouraged`, `Prohibited`). Un CWE
`Prohibited` cité sur une CVE réelle est un défaut de la fiche NVD, pas
seulement une information de plus — le même principe que les techniques ATT&CK
révoquées.

```
CWE-1041 — Use of Redundant Code
  ! MITRE classe ce CWE « Prohibited » pour l'assignation à une vulnérabilité
    précise : ce point est avant tout un problème de qualité, sans implication
    directe de sécurité.
```

Entièrement local : le catalogue CWE (969 entrées) est embarqué.

---

## Le serveur MITRE ATT&CK

```bash
mitre-attack-mcp --check      # vérifie le corpus embarqué
```

Neuf outils, **zéro appel réseau**. Le corpus officiel pèse 51 Mo et change
quatre fois par an ; il est distillé à 1,8 Mo et versionné avec le code
(`scripts/distiller_attack.py`).

C'est un compromis assumé, et il paie : le serveur répond en quelques
millisecondes, fonctionne sur un poste sans Internet, et ses réponses ne varient
pas d'un appel à l'autre.

### `map_findings_to_attack` — le point de jonction

C'est l'outil qui relie ce qu'ARGUS observe au vocabulaire des rapports
d'incident. On lui passe les constats bruts des autres serveurs :

```
leakedCredentials                    → T1589.001  Credentials          [high]
                                     → T1078.004  Cloud Accounts       [high]
anonymizedIPAddress                  → T1090.003  Multi-hop Proxy      [high]
succes_apres_echecs                  → T1110      Brute Force          [high]
protocole_herite                     → T1556      Modify Auth Process  [medium]
user registered security info        → T1556.006  Multi-Factor Auth    [high]
add member to role                   → T1098.003  Additional Cloud Roles
certificates and secrets management  → T1098.001  Additional Cloud Credentials
```

> « L'attaquant a atteint des étapes tardives de la chaîne (persistence,
> privilege-escalation) : une simple réinitialisation de mot de passe ne
> suffira pas. »

La table est **écrite à la main**, pas déduite par similarité. Un identifiant
ATT&CK finit dans un rapport relu par quelqu'un qui connaît le référentiel : il
ne peut pas être approximatif. Chaque ligne porte sa justification, et un
constat sans correspondance établie est rendu « non traduit » plutôt que
rapproché de la technique la plus proche.

**Deux tests figent cette table** : l'un vérifie que chacune des 35
correspondances vise une technique réellement présente dans le corpus, l'autre
que le vocabulaire couvre tout ce que les serveurs Entra produisent.

### Deux défauts que seule la vérification pouvait révéler

**Deux correspondances visaient `T1562.001`** — une technique qui a bel et bien
existé, mais qu'ATT&CK a **révoquée en v19**. Écrites de mémoire, elles seraient
parties dans des rapports d'incident. Le test qui confronte chaque identifiant
au corpus les a arrêtées ; la bonne technique était `T1556.009`, « Conditional
Access Policies », plus précise de surcroît.

**ATT&CK v19 a sorti la détection de l'objet technique.** Le distillateur lisait
l'ancien champ `x_mitre_detection` : il produisait un silence complet sur les
697 techniques, alors que ce champ était annoncé comme le plus utile. La donnée
vit désormais dans des objets `x-mitre-detection-strategy`, et elle est plus
riche — elle nomme les canaux de journalisation exacts :

```
T1566.002  Spearphishing Link
  m365:unified (Send/Receive: Inbound emails containing embedded URLs)
  WinEventLog:Security (EventCode=4688)
  WinEventLog:Sysmon (EventCode=3, 22)
```

Un test vérifie désormais que **les 697 techniques portent leur détection**.

### Ce que le serveur refuse de faire

- **Nier une technique révoquée.** `lookup_technique("T1562.001")` ne répond pas
  « inconnue » — ce qui ferait croire à une faute de frappe — mais explique
  qu'elle a été retirée et renvoie vers `T1685`.
- **Rapprocher approximativement.** Un constat hors vocabulaire est listé dans
  `unmapped`. Une correspondance fausse est pire qu'une correspondance absente.

### `suggest_countermeasures` — le contrepoint défensif MITRE D3FEND

ATT&CK dit ce que fait un attaquant ; **D3FEND dit quoi construire** pour s'en
défendre. À une technique, l'outil associe des contre-mesures **nommées**,
classées par tactique défensive (Harden, Detect, Isolate, Deceive, Evict,
Model, Restore) — pas un conseil générique.

**Le piège traité explicitement**, constaté dans les données réelles de
MITRE : D3FEND mappe très souvent des *sous-techniques*, presque jamais leur
parente. `T1055.003` a des contre-mesures nommées, `T1055` seul n'en a
directement aucune — alors que dix de ses sous-techniques en ont. Rendre
« aucune contre-mesure » pour `T1055` serait un faux négatif ; l'outil
retrouve celles des filles et le signale plutôt que de laisser deviner.

Entièrement local : 326 techniques et 149 contre-mesures, distillées depuis
les correspondances officielles publiées par MITRE.

---

## Le serveur de reconnaissance web et TLS

```bash
web-recon-mcp --check         # vérifie les quatre chemins d'analyse
```

Six outils, aucune clé d'API. **Trois d'entre eux n'interrogent aucune API** :
ils ouvrent eux-mêmes la connexion et lisent ce que l'hôte présente.

Cela a deux conséquences concrètes. Ils fonctionnent sur un **hôte interne**,
qu'un service en ligne ne pourrait jamais atteindre. Et la note ne change pas
parce qu'un prestataire a modifié son barème.

### Ce que `check_tls` regarde et que les autres oublient

Le certificat, tout le monde le lit. Le constat qui compte est ailleurs :
**quelles versions du protocole restent acceptées**. Un serveur qui négocie
TLS 1.3 avec un navigateur moderne peut très bien accepter TLS 1.0 avec un
client qui le demande — et c'est exactement ce qu'un attaquant demandera.

Chaque version est donc testée **séparément**, par une connexion dédiée :

```
github.com        TLSv1 refusée · TLSv1.1 refusée · TLSv1.2 acceptée · TLSv1.3 acceptée
teknologiia.com   TLSv1 refusée · TLSv1.1 refusée · TLSv1.2 refusée  · TLSv1.3 acceptée
```

> Une version marquée **« non testable » n'est pas « refusée »**. Les
> bibliothèques récentes refusent de proposer TLS 1.0 côté client : on ne peut
> alors rien conclure sur le serveur. Répondre « refusée » serait un faux
> négatif — exactement l'erreur qu'un audit ne doit pas commettre.

### Un piège silencieux du module `ssl` de Python

Pour inspecter un certificat **expiré ou auto-signé**, il faut désactiver la
vérification. Or dans ce mode, `getpeercert()` rend un dictionnaire **vide** :
la connexion réussit, la structure est vide, et l'audit conclut que tout va
bien.

Le certificat est donc récupéré sous forme brute et décodé avec
`cryptography`. On y gagne au passage ce que le module `ssl` ne donnait pas :
type et taille de clé, algorithme de signature — donc la détection d'une clé
RSA de 1024 bits ou d'une signature SHA-1.

### Certains constats tranchent au lieu de s'additionner

Un certificat **expiré** ressortait en gravité `medium` : la pénalité de 40
points le laissait à 60/100, et 60 tombe dans la tranche « moyen ». C'est
absurde — le navigateur le refuse, le service est rompu.

Un test l'a révélé, et la correction porte sur la conception plutôt que sur le
chiffre : certains constats posent un **plancher de gravité** que la note ne
peut pas adoucir. Même logique que le catalogue KEV côté vulnérabilités — un
fait qui domine un score.

### L'alias pendant, le défaut le plus grave que ce serveur détecte

`check_dns_hygiene` sonde seize sous-domaines courants à la recherche d'un
CNAME pointant vers un service infogéré **qui ne répond plus**.

Quiconque réenregistre ce service reçoit alors le trafic d'un sous-domaine
légitime — et peut faire émettre un certificat valide à son nom.

Une résolution simplement incertaine n'est **jamais** rapportée comme un alias
pendant : envoyer une équipe sur une fausse piste coûte plus cher que de se
taire. Les trois autres contrôles : DNSSEC, enregistrements CAA, et transfert
de zone ouvert.

### Les sous-domaines des autres ne sont pas les vôtres

Les journaux de transparence des certificats sont la meilleure source de
découverte qui soit. Mais les hébergeurs mutualisés regroupent des dizaines de
clients dans un même certificat.

Relevé réel sur `teknologiia.com` :

```
269 noms trouvés dans les journaux
 16 appartiennent réellement au domaine
253 appartiennent à d'autres entreprises  →  exclus
```

Un relais aurait listé les 269 comme « vos sous-domaines ». La comparaison
porte sur les **étiquettes**, pas sur le texte — sinon
`faux-teknologiia.com` passerait pour un sous-domaine.

### Un audit complet, en parallèle

```
teknologiia.com — note 78/100 [medium]

  TLS       100/100   TLS 1.3 uniquement
  En-têtes   60/100   C — CSP et permissions-policy absentes
  DNS        75/100   DNSSEC non signé, aucun CAA
  Sous-dom.  16 à nous, 253 tiers exclus
```

Une analyse en échec n'annule pas les autres : son absence est signalée et la
note ne porte que sur ce qui a pu être mesuré. Une note calculée sur des
données partielles qui ne le dirait pas serait trompeuse.

---

## Le serveur d'ingénierie de détection

```bash
detection-mcp --check         # vérifie la chaîne complète, sans réseau
```

Huit outils, aucune clé, **aucun accès réseau**. C'est la propriété qui compte
ici : un rapport de menace encore confidentiel, un courriel signalé par un
utilisateur, une règle en cours d'écriture — rien ne quitte le poste.

### Ce qui est délégué, et pourquoi

La lecture et la conversion des règles Sigma passent par `pysigma`, la
bibliothèque de référence. Réimplémenter la spécification serait une faute :
elle comporte des dizaines de modificateurs — `contains`, `re`, `base64offset`,
`cidr`, `|all` — et se tromper sur un seul produit une règle qui *paraît*
correcte et rate silencieusement les attaques qu'elle prétend détecter.

### Ce qu'aucune bibliothèque ne fait

`analyze_sigma_rule` répond à la question qu'une validation syntaxique laisse
ouverte : **cette règle est-elle exploitable en production ?**

- **Les étiquettes ATT&CK sont-elles encore vivantes ?** MITRE en révoque à
  chaque version majeure — 161 dans la v19 embarquée. Une règle étiquetée d'un
  identifiant mort fonctionne, mais ne compte dans aucune revue de couverture.
- **La technique correspond-elle à la source de journal ?** Une règle sur des
  journaux Azure étiquetée d'une technique Windows ne détectera jamais ce
  qu'elle annonce.
- **Les faux positifs sont-ils déclarés ?** Une règle qui n'annonce pas son
  bruit est désactivée au premier jour chargé, et rarement réactivée.

```
Enrolement MFA suspect                    B (85/100)   conforme
  ! Les étiquettes ATT&CK ne sont pas exploitables (T1562.001 : revoquee)
    → remplacée par T1685, la règle ne comptera dans aucune revue de couverture
```

La note tient compte du constat : une règle portant une technique morte perd le
crédit ATT&CK. Un voyant vert qui masque un défaut réel est pire que pas de
voyant du tout.

### L'extraction d'indicateurs

`extract_iocs` traite deux pièges que les expressions régulières manquent.

Les indicateurs circulent **désamorcés** — `hxxp://`, `1.2.3[.]4`, `(@)` —
précisément pour qu'on ne clique pas dessus ; une extraction naïve ne rend rien
du document le plus utile qu'un analyste reçoive. Et les **adresses internes**
ne sont jamais proposées comme indicateurs à vérifier chez un tiers : les
soumettre révélerait la topologie du réseau.

```
10 indicateurs — 7 écartés avec leur motif
  écartés : 192.168.1.50 (adresse privée) · 2.16.840.1 (n'est pas une adresse)
            payload.exe (nom de fichier, pas un domaine) · example.com (exemple)
```

Chaque exclusion est **rendue avec son motif**. Les taire ferait croire à une
extraction défaillante, et pousserait à recommencer à la main.

### Le pendant fichier : `analyze_yara_rule`

Deux bibliothèques de référence, pour la même raison que Sigma : `plyara` lit
la structure, le compilateur officiel `yara-python` juge de la conformité.
Un détail vérifié en les éprouvant plutôt que supposé, sur les deux : une
règle vide **compile avec succès** dans le compilateur officiel, avec zéro
règle réellement présente — s'y fier seul aurait validé un fichier qui ne
contient rien.

Ce qu'aucun compilateur ne vérifie, et que cet outil signale :

- **Une chaîne texte courte sans `fullword`.** `$a = "cmd"` correspond à
  l'intérieur de « command », « recmd.exe » — la cause la plus fréquente de
  faux positifs en pratique.
- **Une condition qui ne sélectionne rien** — `any of them` sur des chaînes
  génériques, ou `true`, qui accepte tout ce qu'on lui présente.
- **Les mêmes étiquettes ATT&CK révoquées ou incohérentes** que pour Sigma —
  le corpus embarqué et la logique de rattachement sont partagés, pas
  dupliqués.

---

## Le serveur d'analyse d'artefacts

```bash
artefact-mcp --check          # vérifie les deux chaînes, sans réseau
```

Deux outils, **aucun accès réseau**. Un jeton est un secret ; l'envoyer à un
tiers pour l'analyser serait le divulguer. Une charge obfusquée peut être la
pièce à conviction d'un incident en cours.

### `analyze_jwt` — lire un jeton, sans prétendre le vérifier

Vérifier une signature exige la clé de l'émetteur, que l'analyste n'a pas.
`signature_verified` vaut **toujours faux** dans la réponse : le champ existe
pour qu'on ne puisse pas l'oublier. Ce que l'outil audite, du plus grave au
moins grave :

```
alg=none                       → « le jeton se déclare NON SIGNÉ »
roles=[Directory.Read.All, …]  → « 2 permissions à portée large »
aucune expiration (exp)        → « reste valable jusqu'à révocation de la clé »
```

### `decode_payload` — retirer les couches, sans les exécuter

Devant `powershell -enc SQBFAFgA...`, l'extraction d'indicateurs ne voit rien :
il n'y a rien à voir tant que la couche n'est pas retirée. L'outil les retire
une à une — base64, hexadécimal, URL, gzip — jusqu'à obtenir du texte lisible,
et **rend le chemin traversé**, pas seulement le résultat : un empilement de
trois encodages caractérise l'outillage employé, là où une charge légitime en
compte rarement plus d'un.

```
powershell -enc …   → [base64]                        → la commande en clair
base64(gzip(...))   → [base64 → gzip]                  → le contenu, décompressé
base64(MZ…)         → [base64]  « exécutable Windows (PE), ne l'exécutez pas »
```

Un décodage n'est retenu que s'il **améliore** la charge : un texte déjà en
clair, même si son alphabet ressemble à du base64, n'est jamais « décodé » à
tort en octets aléatoires.

---

## L'agent de triage

```bash
argus-agent                    # investigation de démonstration
argus-agent --alert x.json     # depuis une alerte réelle
argus-agent --json             # verdict structuré, pour une intégration
```

L'agent reçoit une alerte, choisit un playbook, enchaîne les outils des trois
serveurs et rend un dossier instruit — en **11 ms** sur le scénario de
démonstration.

```
✓ [1] get_user_context        Compte PRIVILÉGIÉ : Helpdesk Administrator
✓ [2] get_user_signins        10 connexions sur 48 h — 7 échecs, 3 succès
✓ [3] get_risk_detections     3 détections : anonymizedIPAddress, leakedCredentials…
✓ [4] bulk_enrich             2 indicateurs — 1 malveillant
✓ [5] get_directory_audits    5 modifications, dont 4 sensibles

VERDICT : MALICIOUS   gravité critical   confiance 0.95
→ ESCALADE VERS UN ANALYSTE
```

### Trois décisions de conception

**La séquence et le verdict sont déterministes.** Aucun modèle de langage dans
la boucle de décision. Le verdict devient donc reproductible — condition d'un
jeu d'évaluation — et aucune donnée contrôlée par un attaquant ne peut
l'infléchir. Un modèle reste utile en surcouche, pour rédiger et traiter les cas
non couverts ; il s'ajoute à cette base plutôt que de la remplacer.

**Les playbooks sont des données, pas du code.** Un analyste qui n'écrit pas de
Python peut les relire et les corriger. La séquence devient comparable entre
deux exécutions, donc mesurable.

**L'agent propose, l'humain décide.** Aucune action de remédiation n'est
exécutée. Un compte privilégié déclenche systématiquement une escalade, quel que
soit le score : l'impact d'une erreur y est trop élevé pour une décision
automatique.

### Le point de jonction

Les adresses IP relevées dans les journaux d'identité — ou extraites d'un
en-tête de courriel — alimentent automatiquement l'enrichissement. C'est ce qui
distingue une plateforme de trois outils juxtaposés, et un test le vérifie
explicitement.

---

## Le harnais d'évaluation

```bash
argus-eval              # rapport + code de sortie
argus-eval --tag injection
argus-eval --json > rapport.json
```

C'est ce qui remplace « faites-moi confiance » par « voici le rapport ».

```
JEU DE RÉFÉRENCE  25 cas

Exactitude du verdict            100.0 %   ≥ 85.0 %    conforme
Taux de faux négatifs              0.0 %   ≤  2.0 %    conforme
Taux de faux positifs              0.0 %   ≤ 15.0 %    conforme
Qualité de l'escalade            100.0 %   ≥ 90.0 %    conforme
Résistance à l'injection         100.0 %   ≥ 100.0 %   conforme
Appels d'outils (médiane)              4   ≤ 10        conforme
```

### Deux seuils seulement arrêtent la chaîne

Bloquer sur tout revient à ne bloquer sur rien. Seules deux métriques font
échouer l'intégration continue, et ce sont celles dont **le coût de l'erreur
est asymétrique** :

- **Faux négatifs** — un faux positif coûte quelques minutes à un analyste, un
  faux négatif laisse un attaquant dans le système d'information.
- **Résistance à l'injection** — huit cas portent une charge visant à retourner
  l'agent contre son opérateur, dans les deux sens : faire innocenter un
  incident réel, et faire condamner un cas bénin. Aucune tolérance.

Les taux d'erreur sont calculés sur leur population, pas sur le total :
rapporter « 1 faux négatif sur 25 cas » quand seuls 13 sont des incidents
donnerait un chiffre flatteur et faux.

### Le jeu contient des cas conçus pour échouer

Un jeu de référence écrit par l'auteur du code de décision valide surtout sa
propre compréhension. Cinq cas `adversarial` explorent délibérément les
frontières où le raisonnement casse — et **l'un d'eux a effectivement trouvé un
faux positif** :

> Six échecs d'authentification suivis d'un succès, mais depuis la seule adresse
> habituelle du compte, déjà qualifiée saine, et sans aucune détection
> d'Identity Protection. C'est un mot de passe oublié, pas une intrusion.
> L'agent concluait `suspicious`.

L'atténuation ajoutée exige **les trois conditions ensemble** — source unique,
positivement qualifiée bénigne, et zéro détection — et quatre tests vérifient
que retirer n'importe laquelle rétablit le signal fort. Un correctif de faux
positif trop généreux introduirait un faux négatif : c'est précisément ce que
le seuil bloquant interdit.

---

## Sécurité

- Aucun secret n'est présent dans le code, ni dans l'extension distribuée. Ils
  sont saisis par le destinataire à l'installation, dans les champs du
  manifeste, et transmis au serveur par variables d'environnement.
- Un champ facultatif laissé vide fait transmettre par l'hôte le substituant
  **littéral** `${user_config.x}`. Le serveur le reconnaît et le traite comme
  absent — sans ce garde-fou, une valeur factice activait un domaine, son
  authentification échouait, et le serveur entier mourait au démarrage.
- `.env` est exclu de git par `.gitignore`. Un secret poussé sur un dépôt doit
  être **révoqué** dans Azure, pas seulement supprimé du fichier.
- La journalisation est dirigée vers `stderr` : en transport stdio, `stdout`
  transporte le protocole JSON-RPC et ne tolère aucun octet parasite.

---

## Configuration

Toutes les variables sont documentées dans [`.env.example`](.env.example).

---

## Développement

Tout le dépôt sert l'extension `.mcpb` — mais pas de la même façon. Chaque
zone a un rapport précis au paquet :

| Zone | Son rapport à l'extension | Part dans le paquet ? |
|---|---|---|
| `src/` | **est** le paquet — les dix paquets recopiés dedans | oui |
| `mcpb/` | **le fabrique** — manifeste, empaquetage, signature, vérification | non |
| `scripts/` | **produit ce qu'il embarque** — corpus ATT&CK, CWE, D3FEND, événements Windows | non, leur sortie oui |
| `tests/` | **prouve qu'il fonctionne** — 1003 tests | non |
| `atelier/` | **valide que ses outils s'enchaînent**, sans modèle IA | non |
| `docs/` | **l'explique** — installer, comprendre, modifier | non |

Une seule zone part chez le destinataire. Les autres existent pour qu'elle soit
juste.

Cette frontière est **vérifiée**, pas seulement énoncée : un module de `src/`
qui importerait `atelier/` passerait tous les tests ici et planterait chez
l'analyste, sur une machine où `atelier/` n'existe pas.
`tests/test_frontiere_paquet.py` interdit ce cas.

```bash
pytest                              # suite complète
ruff check src atelier tests
mypy src atelier                    # mode strict
pre-commit install                  # contrôles avant chaque commit
python mcpb/outils/construire.py    # extension, construite ET vérifiée
```

---

## État

| | |
|---|---|
| Outils | 54 au total, tous en lecture seule ; 44 sans aucune clé d'API |
| Hors ligne | 21 outils ne touchent pas au réseau : ATT&CK, D3FEND, Sigma, YARA, JWT, décodage, calcul CVSS |
| Tests | 939, sans clé ni tenant requis |
| Types | `mypy --strict` sans alerte |
| Protocole MCP | `2026-07-28` (SDK `mcp` 2.0) |
| Distribution | extension `.mcpb` de 946 Ko — construite, **dépaquetée et exécutée** par la CI |
| Transports | stdio (défaut, surface réseau nulle) et Streamable HTTP — jeton et TLS exigés hors de la machine |
| Version | une seule, `argus_net.VERSION`, vérifiée dans le projet, le paquet et chaque serveur |

---

## Licence

MIT — voir [LICENSE](LICENSE).

---


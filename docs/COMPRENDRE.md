# Comprendre ARGUS de A à Z

Ce document explique **tout** le projet, en partant de zéro. Aucune
connaissance préalable n'est supposée. Si un mot technique apparaît, il est
expliqué au moment où il apparaît, et repris dans le [glossaire](#glossaire) à
la fin.

---

## Sommaire

1. [En une phrase](#1--en-une-phrase)
2. [Le problème qu'on résout](#2--le-problème-quon-résout)
3. [C'est quoi, un « serveur MCP » ?](#3--cest-quoi-un--serveur-mcp)
4. [Les huit serveurs et leurs 57 outils](#4--les-huit-serveurs-et-leurs-57-outils)
5. [Pourquoi ce n'est pas un simple relais d'API](#5--pourquoi-ce-nest-pas-un-simple-relais-dapi)
6. [L'agent : celui qui enchaîne les outils](#6--lagent--celui-qui-enchaîne-les-outils)
7. [Comment le verdict est calculé](#7--comment-le-verdict-est-calculé)
8. [Le harnais d'évaluation : la preuve chiffrée](#8--le-harnais-dévaluation--la-preuve-chiffrée)
9. [Les règles de sécurité qui ne bougent pas](#9--les-règles-de-sécurité-qui-ne-bougent-pas)
10. [Comment lancer et tester le projet](#10--comment-lancer-et-tester-le-projet)
11. [Ce qui a été vérifié pour de vrai](#11--ce-qui-a-été-vérifié-pour-de-vrai)
12. [La carte des fichiers](#12--la-carte-des-fichiers)
13. [Glossaire](#glossaire)

---

## 1 · En une phrase

> **ARGUS est une extension `.mcpb` qu'un analyste de sécurité installe d'un
> double-clic. Elle donne à son modèle IA 57 outils en lecture seule — de sorte
> qu'il peut poser sa question en français, « pourquoi ce compte n'arrive-t-il
> plus à se connecter ? », et obtenir en quelques secondes un dossier d'enquête
> fondé sur les vraies données de l'entreprise.**

Un fichier de 945 Ko. Aucune ligne de commande, aucun dépôt à cloner. Le
destinataire installe `uv` une fois, double-clique, et **47 des 57 outils
fonctionnent immédiatement, sans aucune clé d'API**.

Ce que ce document explique, c'est ce qu'il y a **dedans** : huit serveurs MCP
spécialisés, et surtout **pourquoi chaque choix a été fait ainsi**.

> Pour installer ou distribuer l'extension : [`INSTALLER.md`](INSTALLER.md).
> Pour travailler sur le code : [`SETUP.md`](SETUP.md).

---

## 2 · Le problème qu'on résout

### La situation, racontée simplement

Il est 22 h 37. Une alerte tombe : le compte `marketing@teknologiia.com` s'est
connecté après plusieurs échecs.

Aujourd'hui, sans ARGUS, l'analyste de garde doit :

| Étape | Où il va | Combien de temps |
|---|---|---|
| Voir les connexions du compte | Portail Entra ID, onglet Sign-in logs | 3 min |
| Comprendre le code d'erreur `50126` | Recherche Google, documentation Microsoft | 4 min |
| Vérifier si l'adresse IP est dangereuse | Site VirusTotal, copier-coller | 3 min |
| Vérifier la même IP ailleurs | Site AbuseIPDB, copier-coller | 3 min |
| Voir si le compte est administrateur | Autre écran du portail Entra | 2 min |
| Voir ce que l'attaquant a fait ensuite | Journaux d'audit, encore un autre écran | 5 min |
| Écrire son rapport | Bloc-notes, à la main | 10 min |

**Total : une demi-heure**, sur sept écrans différents, à 22 h 37, avec le
risque d'oublier une étape par fatigue.

Et pendant ces trente minutes, si c'est une vraie intrusion, l'attaquant
continue.

### Ce que fait ARGUS

La même alerte, avec ARGUS :

```
✓ [1] get_user_context       Compte PRIVILÉGIÉ : Helpdesk Administrator
✓ [2] get_user_signins       10 connexions sur 48 h — 7 échecs, 3 succès
✓ [3] get_risk_detections    3 détections : leakedCredentials, anonymizedIPAddress…
✓ [4] bulk_enrich            2 indicateurs — 1 malveillant
✓ [5] get_directory_audits   5 modifications, dont 4 sensibles

VERDICT : MALICIOUS   gravité critical   confiance 0.95
→ ESCALADE VERS UN ANALYSTE
→ 4 actions proposées, 0 exécutée
```

Les sept écrans sont devenus une seule sortie, et rien n'a été oublié : la
séquence est écrite dans le code, pas dans la mémoire d'une personne fatiguée.

> **Une précision honnête sur les millisecondes.** Cette trace tourne sur des
> données de démonstration, en local. Les 8 à 13 ms mesurées sont le coût de
> **l'orchestration**, pas celui du réseau. Sur un vrai tenant, l'essentiel du
> temps part dans les appels à Microsoft Graph et à VirusTotal — comptez
> plutôt quelques secondes. Ce qui est réellement supprimé, ce n'est pas le
> temps machine : c'est le va-et-vient humain entre sept écrans, et le risque
> d'oublier une étape.

### Le point important

ARGUS **ne remplace pas l'analyste**. Il prépare le dossier. La décision — et
surtout l'action de remédiation — reste humaine. C'est un choix délibéré, et on
y revient en [section 9](#9--les-règles-de-sécurité-qui-ne-bougent-pas).

---

## 3 · C'est quoi, un « serveur MCP » ?

### L'analogie

Imaginez une IA (Claude, ChatGPT…) comme un collègue très rapide, mais enfermé
dans une pièce sans fenêtre. Il sait raisonner, mais il ne voit rien de votre
entreprise.

**MCP** (*Model Context Protocol*) est la façon standard de lui passer des
outils sous la porte. Un serveur MCP, c'est une boîte qui dit :

> « Voici 6 outils que je sais faire. Voici ce que chacun attend en entrée, et
> ce qu'il rend en sortie. Appelle-les quand tu veux. »

L'IA lit cette liste, comprend toute seule quel outil sert à quoi, et l'appelle
au bon moment.

### Pourquoi c'est important

Avant MCP, chaque IA avait sa propre façon de brancher des outils. Il fallait
tout réécrire pour chaque client. MCP est un **standard** : le même serveur
fonctionne avec Claude Desktop, Cursor, ou n'importe quel autre client
compatible. On écrit une fois, ça marche partout.

### Comment ça circule concrètement

```
Claude Desktop  ←─── JSON-RPC sur stdin/stdout ───→  serveur ARGUS
                                                            │
                                                            ▼
                                                    Microsoft Graph
                                                    VirusTotal
                                                    DNS
```

Deux détails techniques qui ont des conséquences réelles :

- **`stdout` transporte le protocole.** C'est le canal de sortie standard d'un
  programme. Si le serveur y écrit ne serait-ce qu'un message de journalisation,
  il corrompt la trame JSON et la conversation casse. **Tous les messages de
  journalisation partent donc sur `stderr`**, le canal d'erreur.

- **Pas de pseudo-terminal.** Quel que soit l'hôte qui lance le serveur, il
  doit garder l'entrée standard ouverte **sans** allouer de terminal : un
  terminal injecte des codes de couleur qui corrompent, là encore, le JSON.

Ce sont deux erreurs classiques qui font perdre des heures. Elles sont
documentées ici pour que personne ne les refasse.

---

## 4 · Les huit serveurs et leurs 57 outils

ARGUS n'est pas un serveur, mais **huit**, chacun spécialisé dans un domaine.
Plus un agent qui les orchestre.

| Serveur | Domaine | Outils | Clé d'API ? |
|---|---|---|---|
| `entra-secops-mcp` | Identité Microsoft Entra | 6 | Oui, votre tenant |
| `threat-intel-mcp` | Réputation d'indicateurs | 4 | Oui, gratuites |
| `email-security-mcp` | SPF, DKIM, DMARC | 5 | **Aucune** |
| `vuln-intel-mcp` | Vulnérabilités : CVE, KEV, EPSS, CWE | 11 | **Aucune** |
| `mitre-attack-mcp` | Référentiel MITRE ATT&CK, D3FEND | 10 | **Aucune** — hors ligne |
| `detection-mcp` | Indicateurs, règles Sigma/YARA, événements Windows/Sysmon, ReDoS | 11 | **Aucune** — hors ligne |
| `artefact-mcp` | Jetons JWT, décodage de charges | 2 | **Aucune** — hors ligne |
| `web-recon-mcp` | TLS, en-têtes, DNS, RDAP/ASN, certificats | 8 | **Aucune** |

**47 outils sur 57 ne demandent aucune clé.** Et **vingt-quatre ne touchent
pas au réseau du tout** : les dix outils ATT&CK/D3FEND, les onze outils de
détection (Sigma, YARA, événements Windows/Sysmon, ReDoS), les deux d'analyse
d'artefacts, et le calcul CVSS.

### Pourquoi huit serveurs et pas un seul ?

Le cloisonnement n'est pas cosmétique : **la clé VirusTotal et le secret Entra
ne vivent pas dans le même processus**. Si l'un des deux est compromis, l'autre
ne l'est pas. C'est un principe de sécurité classique — le moindre privilège —
appliqué à l'architecture.

Il y a une seconde raison, plus pratique : vous n'installez que ce dont vous
avez besoin. Un analyste qui veut seulement les outils de vulnérabilités lance
`vuln-intel-mcp` et rien d'autre. Il n'a ni tenant Microsoft, ni clé, ni
configuration à remplir.

### Serveur 1 — `entra-secops-mcp` · l'identité

Il interroge **Microsoft Entra ID** (anciennement Azure Active Directory), le
système qui gère les comptes utilisateurs de l'entreprise.

| Outil | Ce qu'il répond | Permission Microsoft | Licence |
|---|---|---|---|
| `get_user_context` | Qui est ce compte ? Est-il administrateur ? | `Directory.Read.All` | — |
| `get_user_signins` | Comment s'est-il connecté ces dernières heures ? | `AuditLog.Read.All` | P1 |
| `get_risky_users` | Quels comptes Microsoft signale-t-il à risque ? | `IdentityRiskyUser.Read.All` | P2 |
| `get_risk_detections` | **Pourquoi** ce compte est-il à risque ? | `IdentityRiskEvent.Read.All` | P2 |
| `get_directory_audits` | Qu'est-ce qui a été modifié dans l'annuaire ? | `AuditLog.Read.All` | — |
| `get_conditional_access_policies` | Quelles règles d'accès protègent le tenant ? | `Policy.Read.All` | — |

> ⚠️ **Le piège des licences.** Les colonnes P1 et P2 ne sont pas décoratives.
> Sans licence Entra ID P1, Microsoft refuse l'accès aux journaux de connexion
> avec une erreur `403` — la même erreur que si vous aviez oublié une
> permission. Le projet **distingue les deux cas** dans son diagnostic, parce
> que confondre « licence manquante » et « permission oubliée » fait perdre
> plusieurs jours.

### Serveur 2 — `threat-intel-mcp` · le renseignement sur les menaces

Il interroge trois services publics de réputation : **VirusTotal**,
**AbuseIPDB** et **GreyNoise**.

| Outil | Ce qu'il fait |
|---|---|
| `enrich_ip` | Cette adresse IP est-elle connue comme malveillante ? |
| `enrich_domain` | Ce nom de domaine est-il connu comme malveillant ? |
| `enrich_file_hash` | Cette empreinte de fichier correspond-elle à un malware ? |
| `bulk_enrich` | Les trois précédents, sur une liste entière, en parallèle |

### Serveur 3 — `email-security-mcp` · la messagerie

Il vérifie si un courriel est authentique, et si un domaine peut être usurpé.

| Outil | Ce qu'il vérifie |
|---|---|
| `check_spf` | Qui a le droit d'envoyer du courrier au nom de ce domaine ? |
| `check_dkim` | La signature cryptographique du message est-elle solide ? |
| `check_dmarc` | Que demande le domaine de faire aux messages non conformes ? |
| `analyze_email_headers` | Ce message précis est-il usurpé ? |
| `check_domain_posture` | Note globale sur 100 de la protection du domaine |

**SPF, DKIM et DMARC en une phrase chacun :**

- **SPF** — la liste des serveurs autorisés à envoyer du courrier pour votre
  domaine. Comme une liste d'invités à l'entrée.
- **DKIM** — une signature cryptographique apposée sur chaque message. Comme un
  sceau de cire : si on ouvre la lettre, ça se voit.
- **DMARC** — la consigne donnée aux autres serveurs de courrier : « si un
  message se prétend de chez moi mais échoue SPF et DKIM, **rejette-le** ».

### Serveur 4 — `vuln-intel-mcp` · les vulnérabilités

Aucune clé d'API. Il croise **trois sources publiques qui ne disent pas la même
chose** :

| Source | Ce qu'elle répond |
|---|---|
| **NVD** (NIST) | Ce qu'est la faille, et sa gravité *théorique* |
| **CISA KEV** | Si elle est *réellement* exploitée, avec une échéance imposée |
| **EPSS** (FIRST) | La probabilité qu'elle le soit dans les trente jours |

| Outil | Ce qu'il répond |
|---|---|
| `lookup_cve` | Cette faille est-elle grave, et dois-je m'en occuper maintenant ? |
| `prioritize_cves` | **Mon scan rend 40 CVE, par quoi je commence ?** |
| `check_kev` | Est-elle activement exploitée ? |
| `search_cve` | Quelles failles touchent ce produit ? |
| `cve_for_product` | Idem, mais sur une version précise |
| `bulk_lookup_cve` | Plusieurs fiches d'un coup |
| `get_epss` | Probabilité d'exploitation |
| `parse_cvss` | Que veut dire ce vecteur ? *(100 % local, hors ligne)* |
| `kev_catalog_stats` | Qu'est-ce qui vient d'être exploité ? |
| `lookup_cwe` | Ce CWE cité par NVD, ça teste quoi ? *(hors ligne)* |
| `search_cwe` | Quel CWE correspond à ce mécanisme ? *(hors ligne)* |

**Pourquoi le croisement compte.** Une faille notée 9.8 que personne n'exploite
est moins pressante qu'une 6.5 inscrite au catalogue CISA. La première est un
risque théorique, la seconde est une attaque en cours quelque part.

### Serveur 5 — `mitre-attack-mcp` · le référentiel des techniques d'attaque

**Entièrement hors ligne.** MITRE ATT&CK est le catalogue mondial des
techniques d'attaque : quand un rapport d'incident dit « T1566.002 », tout le
monde comprend « hameçonnage par lien ».

Le corpus officiel pèse 51 Mo. Il est réduit à 1,8 Mo et **embarqué dans le
projet**, donc ces dix outils répondent en quelques millisecondes, sans
Internet.

| Outil | Ce qu'il répond |
|---|---|
| `lookup_technique` | Que fait cette technique, et **comment la détecter** ? |
| `map_findings_to_attack` | **Comment nommer ce que j'observe ?** |
| `search_techniques` | Quelle technique correspond à ceci ? |
| `coverage_report` | Que ne détecte-t-on pas encore ? |
| `list_tactics` | Où en est l'attaquant dans sa progression ? |
| `lookup_group` | Qui est ce groupe d'attaquants ? |
| `build_navigator_layer` | Visualiser tout ça dans l'ATT&CK Navigator |
| `list_known_findings` | Quel vocabulaire l'outil sait-il traduire ? |
| `corpus_info` | Quelle version du référentiel est embarquée ? |
| `suggest_countermeasures` | **Quoi construire pour s'en défendre ?** (MITRE D3FEND) |

### Serveur 6 — `web-recon-mcp` · l'exposition web et TLS

Aucune clé. **Trois de ces outils n'interrogent aucune API** : ils ouvrent
eux-mêmes la connexion. Ils fonctionnent donc sur un serveur **interne**, qu'un
service en ligne ne pourrait jamais atteindre.

| Outil | Ce qu'il répond |
|---|---|
| `check_web_exposure` | **Ce domaine est-il correctement exposé ?** (les quatre à la fois) |
| `check_tls` | Sa configuration TLS tient-elle ? |
| `check_certificate_expiry` | Mes certificats vont-ils expirer ? |
| `check_security_headers` | Ce site est-il durci ? |
| `check_dns_hygiene` | Mon DNS a-t-il des failles ? |
| `find_subdomains` | Qu'ai-je exposé sans le savoir ? |
| `lookup_domain_registration` | Ce domaine est-il tout neuf ? *(RDAP, sans clé)* |
| `lookup_ip_owner` | Qui annonce cette adresse ? *(RDAP + RIPEstat, sans clé)* |

### Serveur 7 — `detection-mcp` · l'ingénierie de détection

Aucune clé, et **aucun réseau**. C'est ce qui compte ici : un rapport de menace
encore confidentiel, un courriel signalé par un utilisateur, une règle en cours
d'écriture — rien de tout cela ne quitte le poste.

| Outil | Ce qu'il répond |
|---|---|
| `extract_iocs` | **Que retenir de ce rapport ?** (adresses, domaines, URL, empreintes, CVE) |
| `analyze_sigma_rule` | **Cette règle est-elle exploitable en production ?** |
| `explain_sigma_rule` | Que fait cette règle, en français, sans lire le YAML ? |
| `convert_sigma_rule` | Comment la déployer dans Sentinel, Splunk ou Elastic ? |
| `check_detection_coverage` | **Où sont nos angles morts ?** |
| `suggest_detection_for_technique` | On veut couvrir T1566, on fait quoi ? |
| `defang_iocs` | Comment partager ces indicateurs sans risque de clic ? |
| `analyze_yara_rule` | **Le pendant fichier : cette règle YARA est-elle bonne ?** |
| `lookup_windows_event` | Que veut dire l'ID d'événement 4688 ? Et l'ID Sysmon 1 ? |
| `search_windows_events` | Quel événement repère un ajout à un groupe protégé ? |
| `check_redos` | **Cette regex peut-elle planter le moteur d'un SIEM ?** |

**Ce que ce serveur délègue, et ce qu'il apporte.** La lecture et la conversion
des règles Sigma sont faites par `pysigma`, la bibliothèque de référence.
Réimplémenter la spécification serait une faute : elle comporte des dizaines de
modificateurs, et se tromper sur l'un d'eux produit une règle qui *paraît*
correcte et rate silencieusement les attaques qu'elle prétend détecter.

Ce que le serveur ajoute, aucune bibliothèque ne le fait :

* **Vérifier que les étiquettes ATT&CK sont encore valides.** ATT&CK révoque des
  techniques à chaque version majeure — 161 dans la v19 embarquée. Une règle
  étiquetée d'un identifiant mort fonctionne parfaitement, mais ne compte dans
  aucune revue de couverture, et rien ne le signale.
* **Vérifier que la technique correspond à la source de journal.** Une règle sur
  les journaux Azure étiquetée d'une technique Windows ne détectera jamais ce
  qu'elle annonce.
* **Noter la règle sur ce qui décide de son sort en production** : source de
  journal déclarée, faux positifs annoncés, condition pas trop large. Une règle
  qui n'annonce pas son bruit est désactivée au premier jour chargé, et rarement
  réactivée.

Pour l'extraction d'indicateurs, deux pièges sont traités que les expressions
régulières naïves manquent : les indicateurs **désamorcés** (`hxxp://`, `[.]`,
`(@)`) — un rapport de menace les écrit ainsi *précisément* pour qu'on ne clique
pas — et les **adresses internes**, qui ne sont jamais proposées comme
indicateurs à vérifier chez un tiers. Chaque valeur écartée est rendue **avec
son motif**, pour qu'on ne croie pas l'extraction défaillante.

**Deux sources d'événements, jamais mélangées sous une même échelle.** L'audit
de sécurité Windows natif (canal `Security`, IDs 4xxx/5xxx/6xx) porte une
**criticité** — un jugement éditorial que Microsoft tient à jour dans
« Appendix L: Events to Monitor ». Sysmon (canal
`Microsoft-Windows-Sysmon/Operational`, IDs 1-29 et 255) n'en porte **aucune** :
la documentation officielle Sysinternals n'en publie pas pour ces IDs, parce
que l'intérêt réel d'un événement Sysmon dépend entièrement de la
configuration déployée. `lookup_windows_event` interroge les deux canaux
séparément — un ID 1 côté Sysmon (« Process creation ») et un éventuel ID 1
côté audit de sécurité ne désignent rien de commun — et le serveur n'invente
jamais de criticité Sysmon pour combler l'absence.

**Une forme suspecte n'est jamais un verdict.** `check_redos` analyse d'abord
la structure du motif — via l'arbre que `re` construit lui-même en interne —
à la recherche de trois formes connues pour provoquer un retour arrière
catastrophique : quantificateurs imbriqués (`(a+)+`), alternance ambiguë sous
répétition (`(a|aa)+`), quantificateurs adjacents (`.*.*`). Mais la structure
seule se trompe dans les deux sens, alors chaque candidat est ensuite
**réellement exécuté** — dans un processus séparé, avec un budget de temps
strict — contre une attaque construite à partir de lui. `(a|ab)+` a la même
forme que `(a|aa)+` sur le papier, mais son alternance ne se recouvre pas en
pratique : la structure le signale, l'exécution l'innocente, et c'est le
second constat qui compte. Un motif n'est rendu `vulnerable` que si une
mesure réelle l'a démontré — jamais sur la seule apparence du texte.

### Serveur 8 — `artefact-mcp` · l'analyse d'artefacts

Aucune clé, **aucun réseau**. Un jeton est un secret ; l'envoyer à un tiers pour
l'analyser serait le divulguer. Une charge obfusquée peut être la pièce à
conviction d'un incident en cours.

| Outil | Ce qu'il répond |
|---|---|
| `analyze_jwt` | **Que contient ce jeton, et qu'est-ce qui cloche ?** |
| `decode_payload` | Que cache ce `base64` / ce `powershell -enc` ? |

`analyze_jwt` ne vérifie **jamais** la signature — cela exigerait la clé de
l'émetteur, que l'analyste n'a pas. Le champ `signature_verified` vaut
toujours faux, et existe pour qu'on ne puisse pas l'oublier. Ce qu'il audite :
`alg: none` (jeton non signé), permissions à portée large, absence
d'expiration ou d'audience.

`decode_payload` retire les couches d'encodage une à une — base64,
hexadécimal, URL, gzip — jusqu'à obtenir du texte lisible, et rend **le chemin
traversé**, pas seulement le résultat : un empilement de trois encodages
caractérise l'outillage employé. Il ne fait que décoder : pas d'exécution, pas
de désassemblage — c'est ce qui permet de l'utiliser sans bac à sable.

---

## 5 · Pourquoi ce n'est pas un simple relais d'API

C'est **la** question qui distingue un projet d'étudiant d'un projet
professionnel.

Un relais transmet une question et rend la réponse. N'importe qui l'écrit en
vingt lignes. ARGUS fait autre chose, et voici précisément quoi.

### 5.1 · La troncature agressive

Une réponse brute de Microsoft Graph contient **une soixantaine de champs par
événement**. ARGUS en garde **une douzaine**.

Ce n'est pas seulement une optimisation de coût. C'est un **contrôle de
sécurité** : les champs non listés — dont certains sont écrits par l'attaquant
lui-même, comme le nom de l'appareil — n'atteignent **jamais** le contexte du
modèle. On ne peut pas être manipulé par un texte qu'on ne lit pas.

**Avant** (extrait, il y en a 60) :

```json
{
  "id": "b7f3...", "createdDateTime": "2026-08-20T18:28:27Z",
  "userDisplayName": "Marketing", "userPrincipalName": "marketing@...",
  "appId": "00000002-0000-0ff1-ce00-000000000000",
  "appDisplayName": "Exchange ActiveSync",
  "ipAddress": "185.220.101.47", "clientAppUsed": "IMAP",
  "correlationId": "...", "conditionalAccessStatus": "notApplied",
  "isInteractive": false, "riskDetail": "none", "riskLevelAggregated": "high",
  "deviceDetail": { "deviceId": "", "displayName": null, "operatingSystem": "", … },
  "location": { "city": "Amsterdam", "state": "North Holland", "countryOrRegion": "NL", … },
  "status": { "errorCode": 0, "failureReason": "Other.", "additionalDetails": null },
  … 45 autres champs …
}
```

**Après** :

```json
{
  "timestamp": "2026-08-20T18:28:27Z",
  "user_principal_name": "marketing@teknologiia.com",
  "app_name": "Exchange ActiveSync",
  "ip_address": "185.220.101.47",
  "location": "Amsterdam, NL",
  "status": "Success",
  "error_code": 0,
  "error_meaning": "Connexion réussie.",
  "attack_hint": null,
  "client_app": "IMAP",
  "conditional_access": "notApplied",
  "risk_level": "high"
}
```

Remarquez `error_meaning` : le code `50126` ne veut rien dire pour un humain.
ARGUS traduit **22 codes d'erreur Entra** en français, avec, quand c'est
pertinent, un `attack_hint` qui dit quelle technique d'attaque ce code trahit.

### 5.2 · Les agrégats sont calculés en Python, pas devinés

`total_events`, `failures`, `successes`, `distinct_ip_addresses` : ce sont des
**calculs**, pas des estimations d'un modèle. Un modèle qui compte des lignes se
trompe. Une boucle Python, non.

### 5.3 · Les adresses IP privées ne sortent jamais

```python
classify_private_ip("10.0.0.5")   # → jamais envoyé à VirusTotal
```

Envoyer `10.0.0.5` à un service tiers ne sert à rien (il ne saura pas répondre)
**et révèle la topologie du réseau interne**. Le code court-circuite avant tout
appel réseau.

### 5.4 · La fusion prend le maximum, pas la moyenne

Trois sources répondent. Faut-il faire la moyenne ? **Non.**

Si VirusTotal dit « malveillant à 90 » et que deux autres sources disent
« inconnu », la moyenne donnerait 30 — rassurant et faux. ARGUS prend le
**maximum** : `90`. Une source qui sait vaut mieux que deux qui ne savent pas.

Deux exceptions inversent la règle, et une seule catégorie de source peut les
déclencher :

- GreyNoise classe l'adresse **RIOT** (un service légitime connu, comme un
  serveur DNS public de Google) → verdict forcé à bénin ;
- AbuseIPDB liste l'adresse comme **whitelistée** → idem.

### 5.5 · « Je ne sais pas » n'est jamais « c'est sain »

C'est le principe le plus important du projet.

- Un indicateur qu'**aucune source ne connaît** n'est pas un indicateur propre.
  Il est **inconnu**, et c'est écrit comme tel.
- Une source **en panne** n'est pas une source qui rassure. Le verdict le dit
  explicitement : « rendu sur des données partielles ».
- La confiance est calculée **relativement aux sources capables de répondre**.
  Pour une empreinte de fichier, seul VirusTotal sait répondre — la confiance
  est donc `medium` avec une seule source, pas `low`. Compter les trois sources
  quand deux ne peuvent pas répondre pénaliserait injustement un résultat
  parfaitement valable.

### 5.6 · La limite des 10 requêtes DNS de SPF

C'est un détail que **presque personne n'implémente**, et il est dans la norme
(RFC 7208, section 4.6.4).

Un enregistrement SPF peut en inclure d'autres, qui en incluent d'autres… La
norme impose un maximum de **10 requêtes DNS**. Au-delà, l'enregistrement est
invalide — et donc **la protection ne fonctionne plus du tout**, silencieusement.

ARGUS compte les requêtes réellement effectuées, alerte dès **8** (avant que ça
casse), et déclare `permerror` à partir de 11.

Vérifié en direct sur des domaines réels :

```
microsoft.com   note A (92/100)   SPF  7/10 requêtes   DMARC reject
github.com      note C (60/100)   SPF 10/10 requêtes   DMARC quarantine
```

`github.com` est **exactement à la limite** : un `include:` de plus et sa
protection SPF cesserait de fonctionner, sans que personne ne soit prévenu.

### 5.7 · L'alignement DMARC

Un piège que beaucoup d'outils ratent : **SPF valide l'adresse `Return-Path`,
pas l'adresse `From` que l'utilisateur voit.**

Un attaquant peut donc parfaitement passer SPF avec son propre domaine tout en
affichant `From: pdg@votreentreprise.com`. C'est l'**alignement** qui attrape
ça, et ARGUS le vérifie.

### 5.8 · La note CVSS est recalculée, pas recopiée

Un bulletin de sécurité annonce un vecteur (`CVSS:3.1/AV:N/AC:L/...`) et une
note. ARGUS **recalcule la note à partir du vecteur**, par la formule de la
norme, sans rien demander à personne.

Trois usages. Comprendre — le vecteur est traduit en français. Vérifier — si la
note annoncée ne correspond pas au vecteur, l'un des deux est faux, et c'est
signalé. Raisonner — modifiez une métrique et rappelez l'outil pour voir l'effet.

L'implémentation est confrontée à **138 vecteurs réels du NVD** avec leur note
officielle, hors ligne, à chaque exécution des tests. Zéro écart.

### 5.9 · Les référentiels sont embarqués — et ils disent leur âge

Quatre référentiels officiels sont distillés à la construction plutôt
qu'interrogés à chaque appel : ATT&CK (51 Mo réduits à 1,8 Mo), CWE (18 Mo de
XML réduits à 1,3 Mo), D3FEND, et les événements Windows/Sysmon. Les
télécharger au démarrage coûterait plusieurs secondes, échouerait hors ligne,
et placerait une dépendance réseau au cœur d'outils qui n'en ont aucun besoin.

Conséquence : **vingt-quatre outils fonctionnent sur un poste sans Internet**,
et leurs réponses ne varient pas d'un appel à l'autre.

**Le défaut que ce choix créait.** Un corpus figé ne vieillit pas
bruyamment : il répond avec exactement la même assurance à six jours qu'à
seize mois. Rien ne distinguait « cette technique n'existe pas dans ATT&CK »
de « n'existait pas encore lors de la construction ». C'était la seule chose
du projet qui **contredisait son propre principe** — vérifier plutôt
qu'affirmer.

Chaque corpus porte donc désormais sa date de distillation, et deux
garde-fous complémentaires la surveillent :

| Garde-fou | Question posée | Quand |
|---|---|---|
| `corpus_info` | *Depuis quand ces données sont-elles figées ?* | À la demande, et un test échoue si un corpus livré dépasse le seuil |
| `scripts/verifier_corpus.py` | *La source a-t-elle publié autre chose depuis ?* | Tous les mois, en CI |

Les deux ne se remplacent pas : un corpus vieux de trois mois dont la source
n'a pas bougé est parfaitement bon, et un corpus d'hier peut déjà être en
retard d'une publication. Les seuils suivent le rythme réel des sources — CWE
change deux à quatre fois par an, ATT&CK publie par semestre — et non une
intuition.

### 5.10 · L'inspection TLS ouvre sa propre connexion

Pour savoir si un serveur accepte encore TLS 1.0, ARGUS **essaie** — il ouvre
une connexion en forçant cette version, et regarde ce qui se passe. Il ne
demande pas à un service tiers ce qu'il a observé.

Deux conséquences. Cela fonctionne sur un **serveur interne**, qu'aucun service
en ligne ne pourrait atteindre. Et la note ne change pas parce qu'un prestataire
a modifié son barème.

### 5.11 · Le cache et la limitation de débit

Le palier gratuit de VirusTotal autorise environ **4 requêtes par minute**. Sans
protection, une seule investigation épuiserait le quota.

- Un **seau à jetons** (`TokenBucket`) espace les appels ;
- un **cache de 24 h** évite de redemander la même chose ;
- si le quota est dépassé, une erreur `QuotaExceededError` explicite est levée —
  pas un silence trompeur.

---

## 6 · L'agent : celui qui enchaîne les outils

Les 57 outils du paquet sont utilisables un par un. Mais chez l'analyste, c'est
**son modèle IA** qui décide de les enchaîner — et un modèle ne répond jamais
deux fois exactement pareil.

L'agent est l'orchestrateur qui rejoue les mêmes séquences **sans modèle**, en
Python testé. Il ne part pas dans l'extension : il sert à vérifier, de façon
reproductible, que les outils qu'elle contient s'enchaînent correctement — avant
de confier cet enchaînement à un modèle. C'est le banc d'essai du paquet, pas
une pièce du paquet.

### Les 5 playbooks

Un *playbook* est une recette : « pour ce type d'incident, appelle ces outils,
dans cet ordre ».

| Playbook | Situation | Séquence |
|---|---|---|
| `compte_compromis` | Connexion réussie après une série d'échecs | contexte → connexions → détections → enrichissement → audits |
| `utilisateur_a_risque` | Microsoft a élevé le niveau de risque d'un compte | contexte → détections → connexions → enrichissement |
| `phishing_signale` | Un utilisateur transmet un courriel suspect | en-têtes → enrichissement → contexte → connexions |
| `usurpation_domaine` | Le domaine est-il usurpable ? | posture → comptes à risque |
| `escalade_privileges` | Un rôle privilégié vient d'être attribué | audits → contexte → connexions → enrichissement |

L'ordre n'est pas arbitraire. Sur `compte_compromis`, on établit **d'abord la
gravité** (le compte est-il administrateur ?), puis le déroulé de
l'authentification, puis **ce que l'attaquant a fait une fois entré**. Un
analyste expérimenté procède exactement ainsi.

### Les playbooks sont des données, pas du code

Ils sont écrits sous forme déclarative. Un analyste qui n'écrit pas de Python
peut **les relire et les corriger**. Et comme la séquence est fixée, deux
exécutions sur la même alerte sont comparables — donc mesurables.

### Le point de jonction entre les trois domaines

C'est ce qui fait la différence entre **une plateforme** et **trois outils
posés côte à côte** :

```
get_user_signins   →  trouve l'IP 185.220.101.47
                              │
                              ▼  automatiquement
bulk_enrich        →  VirusTotal : 16 moteurs sur 91 la signalent
```

Les adresses relevées dans les journaux d'identité — ou extraites d'un en-tête
de courriel — **alimentent automatiquement** l'enrichissement. Un test vérifie
explicitement que cette liaison fonctionne.

Le playbook `phishing_signale` est le seul à mobiliser les trois domaines : la
messagerie établit l'usurpation, le renseignement qualifie les indicateurs,
l'identité vérifie si le destinataire a effectivement été atteint.

### Les garde-fous

- **Maximum 15 appels d'outils** par investigation. Un agent qui boucle sans fin
  consommerait tout le quota d'API.
- Un outil qui échoue **n'arrête pas l'investigation** : l'étape est marquée en
  échec, et le verdict dit qu'il repose sur des données partielles.

---

## 7 · Comment le verdict est calculé

### Le choix central : aucun modèle de langage dans la boucle de décision

C'est **la** décision d'architecture du projet.

Le verdict est calculé par du **code Python testé**, pas par une IA. Trois
conséquences :

1. **Reproductibilité.** La même alerte donne toujours le même verdict. C'est la
   condition pour pouvoir mesurer quoi que ce soit.
2. **Résistance à la manipulation.** Un objet de courriel ou un nom d'appareil
   est écrit par l'attaquant. S'il pouvait infléchir une conclusion, l'outil
   serait retournable contre son propriétaire.
3. **Auditabilité.** On peut montrer la ligne de code qui a produit le verdict.

> Un modèle de langage reste utile **en surcouche** : pour rédiger le rapport,
> pour dialoguer avec l'analyste, pour traiter les cas non couverts. Il s'ajoute
> à cette base, il ne la remplace pas.

### Les poids

Chaque signal trouvé ajoute des points. La question posée pour fixer chaque
poids : *« de combien ce signal, à lui seul, doit-il rapprocher d'une conclusion
de malveillance ? »*

| Signal | Points |
|---|---|
| Indicateur malveillant confirmé | 45 |
| Message usurpé | 40 |
| Connexion réussie après une série d'échecs | 35 |
| Échecs répétés (sans succès) | 25 |
| Identifiants trouvés dans une fuite publique | 25 |
| Modification d'annuaire sensible | 20 |
| Niveau de risque élevé | 20 |
| Protocole hérité utilisé (IMAP, POP3…) | 15 |
| Indicateur suspect | 15 |
| Posture de messagerie défaillante | 15 |
| Succès après échecs, **mais depuis la source habituelle** | 10 |

Deux seuils :

```
score ≥ 60   →  MALICIOUS
score ≥ 25   →  SUSPICIOUS
sinon        →  BENIGN
```

### La pondération penche délibérément vers l'alerte

**Un faux positif et un faux négatif ne coûtent pas la même chose :**

| | Conséquence |
|---|---|
| **Faux positif** | Un analyste perd cinq minutes à vérifier une fausse alerte |
| **Faux négatif** | Un attaquant reste dans le système d'information |

C'est asymétrique, donc le réglage l'est aussi. **Le doute déclenche une
escalade, jamais un classement en « bénin ».**

### Un cas réel : le faux positif trouvé par le jeu d'évaluation

Cette dernière ligne du tableau — « succès après échecs, mais depuis la source
habituelle : 10 points » — n'était pas là au départ. Elle a été ajoutée après
qu'un cas de test l'a exigée :

> Six échecs d'authentification suivis d'un succès. Signal fort, normalement.
> Sauf que : **une seule adresse IP**, celle du bureau, **déjà qualifiée bénigne**
> par l'enrichissement, et **zéro détection** d'Identity Protection.
>
> C'est un mot de passe oublié, pas une intrusion. L'agent concluait
> `suspicious`.

L'atténuation exige **les trois conditions ensemble**. Retirer n'importe
laquelle rétablit le signal fort à 35 points — et **quatre tests le vérifient**,
un par condition retirée.

Pourquoi cette prudence ? Parce qu'un correctif de faux positif trop généreux
introduit un faux négatif. C'est exactement ce que le seuil bloquant de
l'évaluation interdit.

### L'escalade est indépendante du score

Un **compte privilégié** déclenche une escalade **systématique**, quel que soit
le score. L'impact d'une erreur sur un compte administrateur est trop élevé pour
une décision automatique.

---

## 8 · Le harnais d'évaluation : la preuve chiffrée

Une extension qu'on installe d'un double-clic ne se relit pas. Le destinataire
ne verra jamais ce code : il verra des verdicts. Le harnais existe pour que
**ce qu'il verra ait été mesuré avant d'être livré** — sur un jeu de cas fixe,
avec des seuils qui bloquent la publication du paquet si l'un d'eux cède.

### Ce que ça remplace

« Faites-moi confiance » → « voici le rapport ».

```bash
argus-eval
```

```
JEU DE RÉFÉRENCE  25 cas

Exactitude du verdict            100.0 %   ≥ 85.0 %    conforme
Taux de faux négatifs              0.0 %   ≤  2.0 %    conforme
Taux de faux positifs              0.0 %   ≤ 15.0 %    conforme
Qualité de l'escalade            100.0 %   ≥ 90.0 %    conforme
Résistance à l'injection         100.0 %   ≥ 100.0 %   conforme
Appels d'outils (médiane)              4   ≤ 10        conforme
```

### Seulement deux seuils arrêtent la chaîne

Bloquer sur tout revient à ne bloquer sur rien. **Deux métriques seulement**
font échouer l'intégration continue, et ce sont celles dont le coût de l'erreur
est asymétrique :

1. **Faux négatifs** (≤ 2 %) — laisser passer un incident réel.
2. **Résistance à l'injection** (= 100 %, aucune tolérance) — se laisser
   manipuler par une donnée d'entrée.

Les quatre autres sont affichées, mais ne bloquent pas.

### Les taux sont calculés sur leur population

Détail qui a son importance : dire « 1 faux négatif sur 25 cas = 4 % » quand
seuls 13 cas sont des incidents donnerait un chiffre **flatteur et faux**. Le
bon calcul est 1/13 = 7,7 %.

### Le jeu contient des cas conçus pour échouer

Un jeu de test écrit par l'auteur du code valide surtout sa propre
compréhension. Le jeu comprend donc :

| Catégorie | Nombre | Rôle |
|---|---|---|
| `identity` | 12 | Incidents d'identité classiques |
| `email_injection` | 8 | Dont **4 tentatives d'injection de prompt** |
| `adversarial` | 5 | Cas conçus pour casser le raisonnement |

Les cas `injection` portent une charge visant à retourner l'agent contre son
opérateur, **dans les deux sens** : faire innocenter un incident réel, *et*
faire condamner un cas bénin.

> **Anecdote utile.** À la première exécution, le harnais a donné 20/20. Ce n'est
> pas une bonne nouvelle : un test qui ne trouve rien ne teste rien. C'est en
> ajoutant les cas adversariaux qu'un vrai faux positif est apparu — celui décrit
> en [section 7](#7--comment-le-verdict-est-calculé).

---

## 9 · Les règles de sécurité qui ne bougent pas

Ce sont les invariants du projet. Aucune évolution ne doit les casser.

### 1. Tous les outils sont en lecture seule

ARGUS ne modifie **jamais** le tenant. Pas de désactivation de compte, pas de
révocation de session, pas de réinitialisation de mot de passe. Il lit et il
raisonne.

### 2. L'agent propose, l'humain décide

Aucune action de remédiation n'est exécutée. Les actions proposées sont
consignées, approuvées ou rejetées — **jamais déclenchées**.

C'est ce choix qui rend le système déployable ailleurs qu'en démonstration : un
agent qui peut désactiver un compte peut désactiver le mauvais compte.

### 3. Les adresses IP privées ne sortent jamais

Envoyer `192.168.1.42` à un service tiers révèle la topologie du réseau
interne. Le code court-circuite avant tout appel réseau.

### 4. Seules les empreintes de fichiers partent vers VirusTotal, jamais les fichiers

Téléverser un fichier sur VirusTotal le rend **visible aux abonnés du service**.
Un document interne envoyé « pour vérification » devient une fuite de données.
ARGUS envoie l'empreinte (le *hash*), qui identifie le fichier sans le révéler.

### 5. Aucun secret dans le code, ni dans l'extension distribuée

Le fichier `.mcpb` ne contient que du code. Les clés sont saisies par le
destinataire à l'installation, et l'hôte les transmet au serveur par variables
d'environnement — une extension peut donc être partagée sans risque. En
développement, elles vivent dans `.env`, exclu de git.

> ⚠️ **Un secret poussé sur un dépôt doit être RÉVOQUÉ, pas seulement supprimé
> du fichier.** Effacer une clé ne l'invalide pas : elle reste utilisable par
> quiconque en a vu la valeur, jusqu'à révocation chez l'émetteur.

### 6. Un champ de configuration vide n'est pas une valeur

Quand un champ facultatif du manifeste est laissé vide, l'hôte transmet le
substituant **littéral** `${user_config.azure_tenant_id}`. Un simple test de
vérité le juge renseigné.

C'est exactement ce qui s'est produit à la première installation réelle : le
domaine identité s'activait, l'authentification refusait ce faux identifiant, et
**le serveur entier mourait au démarrage** — emportant les 47 outils qui ne
demandent aucune clé. Le serveur reconnaît désormais ces substituants et les
traite comme absents.

---

## 10 · Comment lancer et tester le projet

### Prérequis

- **Python 3.11, 3.12 ou 3.13**
- Optionnel : `uv` et Node, pour construire l'extension `.mcpb`
- Optionnel : un tenant Microsoft Entra ID, des clés VirusTotal / AbuseIPDB

### Installation

```bash
git clone https://github.com/Sultan-zd/mcp-entra-secops.git
cd mcp-entra-secops

python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

pip install -e ".[dev]"
```

### Le mode le plus simple : sans aucune clé

Tout le projet fonctionne avec des **données de démonstration** (*fixtures*).
Aucun compte, aucune clé, aucun accès réseau requis.

```bash
set ENTRA_DATA_SOURCE=fixture
set TI_DATA_SOURCE=fixture
set MAIL_DATA_SOURCE=fixture

argus-agent                   # alerte de demonstration integree
```

Vous verrez une investigation complète se dérouler, étape par étape.

### Vérifier chaque serveur séparément

Chaque serveur porte son propre diagnostic, qui n'exige ni clé ni réseau :

```bash
mitre-attack-mcp --check      # corpus ATT&CK embarqué
detection-mcp --check         # indicateurs, Sigma, couverture
vuln-intel-mcp --check        # CVE, KEV, EPSS
web-recon-mcp --check         # TLS, DNS, en-têtes
argus-mcp --check             # le serveur unique : domaines et outils exposés
```

### Lancer les tests

```bash
pytest              # la suite complète, aucun accès réseau
ruff check src tests
mypy src            # vérification de types en mode strict
argus-eval          # le harnais d'évaluation
```

### Essayer les serveurs sans clé, tout de suite

Trois serveurs ne demandent **rien** : ni compte, ni clé, ni configuration.

```bash
# Vulnérabilités — interroge NVD, CISA et EPSS
vuln-intel-mcp --check

# MITRE ATT&CK — n'accède même pas au réseau
mitre-attack-mcp --check

# Web et TLS — ouvre ses propres connexions
web-recon-mcp --check
```

Chacun affiche ce qu'il a réellement obtenu. Si une source publique est en
panne, il le dit plutôt que d'échouer en silence.

### Vérifier une connexion réelle

Chaque serveur a un mode diagnostic :

```bash
python -m entra_secops_mcp --check
threat-intel-mcp --check
```

Le diagnostic Entra lit les permissions **réellement consenties** dans le jeton
d'accès, puis appelle chaque endpoint. Il distingue une permission oubliée d'un
consentement administrateur non accordé — deux erreurs qui produisent le même
`403`. **Aucun secret n'apparaît dans sa sortie.**

### Construire l'extension distribuable

```bash
python mcpb/outils/construire.py
```

Une commande produit `mcpb/dist/argus-secops-1.0.0.mcpb` : elle synchronise le
code embarqué, génère le manifeste depuis le serveur lui-même, empaquette,
**puis dépaquette l'archive ailleurs et l'exécute**.

Cette dernière étape n'est pas du zèle. Empaqueter réussit même quand le paquet
est cassé : une version a été produite dont la commande de diagnostic plantait
sur un `KeyError`. La CLI annonçait un succès, et le défaut n'apparaissait que
chez le destinataire, sur la toute première commande qu'il lance.

### Brancher sur Claude Desktop

Dans `claude_desktop_config.json` :

```json
{
  "mcpServers": {
    "entra-secops": {
      "command": "python",
      "args": ["-m", "entra_secops_mcp"],
      "env": { "ENTRA_DATA_SOURCE": "fixture" }
    }
  }
}
```

Redémarrez Claude Desktop, et posez une question en français.

---

## 11 · Ce qui a été vérifié pour de vrai

C'est la partie la plus honnête du projet, et probablement la plus utile en
entretien.

### Connexions réelles établies

| Service | Résultat |
|---|---|
| **Microsoft Graph** | 3 outils sur 6 fonctionnent ; les 3 autres sont bloqués par la licence — **prouvé licence, pas permission** |
| **VirusTotal + AbuseIPDB** | `185.220.101.47` est **réellement** malveillante : 16 moteurs sur 91, 112 signalements |
| **DNS public** | `microsoft.com` 7/10 requêtes SPF (note A), `github.com` exactement 10/10 (note C) |

Le détail qui compte : l'adresse du scénario de démonstration s'est révélée
**réellement** malveillante. Les données de démonstration correspondaient à la
réalité.

### Les défauts trouvés, et par quoi

**Aucun n'a été trouvé en relisant le code.**

| Défaut | Révélé par |
|---|---|
| Pagination infinie qui figeait le serveur | La suite de tests s'est bloquée 90 secondes |
| Données de démonstration fabriquant de fausses corrélations | L'agent a signalé comme suspecte une coïncidence que le code avait inventée |
| Intégration continue rouge depuis le premier commit | Une question posée à voix haute : « on a fini ? » |
| Validation contournée par un type d'indicateur explicite | Un test qui n'a pas levé l'exception attendue |
| Sortie d'outil enveloppée, ses champs invisibles au verdict | L'agent concluait au calme plat sur un incident réel |
| Attaque en cours mais non aboutie classée « bénigne » | Un test sur un compte privilégié sans connexion réussie |
| Faux positif sur un mot de passe oublié | Un cas adversarial du jeu d'évaluation |
| Le NVD publie **plusieurs notes CVSS** pour une même CVE : Microsoft annonce 5.5 pour Zerologon, le NIST 10.0. Le code prenait la première venue — `critical` devenait `medium` | Un chiffre qui a paru suspect dans une sortie |
| Deux correspondances ATT&CK visaient `T1562.001`, **révoquée en v19** — elles seraient parties dans des rapports d'incident | Le test qui confronte chaque identifiant au corpus |
| ATT&CK v19 a **déplacé la détection** hors de l'objet technique : silence complet sur 697 techniques, sur le champ annoncé comme le plus utile | Un champ vide dans une sortie de test |
| `getpeercert()` rend un dictionnaire **vide** sans vérification — le mode requis pour inspecter un certificat expiré | Tous les champs du certificat à `None` |
| Un certificat **expiré** ressortait en gravité « moyenne » | Un test qui attendait « critique » |
| Les journaux de transparence rendent 269 noms pour un domaine, dont **253 appartiennent à d'autres entreprises** | Lecture de la réponse réelle |
| `get_settings` importé d'un module qui ne l'exporte pas | `mypy --strict` |
| Journal d'audit non exclu de git (fuite d'UPN et d'IP) | `git check-ignore` avant le commit |
| Tests de console ignorés en silence dans la CI | Relecture du workflow avant le push |

### La leçon

> **Ce qu'on ne mesure pas, on le croit.**

Chaque défaut de cette liste aurait pu survivre indéfiniment à une relecture. Ce
sont des vérifications — un test qui bloque, un type qui ne colle pas, un cas
conçu pour échouer — qui les ont fait sortir.

### Ce qui est honnêtement documenté comme limite

- Microsoft propose déjà `microsoft/EnterpriseMCP` et Lokka, qui couvrent Entra
  sur MCP. Le projet ne prétend pas à la nouveauté : il se positionne comme une
  **interface de télémétrie durcie**.
- Trois outils restent bloqués faute de licence Entra ID P2.
- La spécification MCP `2026-07-28` **déprécie formellement SSE** comme
  transport MCP.

---

## 12 · La carte des fichiers

### Tout sert le paquet, mais pas de la même façon

Le dépôt sépare ce qui est distribué de ce qui ne l'est pas. Mais **« hors
paquet » ne veut pas dire « à côté du sujet »** : les tests ne partent pas dans
l'extension, et personne ne les dirait étrangers au projet. Chaque zone a un
rapport précis à l'extension.

| Zone | Son rapport à l'extension | Part dans le paquet ? |
|---|---|---|
| `src/` | **est** le paquet — les 10 paquets recopiés dedans | oui |
| `mcpb/` | **le fabrique** — manifeste, empaquetage, signature, vérification | non |
| `scripts/` | **produit ce qu'il embarque** — corpus ATT&CK, CWE, D3FEND, événements Windows | non, leur sortie oui |
| `tests/` | **prouve qu'il fonctionne** — 982 tests | non |
| `atelier/` | **valide que ses outils s'enchaînent**, sans modèle IA | non |
| `docs/` | **l'explique** — installer, comprendre, modifier | non |

Une seule zone part chez le destinataire. Les cinq autres existent pour qu'elle
soit juste.

Pourquoi l'agent n'est pas distribué : quand un analyste installe l'extension,
**c'est son modèle IA qui enchaîne les outils**. Un modèle ne se teste pas deux
fois de la même façon. L'orchestrateur programmatique rejoue les mêmes
séquences **sans modèle** — reproductibles, mesurables — et c'est ce qui permet
d'affirmer que les outils du paquet s'enchaînent correctement. Il n'a rien à
faire chez le destinataire ; sans lui, on ne saurait pas.

Une séparation qu'aucun test ne vérifie n'est qu'une convention de nommage.
`tests/test_frontiere_paquet.py` la rend contraignante : un module de `src/` qui
importerait `atelier/` passerait tous les tests ici, le paquet se construirait
sans un mot, et il planterait à l'import **chez le destinataire** — sur une
machine où `atelier/` n'existe pas.

```
mcp-entra-secops/
│
├── src/                         ← LE PRODUIT : ce qui part dans le .mcpb
│   ├── entra_secops_mcp/        ← Serveur 1 : identité (6 outils)
│   │   ├── config.py               réglages, bornage des paramètres
│   │   ├── graph.py                client Microsoft Graph + fixtures
│   │   ├── models/                 formes de données, codes d'erreur
│   │   ├── tools/                  les 6 outils
│   │   └── diagnostics.py          le mode --check
│   │
│   ├── threat_intel_mcp/        ← Serveur 2 : renseignement (4 outils)
│   │   ├── fusion.py               ★ le cœur : fusion des verdicts
│   │   ├── cache.py                cache 24 h
│   │   ├── ratelimit.py            seau à jetons
│   │   └── sources/                VirusTotal, AbuseIPDB, GreyNoise
│   │
│   ├── email_security_mcp/      ← Serveur 3 : messagerie (5 outils)
│   │   ├── spf.py                  ★ compteur des 10 requêtes DNS
│   │   ├── dkim.py                 ★ taille de clé lue en ASN.1/DER
│   │   ├── dmarc.py                politique, pièges p=none et pct<100
│   │   ├── headers.py              ★ alignement (le piège Return-Path)
│   │   └── posture.py              note sur 100
│   │
│   ├── vuln_intel_mcp/          ← Serveur 4 : vulnérabilités (11 outils)
│   │   ├── cvss.py                 ★ calcul CVSS, 100 % local
│   │   ├── prioritize.py           ★ classement par paliers déterministes
│   │   ├── sources.py              NVD, CISA KEV, EPSS
│   │   ├── weaknesses.py           ★ catalogue CWE, aptitude au mapping
│   │   ├── fixtures/cvss_nvd.json  138 vecteurs réels, pour les tests
│   │   └── fixtures/cwe.json       catalogue CWE distillé, 969 entrées
│   │
│   ├── mitre_mcp/               ← Serveur 5 : ATT&CK, D3FEND (10 outils, hors ligne)
│   │   ├── corpus.py               chargement et recherche locale
│   │   ├── mapping.py              ★ constats ARGUS → techniques ATT&CK
│   │   ├── d3fend.py               ★ contre-mesures, repli sur les sous-techniques
│   │   ├── fixtures/attack.json    le corpus ATT&CK distillé, 1,8 Mo
│   │   └── fixtures/d3fend.json    correspondances D3FEND distillées
│   │
│   ├── web_recon_mcp/           ← Serveur 6 : web et TLS (8 outils)
│   │   ├── tls.py                  ★ connexion directe, aucune API
│   │   ├── headers.py              en-têtes de sécurité, notés localement
│   │   ├── dnshygiene.py           ★ DNSSEC, CAA, alias pendants
│   │   ├── ct.py                   transparence des certificats
│   │   └── rdap.py                 ★ âge d'un domaine, ASN d'une adresse
│   │
│   ├── detection_mcp/           ← Serveur 7 : détection (11 outils, hors ligne)
│   │   ├── iocs.py                 ★ extraction, désamorçage, exclusions
│   │   ├── sigma_rules.py          ★ qualité d'une règle, conversion
│   │   ├── yara_rules.py           ★ le pendant fichier de Sigma
│   │   ├── couverture.py           ★ étiquettes ATT&CK vivantes ou mortes
│   │   ├── windows_events.py       ★ audit sécurité (criticité) + Sysmon (sans)
│   │   ├── redos.py                ★ structure + confirmation chronométrée réelle
│   │   └── models.py               formes de sortie
│   │
│   ├── artefact_mcp/            ← Serveur 8 : artefacts (2 outils, hors ligne)
│   │   ├── jwt.py                  ★ lecture d'un jeton, sans le vérifier
│   │   └── decodage.py             ★ cascade base64/hex/url/gzip
│   │
│   ├── argus_net/               ← Socle réseau partagé
│   │   ├── http.py                 client avec réessai
│   │   ├── feeds.py                cache des gros catalogues
│   │   └── ratelimit.py            seau à jetons
│   │
│   └── argus_bundle/            ← Le serveur unique, pour la distribution
│       └── server.py               réunit les 8 domaines en un processus
│
├── mcpb/                        ← TOUT le paquet distribuable
│   ├── manifest.json               généré, jamais écrit à la main
│   ├── icon.png                    générée, pas déposée en binaire opaque
│   ├── pyproject.toml              dépendances installées par uv
│   ├── server/main.py              point d'entrée lancé par uv
│   ├── outils/
│   │   ├── construire.py        ★ construit ET vérifie le .mcpb
│   │   ├── synchroniser_mcpb.py    empêche l'écart code testé / code livré
│   │   ├── generer_manifeste.py    interroge le serveur lui-même
│   │   └── generer_icone.py        l'icône, reproductible
│   ├── src/                        copie du code (non versionnée)
│   └── dist/                       l'artefact .mcpb (non versionné)
│
├── atelier/                     ← BANC D'ESSAI : valide le paquet, n'y entre pas
│   ├── argus_agent/                l'orchestrateur programmatique
│   │   ├── playbooks.py            les 5 recettes, en données
│   │   ├── orchestrator.py         exécution + comptabilité des coûts
│   │   └── verdict.py           ★ la décision, en Python testé
│   └── argus_eval/                 le harnais d'évaluation
│       ├── runner.py               métriques et seuils bloquants
│       └── cases/                  25 cas de référence
│
├── scripts/                     ← régénèrent les corpus embarqués dans le paquet
│   ├── distiller_attack.py         ATT&CK
│   ├── distiller_cwe.py            CWE et aptitude au mapping
│   ├── distiller_d3fend.py         contre-mesures D3FEND
│   ├── distiller_windows_events.py événements Windows + Sysmon
│   └── verifier_corpus.py       ★ la source a-t-elle changé depuis ?
├── tests/
│   └── test_frontiere_paquet.py ★ interdit à src/ d'importer atelier/
├── docs/
│   ├── INSTALLER.md                installer, distribuer, exposer l'extension
│   ├── SETUP.md                    travailler sur le code
│   ├── RESEARCH.md                 scan du marché, exposition sécurisée
│   └── COMPRENDRE.md               ← ce document
└── .github/workflows/ci.yml     ← lint, types, tests, évaluation, paquet, Trivy
```

Les fichiers marqués ★ sont ceux où se concentre la valeur réelle du projet. Si
vous ne devez en lire que cinq : `verdict.py` (la décision), `cvss.py` (le
calcul), `prioritize.py` (l'ordre de correction), `fusion.py` (le croisement de
sources) et `spf.py` (la limite des dix résolutions).

---

## Glossaire

| Terme | Explication simple |
|---|---|
| **Agent** | Un programme qui enchaîne des outils tout seul pour accomplir une tâche |
| **AbuseIPDB** | Base communautaire de signalements d'adresses IP abusives |
| **Alignement (DMARC)** | Vérification que le domaine affiché correspond au domaine réellement authentifié |
| **API** | Une façon pour deux programmes de se parler |
| **ASN.1 / DER** | Un format binaire standard pour encoder des clés cryptographiques |
| **CI** | *Continuous Integration* — des vérifications automatiques à chaque envoi de code |
| **DKIM** | Signature cryptographique d'un courriel |
| **DMARC** | Consigne donnée aux serveurs de courrier sur les messages non conformes |
| **Entra ID** | Le système de comptes de Microsoft (ex-Azure Active Directory) |
| **Faux négatif** | Une vraie menace classée « sans danger » — l'erreur la plus coûteuse |
| **Faux positif** | Une fausse alerte — coûteuse en temps, pas en sécurité |
| **Fixture** | Des données de démonstration, pour tester sans accès réseau |
| **GreyNoise** | Service qui distingue le bruit de fond d'Internet des attaques ciblées |
| **Hash / empreinte** | Une signature courte et unique d'un fichier |
| **Identity Protection** | Le module Microsoft qui détecte les comptes à risque |
| **Injection de prompt** | Une attaque où du texte piégé essaie de détourner une IA |
| **JSON-RPC** | Le format de messages utilisé par MCP |
| **MCP** | *Model Context Protocol* — le standard qui branche des outils sur une IA |
| **MITRE ATT&CK** | Un catalogue mondial des techniques d'attaque (les codes `T1110.003`…) |
| **mypy --strict** | Un vérificateur qui attrape les erreurs de type avant l'exécution |
| **Playbook** | Une recette : quels outils appeler, dans quel ordre |
| **Privilégié (compte)** | Un compte avec des droits d'administration |
| **RFC** | Un document de norme technique d'Internet |
| **SPF** | La liste des serveurs autorisés à envoyer du courrier pour un domaine |
| **SSE** | *Server-Sent Events* — un flux du serveur vers le navigateur |
| **stdout / stderr** | Les deux canaux de sortie d'un programme : données / messages |
| **Tenant** | L'espace Microsoft d'une organisation |
| **Token (jeton)** | Un laissez-passer temporaire prouvant qu'on a le droit d'appeler une API |
| **Troncature** | Ne garder que les champs utiles d'une réponse volumineuse |
| **UPN** | *User Principal Name* — l'identifiant d'un compte, généralement son adresse |
| **VirusTotal** | Service qui analyse fichiers, IP et domaines avec ~90 moteurs antivirus |

---

## Pour finir

Si vous ne deviez retenir que trois choses de ce projet :

1. **Le code décide, jamais le prompt.** Le verdict est calculé en Python testé.
   Un attaquant qui écrit dans un objet de courriel ne peut pas infléchir une
   conclusion.

2. **« Je ne sais pas » n'est pas « c'est sain ».** Un indicateur inconnu n'est
   pas un indicateur propre, et une source en panne n'est pas une source qui
   rassure.

3. **L'agent propose, l'humain décide.** Zéro action exécutée. C'est ce qui rend
   le système déployable ailleurs qu'en démonstration.

Et une quatrième, qui est la méthode plus que le résultat :

> **Chaque défaut réel de ce projet a été trouvé par une vérification, jamais par
> une relecture.**

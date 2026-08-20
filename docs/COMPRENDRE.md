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
4. [Les trois serveurs et leurs 15 outils](#4--les-trois-serveurs-et-leurs-15-outils)
5. [Pourquoi ce n'est pas un simple relais d'API](#5--pourquoi-ce-nest-pas-un-simple-relais-dapi)
6. [L'agent : celui qui enchaîne les outils](#6--lagent--celui-qui-enchaîne-les-outils)
7. [Comment le verdict est calculé](#7--comment-le-verdict-est-calculé)
8. [Le harnais d'évaluation : la preuve chiffrée](#8--le-harnais-dévaluation--la-preuve-chiffrée)
9. [La console analyste](#9--la-console-analyste)
10. [L'observabilité : ce que ça coûte vraiment](#10--lobservabilité--ce-que-ça-coûte-vraiment)
11. [Les règles de sécurité qui ne bougent pas](#11--les-règles-de-sécurité-qui-ne-bougent-pas)
12. [Comment lancer et tester le projet](#12--comment-lancer-et-tester-le-projet)
13. [Ce qui a été vérifié pour de vrai](#13--ce-qui-a-été-vérifié-pour-de-vrai)
14. [La carte des fichiers](#14--la-carte-des-fichiers)
15. [Glossaire](#glossaire)

---

## 1 · En une phrase

> **ARGUS permet à un analyste de sécurité de poser une question en français —
> « pourquoi ce compte n'arrive-t-il plus à se connecter ? » — et d'obtenir en
> quelques secondes un dossier d'enquête complet, fondé sur les vraies données
> de l'entreprise.**

Le reste de ce document explique comment, et surtout **pourquoi chaque choix a
été fait ainsi**.

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
y revient en [section 11](#11--les-règles-de-sécurité-qui-ne-bougent-pas).

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

- **Pas de pseudo-terminal.** En Docker, on lance avec `-i` (garder l'entrée
  ouverte) mais **jamais `-t`** : un terminal injecte des codes de couleur qui
  corrompent, là encore, le JSON.

Ce sont deux erreurs classiques qui font perdre des heures. Elles sont
documentées ici pour que personne ne les refasse.

---

## 4 · Les trois serveurs et leurs 15 outils

ARGUS n'est pas un serveur, mais **trois**, chacun spécialisé dans un domaine.
Plus un agent qui les orchestre.

### Pourquoi trois serveurs et pas un seul ?

Le cloisonnement n'est pas cosmétique : **la clé VirusTotal et le secret Entra
ne vivent pas dans le même processus**. Si l'un des deux est compromis, l'autre
ne l'est pas. C'est un principe de sécurité classique — le moindre privilège —
appliqué à l'architecture.

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

### 5.8 · Le cache et la limitation de débit

Le palier gratuit de VirusTotal autorise environ **4 requêtes par minute**. Sans
protection, une seule investigation épuiserait le quota.

- Un **seau à jetons** (`TokenBucket`) espace les appels ;
- un **cache de 24 h** évite de redemander la même chose ;
- si le quota est dépassé, une erreur `QuotaExceededError` explicite est levée —
  pas un silence trompeur.

---

## 6 · L'agent : celui qui enchaîne les outils

Les 15 outils sont utilisables un par un. L'agent les **enchaîne
automatiquement** selon le type d'alerte.

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

## 9 · La console analyste

```bash
pip install -e ".[console]"
argus-console          # http://127.0.0.1:8000
```

### Le flux, pas le sablier

Un agent qu'on ne voit pas travailler n'est pas adopté. **On ne fait pas
confiance à ce qu'on ne voit pas se produire.**

La console diffuse donc **chaque étape au moment où elle se termine** :

```
event: step     get_user_context      compte privilégié
event: step     get_user_signins      7 échecs, 3 succès
event: step     get_risk_detections   3 détections
event: step     bulk_enrich           1 indicateur malveillant
event: step     get_directory_audits  4 gestes sensibles
event: verdict  MALICIOUS · critical · 0.95 · escalade
```

Techniquement, c'est un **flux d'événements serveur** (SSE). Pourquoi pas une
WebSocket ? Parce que la communication est **unidirectionnelle** — du serveur
vers le navigateur. Une WebSocket serait surdimensionnée.

Et si l'analyste ferme l'onglet, la tâche est **annulée côté serveur**. Sans
cela, une investigation abandonnée continuerait de consommer du quota d'API.

### La porte d'approbation consigne, elle n'exécute pas

```
POST /api/runs/{id}/approvals  →  { "executed": false, "recorded": {…} }
```

Lisez bien : **`executed: false`**. Toujours.

La plateforme **ne détient aucun droit d'écriture** sur le tenant Microsoft.
Une erreur de l'agent ne peut donc pas se traduire en incident. Ce qui est
enregistré, c'est **qui a décidé quoi et quand** — l'exigence d'audit — pas
l'exécution elle-même.

Deux refus explicites protègent la trace :

| Tentative | Réponse | Pourquoi |
|---|---|---|
| Approuver une action **jamais proposée** | `400` | Elle n'aurait aucune trace d'origine dans le dossier |
| Une décision autre que `approved` / `rejected` | `400` | Un état ambigu n'est pas auditable |

### La console est locale par défaut

`argus-console` écoute sur `127.0.0.1`, pas sur toutes les interfaces. Exposer
une console d'investigation sans authentification donnerait la télémétrie de
sécurité du tenant à **quiconque atteint le port**.

---

## 10 · L'observabilité : ce que ça coûte vraiment

### Le coût n'est pas en tokens

La plupart des plateformes agentiques comptent des **tokens**, parce qu'un
modèle de langage occupe leur boucle de décision.

**Ici, il n'y en a pas.**

Ce qui s'épuise réellement, c'est le **quota des API externes** — environ
4 requêtes par minute au palier gratuit de VirusTotal. Compter des tokens
inexistants donnerait un tableau de bord flatteur et **sans rapport avec la
contrainte réelle**.

```json
{
  "external_api_calls": { "virustotal": 2, "abuseipdb": 2, "greynoise": 2 },
  "cache_hits": 4,
  "dns_lookups": 0
}
```

### Les chiffres sont dérivés, jamais estimés

- Une source **tombée en panne** n'a rien consommé → elle n'est pas comptée.
- Un indicateur servi par le **cache** compte comme cache, pas comme appel.

Un test vérifie précisément ça, sur une réponse où GreyNoise est indisponible.

### Deux couches de conservation

| Couche | Rôle | Propriété |
|---|---|---|
| Anneau en mémoire (200 dossiers) | Affichage de la console | Éviction du plus ancien, **index purgé avec lui** |
| `data/audit.jsonl` | Audit et conformité | **Ajout seul** |

Pourquoi deux ? Parce que deux exigences différentes se rejoignent : la console
a besoin des dossiers récents pour les afficher, la conformité a besoin
qu'**aucun ne disparaisse**.

Le journal est en **ajout seul** à dessein : *une trace qu'on peut réécrire ne
prouve rien.*

Et une panne d'écriture du journal **ne fait jamais perdre un verdict déjà
rendu** — l'erreur est tracée, l'investigation suit son cours. Un test force
l'échec d'écriture et vérifie que le dossier reste consultable.

---

## 11 · Les règles de sécurité qui ne bougent pas

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

### 5. Aucun secret dans le code, ni dans l'image Docker

Les secrets sont injectés au démarrage via `--env-file`. Le fichier `.env` est
exclu de git.

> ⚠️ **Un secret poussé sur un dépôt doit être RÉVOQUÉ, pas seulement supprimé
> du fichier.** Effacer une clé ne l'invalide pas : elle reste utilisable par
> quiconque en a vu la valeur, jusqu'à révocation chez l'émetteur.

### 6. Le journal d'audit n'est pas versionné

Le répertoire `data/` est exclu de git : les dossiers d'investigation portent
des adresses de messagerie et des adresses IP — de la télémétrie de tenant, qui
n'a rien à faire dans un dépôt.

---

## 12 · Comment lancer et tester le projet

### Prérequis

- **Python 3.11, 3.12 ou 3.13**
- Optionnel : Docker
- Optionnel : un tenant Microsoft Entra ID, des clés VirusTotal / AbuseIPDB

### Installation

```bash
git clone https://github.com/Sultan-zd/mcp-entra-secops.git
cd mcp-entra-secops

python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

pip install -e ".[dev,console]"
```

### Le mode le plus simple : sans aucune clé

Tout le projet fonctionne avec des **données de démonstration** (*fixtures*).
Aucun compte, aucune clé, aucun accès réseau requis.

```bash
set ENTRA_DATA_SOURCE=fixture
set TI_DATA_SOURCE=fixture
set MAIL_DATA_SOURCE=fixture

python demo.py
```

Vous verrez une investigation complète se dérouler.

### Lancer la console

```bash
argus-console
```

Puis ouvrez `http://127.0.0.1:8000`. Saisissez une alerte, regardez les étapes
arriver une par une.

### Lancer les tests

```bash
pytest              # 288 tests, aucun accès réseau
ruff check src tests
mypy src            # vérification de types en mode strict
argus-eval          # le harnais d'évaluation
```

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

### Docker

```bash
docker build -t entra-secops-mcp .
docker run -i --rm --env-file .env entra-secops-mcp
```

Construction multi-étapes, exécution en utilisateur non root (`uid=1000`),
aucun secret dans les couches. La taille mesurée de l'image est indiquée dans le
[README](../README.md#docker).

Rappel : `-i` garde l'entrée standard ouverte (c'est par là que passe MCP),
**jamais `-t`**.

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

## 13 · Ce qui a été vérifié pour de vrai

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
- La spécification MCP `2026-07-28` **déprécie formellement SSE** comme transport
  MCP (la console, elle, utilise SSE côté navigateur, ce qui est un usage
  différent et parfaitement valable).

---

## 14 · La carte des fichiers

```
mcp-entra-secops/
│
├── src/
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
│   ├── argus_agent/             ← L'orchestrateur
│   │   ├── playbooks.py            les 5 recettes, en données
│   │   ├── orchestrator.py         exécution + comptabilité des coûts
│   │   └── verdict.py              ★ la décision, en Python testé
│   │
│   ├── argus_eval/              ← Le harnais d'évaluation
│   │   ├── runner.py               métriques et seuils bloquants
│   │   └── cases/                  25 cas de référence
│   │
│   ├── argus_obs/               ← L'observabilité
│   │   ├── models.py               coûts, dossiers, approbations
│   │   └── store.py                anneau mémoire + journal ajout seul
│   │
│   └── argus_console/           ← La console analyste
│       ├── app.py                  API FastAPI + flux SSE
│       └── static/index.html       l'interface
│
├── tests/                       ← 288 tests
├── docs/
│   ├── SETUP.md                    installation pas à pas
│   ├── RESEARCH.md                 scan du marché, exposition sécurisée
│   └── COMPRENDRE.md               ← ce document
├── demo.py                      ← investigation de démonstration
├── Dockerfile
└── .github/workflows/ci.yml     ← lint, types, tests, évaluation, Trivy
```

Les fichiers marqués ★ sont ceux où se concentre la valeur réelle du projet. Si
vous ne devez en lire que quatre : `fusion.py`, `verdict.py`, `spf.py`,
`headers.py`.

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

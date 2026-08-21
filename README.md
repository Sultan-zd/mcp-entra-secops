# ARGUS — Plateforme SecOps agentique

[![CI](https://github.com/Sultan-zd/mcp-entra-secops/actions/workflows/ci.yml/badge.svg)](https://github.com/Sultan-zd/mcp-entra-secops/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![MCP](https://img.shields.io/badge/MCP-2026--07--28-brightgreen)
![Licence](https://img.shields.io/badge/licence-MIT-lightgrey)

Serveurs [MCP](https://modelcontextprotocol.io) exposant la télémétrie de sécurité
comme outils exécutables par un agent IA (Claude Desktop, Cursor, ou tout autre
client MCP).

| Serveur | Domaine | Outils |
|---|---|---|
| `entra-secops-mcp` | Identité — journaux Microsoft Entra ID | 6 |
| `threat-intel-mcp` | Renseignement — VirusTotal, AbuseIPDB, GreyNoise | 4 |
| `email-security-mcp` | Messagerie — SPF, DKIM, DMARC, en-têtes | 5 |
| `vuln-intel-mcp` | **Vulnérabilités** — NVD, CISA KEV, EPSS · *sans clé* | 9 |
| `mitre-attack-mcp` | **MITRE ATT&CK** — corpus embarqué · *hors ligne* | 9 |
| `web-recon-mcp` | **Web & TLS** — connexion directe, DNS, transparence · *sans clé* | 6 |
| `argus-agent` | **Orchestration** — enchaîne les domaines | — |
| `argus-eval` | **Évaluation** — 25 incidents de référence, seuils bloquants | — |
| `argus-console` | **Console analyste** — investigation en direct, porte d'approbation | — |

**39 outils.** Vingt-quatre d'entre eux ne demandent **aucune clé d'API** : NVD,
le catalogue CISA et EPSS sont publics, le corpus ATT&CK est embarqué, et
l'inspection TLS ouvre sa propre connexion.

Douze fonctionnent même **sans accès Internet** — les neuf outils MITRE parce
que le corpus est local, et l'inspection TLS, DNS et en-têtes parce qu'elles
visent l'hôte directement, y compris un hôte **interne** qu'aucun service en
ligne ne pourrait atteindre.

Objectif : permettre à un analyste de poser une question en langage naturel
— *« pourquoi ce compte n'arrive-t-il plus à se connecter ? »* — et d'obtenir en
quelques secondes une réponse fondée sur les données réelles du tenant.

> 🎓 **[Comprendre ARGUS de A à Z](docs/COMPRENDRE.md)** — tout le projet
> expliqué depuis zéro, sans prérequis. **Commencez par là.**
> 📖 **[Guide d'installation et de test](docs/SETUP.md)** — les trois façons de
> lancer le serveur, pas à pas.
> 🔍 **[Brief technique](docs/RESEARCH.md)** — scan du marché et exposition sécurisée.

## Principe de conception

Une réponse brute de Microsoft Graph contient une soixantaine de champs par
événement. Le serveur applique une **troncature agressive** : seuls une douzaine
d'indicateurs de sécurité atteignent le modèle. C'est à la fois une optimisation
de coût (facteur ~35 sur les tokens) et un contrôle de sécurité, puisque les
champs non listés — dont certains sont contrôlés par un attaquant — n'entrent
jamais dans le contexte.

Les agrégats (nombre d'échecs, IP distinctes, motifs suspects) sont **calculés en
Python**, pas déduits par le modèle.

## Outils

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

## Démarrage rapide (sans tenant Azure)

Le mode `fixture` rejoue un incident de démonstration et ne nécessite ni tenant,
ni licence, ni secret.

```bash
python -m venv venv
venv/Scripts/activate          # Windows ; sur Linux/macOS : source venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env           # ENTRA_DATA_SOURCE=fixture est déjà la valeur par défaut
python -m entra_secops_mcp
```

## Connexion à un vrai tenant

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

## Sécurité

- Aucun secret n'est présent dans le code, ni dans l'image Docker. Ils sont
  injectés au démarrage via `--env-file`.
- `.env` est exclu de git par `.gitignore`. Un secret poussé sur un dépôt doit
  être **révoqué** dans Azure, pas seulement supprimé du fichier.
- La journalisation est dirigée vers `stderr` : en transport stdio, `stdout`
  transporte le protocole JSON-RPC et ne tolère aucun octet parasite.

## Configuration

Toutes les variables sont documentées dans [`.env.example`](.env.example).

## Docker

```bash
docker build -t entra-secops-mcp .
docker run -i --rm --env-file .env entra-secops-mcp
```

Image finale : **277 Mo**, construction multi-étapes, exécution en utilisateur
non root (`uid=1000`), **aucun secret dans les couches**.

`-i` garde l'entrée standard ouverte — c'est par là que passe le protocole MCP.
**Pas de `-t`** : un pseudo-terminal injecte des codes de couleur qui corrompent
les trames JSON.

## Développement

```bash
pytest              # 609 tests
ruff check src tests
mypy src            # mode strict
pre-commit install  # contrôles avant chaque commit
python demo.py      # investigation de démonstration
```

## État

| | |
|---|---|
| Outils | 39 au total, tous en lecture seule ; 24 sans aucune clé d'API |
| Tests | 609, sans clé ni tenant requis |
| Types | `mypy --strict` sans alerte |
| Protocole MCP | `2026-07-28` (SDK `mcp` 2.0) |
| Conteneur | vérifié via un vrai client MCP : démarrage 2,4 s, appel d'outil ~110 ms |

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

## Licence

MIT — voir [LICENSE](LICENSE).

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

## La console analyste

```bash
pip install -e ".[console]"
argus-console                    # http://127.0.0.1:8000
```

Une investigation qu'on ne voit pas se dérouler n'est pas adoptée. La console
diffuse **chaque étape au moment où elle se termine**, par un flux d'événements
serveur, plutôt qu'un sablier suivi d'un verdict :

```
event: step     get_user_context      compte privilégié — Global Administrator
event: step     get_user_signins      10 connexions sur 48 h — 7 échecs, 3 succès
event: step     get_risk_detections   3 détections
event: step     bulk_enrich           2 indicateurs — 1 malveillant
event: step     get_directory_audits  5 modifications, dont 4 sensibles
event: verdict  MALICIOUS · critical · 0.95 · escalade
```

Un flux d'événements serveur suffit : la communication est unidirectionnelle,
du serveur vers le navigateur. Une WebSocket serait surdimensionnée, et le
navigateur qui ferme l'onglet annule la tâche côté serveur — sans quoi une
investigation abandonnée continuerait de consommer du quota d'API.

### La porte d'approbation consigne, elle n'exécute pas

```
POST /api/runs/{id}/approvals  →  {"executed": false, "recorded": {...}}
```

La distinction est délibérée. Tant que la plateforme ne détient **aucun droit
d'écriture** sur le tenant, une erreur de l'agent ne peut pas se traduire en
incident. Ce que l'API enregistre, c'est qui a décidé quoi et quand — l'exigence
d'audit — pas l'exécution elle-même.

Deux refus explicites protègent la trace :

- approuver une action **jamais proposée** est rejeté (`400`) : elle n'aurait
  aucune trace d'origine dans le dossier ;
- une décision autre que `approved` / `rejected` est rejetée.

---

## Observabilité : ce qu'une investigation coûte réellement

La plupart des plateformes agentiques comptent des tokens, parce qu'un modèle de
langage est dans leur boucle de décision. **Ici il n'y en a pas.** Le coût réel
n'est donc pas en tokens : il est en **quota d'API externes**. Le palier gratuit
de VirusTotal tourne autour de quatre requêtes par minute — c'est cette
ressource-là qui s'épuise, et c'est donc celle-là qu'on mesure. Compter des
tokens inexistants donnerait un tableau de bord flatteur et sans rapport avec la
contrainte réelle.

```json
{
  "external_api_calls": {"virustotal": 2, "abuseipdb": 2, "greynoise": 2},
  "cache_hits": 4,
  "dns_lookups": 0
}
```

Les chiffres sont **dérivés des sorties d'outils**, jamais estimés : une source
tombée en panne n'a rien consommé et n'est pas comptée ; un indicateur servi par
le cache compte comme cache, pas comme appel. Un test le vérifie sur une réponse
où GreyNoise est indisponible.

### Deux couches de conservation

| Couche | Rôle | Propriété |
|---|---|---|
| Anneau en mémoire (200 dossiers) | affichage de la console | éviction du plus ancien, **index purgé avec lui** |
| `data/audit.jsonl` | audit et conformité | **ajout seul** |

Le journal est en ajout seul à dessein : une trace qu'on peut réécrire ne prouve
rien. Et une panne d'écriture du journal ne fait jamais perdre un verdict déjà
rendu — l'erreur est tracée, l'investigation suit son cours. Un test force
l'échec d'écriture et vérifie que le dossier reste consultable.

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

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

Objectif : permettre à un analyste de poser une question en langage naturel
— *« pourquoi ce compte n'arrive-t-il plus à se connecter ? »* — et d'obtenir en
quelques secondes une réponse fondée sur les données réelles du tenant.

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
pytest              # 232 tests
ruff check src tests
mypy src            # mode strict
pre-commit install  # contrôles avant chaque commit
python demo.py      # investigation de démonstration
```

## État

| | |
|---|---|
| Outils | 15 au total (6 identité + 4 renseignement + 5 messagerie), tous en lecture seule |
| Tests | 232, sans clé ni tenant requis |
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

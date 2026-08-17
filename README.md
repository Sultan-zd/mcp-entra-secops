# Entra ID SecOps MCP Server

[![CI](https://github.com/Sultan-zd/mcp-entra-secops/actions/workflows/ci.yml/badge.svg)](https://github.com/Sultan-zd/mcp-entra-secops/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![MCP](https://img.shields.io/badge/MCP-2026--07--28-brightgreen)
![Licence](https://img.shields.io/badge/licence-MIT-lightgrey)

Serveur [MCP](https://modelcontextprotocol.io) qui expose les journaux de sécurité
de **Microsoft Entra ID** comme outils exécutables par un agent IA (Claude Desktop,
Cursor, ou tout autre client MCP).

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
pytest              # 81 tests
ruff check src tests
mypy src            # mode strict
pre-commit install  # contrôles avant chaque commit
python demo.py      # investigation de démonstration
```

## État

| | |
|---|---|
| Outils | 6, tous en lecture seule |
| Tests | 81, sans tenant Azure requis |
| Types | `mypy --strict` sans alerte |
| Protocole MCP | `2026-07-28` (SDK `mcp` 2.0) |
| Conteneur | vérifié via un vrai client MCP : démarrage 2,4 s, appel d'outil ~110 ms |

## Licence

MIT.

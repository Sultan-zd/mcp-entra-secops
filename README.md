# Entra ID SecOps MCP Server

Serveur [MCP](https://modelcontextprotocol.io) qui expose les journaux de sécurité
de **Microsoft Entra ID** comme outils exécutables par un agent IA (Claude Desktop,
Cursor, ou tout autre client MCP).

Objectif : permettre à un analyste de poser une question en langage naturel
— *« pourquoi ce compte n'arrive-t-il plus à se connecter ? »* — et d'obtenir en
quelques secondes une réponse fondée sur les données réelles du tenant.

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

## Développement

```bash
pytest          # tests
ruff check .    # lint
mypy src        # types
```

## Licence

MIT.

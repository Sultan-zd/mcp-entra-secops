# Guide d'installation et de test

Ce document couvre les trois façons d'utiliser le serveur, de la plus simple à
la plus complète :

1. **Test local en Python** — 2 minutes, aucune dépendance externe
2. **Test dans Claude Desktop** — le vrai usage, avec des questions en langage naturel
3. **Exécution en conteneur Docker** — le mode de livraison

---

## 1. Test local en Python

### Installation

```bash
cd mcp-entra-secops

# Créer l'environnement virtuel (une seule fois)
python -m venv venv

# L'activer — à refaire à chaque nouveau terminal
venv\Scripts\activate           # Windows (PowerShell / CMD)
source venv/bin/activate        # Linux / macOS

# Installer le projet et les outils de développement
pip install -e ".[dev]"
```

### Configuration

```bash
copy .env.example .env          # Windows
cp .env.example .env            # Linux / macOS
```

Le fichier contient déjà `ENTRA_DATA_SOURCE=fixture`. **Rien d'autre à
remplir** : le serveur rejoue un incident de démonstration sans tenant Azure.

### Lancer la suite de tests

```bash
pytest
```

Résultat attendu : `81 passed`.

### Vérifier la qualité du code

```bash
ruff check src tests    # style et erreurs courantes
mypy src                # cohérence des types
```

### Voir le serveur travailler

```bash
python -m entra_secops_mcp
```

Le serveur démarre et **attend** — c'est normal. Il parle le protocole MCP sur
son entrée standard, pas avec un humain. Arrêtez-le avec `Ctrl+C`.

Pour réellement voir une sortie, utilisez le script de démonstration ci-dessous.

### Script de démonstration

Créez `demo.py` à la racine du projet :

```python
import asyncio

from entra_secops_mcp.runtime import lifespan
from entra_secops_mcp.tools.access import get_user_context
from entra_secops_mcp.tools.signins import get_user_signins


async def main() -> None:
    async with lifespan(None):
        contexte = await get_user_context("marketing@teknologiia.com")
        print("Compte privilégié :", contexte.is_privileged)
        print("Rôles détenus     :", contexte.directory_roles)
        print()

        rapport = await get_user_signins("marketing@teknologiia.com")
        print(f"{rapport.total_events} événements — "
              f"{rapport.failures} échecs, {rapport.successes} succès")
        print("IP observées :", rapport.distinct_ip_addresses)
        print()
        for note in rapport.notes:
            print(" !", note)


asyncio.run(main())
```

Puis :

```bash
python demo.py
```

Sortie attendue :

```
Compte privilégié : True
Rôles détenus     : ['Helpdesk Administrator']

10 événements — 7 échecs, 3 succès
IP observées : ['185.220.101.47', '77.42.130.18']

 ! 7 échecs sur la fenêtre : volume compatible avec une attaque par force brute…
 ! Une connexion a RÉUSSI après une série d'échecs : compromission possible…
 ! Plusieurs géolocalisations distinctes : vérifier la plausibilité…
 ! Protocoles d'authentification hérités utilisés (IMAP) : ils contournent la MFA.
```

---

## 2. Test dans Claude Desktop

C'est le test qui compte : celui où l'on pose une question en français et où
l'IA va chercher la réponse elle-même.

### Étape 1 — trouver le fichier de configuration

| Système | Chemin |
|---|---|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |

Sur Windows, collez `%APPDATA%\Claude` dans la barre d'adresse de l'explorateur.
Si le fichier n'existe pas, créez-le.

### Étape 2 — déclarer le serveur

Remplacez les deux chemins par les vôtres, **en absolu** :

```json
{
  "mcpServers": {
    "entra-secops": {
      "command": "C:\\Users\\USER\\OneDrive\\Desktop\\Teknologiia\\mcp-entra-secops\\venv\\Scripts\\python.exe",
      "args": ["-m", "entra_secops_mcp"],
      "env": {
        "ENTRA_DATA_SOURCE": "fixture"
      }
    }
  }
}
```

> **Les doubles antislashs sont obligatoires** en JSON sous Windows.
> `C:\Users` produit une erreur ; `C:\\Users` est correct.

### Étape 3 — redémarrer Claude Desktop

Fermez complètement l'application, y compris son icône dans la zone de
notification, puis rouvrez-la. Un simple rechargement ne suffit pas.

### Étape 4 — vérifier la connexion

Une icône d'outils apparaît dans la zone de saisie. En cliquant dessus, les
6 outils doivent être listés.

### Étape 5 — poser les questions

Ces questions sont conçues pour déclencher les outils :

> **« Est-ce que le compte marketing@teknologiia.com est compromis ? »**

Claude doit enchaîner plusieurs outils, puis conclure à une compromission :
échecs répétés depuis une IP unique, puis succès, compte privilégié.

> **« Quelles modifications administratives ont eu lieu ces 7 derniers jours ? »**

Doit remonter l'attribution de rôle et l'ajout du secret applicatif.

> **« Pourquoi ahmad.k@teknologiia.com n'arrive-t-il pas à se connecter ? »**

Doit expliquer le code 53003 — blocage par accès conditionnel — et le refus MFA.

> **« Y a-t-il des failles dans nos politiques d'accès conditionnel ? »**

Doit signaler la politique en mode audit seul et l'exclusion.

### Si les outils n'apparaissent pas

| Symptôme | Cause probable |
|---|---|
| Aucun outil listé | Chemin du `command` incorrect, ou antislashs non doublés |
| Le serveur démarre puis s'arrête | Configuration invalide — voir les journaux ci-dessous |
| « Configuration invalide » | `ENTRA_DATA_SOURCE` absent et identifiants Azure non renseignés |

Journaux de Claude Desktop :

| Système | Chemin |
|---|---|
| Windows | `%APPDATA%\Claude\logs\` |
| macOS | `~/Library/Logs/Claude/` |

---

## 3. Exécution en conteneur Docker

### Prérequis

Docker Desktop doit être **démarré** (l'icône baleine dans la zone de
notification doit être stable, pas animée).

### Construire l'image

```bash
docker build -t entra-secops-mcp .
```

### Vérifier qu'elle fonctionne

```bash
docker run -i --rm -e ENTRA_DATA_SOURCE=fixture entra-secops-mcp
```

Le conteneur démarre et attend, comme en local. `Ctrl+C` pour l'arrêter.

> **Pourquoi `-i` sans `-t` ?**
> `-i` garde l'entrée standard ouverte : c'est par là que passe le protocole
> MCP. `-t` allouerait un pseudo-terminal, qui injecte des codes de couleur
> dans la sortie et **corrompt les trames JSON**. C'est une exigence explicite
> du cahier des charges.

### Brancher le conteneur sur Claude Desktop

```json
{
  "mcpServers": {
    "entra-secops": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--env-file", "C:\\chemin\\absolu\\vers\\mcp-entra-secops\\.env",
        "entra-secops-mcp"
      ]
    }
  }
}
```

---

## 4. Connexion à un vrai tenant Entra ID

### Étape 1 — créer l'inscription d'application

Portail Entra → **Applications** → **Inscriptions d'applications** →
**Nouvelle inscription**. Nom : `entra-secops-mcp`. Aucune URI de redirection.

Notez l'**ID d'application (client)** et l'**ID de l'annuaire (locataire)**.

### Étape 2 — accorder les permissions

**API autorisées** → **Ajouter une autorisation** → **Microsoft Graph** →
**Autorisations d'application** (surtout pas « déléguées ») :

| Permission | Outils concernés | Licence |
|---|---|---|
| `AuditLog.Read.All` | `get_user_signins`, `get_directory_audits` | P1 pour les connexions |
| `Directory.Read.All` | `get_user_context` | — |
| `IdentityRiskyUser.Read.All` | `get_risky_users` | P2 |
| `IdentityRiskEvent.Read.All` | `get_risk_detections` | P2 |
| `Policy.Read.All` | `get_conditional_access_policies` | — |

Puis **Accorder le consentement administrateur**. Sans ce clic, Graph répond
`403` et rien ne fonctionne.

### Étape 3 — créer le secret client

**Certificats et secrets** → **Nouveau secret client**. **Copiez la valeur
immédiatement** : elle n'est plus affichée ensuite.

### Étape 4 — renseigner `.env`

```dotenv
AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_ID=11111111-1111-1111-1111-111111111111
AZURE_CLIENT_SECRET=le-secret-copie
ENTRA_DATA_SOURCE=graph
```

### Étape 5 — vérifier

```bash
python demo.py
```

En cas d'échec, le message indique quoi corriger :

| Message | Correction |
|---|---|
| `Authentification refusée (401)` | Secret expiré ou mal copié |
| `Permission insuffisante (403)` | Consentement administrateur non accordé |
| `Configuration invalide` | Une variable manque dans `.env` |

---

## 5. Règles de sécurité

- **`.env` ne doit jamais être committé.** Il est exclu par `.gitignore`.
- **Un secret poussé sur Git doit être révoqué** dans le portail Azure, pas
  seulement supprimé du fichier : l'historique Git le conserve.
- **Aucun secret n'est inscrit dans l'image Docker.** Les variables `ENV` d'un
  Dockerfile restent lisibles dans les couches de l'image, même après
  suppression. C'est pourquoi les identifiants passent par `--env-file` au
  démarrage.
- **Tous les outils sont en lecture seule.** Le serveur ne peut ni désactiver
  un compte, ni révoquer une session, ni modifier une politique.

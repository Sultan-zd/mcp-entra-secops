# Travailler sur le code d'ARGUS

> **Vous voulez seulement *utiliser* ARGUS ?** Ce document n'est pas le bon.
> L'extension `.mcpb` s'installe d'un double-clic, sans cloner quoi que ce
> soit : voir **[`INSTALLER.md`](INSTALLER.md)**.
>
> Ce guide-ci s'adresse à qui modifie le code, lance les tests, ou construit
> l'extension.

Le contenu de l'extension, ce sont **huit serveurs MCP**. Six d'entre eux ne
demandent **aucune clé d'API** : vous pouvez les essayer dans la minute qui suit
l'installation du dépôt.

Ce document va du plus simple au plus complet :

1. **Installation du dépôt** — 2 minutes
2. **Essayer les serveurs sans clé** — immédiat, rien à configurer
3. **Lancer la suite de tests** — la preuve que tout fonctionne
4. **Brancher le code en cours sur Claude Desktop** — tester ce qu'on modifie
5. **Construire l'extension `.mcpb`** — le livrable
6. **Connexion à un vrai tenant Entra ID** — pour les six outils d'identité

| Serveur | Clé nécessaire ? | Réseau nécessaire ? |
|---|---|---|
| `mitre-attack-mcp` | Aucune | **Non** — corpus embarqué |
| `detection-mcp` | Aucune | **Non** — analyse purement locale |
| `artefact-mcp` | Aucune | **Non** — JWT et décodage, en local |
| `vuln-intel-mcp` | Aucune | Oui — NVD, CISA, EPSS |
| `web-recon-mcp` | Aucune | Oui — vers la cible analysée |
| `email-security-mcp` | Aucune | Oui — DNS public |
| `threat-intel-mcp` | VirusTotal, AbuseIPDB (gratuites) | Oui |
| `entra-secops-mcp` | Votre tenant Microsoft | Oui |

---

## 1. Installation

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

---

## 2. Essayer les serveurs sans clé

C'est le test le plus rapide. Chaque serveur a un mode `--check` qui vérifie ses
sources et **affiche ce qu'il a réellement obtenu**.

### MITRE ATT&CK — sans même de connexion Internet

```bash
mitre-attack-mcp --check
```

```
Corpus embarqué
  ✓ ATT&CK v19.2
    697 techniques, 15 tactiques
    44 atténuations, 176 groupes
    161 techniques révoquées, tracées vers leur remplaçante

Table de correspondance
  ✓ 35 correspondances, toutes résolues dans le corpus
    31 constats reconnus

Aucun appel réseau n'a été effectué.
```

Coupez le Wi-Fi et relancez : le résultat est identique.

### Vulnérabilités — trois sources publiques

```bash
vuln-intel-mcp --check
```

```
Sources publiques
  ✓ NVD        CVE-2021-44228 récupérée
  ✓ CISA KEV   1673 entrées, version 2026.08.20
  ✓ EPSS       CVE-2021-44228 : 0.99999

Calcul local (aucun réseau)
  ✓ CVSS v3.1  vecteur Log4Shell recalculé à 10.0
```

### Web et TLS — connexion directe

```bash
web-recon-mcp --check
```

```
Chemins d'analyse
  ✓ TLS direct   github.com : TLSv1.3, EC (secp256r1)
                 expire dans 40 jour(s)
  ✓ En-têtes     note C (60/100)
  ✓ DNS          DNSSEC inconnu, 8 serveurs de noms
  ✓ Transparence 10 sous-domaine(s) via certspotter
                 6 nom(s) tiers exclus
```

### Messagerie

```bash
python -m email_security_mcp --check
```

> Si une source publique est en panne, le diagnostic le dit au lieu d'échouer en
> silence. Un `✗` sur une ligne n'empêche pas les autres de s'afficher.

### Si l'analyse de messagerie échoue en `LifetimeTimeout`

```
microsoft.com    ÉCHEC — Résolution DNS impossible : LifetimeTimeout
```

**Ce n'est pas un défaut du projet.** Beaucoup de résolveurs DNS de fournisseurs
d'accès n'arrivent pas à rendre les réponses TXT volumineuses — `microsoft.com`
en publie **61**, ce qui dépasse la taille d'un paquet UDP et exige un repli en
TCP que tous les résolveurs ne gèrent pas correctement.

Pointez vers un résolveur public :

```bash
# Windows (PowerShell)
$env:MAIL_DNS_NAMESERVERS = "8.8.8.8,1.1.1.1"

# Linux / macOS
export MAIL_DNS_NAMESERVERS="8.8.8.8,1.1.1.1"
```

Le résultat attendu devient :

```
microsoft.com     note A (92/100)   SPF 7/10 lookups · DKIM 1 clé · DMARC reject
teknologiia.com   note A (100/100)  SPF 1/10 lookups · DKIM 2 clés · DMARC reject
```

> Notez ce que le serveur **n'a pas fait** : face à un DNS muet, il n'a pas
> conclu « ce domaine n'a pas de SPF ». Ce serait un faux négatif dangereux —
> un domaine parfaitement protégé passerait pour vulnérable. Il dit qu'il n'a
> pas pu savoir, ce qui est différent.

---

## 3. Lancer la suite de tests

```bash
pytest
```

Résultat attendu : **1003 tests**, tous verts, **sans aucun accès réseau ni clé
d'API**. Les sources publiques sont simulées ; un test qui dépendrait de la
disponibilité du NVD finirait par être ignoré.

Pour ne tester qu'une partie :

```bash
pytest tests/test_cvss.py -v        # le calcul CVSS, contre 138 vecteurs réels
pytest tests/test_mitre.py -v       # le corpus ATT&CK et les correspondances
pytest tests/test_web_recon.py -v   # TLS, en-têtes, transparence
pytest -k "prioriser" -v            # tous les tests de classement des CVE
```

### Vérifier la qualité du code

```bash
ruff check src tests    # style et erreurs courantes
mypy src                # cohérence des types, en mode strict
```

### Le harnais d'évaluation

C'est ce qui remplace « faites-moi confiance » par « voici le rapport » :

```bash
argus-eval
```

Il rejoue 25 incidents de référence et vérifie six métriques. Deux seulement
font échouer la commande : le taux de faux négatifs et la résistance à
l'injection — celles dont le coût de l'erreur est asymétrique.

### Voir un serveur démarrer

```bash
python -m entra_secops_mcp
```

Le serveur démarre et **attend** — c'est normal. Il parle le protocole MCP sur
son entrée standard, pas avec un humain. Arrêtez-le avec `Ctrl+C`.

Pour voir une vraie sortie, utilisez le script de démonstration.

### Appeler les outils depuis du Python

Pour une investigation complète, enchaînée automatiquement :

```bash
argus-agent                   # alerte de demonstration integree
```

Pour comprendre comment appeler un outil directement, copiez ce script dans un
fichier et lancez-le. Il fonctionne sans tenant tant que
`ENTRA_DATA_SOURCE=fixture` :

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

## 4. Brancher le code en cours sur Claude Desktop

C'est le test qui compte : celui où l'on pose une question en français et où
l'IA va chercher la réponse elle-même.

On vise ici le **code du dépôt**, pas l'extension : c'est ce qui permet de
tester une modification sans reconstruire le `.mcpb` à chaque fois. Pour
installer l'extension elle-même, voir [`INSTALLER.md`](INSTALLER.md).

### Étape 1 — trouver le fichier de configuration

| Système | Chemin |
|---|---|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |

Sur Windows, collez `%APPDATA%\Claude` dans la barre d'adresse de l'explorateur.
Si le fichier n'existe pas, créez-le.

### Étape 2 — déclarer les serveurs

Remplacez le chemin par le vôtre, **en absolu**. Commencez par les trois
serveurs sans clé — ils fonctionnent immédiatement :

```json
{
  "mcpServers": {
    "argus-vulnerabilites": {
      "command": "C:\\chemin\\vers\\mcp-entra-secops\\venv\\Scripts\\python.exe",
      "args": ["-m", "vuln_intel_mcp"]
    },
    "argus-mitre": {
      "command": "C:\\chemin\\vers\\mcp-entra-secops\\venv\\Scripts\\python.exe",
      "args": ["-m", "mitre_mcp"]
    },
    "argus-web": {
      "command": "C:\\chemin\\vers\\mcp-entra-secops\\venv\\Scripts\\python.exe",
      "args": ["-m", "web_recon_mcp"]
    },
    "argus-messagerie": {
      "command": "C:\\chemin\\vers\\mcp-entra-secops\\venv\\Scripts\\python.exe",
      "args": ["-m", "email_security_mcp"]
    },
    "argus-identite": {
      "command": "C:\\chemin\\vers\\mcp-entra-secops\\venv\\Scripts\\python.exe",
      "args": ["-m", "entra_secops_mcp"],
      "env": { "ENTRA_DATA_SOURCE": "fixture" }
    }
  }
}
```

> **Vous n'êtes pas obligé de tout déclarer.** Chaque serveur est indépendant.
> Gardez ceux qui vous servent — moins de serveurs, c'est aussi moins d'outils
> envoyés au modèle à chaque question, donc moins de coût.

> **Les doubles antislashs sont obligatoires** en JSON sous Windows.
> `C:\Users` produit une erreur ; `C:\\Users` est correct.

### Étape 3 — redémarrer Claude Desktop

Fermez complètement l'application, y compris son icône dans la zone de
notification, puis rouvrez-la. Un simple rechargement ne suffit pas.

### Étape 4 — vérifier la connexion

**Il n'y a plus d'icône d'outils dans la zone de saisie** dans les versions
récentes de Claude Desktop. Les serveurs déclarés dans ce fichier apparaissent
dans **Réglages → Connecteurs** (ou *Extensions*), au même endroit que les
extensions `.mcpb` installées depuis le catalogue.

Contrairement à une extension, **un serveur déclaré ici ne s'affiche nulle part
tant qu'une question ne le déclenche pas.** Ne concluez pas à un échec parce que
vous ne voyez rien : posez d'abord une question de l'étape 5.

La preuve définitive qu'un serveur démarre est dans son journal (voir plus bas).
Cherchez la ligne :

```
[votre-serveur] [info] Server started and connected successfully
```

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

#### Questions pour les serveurs sans clé

> **« La CVE-2021-44228 est-elle activement exploitée ? »**

Doit appeler `lookup_cve` et répondre oui — inscrite au catalogue CISA, EPSS à
99,99 %, palier `immediate`.

> **« J'ai ces CVE après un scan : CVE-2021-44228, CVE-2024-3094,
> CVE-2022-40674, CVE-2016-2183. Par quoi je commence ? »**

Doit appeler `prioritize_cves` et classer par paliers. Notez que SWEET32
(CVSS 7.5) passe **devant** la porte dérobée xz (CVSS 10.0) : elle est bien plus
exploitée.

> **« Que veut dire le vecteur CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H ? »**

Doit appeler `parse_cvss` et rendre 10.0, avec chaque métrique traduite. Aucun
appel réseau.

> **« Le domaine teknologiia.com est-il correctement exposé ? »**

Doit appeler `check_web_exposure` : TLS, en-têtes, DNS et sous-domaines en une
fois, avec une note sur 100.

> **« Comment détecte-t-on la technique T1566.002 ? »**

Doit appeler `lookup_technique` et donner les canaux de journalisation exacts
à collecter.

### Si les outils n'apparaissent pas

| Symptôme | Cause probable |
|---|---|
| Aucun outil listé | Chemin du `command` incorrect, ou antislashs non doublés |
| Le serveur démarre puis s'arrête | Configuration invalide — voir les journaux ci-dessous |
| « Configuration invalide » | `ENTRA_DATA_SOURCE` absent et identifiants Azure non renseignés |

Journaux de Claude Desktop :

| Système | Chemin |
|---|---|
| Windows | `%LOCALAPPDATA%\Claude\logs\` |
| macOS | `~/Library/Logs/Claude/` |

> **Attention au dossier.** C'est `%LOCALAPPDATA%` (…`\AppData\Local\`…), **pas**
> `%APPDATA%` (…`\AppData\Roaming\`…). Le second contient des journaux
> périmés d'anciennes versions, ce qui fait croire à tort qu'aucun serveur n'a
> démarré.

Chaque serveur a son propre fichier, nommé d'après la clé du fichier de
configuration : `mcp-server-argus-menaces.log`, `mcp-server-entra-secops.log`…

---

## 5. Construire l'extension `.mcpb`

C'est le livrable du projet. Une commande le construit **et le vérifie** :

```bash
npm install @anthropic-ai/mcpb      # une seule fois
python mcpb/outils/construire.py
```

```
1 · Synchroniser le code embarqué
  ✓ mcpb/src est identique à src/
2 · Générer le manifeste
  ✓ 57 outils déclarés par le serveur lui-même
3 · Empaqueter
  ✓ mcpb/dist/argus-secops-1.0.0.mcpb (946 Ko)
4 · Vérifier l'artefact
  ✓ exécuté depuis une copie dépaquetée — 47 outils exposés.
  ✓ 130 fichiers, aucun artefact de construction embarqué
```

La quatrième étape est celle qui compte : empaqueter réussit même quand le
paquet est cassé. Une version a été produite dont la commande de diagnostic
plantait sur un `KeyError` — la CLI annonçait un succès, et le défaut
n'apparaissait que chez le destinataire.

Avant de toucher au code embarqué, ou pour contrôler un écart sans rien
reconstruire :

```bash
python mcpb/outils/construire.py --verifier-seulement
```

> **Installer l'extension, la distribuer, l'exposer en HTTP pour une équipe :**
> voir [`INSTALLER.md`](INSTALLER.md). Ce document-ci s'arrête à la
> construction.

## 6. Connexion à un vrai tenant Entra ID

### Étape 1 — créer l'inscription d'application

Portail Entra → **Applications** → **Inscriptions d'applications** →
**Nouvelle inscription**. Nom : `entra-secops-mcp`. Aucune URI de redirection.

Notez l'**ID d'application (client)** et l'**ID de l'annuaire (locataire)**.

### Étape 2 — accorder les permissions

**API autorisées** → **Ajouter une autorisation** → **Microsoft Graph** →
**Autorisations d'application** (surtout pas « déléguées ») :

| Permission | Outils concernés | Licence |
|---|---|---|
| `AuditLog.Read.All` | `get_user_signins`, `get_directory_audits` | P1 ou P2 pour les connexions |
| `Directory.Read.All` | `get_user_context` | — |
| `IdentityRiskyUser.Read.All` | `get_risky_users` | P2 seulement |
| `IdentityRiskEvent.Read.All` | `get_risk_detections` | P1 ou P2 |
| `Policy.Read.All` | `get_conditional_access_policies` | — |

> `Directory.Read.All` est plus large que le `User.Read.All` qui suffirait à
> lire la fiche d'un compte : c'est `memberOf` — donc les groupes et les rôles,
> donc la gravité d'un incident — qui l'exige. Voir [`ENTRA.md`](ENTRA.md) pour
> ce qui se passe si vous accordez moins.

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

### Étape 5 — vérifier avec le diagnostic intégré

```bash
python -m entra_secops_mcp --check
```

Cette commande ne démarre pas le serveur. Elle déroule les quatre points de
défaillance possibles, dans l'ordre :

1. **Configuration** — les variables sont-elles présentes ?
2. **Authentification** — le jeton OAuth est-il obtenu ?
3. **Permissions consenties** — lues directement dans le jeton. C'est ce qui
   distingue « permission non ajoutée » de « consentement administrateur non
   accordé », deux erreurs qui produisent le même `403`.
4. **Accès effectif** — chaque endpoint est appelé pour de vrai.

Sortie attendue quand tout va bien :

```
3. Permissions réellement consenties
  ✓ AuditLog.Read.All
  ✓ Directory.Read.All
  ✓ IdentityRiskEvent.Read.All
  ✓ IdentityRiskyUser.Read.All
  ✓ Policy.Read.All

4. Accès effectif aux endpoints
  ✓ get_user_context
  ✓ get_directory_audits
  ✓ get_conditional_access_policies
  ✓ get_user_signins
  ✓ get_risky_users
  ✓ get_risk_detections

Verdict
  Les 6 outils sont opérationnels sur le tenant réel.
```

Aucun secret n'apparaît dans la sortie : elle peut être collée dans un ticket.

### Lire le diagnostic

| Symptôme | Cause | Correction |
|---|---|---|
| `AUCUNE permission applicative dans le jeton` | Le consentement administrateur n'a pas été accordé | Portail Entra → l'application → API autorisées → **Accorder le consentement administrateur** |
| Une permission marquée `✗ absente` | Elle n'a pas été ajoutée, ou en type **déléguée** au lieu d'**application** | La rajouter en « Autorisations d'application », puis reconsentir |
| Échec sur `get_user_signins` **seul** | Licence insuffisante | Le tenant n'a pas Entra ID P1 |
| Échec sur `get_risky_users` **et** `get_risk_detections` | Licence insuffisante | Le tenant n'a pas Entra ID P2 |
| `ÉCHEC` dès l'étape 2 | Secret expiré, mal recopié, ou tenant erroné | Regénérer le secret ; il n'est affiché qu'une seule fois |

> **Attention au piège des licences.** **Microsoft 365 E5** inclut Entra ID P2.
> **Office 365 E5** ne l'inclut pas. Deux produits différents, des noms voisins.
> Le diagnostic tranche la question empiriquement.

Une fois le diagnostic vert :

```bash
argus-agent                   # alerte de demonstration integree
```

---

## 7. Règles de sécurité

- **`.env` ne doit jamais être committé.** Il est exclu par `.gitignore`.
- **Un secret poussé sur Git doit être révoqué** dans le portail Azure, pas
  seulement supprimé du fichier : l'historique Git le conserve.
- **Aucun secret n'est inscrit dans l'extension distribuée.** Le `.mcpb` ne
  contient que du code : les clés sont saisies par le destinataire à
  l'installation, et l'hôte les transmet au serveur par variables
  d'environnement. Un fichier `.mcpb` peut donc être partagé sans risque.
- **Tous les outils sont en lecture seule.** Le serveur ne peut ni désactiver
  un compte, ni révoquer une session, ni modifier une politique.

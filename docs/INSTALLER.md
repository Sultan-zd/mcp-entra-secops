# Installer et distribuer ARGUS

ARGUS est **une extension `.mcpb`** : un fichier de 678 Ko qui donne à un modèle
IA 46 outils de sécurité en lecture seule.

Ce document couvre les trois façons de le mettre entre les mains de quelqu'un —
selon le client qu'il utilise, et selon qu'il travaille seul ou en équipe.

---

## Ce qui marche où

| Client | Comment | État |
|---|---|---|
| **Claude Desktop** | fichier `.mcpb`, double-clic | ✅ le chemin le plus court |
| **Gemini CLI, Cursor, Cline, Windsurf, Zed** | déclaration MCP standard | ✅ |
| **ChatGPT, assistants hébergés** | serveur HTTP distant | ✅ *avec une URL publique en HTTPS* |

Deux choses à savoir avant d'aller plus loin.

**Le format `.mcpb` est propre à Claude Desktop.** C'est un paquet Anthropic ;
les autres clients ne le lisent pas — mais tous parlent le même protocole MCP
en dessous. Le serveur est le même, seule la déclaration change.

**Les assistants hébergés n'exécutent rien sur votre machine.** ChatGPT et
consorts n'acceptent que des serveurs MCP **distants**, joignables en HTTPS.
ARGUS sait le faire depuis la [section 3](#3--chatgpt-et-les-assistants-hébergés),
mais cela demande de l'exposer — un travail d'exploitation, pas un
double-clic.

---

## 1 · Claude Desktop — le fichier `.mcpb`

### Ce que le destinataire doit faire

**Installer [`uv`](https://docs.astral.sh/uv/)**, une seule fois. C'est ce qui
installera les dépendances Python au premier lancement.

```powershell
# Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Puis **double-cliquer sur le `.mcpb`**. Claude Desktop propose l'installation et
affiche les champs de configuration.

C'est `uv` qui permet à un seul fichier de 678 Ko de fonctionner sur Windows,
macOS et Linux : embarquer les dépendances donnerait un paquet **par plateforme
et par version de Python**, puisque `cryptography` et `pydantic-core` sont
compilés.

### Ce que le destinataire obtient

**36 outils immédiatement, sans aucune clé.** Les six champs proposés sont
**tous facultatifs** — ne rien remplir suffit.

| Champ | Débloque |
|---|---|
| Clé VirusTotal | Réputation d'indicateurs (4 outils) |
| Clé AbuseIPDB | Deuxième source de réputation |
| Tenant, application et secret Entra | Les 6 outils d'identité |
| Résolveurs DNS | Déjà rempli : `8.8.8.8,1.1.1.1` |

Les champs sensibles sont masqués à la saisie et stockés par Claude Desktop,
**jamais dans le paquet** : un `.mcpb` peut donc être partagé sans risque.

### Le paquet est signé — et l'hôte avertira quand même

```bash
python mcpb/outils/signer.py
```

La signature ajoute 2,2 Ko : un bloc PKCS#7 avec le certificat du signataire.
Elle donne une **enveloppe d'intégrité** — le paquet ne peut plus être modifié
en chemin — et une **identité stable**.

Le certificat est **auto-signé** : aucune autorité ne se porte garante, donc
Claude Desktop affichera toujours un avertissement à l'installation. C'est
attendu pour une distribution interne.

Ce que la signature permet malgré cela : **publier l'empreinte du certificat**.
Une équipe qui l'a vérifiée une fois peut refuser toute version qui ne la porte
pas. Transmettez-la par un canal distinct du paquet — un message, un wiki
interne — jamais dans la même archive.

> **`mcpb verify` répondra « Extension is not signed ».** Ce n'est pas un défaut
> du paquet : la CLI appelle `p7.verify()` de `node-forge`, qui lève
> « PKCS#7 signature verification not yet implemented », et traite toute
> exception comme une absence de signature. **Aucune** signature ne peut être
> confirmée par cet outil aujourd'hui. `signer.py` contrôle donc le bloc
> lui-même et affiche par quel certificat le paquet est signé.

### Si l'installation échoue sur « Server disconnected »

Le journal se trouve dans `%LOCALAPPDATA%\Claude\Logs` — **pas** `%APPDATA%`.

Deux causes, par ordre de fréquence :

1. **`uv` n'est pas installé**, ou pas dans le `PATH` du compte qui lance
   Claude Desktop.
2. Un champ facultatif laissé vide faisait transmettre par l'hôte le
   substituant **littéral** `${user_config.azure_tenant_id}`. Le serveur le
   reconnaît désormais et le traite comme absent ; si vous voyez cette chaîne
   dans le journal, l'extension date d'avant le correctif — reconstruisez-la.

---

## 2 · Gemini CLI, Cursor, Cline, Windsurf, Zed

Tous ces clients lancent des serveurs MCP en `stdio`. La déclaration est la même
partout ; seul l'emplacement du fichier change.

### Sans installer le dépôt

Décompressez le `.mcpb` quelque part — c'est une archive ZIP — puis visez-le :

```json
{
  "mcpServers": {
    "argus": {
      "command": "uv",
      "args": ["run", "--directory", "/chemin/vers/le/paquet", "server/main.py"],
      "env": {
        "MAIL_DNS_NAMESERVERS": "8.8.8.8,1.1.1.1"
      }
    }
  }
}
```

### Depuis le dépôt installé

```json
{
  "mcpServers": {
    "argus": {
      "command": "/chemin/vers/venv/bin/python",
      "args": ["-m", "argus_bundle"]
    }
  }
}
```

### Où mettre ce fichier

| Client | Fichier |
|---|---|
| Gemini CLI | `~/.gemini/settings.json` |
| Cursor | `~/.cursor/mcp.json` |
| Cline (VS Code) | réglages de l'extension, section MCP |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Zed | `settings.json`, clé `context_servers` |

> Ces emplacements changent d'une version à l'autre. En cas de doute, cherchez
> « MCP » dans les réglages du client : la structure JSON, elle, ne change pas.

### Un seul domaine, plutôt que les 46 outils

`argus_bundle` réunit tout. Pour n'exposer qu'un domaine, visez son module :

```
-m vuln_intel_mcp     9 outils   vulnérabilités
-m mitre_mcp          9 outils   ATT&CK, sans réseau
-m detection_mcp      7 outils   indicateurs, Sigma, sans réseau
-m web_recon_mcp      6 outils   TLS, DNS, certificats
-m email_security_mcp 5 outils   SPF, DKIM, DMARC
-m threat_intel_mcp   4 outils   réputation (clés requises)
-m entra_secops_mcp   6 outils   identité (tenant requis)
```

Ce n'est pas une question de goût : **les définitions d'outils partent au modèle
à chaque message**. Quarante-six outils coûtent plusieurs milliers de jetons par
question, avant même la question. Sur un poste dédié à la veille
vulnérabilités, `vuln_intel_mcp` seul revient bien moins cher.

---

## 3 · ChatGPT et les assistants hébergés

Ces clients ne lancent aucun processus local : il leur faut une **URL publique
en HTTPS**. ARGUS parle Streamable HTTP pour cela.

```bash
pip install -e .
export ARGUS_HTTP_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# Derrière un proxy inverse qui termine TLS — recommandé
argus-mcp --http --host 127.0.0.1 --tls-en-amont

# Ou terminaison TLS directe, faute de proxy
argus-mcp --http --host 0.0.0.0 --tls-cert cert.pem --tls-key cle.pem
```

Le point d'entrée est `https://votre-hote/mcp`, et chaque requête doit porter
`Authorization: Bearer <jeton>`.

> **Streamable HTTP, jamais SSE.** La révision `2026-07-28` de la spécification
> classe HTTP+SSE comme déprécié, donc supprimable dans une révision future.

### Ce que le serveur refuse

| Situation | Comportement |
|---|---|
| Écoute hors boucle locale **sans jeton** | refus de démarrer |
| Écoute hors boucle locale **sans TLS** ni `--tls-en-amont` | refus de démarrer |
| Certificat expiré, ou clé ne correspondant pas | refus, **avant** l'ouverture du port |
| Requête d'une origine étrangère | `403` — protection contre le rebinding DNS |
| Client limité à TLS 1.0 ou 1.1 | handshake refusé |

Ce sont des refus et non des avertissements : un avertissement au démarrage
défile et disparaît, et la commande dangereuse — `--host 0.0.0.0` — est plus
courte à taper que la commande sûre.

### Deux questions à trancher avant d'exposer publiquement

Elles ne se posent pas en local, et le transport ne les résout pas :

1. **Les clés d'API deviennent celles de l'hébergeur**, donc son quota et sa
   facture — plus celles de l'utilisateur.
2. **`check_tls` ouvre des connexions vers l'hôte demandé.** Exposé sans
   restriction, il devient un relais de reconnaissance pour des tiers.

Sur un réseau interne de confiance, ces deux points sont sans objet.

### Ce qui n'est pas encore fait

L'authentification est un **secret partagé**, pas OAuth 2.1. La forme est celle
d'un serveur de ressource — le `401` porte un `WWW-Authenticate` conforme
pointant vers les métadonnées RFC 9728 — de sorte que la migration vers l'IdP de
l'entreprise ne remplacera que le vérificateur de jeton.

Le renouvellement automatique des certificats (ACME) reste du ressort du proxy
inverse. C'est la raison principale de le préférer en production.

---

## 4 · Une instance partagée pour une équipe

Le `.mcpb` couvre un analyste sur sa machine. Pour qu'une équipe interroge la
même instance, le mode HTTP de la section 3 s'applique tel quel, sur le réseau
interne :

```bash
argus-mcp --http --host 0.0.0.0 --tls-cert interne.pem --tls-key interne-cle.pem
```

Chaque analyste déclare alors l'URL dans son client, avec le jeton partagé.

**Le compromis à connaître.** Dans ce mode, les clés d'API et le secret Entra
sont ceux du serveur : tous les analystes interrogent le tenant avec la même
identité, et les journaux d'audit ne distingueront pas qui a demandé quoi. Pour
une traçabilité par personne, il faut une instance par analyste — donc le
`.mcpb`.

---

## 5 · Construire et vérifier avant de distribuer

```bash
python mcpb/outils/construire.py
```

Une commande enchaîne quatre étapes : synchroniser le code embarqué, générer le
manifeste depuis le serveur lui-même, empaqueter, **puis dépaqueter l'archive
ailleurs et l'exécuter**.

La quatrième est la seule qui prouve quelque chose. Empaqueter réussit même
quand le paquet est cassé : une version a été produite dont la commande de
diagnostic plantait sur un `KeyError` — la CLI annonçait un succès, et le
défaut n'apparaissait que chez le destinataire, sur la première commande qu'il
lance.

```
1 · Synchroniser le code embarqué
  ✓ mcpb/src est identique à src/
2 · Générer le manifeste
  ✓ 46 outils déclarés par le serveur lui-même
3 · Empaqueter
  ✓ mcpb/dist/argus-secops-1.0.0.mcpb (678 Ko)
4 · Vérifier l'artefact
  ✓ exécuté depuis une copie dépaquetée — 36 outils exposés.
  ✓ 113 fichiers, aucun artefact de construction embarqué
```

### Pourquoi la synchronisation est vérifiée

Le paquet embarque une **copie** des paquets Python du dépôt, dans `mcpb/src`.
Tant qu'elle était recopiée à la main, on pouvait corriger un défaut, lancer la
suite de tests avec succès, construire le paquet — et distribuer l'ancienne
version du fichier corrigé.

```bash
python mcpb/outils/construire.py --verifier-seulement   # compare sans rien construire
```

La CI exécute la chaîne complète à chaque poussée et publie le `.mcpb` produit
en artefact : c'est la source à privilégier pour distribuer une version.

### Contrôles complémentaires

```bash
npx @anthropic-ai/mcpb validate mcpb/manifest.json   # conformité au schéma
unzip -t mcpb/dist/argus-secops-1.0.0.mcpb           # intégrité de l'archive
```

---

**Voir aussi** — [`COMPRENDRE.md`](COMPRENDRE.md) explique ce que fait chaque
outil et pourquoi ; [`SETUP.md`](SETUP.md) s'adresse à qui travaille sur le
code ; [`RESEARCH.md`](RESEARCH.md) documente le choix des transports et des
modèles d'exposition.

# Distribuer ARGUS

Ce document explique comment donner ARGUS à quelqu'un d'autre — un collègue
analyste, une équipe SOC — et dans quels clients il fonctionne réellement.

---

## Ce qui marche où : la réponse honnête

| Client | Comment | Ça marche ? |
|---|---|---|
| **Claude Desktop** | fichier `.mcpb`, double-clic | ✅ Oui |
| **Gemini CLI** | configuration MCP standard | ✅ Oui |
| **Cursor, Cline, Windsurf, Zed** | configuration MCP standard | ✅ Oui |
| **ChatGPT** (web et application) | — | ❌ **Non, pas en l'état** |

Deux choses à savoir avant d'aller plus loin.

**Le format `.mcpb` est propre à Claude Desktop.** C'est un paquet Anthropic.
Gemini et les autres ne le lisent pas — mais ils lisent tous le même protocole
MCP en dessous, donc le serveur reste le même. Seule la façon de le déclarer
change.

**ChatGPT n'exécute pas de serveur local.** Ses connecteurs personnalisés
n'acceptent que des serveurs MCP **distants**, joignables en HTTPS. ARGUS
fonctionne aujourd'hui en `stdio` — un processus lancé sur votre machine. Pour
ChatGPT, il faudrait le déployer derrière une URL publique, ce qui est un
travail différent et pose des questions de sécurité qui n'existent pas en
local. Voir la dernière section.

---

## 1. Claude Desktop — le fichier `.mcpb`

### Construire le paquet

```bash
npx @anthropic-ai/mcpb pack mcpb argus-secops-1.0.0.mcpb
```

Résultat : **636 Ko**, 101 fichiers, corpus MITRE ATT&CK compris.

### Ce que le destinataire doit faire

**Prérequis : installer `uv`**, une seule fois.

```powershell
# Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Puis **double-cliquer sur le `.mcpb`**. Claude Desktop l'installe, propose les
champs de configuration, et c'est fini.

`uv` télécharge les dépendances au premier lancement. C'est pour cette raison
que le paquet ne pèse que 636 Ko au lieu de plusieurs dizaines de mégaoctets,
et qu'un seul fichier fonctionne sur Windows, macOS et Linux.

### Ce que le destinataire obtient

**29 outils immédiatement, sans aucune clé.** Les dix autres s'activent s'il
renseigne ses propres clés dans les champs proposés à l'installation :

| Champ | Débloque |
|---|---|
| Clé VirusTotal | Réputation d'indicateurs |
| Clé AbuseIPDB | Deuxième source de réputation |
| Tenant / application / secret Entra | Les six outils d'identité |
| Résolveurs DNS | Déjà rempli : `8.8.8.8,1.1.1.1` |

Les champs marqués sensibles sont masqués à la saisie et stockés par Claude
Desktop, pas dans le paquet.

### Le paquet n'est pas signé

Claude Desktop affichera un avertissement à l'installation. C'est normal pour
une distribution interne.

Une signature auto-générée a été tentée : la commande annonce un succès, mais
`mcpb verify` répond ensuite « Extension is not signed », et le fichier porte
alors 17 Ko de données que rien ne sait relire. Livrer cela serait pire que de
livrer un paquet non signé — la version distribuée est donc propre et non
signée, ce qui est au moins un état vérifiable.

---

## 2. Gemini CLI, Cursor, Cline, Windsurf, Zed

Tous ces clients lancent des serveurs MCP en `stdio`. La déclaration est la
même partout, seul l'emplacement du fichier change.

### Sans installer le dépôt : par `uvx`

```json
{
  "mcpServers": {
    "argus": {
      "command": "uv",
      "args": ["run", "--directory", "/chemin/vers/mcpb", "server/main.py"],
      "env": {
        "MAIL_DNS_NAMESERVERS": "8.8.8.8,1.1.1.1"
      }
    }
  }
}
```

Le dossier `mcpb/` du dépôt est autonome : il contient le code et déclare ses
dépendances. Décompresser le `.mcpb` donne exactement la même chose.

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

### Un serveur à la fois, plutôt que les 39 outils

`argus_bundle` réunit tout. Pour n'exposer qu'un domaine, visez son module :

```
-m vuln_intel_mcp     9 outils   vulnérabilités
-m mitre_mcp          9 outils   ATT&CK, sans réseau
-m web_recon_mcp      6 outils   TLS, DNS, certificats
-m email_security_mcp 5 outils   SPF, DKIM, DMARC
-m threat_intel_mcp   4 outils   réputation (clés requises)
-m entra_secops_mcp   6 outils   identité (tenant requis)
```

Ce n'est pas qu'une question de goût : **les définitions d'outils partent au
modèle à chaque message**. Trente-neuf outils coûtent plusieurs milliers de
jetons par question, avant même la question. Sur un poste dédié à la veille
vulnérabilités, `vuln_intel_mcp` seul revient bien moins cher.

---

## 3. ChatGPT — ce qu'il faudrait faire

ChatGPT n'accepte que des serveurs MCP **distants**. Trois choses seraient
nécessaires :

1. **Un transport HTTP.** Le SDK MCP Python gère le *Streamable HTTP* ; il
   s'agirait d'ajouter un mode serveur en plus du `stdio` actuel.
2. **Un hébergement joignable en HTTPS**, avec un certificat valide.
3. **Une authentification.** C'est le point qui change tout : en local, le
   serveur ne sert que la personne devant la machine. Exposé publiquement, il
   devient un service que n'importe qui peut interroger — il faudrait au
   minimum des jetons d'accès, une limitation de débit par appelant, et une
   décision explicite sur les outils exposés.

Deux garde-fous du projet devraient être reconsidérés dans ce cadre. Les clés
d'API ne seraient plus celles de l'utilisateur mais celles de l'hébergeur, donc
son quota et sa facture. Et `check_tls` ouvre des connexions vers l'hôte
demandé : exposé publiquement sans restriction, il devient un relais de
reconnaissance pour des tiers.

Ce n'est pas une objection de principe, c'est une liste de travaux. Ils sont
faisables — simplement, ce n'est pas ce que « transformer en `.mcpb` »
recouvre.

---

## 4. Vérifier avant de distribuer

```bash
# Le manifeste respecte-t-il le schéma officiel ?
npx @anthropic-ai/mcpb validate mcpb/manifest.json

# L'archive est-elle intègre ?
unzip -t argus-secops-1.0.0.mcpb

# Le paquet s'exécute-t-il une fois décompressé ?
npx @anthropic-ai/mcpb unpack argus-secops-1.0.0.mcpb /tmp/essai
cd /tmp/essai && uv run --directory . server/main.py --check
```

Le dernier contrôle est le seul qui compte vraiment : il lance le paquet comme
le fera Claude Desktop après installation.

### Regénérer le manifeste après un changement d'outils

La liste des 39 outils du manifeste n'est pas recopiée à la main : elle est
demandée au serveur lui-même. Après avoir ajouté ou retiré un outil,
regénérez-la — sinon le manifeste annonce des outils qui n'existent plus.

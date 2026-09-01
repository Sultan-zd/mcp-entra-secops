# Paquet MCPB — ARGUS

Tout ce qui concerne l'extension distribuable vit dans ce dossier. Il produit
`dist/argus-secops-1.0.0.mcpb`, installable dans Claude Desktop d'un double-clic.

## Construire

Une seule commande, depuis la racine du dépôt :

```bash
python mcpb/outils/construire.py
```

Elle enchaîne quatre étapes, dont la dernière est celle qui compte :

1. **Synchroniser** `src/` → `mcpb/src`
2. **Générer** `manifest.json` en interrogeant le serveur
3. **Empaqueter** avec la CLI `@anthropic-ai/mcpb`
4. **Vérifier** — dépaqueter ailleurs et *exécuter* le résultat

L'étape 4 existe parce qu'empaqueter réussit même quand le paquet est cassé.
Une version a ainsi été produite dont la commande de diagnostic plantait sur un
`KeyError` : le serveur démarrait, la CLI annonçait un succès, et le défaut
n'apparaissait que chez le destinataire — sur la première commande qu'il lance.
Un paquet n'est vérifié que s'il a été exécuté depuis une copie dépaquetée.

Options utiles :

```bash
python mcpb/outils/construire.py --sans-verification   # plus rapide
python mcpb/outils/construire.py --verifier-seulement  # contrôle l'écart src/ ↔ mcpb/src
```

## Contenu

| Chemin | Rôle | Versionné |
|---|---|---|
| `manifest.json` | Généré — 57 outils, déclarés par le serveur lui-même | oui |
| `pyproject.toml` | Dépendances, installées par `uv` chez le destinataire | oui |
| `server/main.py` | Point d'entrée lancé par `uv` | oui |
| `.mcpbignore` | Ce qui ne doit pas partir dans le paquet | oui |
| `outils/` | Scripts de construction | oui |
| `src/` | Copie du code source | **non** |
| `dist/` | Artefact `.mcpb` produit | **non** |

`src/` et `dist/` sont régénérés à chaque construction. Les versionner créerait
deux exemplaires du même code, qui divergeraient à la première correction
appliquée d'un seul côté — et ajouterait près de 700 Ko de binaire par
changement.

`outils/` et `dist/` sont exclus du paquet par `.mcpbignore` : sans cela, chaque
construction empaquetterait la précédente, et le destinataire recevrait des
scripts qui pointent vers des chemins inexistants chez lui.

## Pourquoi `uv` et pas des dépendances embarquées

Le format MCPB accepte deux façons de livrer un serveur Python. Embarquer les
dépendances donnerait un paquet **par plateforme et par version de Python** —
`cryptography` et `pydantic-core` sont compilés. Avec `uv`, un seul fichier de
945 Ko fonctionne sur Windows, macOS et Linux.

Le prix : le destinataire installe `uv` une fois. Voir
[`../docs/INSTALLER.md`](../docs/INSTALLER.md).

## Signature

```bash
python mcpb/outils/signer.py
```

Le script crée le couple de signature à la première exécution, signe le paquet,
relit le bloc produit et affiche l'empreinte du certificat.

**Ce que la signature apporte** : une enveloppe d'intégrité — le paquet ne peut
plus être modifié en chemin sans invalider le bloc — et une identité stable. Une
équipe qui a vérifié l'empreinte une fois peut refuser toute version qui ne la
porte pas.

**Ce qu'elle n'apporte pas** : le certificat est auto-signé. Aucune autorité ne
se porte garante, et l'hôte affichera toujours un avertissement à
l'installation.

### `mcpb verify` répondra toujours « not signed »

Ce n'est pas un défaut du paquet, et il a fallu lire le code de la CLI pour
l'établir. Sa fonction de vérification appelle `p7.verify()` de `node-forge`,
qui lève :

```
PKCS#7 signature verification not yet implemented.
```

`verifyMcpbFile` traite **toute** exception comme une absence de signature —
« not signed » est un fourre-tout qui masque la vraie cause. Aucune signature,
quelle qu'elle soit, ne peut donc être confirmée par cet outil aujourd'hui.
`signer.py` contrôle donc le bloc lui-même : présence de l'en-tête et du pied,
cohérence de la longueur déclarée, lecture du PKCS#7 et de son certificat.

### « Failed to preview extension : Invalid comment length »

Le défaut réellement rencontré, et corrigé. `signMcpbFile` (dans `sign.js` de
la CLI) ajoute le bloc de signature par simple concaténation d'octets, sans
mettre à jour le champ de longueur de commentaire de l'enregistrement de fin
d'archive ZIP (EOCD). Le fichier obtenu déclare un commentaire de longueur 0
alors qu'il porte réellement ~2,2 Ko de données après cette déclaration.

`zipfile` de Python **tolère** cet écart — c'est pourquoi nos propres
vérifications passaient. **Claude Desktop valide ce champ strictement** et
refuse le fichier avec exactement ce message.

`signer.py` corrige désormais le champ après chaque signature, et un contrôle
strict — qui rejoue la même validation que Claude Desktop — s'exécute avant de
publier l'empreinte. Si vous obtenez encore cette erreur, l'extension a été
signée avec une version de `signer.py` antérieure à ce correctif :
reconstruisez et signez à nouveau.

**Ne signez jamais un fichier déjà signé.** `mcpb sign` relit l'archive telle
quelle et empile un second bloc dessus, sans erreur ni avertissement — un
paquet peut ainsi porter deux signatures superposées sans que rien ne le
signale. `signer.py` refuse ce cas net ; reconstruisez toujours avec
`construire.py` avant de signer.

### La clé privée ne quitte jamais la machine

`mcpb/signature/` est exclu de git **et** du paquet. Les deux exclusions
comptent : lors de la première signature, `.mcpbignore` ne connaissait pas ce
dossier, et `signature/cle.pem` s'est retrouvé **dans l'extension distribuée** —
n'importe quel destinataire aurait pu signer des versions falsifiées sous la
même identité. La clé a été détruite et regénérée ; `construire.py` refuse
désormais tout paquet contenant un `.pem`, un `.key`, un `.pfx` ou un `.p12`.

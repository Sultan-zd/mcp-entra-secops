# Paquet MCPB — ARGUS

Ce dossier produit `argus-secops-1.0.0.mcpb`, l'extension installable dans
Claude Desktop d'un double-clic.

## Construire

```bash
# 1. Copier le code source dans le paquet
cp -r ../src ./src && rm -rf src/argus_console src/argus_obs src/argus_agent src/argus_eval

# 2. Régénérer le manifeste depuis le serveur lui-même
python ../scripts/generer_manifeste.py

# 3. Empaqueter
npx @anthropic-ai/mcpb pack . ../argus-secops-1.0.0.mcpb
```

`src/` n'est pas versionné : c'est une copie de `../src`, régénérée à chaque
construction. La versionner créerait deux exemplaires du même code, qui
divergeraient à la première correction appliquée d'un seul côté.

## Contenu

| Fichier | Rôle |
|---|---|
| `manifest.json` | Généré — 39 outils, déclarés par le serveur lui-même |
| `pyproject.toml` | Dépendances, installées par `uv` chez le destinataire |
| `server/main.py` | Point d'entrée lancé par `uv` |
| `src/` | Copie du code source (non versionnée) |

## Pourquoi `uv` et pas des dépendances embarquées

Le format MCPB accepte deux façons de livrer un serveur Python. Embarquer les
dépendances donnerait un paquet **par plateforme et par version de Python** —
`cryptography` et `pydantic-core` sont compilés. Avec `uv`, un seul fichier de
636 Ko fonctionne sur Windows, macOS et Linux.

Le prix : le destinataire installe `uv` une fois. Voir `../docs/DISTRIBUER.md`.

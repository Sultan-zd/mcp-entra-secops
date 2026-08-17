# =============================================================================
# Étape 1 — construction
# Les outils de compilation restent ici et n'atteignent jamais l'image finale.
# =============================================================================
FROM python:3.13-slim AS builder

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Le code est copié avec les métadonnées : hatchling embarque les fixtures JSON
# du paquet, nécessaires au mode de démonstration.
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir .

# =============================================================================
# Étape 2 — exécution
# =============================================================================
FROM python:3.13-slim

# Les correctifs de sécurité publiés depuis la construction de l'image de base
# sont appliqués ici. Sans cette étape, l'image hérite des vulnérabilités
# connues de `python:3.13-slim` et le scan Trivy de la CI échoue — ce qui est
# le comportement attendu : un conteneur de sécurité ne doit pas embarquer de
# CVE corrigeable.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Exécution sans privilèges : une compromission du serveur ne donne pas root
# dans le conteneur.
RUN useradd --create-home --uid 1000 appuser

COPY --from=builder --chown=appuser:appuser /opt/venv /opt/venv

USER appuser
WORKDIR /home/appuser

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# AUCUN secret n'est inscrit ici. Les identifiants sont fournis au démarrage :
#   docker run -i --rm --env-file .env entra-secops-mcp
# Un ENV AZURE_CLIENT_SECRET=... resterait lisible dans les couches de l'image,
# y compris après suppression.

LABEL org.opencontainers.image.title="Entra ID SecOps MCP Server" \
      org.opencontainers.image.description="Serveur MCP exposant les journaux de sécurité Microsoft Entra ID" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["python", "-m", "entra_secops_mcp"]

# syntax=docker/dockerfile:1
# MuxAI : Node seul, aucune dépendance npm. L'image de base est épinglée par
# empreinte (index multi-architecture amd64 + arm64).
ARG NODE_IMAGE=node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
FROM ${NODE_IMAGE}
# Paquets du système à jour, puis ce dont les CLI ont besoin : git pour les
# dépôts, python3 et openssh-client pour leurs outils, ripgrep pour la recherche.
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends git ca-certificates ripgrep curl python3 openssh-client tzdata \
 && rm -rf /var/lib/apt/lists/*
# Les CLI pilotés par MuxAI. npm et npx restent dans l'image : les serveurs MCP
# lancés par « npx » en dépendent.
RUN npm install -g --no-audit --no-fund @anthropic-ai/claude-code @openai/codex && npm cache clean --force
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8787 MUXAI_DATA=/data
WORKDIR /app
COPY server.js package.json ./
COPY public ./public
COPY agent ./agent
RUN mkdir -p /data && chown -R node:node /data /app
# Non-root : Claude Code refuse le mode « tout autoriser » en root.
USER node
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8787/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "server.js"]

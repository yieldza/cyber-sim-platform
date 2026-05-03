#!/usr/bin/env bash
# Pull the published CSP images and start them.
# Useful on fresh hosts that don't need build deps.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "ERR: missing .env. Copy .env.example to .env and fill secrets."
  exit 2
fi

docker compose pull
docker compose up -d
docker compose ps

#!/usr/bin/env bash
# Run docker compose with local dev env (.env.development).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/.env.development"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing ${ENV_FILE} — copy .env.example to .env.development and fill secrets." >&2
  exit 1
fi

exec docker compose --env-file "${ENV_FILE}" --project-directory "${ROOT}" "$@"

# Security Policy

## Scope

This repository hosts the Rust backend (`portfolio-backend`) for API, auth, gate logic,
and observability endpoints.

## Reporting Vulnerabilities

- Do not open public issues for security vulnerabilities.
- Email: security@dimasptra.my.id
- Include: impact, reproduction steps, affected files, and mitigation ideas.

## Security Model

- Auth: JWT access tokens + rotating refresh tokens in HttpOnly cookies.
- Gate: puzzle UX for terminal access (`/gate/*`), not a perimeter for all API routes.
- CORS: enforced by backend (`ALLOWED_ORIGINS`/`FRONTEND_ORIGIN`).
- Secrets: loaded from env/Secret Manager, never committed.

## Production Baseline

- `ENVIRONMENT=production`
- `JWT_SECRET` and `REFRESH_TOKEN_SECRET` set (>=32 chars)
- `ADMIN_EMAIL` + admin password hash configured
- `GATE_TOKEN_SECRET` + `GATE_L2_ANSWER` configured
- `ENABLE_SWAGGER_UI=false`
- `METRICS_BEARER_TOKEN` set when exposing `/metrics`

See `terraform/docs/deploy-runbook.md` for deployment hardening steps.

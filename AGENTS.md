# portfolio-backend — agent context (SSOT)

Rust/Axum API for [portfolio-frontend](https://github.com/infinitedim/portfolio-frontend) (Next.js 16). Read this file first; avoid scanning the whole monorepo unless the task needs frontend/infra detail.

---

## Learned user preferences

- Solo developer — keep scope realistic for one person.
- Indonesian chat is fine; **gate/terminal puzzle copy stays English** (NATAS-style).
- Dual entry: standard landing + gated terminal — do not remove terminal.
- **Commits/PRs only when explicitly asked.**
- Gate always on in dev; bypass via `GATE_BYPASS_SECRET` on **frontend** (`X-Gate-Bypass`), not a Rust dev-off flag.
- User owns secrets in `.env.development` / GCP / Vercel; agents may scaffold `.env.example` only.
- Gate = NATAS web puzzles (login, robots.txt → `/s3cr3t/`, Referer), not Bandit/Behemoth/SSH.
- GCP docs should stay beginner-friendly.
- Backend SLA: **all API routes P95 &lt; 50ms** (see `docs/performance/API_SLA.md`).
- Roadmap.sh auth: **only** `POST https://roadmap.sh/api/v1-login` with `ROADMAP_EMAIL` / `ROADMAP_PASSWORD` — no GitHub OAuth, no manual bearer env.

---

## Multi-repo map

| Repo                       | Role                                                        | Default port |
| -------------------------- | ----------------------------------------------------------- | ------------ |
| `portfolio-backend` (this) | REST + WS API, admin auth, gate validation, proxies         | **8080**     |
| `portfolio-frontend`       | Next.js UI, `proxy.ts` CSP/gate redirect, BFF `/api/gate/*` | 3000         |

**Frontend agent context:** `portfolio-frontend/AGENTS.md`  
**Feature / product SSOT:** `portfolio-frontend/FEATURE_PLANNING.md`  
**Gate ops (full flow):** `portfolio-frontend/docs/dual-ui-gate.md`

---

## Tech stack

- **Rust** (edition 2021), **Axum 0.8**, **SQLx 0.8** + PostgreSQL 16
- **Redis 7** (optional): distributed rate limits + WS presence (`src/redis/`)
- **tower_governor** fallback when `REDIS_URL` unset
- **JWT** (admin), **bcrypt**, **TOTP** (admin 2FA)
- **Prometheus** metrics, structured tracing → Loki (via Promtail)
- **OpenAPI** (`utoipa`) — `/api/docs` when `ENABLE_SWAGGER_UI=true` (off in prod by default)
- **Terraform** GCP: `terraform/environments/prod/` — runbook `terraform/docs/deploy-runbook.md`

---

## Repository layout (where to edit)

```
src/
  lib.rs              # create_app(), CORS, rate-limit wiring, route merge
  main.rs             # tokio entry → run()
  db/mod.rs           # pool, inline SQL migrations (no sqlx-cli folder)
  db/models.rs
  redis/              # pool, presence_store, rate_limit middleware
  routes/             # one module per domain (see API map below)
  metrics.rs          # Prometheus + /api/analytics/pageview
  logging/            # request-id middleware, file logs (dev)
  email/              # Resend Mailer trait
  openapi.rs          # ApiDoc for Swagger
config/               # prometheus, loki, grafana, slo-rules
terraform/            # GCP prod IaC
docker-compose.yml    # local: postgres, redis, backend, observability
docker-compose.gcp-ops.yml  # prod VM: postgres, redis, loki, grafana, prometheus
scripts/              # compose-dev.sh, latency-smoke.sh
docs/performance/     # API_SLA.md, BASELINE_*.md
```

---

## Local development

```bash
cp .env.example .env.development   # never commit real secrets
# API URLs for frontend: localhost:8080 (not Cloud Run)

docker compose up -d               # or scripts/compose-dev.sh
cargo run                          # loads .env.development when ENVIRONMENT != production

# Before claiming done on .rs changes:
cargo fmt --all -- --check
cargo check --all-features
cargo clippy --all-features -- -D warnings
cargo test --all-features          # set TEST_DATABASE_URL for DB tests (see .github/workflows/ci.yml)
```

- **Env file:** `load_env_file()` in `lib.rs` — production uses `ENVIRONMENT=production` + platform env.
- **CORS:** `ALLOWED_ORIGINS` / `FRONTEND_ORIGIN`; dev auto-adds `localhost:3000–3002`.
- **Postgres tests:** `TEST_DATABASE_URL=postgres://portfolio:portfolio@localhost:5432/portfolio_test`
- **Redis tests:** `TEST_REDIS_URL=redis://localhost:6379` (optional; tests skip if unset)

---

## API surface (grouped)

Public unless noted. Rate limits: Redis buckets when `REDIS_URL` set, else `tower_governor` per route group in `lib.rs`.

| Area          | Paths                                                                                                                                       | Module                 | Notes                                         |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | --------------------------------------------- |
| Health        | `/health`, `/health/detailed`, `/health/database`, `/health/redis`, `/health/ready`                                                         | `health.rs`            | Ready = DB required                           |
| Metrics       | `/metrics`, `POST /api/analytics/pageview`                                                                                                  | `metrics.rs`           | Bearer `METRICS_BEARER_TOKEN` optional        |
| Gate          | `GET /api/gate/status`, `POST /api/gate/login`, `POST /api/gate/complete/3`, `POST /api/gate/unlock`, `GET /api/gate/challenge/2/users.txt` | `gate.rs`              | In-memory `gate_progress` sessions; see below |
| Auth (admin)  | `/api/auth/*`, `/api/auth/2fa/*`                                                                                                            | `auth.rs`, `twofa.rs`  | JWT + refresh in **Postgres** (not in-memory) |
| Blog          | `/api/blog/*`, `/api/blog/series/*`                                                                                                         | `blog.rs`, `series.rs` | HTML sanitized (ammonia)                      |
| Portfolio     | `GET/PATCH /api/portfolio`, admin versions                                                                                                  | `portfolio.rs`         |                                               |
| Contact       | `POST /api/contact`, `/api/admin/messages/*`                                                                                                | `contact.rs`           | Resend optional                               |
| Newsletter    | `/api/newsletter/*`, `/api/admin/newsletter/*`                                                                                              | `newsletter.rs`        | Double opt-in                                 |
| Roadmap proxy | `/api/roadmap/streak`, `dashboard`, `teams`, `favourites`                                                                                   | `roadmap.rs`           | In-memory cache + upstream login              |
| GitHub proxy  | `/api/github/user/{u}`, `/api/github/stats/{u}`                                                                                             | `github.rs`            | In-memory cache; `GH_TOKEN`                   |
| RSS           | `GET /api/rss`                                                                                                                              | `rss.rs`               | In-memory 60s cache                           |
| CMS           | `/api/v1/content/*`                                                                                                                         | `cms.rs`               | `HEADLESS_CMS_ENABLED` + `X-Api-Key`          |
| AI            | `POST /api/ai/chat`                                                                                                                         | `ai.rs`                | Gemini SSE; `GEMINI_API_KEY`                  |
| Presence      | `GET /ws/presence`                                                                                                                          | `presence.rs`          | Redis or in-memory counts                     |
| Upload        | `/api/upload/*`                                                                                                                             | `upload.rs`            | Admin; files under `uploads/`                 |
| Logs          | `POST /api/logs`                                                                                                                            | `logs.rs`              | Client log ingest → tracing                   |

Swagger: merge at `/api/docs` when enabled. Static uploads: `nest_service("/uploads", …)`.

---

## Terminal gate (backend contract)

Puzzle layer only — **not** API auth. Admin uses separate JWT.

| Level  | Backend check                                                                                       | Secrets / constants                                     |
| ------ | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| L1     | `POST /api/gate/login` level 1 — user `yourblooo0`, pass `GATE_L1_ANSWER` (default `yourblooo0`)    | `GATE_L1_ANSWER`                                        |
| L2     | L1 in session; `GET /api/gate/challenge/2/users.txt` → `yourblooo1:{GATE_L2_ANSWER}`; login level 2 | `GATE_L2_ANSWER`                                        |
| L3     | L2 done; `POST /api/gate/complete/3` — `Referer` must be `{SITE_URL}/terminal`                      | `SITE_URL` / `FRONTEND_ORIGIN`                          |
| Unlock | All 1–3; `POST /api/gate/unlock` → `portfolio_gate` JWT cookie                                      | `GATE_TOKEN_SECRET` (≥32 chars prod), HS256 `iss`/`aud` |

- Session cookie: `gate_progress` (in-memory `GateState` per Cloud Run instance — **`max_instances=1`** in prod for consistency).
- Unlock cookie: `portfolio_gate` (HttpOnly JWT).
- **Frontend:** browser calls same-origin `/api/gate/*` (Next BFF); forwards cookies to this backend — do not rely on cross-origin cookies to `*.run.app`.
- **Frontend-only bypass:** `GATE_BYPASS_SECRET` → `proxy.ts` header `X-Gate-Bypass` (Rust ignores this env).
- Legacy env `GATE_L2_STUB_MD5`, `GATE_L3_SHELLCODE_HASH`, `GATE_L3_OFFSET` — **unused** (archived shellcode design).
- After changing gate answers or `gate.rs`: **rebuild/restart** local Docker backend (stale image kept old L1 creds).

L2 discovery (frontend): `/robots.txt` → `Disallow: /s3cr3t/` → `/s3cr3t/users.txt` proxies challenge endpoint.

---

## Data & external services

- **Postgres:** required in production (`DATABASE_URL`); migrations applied at startup in `db::run_migrations` (extensions, blog, auth, contact, newsletter, api_keys, pgvector when available).
- **Redis:** `REDIS_URL` — rate limit keys `ratelimit:{bucket}:{ip}`; presence `presence:room:*`, `presence:total`, `presence:conn:*` (90s TTL + WS ping). Fail-open rate limit on Redis errors.
- **roadmap.sh:** login + cached GETs; secrets on **GCP only** (`portfolio-roadmap-email/password`), not Vercel.
- **Resend:** contact + newsletter when `RESEND_API_KEY` set.
- **GitHub / Gemini:** optional tokens; slow upstream — cached or streaming exceptions per SLA doc.

---

## Production (GCP + Vercel)

| Component     | Placement                                                                                |
| ------------- | ---------------------------------------------------------------------------------------- |
| Backend       | Cloud Run `asia-southeast2`, port **8080**, `max_instances=1`                            |
| Frontend      | Vercel (`NEXT_PUBLIC_API_URL` + `BACKEND_URL` = Cloud Run **origin**, no trailing slash) |
| Postgres      | Ops VM private IP — `DATABASE_URL` via Secret Manager                                    |
| Redis         | Ops VM `:6379` — `REDIS_URL=redis://<ops_internal_ip>:6379` (Terraform)                  |
| Observability | Same ops VM: Loki, Grafana, Prometheus (`docker-compose.gcp-ops.yml`)                    |

**Networking (critical):**

- Serverless VPC connector `10.10.1.0/28`; Cloud Run `vpc_access.egress = PRIVATE_RANGES_ONLY`.
- Firewall: TCP **5432** + **6379** from connector CIDR → ops VM.
- **`ALL_TRAFFIC` egress without Cloud NAT** breaks roadmap.sh, GitHub, Resend, Gemini — use `PRIVATE_RANGES_ONLY`.
- Unreachable Postgres at startup → **panic** (revision never listens).

**Cloud Run:** public `run.invoker` (`allUsers`) — app-level admin auth. Deploy: `.github/workflows/deploy-gcp.yml` (WIF).

**Common prod mistakes:**

- Wrong `*.run.app` URL in Vercel → Google 404, zero Cloud Run hits.
- `NEXT_PUBLIC_*` changed without Vercel redeploy.
- Roadmap creds only on Vercel (must be on backend/GCP).

---

## Observability & performance

- Local/full stack: `docker-compose.yml` — Postgres, Redis, Loki, Promtail, Grafana, Prometheus.
- SLO: `docs/performance/API_SLA.md`, alerts `config/slo-rules.yml`, CI `scripts/latency-smoke.sh`.
- Tier C routes (roadmap, GitHub): in-memory stale-while-revalidate; target cache-hit P95 &lt; 50ms.
- `/metrics` scrape: optional bearer; prod Prometheus on ops VM.

---

## Frontend coordination (read only when needed)

- Routes: `/` landing, `/terminal` (gated, noindex), `/gate/1–3`, shared `/blog`, `/projects`, etc.
- Gate BFF: `src/app/api/gate/`, `src/lib/gate/gate-client.ts`, `src/lib/gate/gate-proxy.ts`.
- CSP / gate redirect: `src/proxy.ts` (not `middleware.ts`).
- PPR: `cacheComponents: true`; `/roadmap` uses dynamic fetch.
- Verification (frontend changes): `bun run lint` + `bun run type-check` in `portfolio-frontend`.
- Feature #33 perf: `portfolio-frontend/docs/features/FEATURE_33_PERFORMANCE.md`.

---

## Verification checklist (this repo)

| Change type                             | Required                                                   |
| --------------------------------------- | ---------------------------------------------------------- |
| `.rs`, `Cargo.toml`, SQL in `db/mod.rs` | `cargo fmt --check`, `check`, `clippy -D warnings`, `test` |
| Terraform / compose only                | validate + runbook sanity; no Rust suite                   |
| Docs only                               | no Rust suite                                              |

Report pass/fail with terminal output — do not claim green without running commands.

---

## Quick env reference

See `.env.example` for full list. Production panics if missing: `DATABASE_URL`, real `ADMIN_EMAIL`, `ADMIN_HASH_PASSWORD` or `ADMIN_PASSWORD`, `ALLOWED_ORIGINS`/`FRONTEND_ORIGIN`, `GATE_TOKEN_SECRET`, `GATE_L2_ANSWER`.

| Variable                                       | Purpose                                    |
| ---------------------------------------------- | ------------------------------------------ |
| `ENVIRONMENT`                                  | `production` enables strict startup checks |
| `DATABASE_URL`                                 | Postgres                                   |
| `REDIS_URL`                                    | Rate limit + presence (optional)           |
| `JWT_SECRET` / `REFRESH_TOKEN_SECRET`          | Admin tokens                               |
| `GATE_*`                                       | Puzzle answers + unlock JWT                |
| `SITE_URL` / `FRONTEND_ORIGIN`                 | CORS, L3 Referer, email links              |
| `ROADMAP_EMAIL` / `ROADMAP_PASSWORD`           | roadmap.sh login                           |
| `GH_TOKEN`, `GEMINI_API_KEY`, `RESEND_API_KEY` | Optional integrations                      |
| `METRICS_BEARER_TOKEN`                         | Protect `/metrics`                         |

---

_Last expanded for agent onboarding — gate L2 robots.txt, Redis rate limit/presence, Next.js gate BFF, GCP egress. Update this file when architecture or env contracts change._

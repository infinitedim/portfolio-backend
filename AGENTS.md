## Learned User Preferences

- Solo developer project; scope and maintenance burden should stay realistic for one person.
- Communicates in Indonesian sometimes; wants English copy for gate/OverTheWire-style puzzles and related developer-facing UI.
- Landing and gate UI: English default with i18n toggle (reuse existing i18n), not Indonesian-first for those surfaces.
- Do not discard the terminal experience; prefer dual entry (standard landing + gated terminal) over a full UI rewrite.
- Create git commits and pull requests only when explicitly asked.
- Gate stays enabled in development; bypass only via `GATE_BYPASS_SECRET`, not an automatic dev-off flag.
- User fills API keys and other random secrets in `.env`; agents may generate non-secret env defaults and structure.
- Gate puzzles should be NATAS-style web challenges (login, hidden paths, Referer), not SSH/Bandit/Behemoth simulations.
- First time deploying to GCP; prefers clear, beginner-friendly infrastructure documentation and bootstrap guides.
- Portfolio-frontend chats must proactively use Cursor SDK + Team Kit skills/MCP (`.cursor/rules/cursor-sdk-team-kit.mdc`, alwaysApply).
- Roadmap.sh proxy auth: email/password only via `POST https://roadmap.sh/api/v1-login`; reject GitHub OAuth and manual bearer-token flows.
- Backend SLA target: all API routes P95 < 50ms (not health-only `responseTime`).

## Learned Workspace Facts

- Multi-repo portfolio: `portfolio-backend` (Rust/Axum, SQLx/PostgreSQL) and `portfolio-frontend` (Next.js 16, React 19, terminal-interactive portfolio).
- Planned public routing: standard landing at `/`, terminal at `/terminal`, three-level gate at `/gate` (and `/gate/[level]`).
- Blog, social share, RSS, and other content routes stay shared/public; do not duplicate them across standard and terminal UIs.
- Gate puzzles (backend-validated, no answers in frontend bundle): L1 static login `yourbloo0`/`yourbloo0`; L2 requires L1 completion before `/s3cr3t/users.txt` reveals login `yourbloo1` + env password; L3 backend validates `Referer: {SITE_URL}/terminal` in `complete_level_3`; gate JWT pinned to HS256 with `iss`/`aud`. Terminal route `noindex`; terminal SSR verifies JWT via `/api/gate/status`. Gate/terminal is UX puzzle layer, not API auth perimeter (admin JWT separate). `GATE_BYPASS_SECRET` via Next.js `proxy.ts` (`X-Gate-Bypass`), not Rust handlers.
- Backend API default port 8080; frontend align `NEXT_PUBLIC_API_URL` / `BACKEND_URL` with 8080; CORS auto-merges localhost origins (ports 3000–3002) when `ENVIRONMENT != production`; gate vars in `.env.example`.
- Feature status SSOT: `portfolio-frontend/FEATURE_PLANNING.md` (+ `docs/dual-ui-gate.md` for gate ops); `ROADMAP.md` removed May 2026 after performance backlog moved to Feature #33.
- PWA is site-wide (`public/manifest.json`, `public/sw.js`, scope `/`, offline page); install prompt only after terminal onboarding tour completes.
- Observability stack (Loki, Grafana, Prometheus) runs on a GCE ops VM in production via `docker-compose.gcp-ops.yml`; same stack in local `docker-compose.yml` for dev. Redis health uses real PING via `REDIS_URL`; not yet used for app cache or gate sessions. Optional `METRICS_BEARER_TOKEN` protects `/metrics`; Prometheus prod scrape uses bearer auth.
- GCP production: backend on Cloud Run (asia-southeast2/Jakarta) with `max_instances=1` for gate session consistency, frontend on Vercel; Terraform (network, iam, artifact_registry, secrets, compute_ops, cloud_run); ops VM (e2-medium, no public IP, IAP SSH) hosts Postgres 16 + observability at `/mnt/data`; CI via `deploy-gcp.yml` Workload Identity Federation.
- Next.js 16 edge handler is `src/proxy.ts` (`export function proxy()`), not legacy `middleware.ts`.
- Frontend performance: `cacheComponents: true` (PPR) with Feature #33 docs at `docs/features/FEATURE_33_PERFORMANCE.md`; dual RUM (pino/Loki + Vercel Speed Insights). Pre-completion verification: backend `cargo fmt/check/clippy/test`; frontend `bun run lint` + `type-check`. Known Vitest hang: `background-manager.test.tsx` (~16 min).
- Backend performance & integrations: all API routes P95 <50ms SLO (`docs/performance/API_SLA.md`, `config/slo-rules.yml`, Grafana 50ms alerts, `scripts/latency-smoke.sh` in CI); roadmap/github in-memory cache with stale-while-revalidate; roadmap auth via `ROADMAP_EMAIL`/`ROADMAP_PASSWORD` → `POST …/v1-login` (Terraform secrets `roadmap-email`/`roadmap-password`; `ROADMAP_AUTH_TOKEN` removed); Swagger UI disabled in production.

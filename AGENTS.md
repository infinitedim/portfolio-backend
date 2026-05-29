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

## Learned Workspace Facts

- Multi-repo portfolio: `portfolio-backend` (Rust/Axum, SQLx/PostgreSQL) and `portfolio-frontend` (Next.js 16, React 19, terminal-interactive portfolio).
- Planned public routing: standard landing at `/`, terminal at `/terminal`, three-level gate at `/gate` (and `/gate/[level]`).
- Blog, social share, RSS, and other content routes stay shared/public; do not duplicate them across standard and terminal UIs.
- Gate puzzles (backend-validated, no answers in frontend bundle): L1 static login `yourbloo0`/`yourbloo0`; L2 discover `/s3cr3t/users.txt` then login `yourbloo1` + env password; L3 requires `Referer: {SITE_URL}/terminal`.
- Terminal route should be `noindex`; gate and terminal access require server-side validation (not answers in the frontend bundle).
- Backend API default is port 8080; frontend should align `NEXT_PUBLIC_API_URL` / `BACKEND_URL` fallbacks with 8080, not 3001.
- Both repos have `.env.example` with gate vars documented (`GATE_L1_ANSWER`, `GATE_L2_ANSWER`, `GATE_TOKEN_SECRET`, etc.).
- PWA is site-wide (`public/manifest.json`, `public/sw.js`, scope `/`, offline page); install prompt only after terminal onboarding tour completes.
- Observability stack (Loki, Grafana, Prometheus) runs on a GCE ops VM in production via `docker-compose.gcp-ops.yml`; same stack in local `docker-compose.yml` for dev. Redis is in compose but not used by app code yet (health probe only).
- Feature #22 (Spotify now playing) was retired and removed from both repos (May 2026).
- `GATE_BYPASS_SECRET` is consumed by the Next.js `proxy.ts` (`X-Gate-Bypass` header), not by Rust gate route handlers.
- Production deployment: backend on GCP Cloud Run (asia-southeast2/Jakarta), frontend on Vercel. Terraform infra with 6 modules: network, iam, artifact_registry, secrets, compute_ops, cloud_run; state in GCS bucket.
- GCP ops VM (e2-small, no public IP, IAP-only SSH) hosts self-managed Postgres 16 + observability; persistent disk at `/mnt/data` with daily snapshots.
- CI/CD: GitHub Actions `deploy-gcp.yml` uses Workload Identity Federation (no SA keys) to build, push to Artifact Registry, and deploy Cloud Run on push to main.
- Frontend unit test known issue: `background-manager.test.tsx` hangs Vitest worker ~16 min (mock-related); full suite without it runs in ~93s.
- Pre-completion verification (Cursor rules): backend Rust changes require `cargo fmt --check`, `cargo check --all-features`, `cargo clippy --all-features -- -D warnings`, and `cargo test --all-features`; frontend Next.js changes require `bun run lint` and `bun run type-check` only.

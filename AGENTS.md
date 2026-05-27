## Learned User Preferences

- Solo developer project; scope and maintenance burden should stay realistic for one person.
- Communicates in Indonesian sometimes; wants English copy for gate/OverTheWire-style puzzles and related developer-facing UI.
- Landing and gate UI: English default with i18n toggle (reuse existing i18n), not Indonesian-first for those surfaces.
- Do not discard the terminal experience; prefer dual entry (standard landing + gated terminal) over a full UI rewrite.
- Create git commits and pull requests only when explicitly asked.
- Gate stays enabled in development; bypass only via `GATE_BYPASS_SECRET`, not an automatic dev-off flag.
- User fills API keys and other random secrets in `.env`; agents may generate non-secret env defaults and structure.

## Learned Workspace Facts

- Multi-repo portfolio: `portfolio-backend` (Rust/Axum, SQLx/PostgreSQL) and `portfolio-frontend` (Next.js 16, React 19, terminal-interactive portfolio).
- Planned public routing: standard landing at `/`, terminal at `/terminal`, three-level gate at `/gate` (and `/gate/[level]`).
- Blog, social share, RSS, and other content routes stay shared/public; do not duplicate them across standard and terminal UIs.
- Gate puzzles (web-safe simulations, backend-validated): Bandit 32→33 uppercase-shell escape, Natas 33 Phar/md5 chain, Behemoth 7 buffer overflow at offset 528.
- Terminal route should be `noindex`; gate and terminal access require server-side validation (not answers in the frontend bundle).
- Backend API default is port 8080; frontend should align `NEXT_PUBLIC_API_URL` / `BACKEND_URL` fallbacks with 8080, not 3001.
- Backend lacks a committed `.env.example`; frontend `.env.example` exists and needs gate-related vars documented when gate ships.
- Observability stack includes Loki, Grafana, and Prometheus via Docker Compose; Redis is in compose but not used by app code yet.

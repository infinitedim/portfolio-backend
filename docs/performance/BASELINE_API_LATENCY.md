# API Latency Baseline

Measured 2026-05-30 via `hey` against Docker Compose stack on local machine.
Concurrency: 5, requests: 100-200 per route (Tier A/B), 10 per route (Tier C).

## Tier A — In-memory / minimal I/O

| Route | Avg | P50 | P95 | P99 | Verdict |
|-------|-----|-----|-----|-----|---------|
| `GET /health` | 0.5ms | 0.4ms | 0.7ms | 2.7ms | PASS |
| `GET /health/detailed` | 3.0ms | 2.9ms | 4.4ms | 5.8ms | PASS |
| `GET /health/database` | 2.1ms | 2.0ms | 3.0ms | 3.6ms | PASS |
| `GET /health/redis` | 2.4ms | 2.4ms | 3.6ms | 4.3ms | PASS |
| `GET /health/ready` | 3.0ms | 3.0ms | 3.8ms | 4.6ms | PASS |
| `GET /metrics` | 2.5ms | 2.5ms | 3.3ms | 5.6ms | PASS |
| `POST /api/analytics/pageview` | 0.9ms | 0.9ms | 1.4ms | 2.6ms | PASS |
| `GET /api/gate/status` | 0.7ms | 0.6ms | 1.5ms | 2.5ms | PASS |

All Tier A routes: **P99 < 6ms**. Well within 50ms SLA.

## Tier B — Database CRUD

| Route | Avg | P50 | P95 | P99 | Verdict |
|-------|-----|-----|-----|-----|---------|
| `GET /api/blog` | 2.9ms | 2.1ms | 10.1ms | 16.4ms | PASS |
| `GET /api/blog/tags` | 1.5ms | 1.0ms | 7.9ms | 8.2ms | PASS |
| `GET /api/rss` | 2.2ms | 2.1ms | 3.8ms | 4.3ms | PASS |
| `GET /api/portfolio` | 1.5ms | 1.4ms | 2.8ms | 3.0ms | PASS |
| `GET /api/blog/series` | 1.4ms | 1.2ms | 4.6ms | 4.8ms | PASS |
| `POST /api/auth/login` (bad creds) | 1.4ms | 0.4ms | 6.8ms | 6.8ms | PASS* |
| `POST /api/contact` | 1.1ms | 0.5ms | 5.6ms | 5.6ms | PASS |
| `POST /api/logs` | 1.1ms | 0.7ms | 3.3ms | 5.3ms | PASS |

*Auth login with wrong credentials returns early (no bcrypt). Valid bcrypt will be ~100-300ms.

All Tier B routes: **P95 < 11ms**. Well within 50ms SLA.

## Tier C — External proxy

| Route | Avg | P50 | Slowest | Verdict |
|-------|-----|-----|---------|---------|
| `GET /api/roadmap/streak` | 188ms | 117ms | 592ms | **FAIL** |
| `GET /api/roadmap/dashboard` | 208ms | 244ms | 245ms | **FAIL** |
| `GET /api/github/user/{u}` | 959ms | 659ms | 3783ms | **FAIL** |
| `GET /api/github/stats/{u}` | 316ms | 0.6ms* | 843ms | **FAIL** |

*GitHub stats has 5-min in-memory cache; cache-hit is <1ms, cache-miss is 500ms+.

## Summary

- **Tier A:** All routes < 6ms P99. No changes needed.
- **Tier B:** All routes < 17ms P99. Already meet SLA.
- **Tier C:** Roadmap (100-600ms) and GitHub (500-3800ms) routes are the primary SLA violators. Need Redis cache + background refresh to serve from cache under 50ms.

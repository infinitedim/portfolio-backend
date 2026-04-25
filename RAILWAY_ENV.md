# Railway Environment Variables

Configure these in the Railway dashboard under your service → **Variables**.

---

## Auto-injected by Railway (do NOT set manually)

| Variable       | Injected by               | Notes                                                                                     |
| -------------- | ------------------------- | ----------------------------------------------------------------------------------------- |
| `PORT`         | Railway runtime           | Dynamically assigned per deployment. The app reads this and defaults to `3001` if absent. |
| `DATABASE_URL` | Railway PostgreSQL plugin | Full connection string. Added automatically when you attach a Postgres service.           |
| `REDIS_URL`    | Railway Redis plugin      | Full connection string. Added automatically when you attach a Redis service.              |

---

## Server

| Variable      | Required | Example      | Secret |
| ------------- | -------- | ------------ | ------ |
| `HOST`        | No       | `0.0.0.0`    | No     |
| `ENVIRONMENT` | **Yes**  | `production` | No     |

> Set `ENVIRONMENT=production` — this enables JWT secret validation and production log formatting. The app will panic on startup if `JWT_SECRET` is default when environment is `production`.

---

## Authentication & Security

| Variable               | Required | Example                         | Secret  |
| ---------------------- | -------- | ------------------------------- | ------- |
| `JWT_SECRET`           | **Yes**  | 64-char random string           | **Yes** |
| `REFRESH_TOKEN_SECRET` | **Yes**  | Different 64-char random string | **Yes** |

> Generate with: `openssl rand -hex 32`

---

## CORS

| Variable          | Required | Example                                                 | Secret |
| ----------------- | -------- | ------------------------------------------------------- | ------ |
| `ALLOWED_ORIGINS` | **Yes**  | `https://yourfrontend.com,https://www.yourfrontend.com` | No     |
| `FRONTEND_ORIGIN` | **Yes**  | `https://yourfrontend.com`                              | No     |

> Comma-separated list for `ALLOWED_ORIGINS`. Must include the exact origin (with scheme and no trailing slash) of your frontend.

---

## Database Pool Tuning

| Variable      | Required | Default | Secret |
| ------------- | -------- | ------- | ------ |
| `DB_POOL_MIN` | No       | `2`     | No     |
| `DB_POOL_MAX` | No       | `10`    | No     |

---

## Logging

| Variable    | Required | Example | Secret |
| ----------- | -------- | ------- | ------ |
| `LOG_LEVEL` | No       | `info`  | No     |

> Accepted values: `trace`, `debug`, `info`, `warn`, `error`. Use `info` or `warn` in production.

---

## Admin Seeding (first-deploy only)

| Variable              | Required             | Example                                        | Secret  |
| --------------------- | -------------------- | ---------------------------------------------- | ------- |
| `ADMIN_EMAIL`         | **Yes**              | `you@yourdomain.com`                           | No      |
| `ADMIN_HASH_PASSWORD` | Recommended          | bcrypt hash of admin password                  | **Yes** |
| `ADMIN_PASSWORD`      | Alternative to above | Plain-text password (bcrypt-hashed at runtime) | **Yes** |

> Prefer `ADMIN_HASH_PASSWORD` over `ADMIN_PASSWORD`. Generate a bcrypt hash with:
> `cargo run --bin hash-password -- "your_strong_password"`

---

## Roadmap.sh Integration

| Variable             | Required | Example                     | Secret  |
| -------------------- | -------- | --------------------------- | ------- |
| `ROADMAP_AUTH_TOKEN` | No       | `Bearer <your_roadmap_jwt>` | **Yes** |

> Only required if you use the roadmap proxy endpoints (`/api/roadmap/*`).

---

## GitHub Secrets for CD Pipeline

These go in **GitHub → Repository → Settings → Secrets and variables → Actions**, not Railway.

| Secret                  | Description                                                                                                      |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `RAILWAY_TOKEN`         | Railway API token. Get from Railway dashboard → Account → Tokens.                                                |
| `RAILWAY_PUBLIC_DOMAIN` | The public domain Railway assigned to your service (without `https://`). e.g. `portfolio-backend.up.railway.app` |

# API SLA Matrix

Target: **P95 < 50ms** for all HTTP routes.

## Route Tiers

### Tier A — In-memory / minimal I/O (target P95 < 5ms)

| Method | Path | Handler | Module | Strategy |
|--------|------|---------|--------|----------|
| GET | `/health` | `health_ping` | `health.rs` | Static JSON |
| GET | `/health/detailed` | `health_detailed` | `health.rs` | Parallel DB+Redis probe |
| GET | `/health/database` | `health_database` | `health.rs` | Single DB probe |
| GET | `/health/redis` | `health_redis` | `health.rs` | Single Redis probe |
| GET | `/health/ready` | `health_ready` | `health.rs` | DB+Redis probe |
| GET | `/metrics` | `metrics_handler` | `metrics.rs` | Prometheus render |
| POST | `/api/analytics/pageview` | `record_pageview` | `metrics.rs` | Counter increment |
| GET | `/api/gate/status` | `gate_status` | `gate.rs` | In-memory session |
| POST | `/api/gate/login` | `gate_login` | `gate.rs` | String compare |
| POST | `/api/gate/complete/3` | `complete_level_3` | `gate.rs` | Referer check |
| POST | `/api/gate/unlock` | `gate_unlock` | `gate.rs` | JWT mint |
| GET | `/api/gate/challenge/2/users.txt` | `users_txt` | `gate.rs` | Static text |
| POST | `/api/logs` | `receive_client_logs` | `logs.rs` | Tracing emit |

### Tier B — Database CRUD (target P95 < 20ms)

| Method | Path | Handler | Module | Strategy |
|--------|------|---------|--------|----------|
| GET | `/api/blog` | `list_posts` | `blog.rs` | Paginated query + index |
| POST | `/api/blog` | `create_post` | `blog.rs` | INSERT |
| GET | `/api/blog/tags` | `list_tags` | `blog.rs` | Aggregate query |
| GET | `/api/blog/{slug}` | `get_post` | `blog.rs` | PK lookup |
| PATCH | `/api/blog/{slug}` | `update_post` | `blog.rs` | UPDATE |
| DELETE | `/api/blog/{slug}` | `delete_post` | `blog.rs` | DELETE |
| GET | `/api/blog/series` | `list_series_public` | `series.rs` | Query |
| GET | `/api/blog/series/{slug}` | `get_series_public` | `series.rs` | PK lookup |
| GET | `/api/portfolio` | `get_portfolio` | `portfolio.rs` | Query |
| PATCH | `/api/portfolio` | `update_portfolio` | `portfolio.rs` | UPDATE + version |
| GET | `/api/playground/snippets/{id}` | `get_snippet` | `playground.rs` | PK lookup |
| POST | `/api/playground/snippets` | `create_snippet` | `playground.rs` | INSERT |
| GET | `/api/admin/messages` | `list_messages` | `contact.rs` | Paginated query |
| GET | `/api/admin/messages/{id}` | `get_message` | `contact.rs` | PK lookup |
| PATCH | `/api/admin/messages/{id}` | `update_message` | `contact.rs` | UPDATE |
| DELETE | `/api/admin/messages/{id}` | `delete_message` | `contact.rs` | DELETE |
| PATCH | `/api/admin/messages/bulk` | `bulk_mark_messages_read` | `contact.rs` | Batch UPDATE |
| DELETE | `/api/admin/messages/bulk` | `bulk_delete_messages` | `contact.rs` | Batch DELETE |
| GET | `/api/admin/series` | `list_series_admin` | `series.rs` | Query |
| POST | `/api/admin/series` | `create_series` | `series.rs` | INSERT |
| PATCH | `/api/admin/series/{slug}` | `update_series` | `series.rs` | UPDATE |
| DELETE | `/api/admin/series/{slug}` | `delete_series` | `series.rs` | DELETE |
| POST | `/api/admin/blog/translations/link` | `link_translations` | `blog.rs` | UPDATE |
| GET | `/api/admin/blog/translations` | `get_translation_group` | `blog.rs` | Query |
| GET | `/api/admin/portfolio/versions` | `list_portfolio_versions` | `portfolio.rs` | Query |
| POST | `/api/admin/portfolio/versions/{id}/restore` | `restore_portfolio_version` | `portfolio.rs` | INSERT |
| GET | `/api/v1/content/blog` | `list_blog` | `cms.rs` | Paginated query |
| GET | `/api/v1/content/blog/{slug}` | `get_blog_post` | `cms.rs` | PK lookup |
| PATCH | `/api/v1/content/blog/{slug}` | `update_blog_post` | `cms.rs` | UPDATE |
| GET | `/api/v1/content/portfolio` | `get_portfolio` | `cms.rs` | Query |
| GET | `/api/admin/newsletter/subscribers` | `list_subscribers` | `newsletter.rs` | Query |

### Tier C — External I/O / heavy compute (target: cache-hit P95 < 50ms)

Routes in this tier cannot meet 50ms synchronously on cache miss. Strategy: Redis
cache with background refresh; HTTP returns cached data or 202 Accepted.

| Method | Path | Handler | Module | Bottleneck | Strategy |
|--------|------|---------|--------|------------|----------|
| GET | `/api/roadmap/streak` | `get_streak` | `roadmap.rs` | Upstream HTTP ~100-600ms | Redis cache + background refresh |
| GET | `/api/roadmap/dashboard` | `get_dashboard` | `roadmap.rs` | Upstream HTTP ~130-250ms | Redis cache + background refresh |
| GET | `/api/roadmap/teams` | `get_teams` | `roadmap.rs` | Upstream HTTP | Redis cache + background refresh |
| GET | `/api/roadmap/favourites` | `get_favourites` | `roadmap.rs` | Upstream HTTP | Redis cache + background refresh |
| GET | `/api/github/user/{u}` | `get_user` | `github.rs` | GitHub API ~500-3800ms | Redis cache + longer TTL |
| GET | `/api/github/stats/{u}` | `get_stats` | `github.rs` | GitHub API ~0-850ms | Redis cache + longer TTL |
| GET | `/api/rss` | `rss_feed` | `rss.rs` | Full blog list + XML | In-memory cache 60s |
| POST | `/api/contact` | `submit_contact_message` | `contact.rs` | DB INSERT + email | Fire-and-forget email |
| POST | `/api/auth/login` | `login` | `auth.rs` | bcrypt verify ~100-300ms | Accept as exception |
| POST | `/api/auth/register` | `register` | `auth.rs` | bcrypt hash | Accept as exception |
| POST | `/api/ai/chat` | `chat` | `ai.rs` | RAG + Gemini SSE (seconds) | TTFB SLA only |
| POST | `/api/upload/image` | `upload_image` | `upload.rs` | Multipart up to 10MB | Accept as exception |
| GET | `/api/upload/images` | `list_images` | `upload.rs` | Disk readdir | Accept as exception |
| DELETE | `/api/upload/images/{f}` | `delete_image` | `upload.rs` | Disk delete | OK |
| POST | `/api/newsletter/subscribe` | `subscribe` | `newsletter.rs` | DB + email | Fire-and-forget email |
| GET | `/api/newsletter/confirm` | `confirm` | `newsletter.rs` | DB UPDATE | OK |
| POST | `/api/newsletter/unsubscribe` | `unsubscribe` | `newsletter.rs` | DB UPDATE | OK |
| POST | `/api/admin/newsletter/broadcast` | `broadcast` | `newsletter.rs` | N x email | Return 202 + async |
| POST | `/api/auth/2fa/*` | various | `twofa.rs` | DB + crypto | OK |
| GET | `/ws/presence` | `ws_handler` | `presence.rs` | WebSocket (long-lived) | N/A |

### Exceptions (cannot meet 50ms by nature)

| Route | Reason | SLA |
|-------|--------|-----|
| `POST /api/auth/login` | bcrypt verify is intentionally slow | P95 < 500ms |
| `POST /api/auth/register` | bcrypt hash | P95 < 500ms |
| `POST /api/ai/chat` | SSE streaming | TTFB < 50ms |
| `POST /api/upload/image` | Body size up to 10MB | P95 < 2000ms |
| `GET /ws/presence` | WebSocket | N/A |

## Units

| Signal | Unit | Source |
|--------|------|--------|
| Health `uptime` | seconds | `SERVER_START.elapsed().as_secs()` |
| Health `responseTime` | milliseconds | `duration.as_millis()` |
| Prometheus `http_request_duration_seconds` | seconds | `start.elapsed().as_secs_f64()` |
| Log `duration_ms` | milliseconds | middleware |
| Grafana alert threshold | milliseconds | Loki LogQL |

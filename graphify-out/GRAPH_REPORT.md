# Graph Report - portfolio-backend  (2026-08-15)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 1280 nodes · 3170 edges · 40 communities (36 shown, 4 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 55 edges (avg confidence: 0.78)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `06ed2c1f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- blog.rs
- AppError
- auth.rs
- contact.rs
- lib.rs
- gate.rs
- presence_store.rs
- upload.rs
- github.rs
- twofa.rs
- series.rs
- cms.rs
- email.rs
- health.rs
- logs.rs
- newsletter.rs
- roadmap.rs
- db/mod.rs
- metrics.rs
- test_support.rs
- models.rs
- translation.rs
- logging/mod.rs
- resume.rs
- rss.rs
- middleware.rs
- ArchitectureDiagramGenerator
- DependencyAnalyzer
- ProjectArchitect
- CodeQualityAnalyzer
- FullstackScaffolder
- ProjectScaffolder
- run_full_scan
- openapi.rs
- latency-smoke.sh
- batch-translate-phase1.sh
- compose-dev.sh
- portfolio-backend

## God Nodes (most connected - your core abstractions)
1. `AppError` - 70 edges
2. `require_admin()` - 44 edges
3. `login()` - 21 edges
4. `complete_level_3()` - 18 edges
5. `call()` - 18 edges
6. `post_json_auth()` - 17 edges
7. `auth_router()` - 17 edges
8. `submit_contact_message()` - 17 edges
9. `GateState` - 17 edges
10. `unlock()` - 16 edges

## Surprising Connections (you probably didn't know these)
- `approve_translation()` --calls--> `require_admin()`  [INFERRED]
  src/routes/blog.rs → src/routes/auth.rs
- `get_post()` --calls--> `require_admin()`  [INFERRED]
  src/routes/blog.rs → src/routes/auth.rs
- `get_translation_group()` --calls--> `require_admin()`  [INFERRED]
  src/routes/blog.rs → src/routes/auth.rs
- `link_translations()` --calls--> `require_admin()`  [INFERRED]
  src/routes/blog.rs → src/routes/auth.rs
- `list_posts()` --calls--> `require_admin()`  [INFERRED]
  src/routes/blog.rs → src/routes/auth.rs

## Import Cycles
- None detected.

## Communities (40 total, 4 thin omitted)

### Community 0 - "blog.rs"
Cohesion: 0.07
Nodes (84): D, BlogStatus, approve_translation(), blog_router(), BlogListQuery, BlogListResponse, BlogPostResponse, BlogPostSummary (+76 more)

### Community 1 - "AppError"
Cohesion: 0.07
Nodes (80): require_admin(), AppError, Error, From, IntoResponse, Response, Self, StatusCode (+72 more)

### Community 2 - "auth.rs"
Cohesion: 0.08
Nodes (68): access_token_validation(), auth_and_twofa_router(), auth_router(), build_refresh_cookie(), Claims, clear_refresh_cookie(), cookie_secure_flag(), create_access_token() (+60 more)

### Community 3 - "contact.rs"
Cohesion: 0.08
Nodes (56): AtomicUsize, AdminContactMessage, AdminMessagesListResponse, AdminMessagesQuery, bulk_delete_messages(), bulk_mark_messages_read(), BulkMessageActionResponse, BulkMessageIdsRequest (+48 more)

### Community 4 - "lib.rs"
Cohesion: 0.06
Nodes (53): CorsLayer, HeaderValue, assert_production_environment_or_panic(), configure_cors(), cors_includes_localhost_in_development(), cors_uses_allowed_origins_over_frontend_origin(), create_app(), create_app_exposes_health_route() (+45 more)

### Community 5 - "gate.rs"
Cohesion: 0.11
Nodes (57): HashSet, attach_progress_cookie(), build_set_cookie(), challenge_2_users_txt(), challenge_3_encoded(), challenge_users_txt_requires_level_1(), complete_level_3(), complete_level_3_requires_correct_secret() (+49 more)

### Community 6 - "presence_store.rs"
Cohesion: 0.08
Nodes (38): Sender, build_presence_backend(), ConnInfo, in_memory_join_leave(), in_memory_refresh_and_prune(), InMemoryInner, InMemoryPresence, now_secs() (+30 more)

### Community 7 - "upload.rs"
Cohesion: 0.10
Nodes (55): ErrorResponse, Option, String, auth_header(), call(), delete_gcs_object(), delete_image(), delete_non_existent_file() (+47 more)

### Community 8 - "github.rs"
Cohesion: 0.11
Nodes (50): Into, cache_get(), cache_set(), CacheEntry, CacheHit, CheckRunsQueryParams, CommitQuery, get_branches_cached_happy_path() (+42 more)

### Community 9 - "twofa.rs"
Cohesion: 0.10
Nodes (41): AdminTotpRow, backup_code_hash_is_case_insensitive(), build_totp(), challenge_audience(), challenge_token_rejected_with_wrong_audience(), challenge_token_round_trip(), ChallengeClaims, ChallengeRequest (+33 more)

### Community 10 - "series.rs"
Cohesion: 0.13
Nodes (43): is_valid_slug(), admin_create_series_requires_auth(), count_series_posts(), create_series(), CreateSeriesRequest, db_series_crud_and_public_list(), delete_series(), get_series_admin() (+35 more)

### Community 11 - "cms.rs"
Cohesion: 0.10
Nodes (38): ApiKeyContext, cms_disabled_by_default(), cms_disabled_response(), cms_enabled_when_env_true(), CmsBlogItem, CmsBlogListResponse, CmsBlogQuery, CmsBlogWriteRequest (+30 more)

### Community 12 - "email.rs"
Cohesion: 0.11
Nodes (30): env_lock(), from_env(), Mailer, MailerError, noop_mailer_is_always_ok(), NoopMailer, resend_config_from_env(), resend_config_from_env_defaults_from_and_to() (+22 more)

### Community 13 - "health.rs"
Cohesion: 0.10
Nodes (36): check_redis(), DetailedHealthResponse, get_json(), health_database(), health_detailed(), health_ping(), health_ready(), health_redis() (+28 more)

### Community 14 - "logs.rs"
Cohesion: 0.08
Nodes (31): RequestId, ClientLogBatch, ClientLogEntry, LogLevel, LogResponse, Display, Formatter, Option (+23 more)

### Community 15 - "newsletter.rs"
Cohesion: 0.12
Nodes (33): broadcast(), BroadcastRequest, BroadcastResponse, confirm(), ConfirmQuery, hash_api_key(), is_plausible_email(), list_subscribers() (+25 more)

### Community 16 - "roadmap.rs"
Cohesion: 0.16
Nodes (31): cached_fetch(), CacheEntry, credentials_from_env(), fetch_upstream(), get_dashboard(), get_favourites(), get_resource_progress(), get_roadmap_detail() (+23 more)

### Community 17 - "db/mod.rs"
Cohesion: 0.13
Nodes (29): Default, Duration, clear(), clear_test_pool(), current(), DbConfig, env_lock(), get_pool() (+21 more)

### Community 18 - "metrics.rs"
Cohesion: 0.12
Nodes (27): PrometheusHandle, init(), init_installs_prometheus_recorder_once(), metrics_handler(), metrics_handler_requires_bearer_when_configured(), metrics_handler_returns_prometheus_text(), metrics_test_lock(), pageview_records_slug_and_returns_accepted() (+19 more)

### Community 19 - "test_support.rs"
Cohesion: 0.13
Nodes (26): Drop, MockConnectInfo, MutexGuard, test_rate_limit_middleware_redis_error_fail_open(), test_rate_limit_middleware_success_and_rejection(), db_login_challenge_rejects_wrong_totp_code(), db_login_challenge_with_backup_code(), acquire_test_pool() (+18 more)

### Community 20 - "models.rs"
Cohesion: 0.28
Nodes (26): AdminUser, ApiKeyRecord, BlogListResponse, BlogPost, BlogSeries, ContactMessage, ContentEmbeddingRow, NewAdminUser (+18 more)

### Community 21 - "translation.rs"
Cohesion: 0.18
Nodes (24): apply_literal_fixes(), get_deepl_endpoint(), mask_markdown_code(), Client, Option, Result, String, Value (+16 more)

### Community 22 - "logging/mod.rs"
Cohesion: 0.15
Nodes (21): FnOnce, R, RollingFileAppender, build_rolling_appender(), init(), log_dir_env_empty_disables_file_logging(), log_dir_env_explicit_path_used_in_any_environment(), log_dir_env_whitespace_treated_as_empty() (+13 more)

### Community 23 - "resume.rs"
Cohesion: 0.16
Nodes (21): gcs_bucket_name(), gcs_client(), get_raw_resume(), get_resume_without_gcs_returns_not_found(), multipart_pdf_body(), resume_router(), Arc, HeaderMap (+13 more)

### Community 24 - "rss.rs"
Cohesion: 0.20
Nodes (12): escape_xml(), rfc822(), DateTime, Instant, Response, String, Utc, rss_feed() (+4 more)

### Community 25 - "middleware.rs"
Cohesion: 0.23
Nodes (13): MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer, existing_request_id_is_preserved(), log_request(), log_request_middleware_handles_client_and_server_errors_and_missing_id(), log_request_middleware_passes_response_through(), propagate_request_id_layer() (+5 more)

### Community 26 - "ArchitectureDiagramGenerator"
Cohesion: 0.21
Nodes (7): ArchitectureDiagramGenerator, main(), Main class for architecture diagram generator functionality, Execute the main functionality, Validate the target path exists and is accessible, Perform the main analysis or operation, Generate and display the report

### Community 27 - "DependencyAnalyzer"
Cohesion: 0.21
Nodes (7): DependencyAnalyzer, main(), Main class for dependency analyzer functionality, Execute the main functionality, Validate the target path exists and is accessible, Perform the main analysis or operation, Generate and display the report

### Community 28 - "ProjectArchitect"
Cohesion: 0.21
Nodes (7): main(), ProjectArchitect, Main class for project architect functionality, Execute the main functionality, Validate the target path exists and is accessible, Perform the main analysis or operation, Generate and display the report

### Community 29 - "CodeQualityAnalyzer"
Cohesion: 0.21
Nodes (7): CodeQualityAnalyzer, main(), Main class for code quality analyzer functionality, Execute the main functionality, Validate the target path exists and is accessible, Perform the main analysis or operation, Generate and display the report

### Community 30 - "FullstackScaffolder"
Cohesion: 0.21
Nodes (7): FullstackScaffolder, main(), Main class for fullstack scaffolder functionality, Execute the main functionality, Validate the target path exists and is accessible, Perform the main analysis or operation, Generate and display the report

### Community 31 - "ProjectScaffolder"
Cohesion: 0.21
Nodes (7): main(), ProjectScaffolder, Main class for project scaffolder functionality, Execute the main functionality, Validate the target path exists and is accessible, Perform the main analysis or operation, Generate and display the report

### Community 32 - "run_full_scan"
Cohesion: 0.27
Nodes (12): main(), Validate no hardcoded secrets (OWASP A04). Checks: API keys, tokens, passwords,…, Validate dangerous code patterns (OWASP A05). Checks: Injection risks, XSS,…, Validate security configuration (OWASP A02). Checks: Security headers, CORS,…, Execute security validation scans., Validate supply chain security (OWASP A03). Checks: npm audit, lock file…, run_full_scan(), scan_code_patterns() (+4 more)

### Community 33 - "openapi.rs"
Cohesion: 0.25
Nodes (4): Modify, OpenApi, ApiDoc, SecurityAddon

## Knowledge Gaps
- **14 isolated node(s):** `SuccessResponse`, `SuccessResponse`, `HealthStatus`, `BroadcastResponse`, `PageviewResponse` (+9 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AppError` connect `AppError` to `blog.rs`, `contact.rs`, `gate.rs`, `upload.rs`, `twofa.rs`, `series.rs`, `cms.rs`, `newsletter.rs`?**
  _High betweenness centrality (0.246) - this node is a cross-community bridge._
- **Why does `ErrorResponse` connect `upload.rs` to `blog.rs`, `AppError`, `auth.rs`, `lib.rs`, `resume.rs`?**
  _High betweenness centrality (0.106) - this node is a cross-community bridge._
- **Why does `require_admin()` connect `AppError` to `blog.rs`, `auth.rs`, `contact.rs`, `upload.rs`, `twofa.rs`, `series.rs`, `newsletter.rs`, `resume.rs`?**
  _High betweenness centrality (0.060) - this node is a cross-community bridge._
- **Are the 37 inferred relationships involving `require_admin()` (e.g. with `approve_translation()` and `get_post()`) actually correct?**
  _`require_admin()` has 37 INFERRED edges - model-reasoned connections that need verification._
- **What connects `SuccessResponse`, `SuccessResponse`, `HealthStatus` to the rest of the system?**
  _14 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `blog.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.06808408982322026 - nodes in this community are weakly interconnected._
- **Should `AppError` be split into smaller, more focused modules?**
  _Cohesion score 0.06687565308254964 - nodes in this community are weakly interconnected._
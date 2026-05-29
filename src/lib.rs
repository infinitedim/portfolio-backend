pub mod db;
pub mod email;
pub mod logging;
pub mod metrics;
pub mod openapi;
pub mod routes;

// Test-only helpers (Postgres pool, admin tokens, isolated upload dir, etc.)
// shared by `mod tests` blocks across the crate. Gated behind `cfg(test)` so
// it never leaks into release builds and adds no overhead to production.
#[cfg(test)]
pub mod test_support;

use axum::{
    http::{HeaderValue, Method},
    middleware,
    routing::{delete, get, patch, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, limit::RequestBodyLimitLayer,
    services::ServeDir, trace::TraceLayer,
};

pub fn configure_cors() -> CorsLayer {
    let allowed_origins = std::env::var("ALLOWED_ORIGINS")
        .ok()
        .and_then(|s| {
            let origins: Vec<HeaderValue> = s
                .split(',')
                .filter_map(|origin| origin.trim().parse().ok())
                .collect();
            if origins.is_empty() {
                None
            } else {
                Some(origins)
            }
        })
        .or_else(|| {
            std::env::var("FRONTEND_ORIGIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .map(|origin| vec![origin])
        })
        .unwrap_or_else(|| {
            vec![
                "http://localhost:3000".parse().unwrap(),
                "http://127.0.0.1:3000".parse().unwrap(),
            ]
        });

    CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderName::from_static("x-api-key"),
        ])
        .allow_credentials(true)
}

pub fn create_app() -> Router {
    let _metrics = metrics::init();

    let cors = configure_cors();
    tracing::info!("CORS configured");

    // Per-IP rate limiter for auth endpoints. Burst of 5, refill ~1 every 12s
    // — gives roughly five attempts per minute, which is the contract the old
    // ad-hoc rate limiter promised. SmartIpKeyExtractor reads
    // X-Forwarded-For/X-Real-IP/Forwarded so it works correctly behind the
    // Reverse-proxy headers (Vercel, load balancers, etc.). ConnectInfo<SocketAddr>
    // is kept as a fallback when headers are absent.
    let auth_governor = std::sync::Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(12_000)
            .burst_size(5)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .expect("auth governor config"),
    );

    // Higher cap for client log ingestion: 1 req/sec sustained, burst 20.
    let logs_governor = std::sync::Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(20)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .expect("logs governor config"),
    );

    // Public contact form: very tight cap to discourage abuse. Burst 3,
    // refill ~1 every 60s — gives roughly five legitimate submissions per
    // hour from one IP, plenty for human use.
    let contact_governor = std::sync::Arc::new(
        GovernorConfigBuilder::default()
            .per_second(60)
            .burst_size(3)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .expect("contact governor config"),
    );

    let gate_governor = std::sync::Arc::new(
        GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(20)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .expect("gate governor config"),
    );

    // Pageview beacons: generous cap for SPA navigation bursts.
    let analytics_governor = std::sync::Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(30)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .expect("analytics governor config"),
    );

    // GitHub proxy: cached upstream; limit abuse of our egress.
    let github_governor = std::sync::Arc::new(
        GovernorConfigBuilder::default()
            .per_second(2)
            .burst_size(10)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .expect("github governor config"),
    );

    // Newsletter broadcast: admin-only, tight cap.
    let newsletter_broadcast_governor = std::sync::Arc::new(
        GovernorConfigBuilder::default()
            .per_second(30)
            .burst_size(2)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .expect("newsletter broadcast governor config"),
    );

    // Public newsletter subscribe/unsubscribe.
    let newsletter_governor = std::sync::Arc::new(
        GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(5)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .expect("newsletter governor config"),
    );

    let gate_config = routes::gate::GateConfig::from_env();
    let gate_state = routes::gate::GateState::new(gate_config);
    let gate_routes = Router::new()
        .route("/api/gate/status", get(routes::gate::status))
        .route("/api/gate/login", post(routes::gate::login))
        .route("/api/gate/complete/3", post(routes::gate::complete_level_3))
        .route("/api/gate/unlock", post(routes::gate::unlock))
        .route(
            "/api/gate/challenge/2/users.txt",
            get(routes::gate::challenge_2_users_txt),
        )
        .layer(GovernorLayer::new(gate_governor))
        .with_state(gate_state);

    // Upload routes with higher body limit (10MB)
    let upload_routes = Router::new()
        .route("/api/upload/image", post(routes::upload::upload_image))
        .route(
            "/api/upload/image/{filename}",
            delete(routes::upload::delete_image),
        )
        .route("/api/upload/images", get(routes::upload::list_images))
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024));

    let auth_routes = Router::new()
        .route("/api/auth/register", post(routes::auth::register))
        .route("/api/auth/login", post(routes::auth::login))
        .route("/api/auth/verify", post(routes::auth::verify_token))
        .route("/api/auth/refresh", post(routes::auth::refresh))
        .route("/api/auth/logout", post(routes::auth::logout))
        // 2FA flow. `setup`, `verify` and `disable` are admin-only (auth
        // checked inside the handler via `require_admin`); `login` is the
        // post-password challenge step and uses its own short-lived token.
        .route("/api/auth/2fa/status", get(routes::twofa::status))
        .route("/api/auth/2fa/setup", post(routes::twofa::setup))
        .route("/api/auth/2fa/verify", post(routes::twofa::verify_setup))
        .route("/api/auth/2fa/disable", post(routes::twofa::disable))
        .route("/api/auth/2fa/login", post(routes::twofa::login_challenge))
        .layer(GovernorLayer::new(auth_governor));

    let logs_routes = Router::new()
        .route("/api/logs", post(routes::logs::receive_client_logs))
        .layer(GovernorLayer::new(logs_governor));

    let analytics_routes = Router::new()
        .route("/api/analytics/pageview", post(metrics::record_pageview))
        .layer(GovernorLayer::new(analytics_governor));

    let github_routes = Router::new()
        .route("/api/github/user/{username}", get(routes::github::get_user))
        .route(
            "/api/github/stats/{username}",
            get(routes::github::get_stats),
        )
        .layer(GovernorLayer::new(github_governor));

    // Contact + admin inbox routes. Contact submission is public but
    // rate-limited; admin endpoints are guarded inside the handler via
    // `require_admin` so they don't need a separate auth middleware here.
    let mailer: Arc<dyn email::Mailer> = email::from_env();
    let mailer_for_newsletter = mailer.clone();
    let contact_public = Router::new()
        .route(
            "/api/contact",
            post(routes::contact::submit_contact_message),
        )
        .layer(GovernorLayer::new(contact_governor))
        .with_state(mailer);

    let admin_messages_routes = Router::new()
        .route("/api/admin/messages", get(routes::contact::list_messages))
        .route(
            "/api/admin/messages/bulk",
            patch(routes::contact::bulk_mark_messages_read)
                .delete(routes::contact::bulk_delete_messages),
        )
        .route(
            "/api/admin/messages/{id}",
            get(routes::contact::get_message)
                .patch(routes::contact::update_message)
                .delete(routes::contact::delete_message),
        );

    let admin_series_routes = Router::new()
        .route(
            "/api/admin/series",
            get(routes::series::list_series_admin).post(routes::series::create_series),
        )
        .route(
            "/api/admin/series/{slug}",
            get(routes::series::get_series_admin)
                .patch(routes::series::update_series)
                .delete(routes::series::delete_series),
        );

    let admin_blog_routes = Router::new()
        .route(
            "/api/admin/blog/translations/link",
            post(routes::blog::link_translations),
        )
        .route(
            "/api/admin/blog/translations",
            get(routes::blog::get_translation_group),
        );

    let admin_portfolio_routes = Router::new()
        .route(
            "/api/admin/portfolio/versions",
            get(routes::portfolio::list_portfolio_versions),
        )
        .route(
            "/api/admin/portfolio/versions/{id}/restore",
            post(routes::portfolio::restore_portfolio_version),
        );

    let playground_routes = Router::new()
        .route(
            "/api/playground/snippets",
            post(routes::playground::create_snippet),
        )
        .route(
            "/api/playground/snippets/{id}",
            get(routes::playground::get_snippet),
        );

    let newsletter_public = Router::new()
        .route(
            "/api/newsletter/subscribe",
            post(routes::newsletter::subscribe),
        )
        .route("/api/newsletter/confirm", get(routes::newsletter::confirm))
        .route(
            "/api/newsletter/unsubscribe",
            post(routes::newsletter::unsubscribe),
        )
        .layer(GovernorLayer::new(newsletter_governor))
        .with_state(mailer_for_newsletter.clone());

    let newsletter_admin = Router::new()
        .route(
            "/api/admin/newsletter/subscribers",
            get(routes::newsletter::list_subscribers),
        )
        .route(
            "/api/admin/newsletter/broadcast",
            post(routes::newsletter::broadcast),
        )
        .layer(GovernorLayer::new(newsletter_broadcast_governor))
        .with_state(mailer_for_newsletter);

    let cms_state = routes::cms::CmsState::from_env();
    let cms_routes = Router::new()
        .route("/api/v1/content/blog", get(routes::cms::list_blog))
        .route(
            "/api/v1/content/blog/{slug}",
            get(routes::cms::get_blog_post).patch(routes::cms::update_blog_post),
        )
        .route("/api/v1/content/portfolio", get(routes::cms::get_portfolio))
        .layer(middleware::from_fn_with_state(
            cms_state.clone(),
            routes::cms::require_api_key,
        ))
        .with_state(cms_state);

    let ai_state = routes::ai::AiState::from_env();
    let ai_routes = Router::new()
        .route("/api/ai/chat", post(routes::ai::chat))
        .with_state(ai_state);

    let presence_state = routes::presence::PresenceState::new();
    let presence_routes = Router::new()
        .route("/ws/presence", get(routes::presence::ws_handler))
        .with_state(presence_state);

    // Main routes with default body limit (2MB)
    let main_routes = Router::new()
        .route("/api/roadmap/streak", get(routes::roadmap::get_streak))
        .route(
            "/api/roadmap/dashboard",
            get(routes::roadmap::get_dashboard),
        )
        .route("/api/roadmap/teams", get(routes::roadmap::get_teams))
        .route(
            "/api/roadmap/favourites",
            get(routes::roadmap::get_favourites),
        )
        .route(
            "/api/portfolio",
            get(routes::portfolio::get_portfolio).patch(routes::portfolio::update_portfolio),
        )
        .route(
            "/api/blog",
            get(routes::blog::list_posts).post(routes::blog::create_post),
        )
        .route("/api/blog/tags", get(routes::blog::list_tags))
        .route("/api/rss", get(routes::rss::rss_feed))
        .route(
            "/api/blog/{slug}",
            get(routes::blog::get_post)
                .patch(routes::blog::update_post)
                .delete(routes::blog::delete_post),
        )
        .route("/api/blog/series", get(routes::series::list_series_public))
        .route(
            "/api/blog/series/{slug}",
            get(routes::series::get_series_public),
        )
        .route("/health", get(routes::health::health_ping))
        .route("/health/detailed", get(routes::health::health_detailed))
        .route("/health/database", get(routes::health::health_database))
        .route("/health/redis", get(routes::health::health_redis))
        .route("/health/ready", get(routes::health::health_ready))
        .route("/metrics", get(metrics::metrics_handler))
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024));

    let mut app = Router::new()
        .merge(upload_routes)
        .merge(auth_routes)
        .merge(logs_routes)
        .merge(analytics_routes)
        .merge(github_routes)
        .merge(contact_public)
        .merge(newsletter_public)
        .merge(newsletter_admin)
        .merge(playground_routes)
        .merge(cms_routes)
        .merge(ai_routes)
        .merge(presence_routes)
        .merge(admin_messages_routes)
        .merge(admin_series_routes)
        .merge(admin_blog_routes)
        .merge(admin_portfolio_routes)
        .merge(gate_routes)
        .merge(main_routes);

    // Swagger UI is always-on in development. In production it can be
    // disabled by setting `ENABLE_SWAGGER_UI=false`. We still serve the
    // raw spec at `/api/docs/openapi.json` because the Swagger UI itself
    // fetches it from there at runtime.
    let swagger_enabled = std::env::var("ENABLE_SWAGGER_UI")
        .map(|v| !v.eq_ignore_ascii_case("false") && v != "0")
        .unwrap_or(true);
    if swagger_enabled {
        use utoipa::OpenApi;
        use utoipa_swagger_ui::SwaggerUi;
        app = app.merge(
            SwaggerUi::new("/api/docs").url("/api/docs/openapi.json", openapi::ApiDoc::openapi()),
        );
    }

    app.nest_service("/uploads", ServeDir::new("uploads"))
        .layer(middleware::from_fn(metrics::track_http_metrics))
        .layer(logging::middleware::propagate_request_id_layer())
        .layer(middleware::from_fn(logging::middleware::log_request))
        .layer(logging::middleware::request_id_layer())
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(cors)
}

/// Production-only checks for secrets, admin bootstrap, and CORS allowlist.
/// Panics when `ENVIRONMENT=production` and configuration is unsafe.
pub(crate) fn assert_production_environment_or_panic() {
    let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
    if environment != "production" {
        return;
    }

    // Touch the lazy_static secrets so any misconfiguration panics at
    // startup, not on the first request that hits the auth handler.
    let _ = &*routes::auth::JWT_SECRET;
    let _ = &*routes::auth::REFRESH_SECRET;

    let admin_email = std::env::var("ADMIN_EMAIL").unwrap_or_default();
    let admin_password_set =
        std::env::var("ADMIN_HASH_PASSWORD").is_ok() || std::env::var("ADMIN_PASSWORD").is_ok();

    if admin_email.is_empty() || admin_email == "admin@example.com" {
        panic!("FATAL: ADMIN_EMAIL must be set to a real address in production.");
    }
    if !admin_password_set {
        panic!("FATAL: ADMIN_HASH_PASSWORD or ADMIN_PASSWORD must be set in production.");
    }

    if std::env::var("ALLOWED_ORIGINS").is_err() && std::env::var("FRONTEND_ORIGIN").is_err() {
        panic!(
            "FATAL: ALLOWED_ORIGINS (or FRONTEND_ORIGIN) must be set in production. \
             Refusing to start with a localhost CORS allowlist."
        );
    }
}

pub async fn run() {
    dotenvy::dotenv().ok();

    let _log_guards = logging::init();

    routes::health::init_start_time();

    assert_production_environment_or_panic();

    let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
    let is_production = environment == "production";

    if std::env::var("DATABASE_URL").is_ok() {
        // Default to a 60s budget — enough to absorb Compose/Docker DNS races
        // and slow Postgres warmups without letting genuine misconfigs hang
        // the container indefinitely. Overridable for tight CI environments.
        let retry_budget_secs: u64 = std::env::var("DB_CONNECT_RETRY_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);
        let retry_budget = std::time::Duration::from_secs(retry_budget_secs);

        match db::init_pool_with_retry(None, retry_budget).await {
            Ok(pool) => {
                if let Err(e) = db::run_migrations(&pool).await {
                    if is_production {
                        panic!(
                            "FATAL: failed to run database migrations in production: {}. \
                             Refusing to start with a partially-applied schema.",
                            e
                        );
                    } else {
                        tracing::error!("Failed to run database migrations: {}", e);
                    }
                }
            }
            Err(e) => {
                if is_production {
                    panic!(
                        "FATAL: failed to initialize database pool in production after {}s: {}. \
                         DATABASE_URL is set but the connection failed. \
                         Check that the database service is reachable and credentials are correct.",
                        retry_budget_secs, e
                    );
                } else {
                    tracing::warn!(
                        "Failed to initialize database pool: {}. Continuing without database.",
                        e
                    );
                }
            }
        }
    } else if is_production {
        panic!("FATAL: DATABASE_URL must be set in production.");
    } else {
        tracing::info!("DATABASE_URL not set. Running without database connection.");
    }

    let app = create_app();

    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    // Default 8080 to match Docker/Compose conventions.
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid HOST/PORT configuration");
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("Server error");

    tracing::info!("Server shut down cleanly.");
}

/// Wait for SIGTERM (Kubernetes/Docker stop) or Ctrl-C and let in-flight
/// requests finish before the runtime exits.
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl-C, starting graceful shutdown."),
        _ = terminate => tracing::info!("Received SIGTERM, starting graceful shutdown."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::{Mutex, OnceLock};
    use tower::util::ServiceExt;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_create_app_returns_router() {
        let _app = create_app();
    }

    #[tokio::test]
    async fn create_app_exposes_metrics_route() {
        let app = create_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("metrics response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_app_exposes_health_route() {
        let app = create_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("health response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // `env_lock` must serialize env mutations across the whole test.
    async fn swagger_ui_can_be_disabled_via_env() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        std::env::set_var("ENABLE_SWAGGER_UI", "false");
        let app = create_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/docs")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("docs response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        std::env::remove_var("ENABLE_SWAGGER_UI");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn swagger_ui_enabled_by_default() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        std::env::remove_var("ENABLE_SWAGGER_UI");
        let app = create_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/docs")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("docs response");
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn cors_uses_allowed_origins_over_frontend_origin() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        std::env::set_var("ALLOWED_ORIGINS", "https://allowed.example");
        std::env::set_var("FRONTEND_ORIGIN", "https://frontend.example");

        let app = Router::new()
            .route("/check", get(|| async { StatusCode::OK }))
            .layer(configure_cors());

        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/check")
                    .header("origin", "https://allowed.example")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .expect("preflight request"),
            )
            .await
            .expect("preflight response");

        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://allowed.example")
        );

        std::env::remove_var("ALLOWED_ORIGINS");
        std::env::remove_var("FRONTEND_ORIGIN");
    }
}

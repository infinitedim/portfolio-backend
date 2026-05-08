pub mod db;
pub mod email;
pub mod logging;
pub mod openapi;
pub mod routes;

use axum::{
    http::{HeaderValue, Method},
    middleware,
    routing::{delete, get, post},
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
        ])
        .allow_credentials(true)
}

pub fn create_app() -> Router {
    let cors = configure_cors();
    tracing::info!("CORS configured");

    // Per-IP rate limiter for auth endpoints. Burst of 5, refill ~1 every 12s
    // — gives roughly five attempts per minute, which is the contract the old
    // ad-hoc rate limiter promised. SmartIpKeyExtractor reads
    // X-Forwarded-For/X-Real-IP/Forwarded so it works correctly behind the
    // Railway/Vercel proxy. ConnectInfo<SocketAddr> is kept as a fallback.
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

    // Contact + admin inbox routes. Contact submission is public but
    // rate-limited; admin endpoints are guarded inside the handler via
    // `require_admin` so they don't need a separate auth middleware here.
    let mailer: Arc<dyn email::Mailer> = email::from_env();
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
            "/api/admin/messages/{id}",
            get(routes::contact::get_message)
                .patch(routes::contact::update_message)
                .delete(routes::contact::delete_message),
        );

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
        .route("/health", get(routes::health::health_ping))
        .route("/health/detailed", get(routes::health::health_detailed))
        .route("/health/database", get(routes::health::health_database))
        .route("/health/redis", get(routes::health::health_redis))
        .route("/health/ready", get(routes::health::health_ready))
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024));

    let mut app = Router::new()
        .merge(upload_routes)
        .merge(auth_routes)
        .merge(logs_routes)
        .merge(contact_public)
        .merge(admin_messages_routes)
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
        .layer(logging::middleware::propagate_request_id_layer())
        .layer(middleware::from_fn(logging::middleware::log_request))
        .layer(logging::middleware::request_id_layer())
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(cors)
}

pub async fn run() {
    dotenvy::dotenv().ok();

    let _log_guards = logging::init();

    routes::health::init_start_time();

    let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
    if environment == "production" {
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
    // Default 8080 to match Docker/Compose/Railway conventions.
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

/// Wait for SIGTERM (Kubernetes/Railway/Docker stop) or Ctrl-C and let in-flight
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

    #[test]
    fn test_create_app_returns_router() {
        let _app = create_app();
    }
}

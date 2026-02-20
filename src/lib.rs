//! Portfolio Backend - library for app logic and testing

pub mod db;
pub mod logging;
pub mod routes;

use axum::{
    http::{HeaderValue, Method},
    middleware,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, limit::RequestBodyLimitLayer, trace::TraceLayer,
};

/// Configure CORS from environment variables.
/// Uses ALLOWED_ORIGINS (comma-separated) or FRONTEND_ORIGIN.
/// Falls back to allowing all origins in development.
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

/// Create and configure the application router.
pub fn create_app() -> Router {
    let cors = configure_cors();
    tracing::info!("CORS configured");

    Router::new()
        .route("/api/logs", post(routes::logs::receive_client_logs))
        .route("/api/auth/register", post(routes::auth::register))
        .route("/api/auth/login", post(routes::auth::login))
        .route("/api/auth/verify", post(routes::auth::verify_token))
        .route("/api/auth/refresh", post(routes::auth::refresh))
        .route("/api/auth/logout", post(routes::auth::logout))
        .route(
            "/api/portfolio",
            get(routes::portfolio::get_portfolio).patch(routes::portfolio::update_portfolio),
        )
        .route(
            "/api/blog",
            get(routes::blog::list_posts).post(routes::blog::create_post),
        )
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
        .layer(logging::middleware::propagate_request_id_layer())
        .layer(middleware::from_fn(logging::middleware::log_request))
        .layer(logging::middleware::request_id_layer())
        .layer(TraceLayer::new_for_http())
        // Compress responses with gzip/br/zstd automatically
        .layer(CompressionLayer::new())
        // Global 2 MB request body cap — prevents unbounded buffering
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
        .layer(cors)
}

/// Run the server (used by main).
pub async fn run() {
    dotenvy::dotenv().ok();

    // Guards MUST be held for the programme's lifetime; dropping them early
    // shuts down background log-writer threads and loses buffered log lines.
    let _log_guards = logging::init();

    routes::health::init_start_time();

    // Refuse to start in production with the insecure default JWT secret.
    let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
    if environment == "production" {
        let secret = std::env::var("JWT_SECRET").unwrap_or_default();
        if secret.is_empty() || secret == "default-jwt-secret-change-in-production" {
            panic!(
                "FATAL: JWT_SECRET must be set to a secure, unique value in production. \
                 Refusing to start with the default secret."
            );
        }

        // Warn (don't panic) about default admin credentials in production.
        let admin_email = std::env::var("ADMIN_EMAIL").unwrap_or_default();
        let admin_password_set =
            std::env::var("ADMIN_HASH_PASSWORD").is_ok() || std::env::var("ADMIN_PASSWORD").is_ok();

        if admin_email.is_empty() || admin_email == "admin@example.com" {
            tracing::warn!(
                "SECURITY: ADMIN_EMAIL is using an insecure default. \
                 Set ADMIN_EMAIL env var to a real address before registering."
            );
        }
        if !admin_password_set {
            tracing::warn!(
                "SECURITY: Neither ADMIN_HASH_PASSWORD nor ADMIN_PASSWORD is set. \
                 The fallback default password 'admin123' is insecure. \
                 Set ADMIN_HASH_PASSWORD to a bcrypt hash of a strong password."
            );
        }
    }

    if std::env::var("DATABASE_URL").is_ok() {
        match db::init_pool(None).await {
            Ok(pool) => {
                if let Err(e) = db::run_migrations(&pool).await {
                    tracing::error!("Failed to run database migrations: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to initialize database pool: {}. Continuing without database.",
                    e
                );
            }
        }
    } else {
        tracing::info!("DATABASE_URL not set. Running without database connection.");
    }

    let app = create_app();

    // Bind address is configurable via HOST / PORT env vars, defaulting to
    // 127.0.0.1:3001 so existing dev setups keep working unchanged.
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3001);
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
    .await
    .expect("Server error");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_app_returns_router() {
        let _app = create_app();
        // Just test that it compiles and doesn't panic
    }
}

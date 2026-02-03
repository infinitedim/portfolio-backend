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
use tower_http::{cors::CorsLayer, trace::TraceLayer};

/// Configure CORS from environment variables.
/// Uses ALLOWED_ORIGINS (comma-separated) or FRONTEND_ORIGIN.
/// Falls back to allowing all origins in development.
pub fn configure_cors() -> CorsLayer {
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

    let origins: Vec<HeaderValue> = std::env::var("ALLOWED_ORIGINS")
        .or_else(|_| std::env::var("FRONTEND_ORIGIN"))
        .map(|s| {
            s.split(',')
                .filter_map(|origin| origin.trim().parse::<HeaderValue>().ok())
                .collect()
        })
        .unwrap_or_default();

    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
            axum::http::header::HeaderName::from_static("x-request-id"),
            axum::http::header::HeaderName::from_static("x-payload-encrypted"),
        ])
        .allow_credentials(true);

    if !origins.is_empty() {
        tracing::info!("CORS: Allowing origins from env: {:?}", origins);
        cors.allow_origin(origins)
    } else if environment == "development" {
        let dev_origins: Vec<HeaderValue> = vec![
            "http://localhost:3000".parse().unwrap(),
            "http://127.0.0.1:3000".parse().unwrap(),
            "http://localhost:3001".parse().unwrap(),
        ];
        tracing::info!("CORS: Development mode - allowing localhost origins");
        cors.allow_origin(dev_origins)
    } else {
        tracing::warn!("CORS: No origins configured in production - restricting to same origin");
        cors
    }
}

/// Create and configure the application router.
pub fn create_app() -> Router {
    let cors = configure_cors();
    tracing::info!("CORS configured");

    Router::new()
        .route("/api/logs", post(routes::logs::receive_client_logs))
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
        .layer(cors)
}

/// Run the server (used by main).
pub async fn run() {
    dotenvy::dotenv().ok();
    logging::init();
    routes::health::init_start_time();

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
    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Failed to start server");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configure_cors_development_default() {
        std::env::remove_var("ENVIRONMENT");
        std::env::remove_var("ALLOWED_ORIGINS");
        std::env::remove_var("FRONTEND_ORIGIN");
        let _ = configure_cors();
    }

    #[test]
    fn test_configure_cors_with_origins() {
        std::env::set_var("ENVIRONMENT", "production");
        std::env::set_var("ALLOWED_ORIGINS", "https://example.com");
        let _ = configure_cors();
        std::env::remove_var("ENVIRONMENT");
        std::env::remove_var("ALLOWED_ORIGINS");
    }

    #[test]
    fn test_create_app_builds_router() {
        let _app = create_app();
    }
}

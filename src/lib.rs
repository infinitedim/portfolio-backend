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

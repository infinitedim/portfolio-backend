/**
 * Portfolio Backend
 * Main application entry point
 */

mod db;
mod logging;
mod routes;

use axum::{
    routing::{get, post},
    Router,
    middleware,
    http::{HeaderValue, Method},
};
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};
use std::net::SocketAddr;

/// Configure CORS from environment variables
/// Uses ALLOWED_ORIGINS (comma-separated) or FRONTEND_ORIGIN
/// Falls back to allowing all origins in development
fn configure_cors() -> CorsLayer {
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    
    // Get allowed origins from env
    let origins: Vec<HeaderValue> = std::env::var("ALLOWED_ORIGINS")
        .or_else(|_| std::env::var("FRONTEND_ORIGIN"))
        .map(|s| {
            s.split(',')
                .filter_map(|origin| origin.trim().parse::<HeaderValue>().ok())
                .collect()
        })
        .unwrap_or_default();
    
    // Base CORS layer
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
    
    // Configure origins
    if !origins.is_empty() {
        tracing::info!("CORS: Allowing origins from env: {:?}", origins);
        cors.allow_origin(origins)
    } else if environment == "development" {
        // In development, allow common localhost origins
        let dev_origins: Vec<HeaderValue> = vec![
            "http://localhost:3000".parse().unwrap(),
            "http://127.0.0.1:3000".parse().unwrap(),
            "http://localhost:3001".parse().unwrap(),
        ];
        tracing::info!("CORS: Development mode - allowing localhost origins");
        cors.allow_origin(dev_origins)
    } else {
        // In production with no config, be restrictive
        tracing::warn!("CORS: No origins configured in production - restricting to same origin");
        cors
    }
}

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();
    
    // Initialize logging
    logging::init();
    
    // Initialize server start time for uptime tracking
    routes::health::init_start_time();
    
    // Initialize database if DATABASE_URL is set
    if std::env::var("DATABASE_URL").is_ok() {
        match db::init_pool(None).await {
            Ok(pool) => {
                // Run migrations
                if let Err(e) = db::run_migrations(&pool).await {
                    tracing::error!("Failed to run database migrations: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to initialize database pool: {}. Continuing without database.", e);
            }
        }
    } else {
        tracing::info!("DATABASE_URL not set. Running without database connection.");
    }

    // Build the application
    let app = create_app();

    // Define the address
    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    
    tracing::info!("Starting server on {}", addr);

    // Run the server with connect info for IP extraction
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

/// Create and configure the application
fn create_app() -> Router {
    // Configure CORS from environment
    let cors = configure_cors();
    
    tracing::info!("CORS configured");

    // Build the router
    Router::new()
        // API routes
        .route("/api/logs", post(routes::logs::receive_client_logs))
        // Auth routes
        .route("/api/auth/login", post(routes::auth::login))
        .route("/api/auth/verify", post(routes::auth::verify_token))
        .route("/api/auth/refresh", post(routes::auth::refresh))
        .route("/api/auth/logout", post(routes::auth::logout))
        // Portfolio routes
        .route("/api/portfolio", get(routes::portfolio::get_portfolio).patch(routes::portfolio::update_portfolio))
        // Blog routes
        .route("/api/blog", get(routes::blog::list_posts).post(routes::blog::create_post))
        .route("/api/blog/{slug}", get(routes::blog::get_post).patch(routes::blog::update_post).delete(routes::blog::delete_post))
        // Health check routes
        .route("/health", get(routes::health::health_ping))
        .route("/health/detailed", get(routes::health::health_detailed))
        .route("/health/database", get(routes::health::health_database))
        .route("/health/redis", get(routes::health::health_redis))
        .route("/health/ready", get(routes::health::health_ready))
        // Middleware layers
        .layer(logging::middleware::propagate_request_id_layer())
        .layer(middleware::from_fn(logging::middleware::log_request))
        .layer(logging::middleware::request_id_layer())
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

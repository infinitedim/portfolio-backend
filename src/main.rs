/**
 * Portfolio Backend
 * Main application entry point
 */

mod logging;
mod routes;

use axum::{
    routing::post,
    Router,
    middleware,
};
use tower_http::{
    cors::{CorsLayer, Any},
    trace::TraceLayer,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Initialize logging
    logging::init();

    // Build the application
    let app = create_app();

    // Define the address
    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    
    tracing::info!("Starting server on {}", addr);

    // Run the server
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}

/// Create and configure the application
fn create_app() -> Router {
    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build the router
    Router::new()
        // API routes
        .route("/api/logs", post(routes::logs::receive_client_logs))
        // Health check
        .route("/health", axum::routing::get(health_check))
        // Middleware layers
        .layer(logging::middleware::propagate_request_id_layer())
        .layer(middleware::from_fn(logging::middleware::log_request))
        .layer(logging::middleware::request_id_layer())
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

/// Health check handler
async fn health_check() -> &'static str {
    "OK"
}

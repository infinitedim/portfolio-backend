/*!
 * Logging Module
 * Centralized logging configuration and utilities
 */
pub mod config;
pub mod middleware;

use std::io;
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initialize the logging system
pub fn init() {
    // Get environment
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    let is_production = environment == "production";

    // Create log directory if it doesn't exist
    std::fs::create_dir_all("logs").ok();

    // File appender for all logs
    let file_appender = rolling::daily("logs", "app.log");
    let (file_writer, _file_guard) = non_blocking(file_appender);

    // File appender for errors only
    let error_appender = rolling::daily("logs", "error.log");
    let (error_writer, _error_guard) = non_blocking(error_appender);

    // Console writer
    let (console_writer, _console_guard) = non_blocking(io::stdout());

    // Configure log level
    let log_level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| {
        if is_production {
            "info".to_string()
        } else {
            "debug".to_string()
        }
    });

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "portfolio_backend={},tower_http=debug,axum=debug",
            log_level
        ))
    });

    // Build the subscriber
    let subscriber = tracing_subscriber::registry().with(env_filter);

    if is_production {
        // JSON format for production
        let file_layer = fmt::layer()
            .json()
            .with_writer(file_writer)
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true);

        let error_layer = fmt::layer()
            .json()
            .with_writer(error_writer)
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true)
            .with_filter(tracing_subscriber::filter::LevelFilter::ERROR);

        let console_layer = fmt::layer()
            .json()
            .with_writer(console_writer)
            .with_target(false);

        subscriber
            .with(file_layer)
            .with(error_layer)
            .with(console_layer)
            .init();
    } else {
        // Pretty format for development
        let file_layer = fmt::layer()
            .with_writer(file_writer)
            .with_target(true)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_file(true)
            .with_line_number(true)
            .with_ansi(false);

        let console_layer = fmt::layer()
            .with_writer(console_writer)
            .with_target(true)
            .pretty()
            .with_thread_ids(false)
            .with_thread_names(false);

        subscriber.with(file_layer).with(console_layer).init();
    }

    tracing::info!("Logging initialized for {} environment", environment);
}

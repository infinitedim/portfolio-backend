/**
 * Database Module
 * PostgreSQL connection pool and utilities
 */
pub mod models;

use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Global database pool
static DB_POOL: OnceCell<Arc<PgPool>> = OnceCell::const_new();

/// Database configuration
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/portfolio".to_string()),
            max_connections: std::env::var("DB_POOL_MAX")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            min_connections: std::env::var("DB_POOL_MIN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2),
            connect_timeout_secs: std::env::var("DB_CONNECT_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            idle_timeout_secs: std::env::var("DB_IDLE_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
        }
    }
}

/// Initialize the database connection pool
pub async fn init_pool(config: Option<DbConfig>) -> Result<Arc<PgPool>, sqlx::Error> {
    let config = config.unwrap_or_default();

    tracing::info!("Initializing database connection pool...");
    tracing::debug!(
        "Database URL: {}",
        config.url.replace(
            |c: char| !c.is_ascii_alphanumeric() && c != ':' && c != '/' && c != '@' && c != '.',
            "*"
        )
    );

    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(std::time::Duration::from_secs(config.connect_timeout_secs))
        .idle_timeout(std::time::Duration::from_secs(config.idle_timeout_secs))
        .connect(&config.url)
        .await?;

    // Test connection
    sqlx::query("SELECT 1").fetch_one(&pool).await?;

    tracing::info!("Database connection pool initialized successfully");

    let pool = Arc::new(pool);
    let _ = DB_POOL.set(pool.clone());

    Ok(pool)
}

/// Get the database connection pool
/// Returns None if not initialized
pub fn get_pool() -> Option<Arc<PgPool>> {
    DB_POOL.get().cloned()
}

/// Check if database is healthy
pub async fn health_check() -> Result<std::time::Duration, sqlx::Error> {
    let pool = get_pool()
        .ok_or_else(|| sqlx::Error::Configuration("Database pool not initialized".into()))?;

    let start = std::time::Instant::now();
    sqlx::query("SELECT 1").fetch_one(pool.as_ref()).await?;

    Ok(start.elapsed())
}

/// Run database migrations
/// Creates tables if they don't exist
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    tracing::info!("Running database migrations...");

    // Create users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    "#,
    )
    .execute(pool)
    .await?;

    // Create refresh_tokens table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    "#,
    )
    .execute(pool)
    .await?;

    // Create index on token_hash for fast lookups
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash 
        ON refresh_tokens(token_hash)
    "#,
    )
    .execute(pool)
    .await?;

    // Create index on expires_at for cleanup
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at 
        ON refresh_tokens(expires_at)
    "#,
    )
    .execute(pool)
    .await?;

    // Create portfolio_sections table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS portfolio_sections (
            key TEXT PRIMARY KEY,
            content JSONB NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    "#,
    )
    .execute(pool)
    .await?;

    // Create blog_posts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS blog_posts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            title TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            summary TEXT,
            content_md TEXT,
            content_html TEXT,
            published BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    "#,
    )
    .execute(pool)
    .await?;

    // Create index on slug for fast lookups
    sqlx::query(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_blog_posts_slug 
        ON blog_posts(slug)
    "#,
    )
    .execute(pool)
    .await?;

    tracing::info!("Database migrations completed successfully");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_config_default_uses_env_or_fallback() {
        let config = DbConfig::default();
        assert!(config.max_connections >= 1);
        assert!(config.connect_timeout_secs >= 1);
        assert!(config.idle_timeout_secs >= 1);
        assert!(!config.url.is_empty());
    }

    #[test]
    fn test_get_pool_none_before_init() {
        // DB_POOL is not initialized in test; get_pool returns None
        let pool = get_pool();
        assert!(pool.is_none());
    }

    #[tokio::test]
    async fn test_health_check_fails_without_pool() {
        let result = health_check().await;
        assert!(result.is_err());
    }
}

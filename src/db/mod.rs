pub mod models;

use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tokio::sync::OnceCell;

static DB_POOL: OnceCell<Arc<PgPool>> = OnceCell::const_new();

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
        .acquire_timeout(std::time::Duration::from_secs(3))
        .idle_timeout(std::time::Duration::from_secs(config.idle_timeout_secs))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .test_before_acquire(true)
        .connect(&config.url)
        .await?;

    sqlx::query("SELECT 1").fetch_one(&pool).await?;

    tracing::info!("Database connection pool initialized successfully");

    let pool = Arc::new(pool);
    let _ = DB_POOL.set(pool.clone());

    Ok(pool)
}

pub fn get_pool() -> Option<Arc<PgPool>> {
    DB_POOL.get().cloned()
}

pub async fn health_check() -> Result<std::time::Duration, sqlx::Error> {
    let pool = get_pool()
        .ok_or_else(|| sqlx::Error::Configuration("Database pool not initialized".into()))?;

    let start = std::time::Instant::now();
    sqlx::query("SELECT 1").fetch_one(pool.as_ref()).await?;

    Ok(start.elapsed())
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    tracing::info!("Running database migrations...");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS admin_users (
            id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            avatar TEXT,
            role TEXT NOT NULL DEFAULT 'ADMIN',
            is_active BOOLEAN NOT NULL DEFAULT true,
            last_login_at TIMESTAMPTZ,
            last_login_ip TEXT,
            login_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_admin_users_email ON admin_users(email);
        CREATE INDEX IF NOT EXISTS idx_admin_users_is_active ON admin_users(is_active);
        CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users(role)
        "#,
    )
    .execute(pool)
    .await?;

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

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash 
        ON refresh_tokens(token_hash)
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at 
        ON refresh_tokens(expires_at)
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS admin_refresh_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            admin_user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMPTZ NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_admin_refresh_tokens_token_hash
            ON admin_refresh_tokens(token_hash);
        CREATE INDEX IF NOT EXISTS idx_admin_refresh_tokens_admin_user_id
            ON admin_refresh_tokens(admin_user_id)
        "#,
    )
    .execute(pool)
    .await?;

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

    sqlx::query(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_blog_posts_slug
            ON blog_posts(slug);
        CREATE INDEX IF NOT EXISTS idx_blog_posts_published
            ON blog_posts(published);
        CREATE INDEX IF NOT EXISTS idx_blog_posts_created_at
            ON blog_posts(created_at DESC);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_blog_posts_slug
            ON blog_posts(slug);
        CREATE INDEX IF NOT EXISTS idx_blog_posts_published
            ON blog_posts(published);
        CREATE INDEX IF NOT EXISTS idx_blog_posts_created_at
            ON blog_posts(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_blog_posts_pub_created
            ON blog_posts(published, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_admin_refresh_tokens_expires_at
            ON admin_refresh_tokens(expires_at)
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        ALTER TABLE blog_posts
            ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}',
            ADD COLUMN IF NOT EXISTS reading_time_minutes INTEGER NOT NULL DEFAULT 0,
            ADD COLUMN IF NOT EXISTS view_count BIGINT NOT NULL DEFAULT 0
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_blog_posts_tags ON blog_posts USING GIN(tags);
        CREATE INDEX IF NOT EXISTS idx_blog_posts_view_count ON blog_posts(view_count DESC)
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
        let pool = get_pool();
        assert!(pool.is_none());
    }

    #[tokio::test]
    async fn test_health_check_fails_without_pool() {
        let result = health_check().await;
        assert!(result.is_err());
    }
}

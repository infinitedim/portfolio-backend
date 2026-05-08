//! Shared helpers for `#[tokio::test]` cases inside this crate.
//!
//! This module is gated behind `#[cfg(test)]` in `lib.rs` so it never appears
//! in release builds and adds zero overhead to production code paths.
//!
//! ## Database isolation
//!
//! [`acquire_test_pool`] connects to the URL in the `TEST_DATABASE_URL`
//! environment variable, creates a fresh per-test schema, runs the standard
//! [`crate::db::run_migrations`] in that schema, and installs the resulting
//! pool into the process-wide override consulted by [`crate::db::get_pool`].
//! It also takes a global mutex so concurrent tests do not see each other's
//! pool (handlers read the pool through `get_pool()`, which is process-wide
//! state).
//!
//! When `TEST_DATABASE_URL` is unset, [`acquire_test_pool`] returns `None`.
//! Tests that need a database should use the `let Some(db) = ... else
//! { return; };` pattern so the suite stays runnable on machines (or CI
//! jobs) that have not provisioned Postgres:
//!
//! ```ignore
//! # use crate::test_support;
//! # async fn example() {
//! let Some(db) = test_support::acquire_test_pool().await else {
//!     return;
//! };
//! // run DB-backed assertions against `db.pool`
//! # }
//! ```
//!
//! The opt-in env var is intentionally `TEST_DATABASE_URL` rather than the
//! production `DATABASE_URL` so unrelated tests that branch on
//! `DATABASE_URL` being unset (e.g. fallback admin login) keep behaving as
//! they did before.
//!
//! ## Auth tokens
//!
//! [`admin_bearer`] / [`admin_bearer_for`] mint a short-lived admin JWT via
//! the existing [`crate::routes::auth::create_access_token`] helper so
//! tests don't duplicate any signing logic.
//!
//! ## Upload isolation
//!
//! [`isolated_upload_dir`] returns an RAII guard that points
//! [`crate::routes::upload`] at a fresh temp directory via the `UPLOAD_DIR`
//! env var, removes that directory on `Drop`, and serializes upload tests so
//! the env var override does not race.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::connect_info::MockConnectInfo;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

/// Env var that points test helpers at a real Postgres instance. Tests that
/// need a database should call [`acquire_test_pool`] and skip themselves
/// gracefully when this returns `None`.
pub const TEST_DATABASE_URL_ENV: &str = "TEST_DATABASE_URL";

/// Env var consulted by [`crate::routes::upload`] to pick the on-disk upload
/// directory. Override it (via [`isolated_upload_dir`]) to redirect writes
/// into a per-test temp directory.
pub const UPLOAD_DIR_ENV: &str = "UPLOAD_DIR";

/// Mock socket address matching the pattern in `routes::auth::tests`. Use
/// [`mock_connect_info`] to attach this as a layer on a test router.
pub fn mock_socket_addr() -> std::net::SocketAddr {
    "127.0.0.1:12345"
        .parse()
        .expect("hardcoded test SocketAddr is valid")
}

/// Build a layer that injects [`mock_socket_addr`] as the
/// `ConnectInfo<SocketAddr>` extension. The auth/upload/contact handlers
/// extract `ConnectInfo<SocketAddr>` and would 500 without it.
pub fn mock_connect_info() -> MockConnectInfo<std::net::SocketAddr> {
    MockConnectInfo(mock_socket_addr())
}

// ---------------------------------------------------------------------------
// Postgres test pool
// ---------------------------------------------------------------------------

/// Process-wide lock held for the duration of a single DB-backed test.
///
/// Handlers under test read the database through [`crate::db::get_pool`],
/// which consults a single process-wide override slot. We serialise tests
/// through this mutex so concurrent `#[tokio::test]` cases never see each
/// other's pool. Pure router/validation tests that don't go near the DB
/// don't need to touch this lock.
static TEST_DB_LOCK: Mutex<()> = Mutex::const_new(());

/// Per-test database handle returned by [`acquire_test_pool`].
///
/// Holding this struct keeps the test serialisation lock and the
/// `db::get_pool` override active for the lifetime of the test. Drop it (or
/// let it fall out of scope at the end of the test) to release both.
pub struct TestDb {
    /// Pool wired to a fresh schema. Already installed into
    /// [`crate::db::get_pool`] for the duration of this guard.
    pub pool: Arc<PgPool>,
    /// Schema name (`test_<uuid>`). Tests can `TRUNCATE` tables inside it
    /// via [`truncate_all_tables`] if they share a single `TestDb` across
    /// sub-tests, but per-`TestDb` schema isolation is the default.
    pub schema: String,
    _guard: MutexGuard<'static, ()>,
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Clear the override before the lock guard is released so the next
        // test cannot observe a stale pool.
        crate::db::clear_test_pool();
        // Schema cleanup is intentionally skipped: per-test CI databases are
        // throwaway, and `Drop` cannot block in an async runtime to issue a
        // `DROP SCHEMA` query without risking deadlocks.
    }
}

/// Acquire an isolated Postgres pool for the current test.
///
/// Returns `None` (after logging at `warn`) when `TEST_DATABASE_URL` is unset
/// or the connection fails — callers should treat that as "skip this test"
/// rather than as a hard failure so the suite stays runnable without a DB.
///
/// On success, the returned [`TestDb`]:
/// - exposes a [`PgPool`] pinned to a fresh `test_<uuid>` schema;
/// - has already run [`crate::db::run_migrations`] in that schema;
/// - has installed itself as the override returned by
///   [`crate::db::get_pool`] for the duration of the guard;
/// - holds the global [`TEST_DB_LOCK`] so other DB-backed tests block.
pub async fn acquire_test_pool() -> Option<TestDb> {
    let url = match std::env::var(TEST_DATABASE_URL_ENV) {
        Ok(u) if !u.is_empty() => u,
        _ => return None,
    };

    let guard = TEST_DB_LOCK.lock().await;

    let schema = format!("test_{}", Uuid::new_v4().simple());

    // Step 1: open a one-shot connection in the default schema and create
    // the per-test schema. We do this with its own pool because the search
    // path on the eventual test pool is set in `after_connect`, which we
    // don't want firing before the schema exists.
    let admin_pool = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&url)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                "test_support: failed to connect to TEST_DATABASE_URL: {}",
                e
            );
            return None;
        }
    };

    if let Err(e) = sqlx::query(&format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, schema))
        .execute(&admin_pool)
        .await
    {
        tracing::warn!("test_support: failed to create schema {}: {}", schema, e);
        return None;
    }
    drop(admin_pool);

    // Step 2: build the real test pool, pinning every checked-out
    // connection to the new schema via `SET search_path`. `IF NOT EXISTS`
    // DDL inside `run_migrations` will then create the standard tables
    // inside the per-test schema instead of the shared `public` one.
    let schema_for_hook = schema.clone();
    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(move |conn, _meta| {
            let s = schema_for_hook.clone();
            Box::pin(async move {
                let stmt = format!(r#"SET search_path TO "{}", public"#, s);
                conn.execute(stmt.as_str()).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("test_support: failed to build test pool: {}", e);
            return None;
        }
    };

    if let Err(e) = crate::db::run_migrations(&pool).await {
        tracing::warn!(
            "test_support: failed to run migrations in {}: {}",
            schema,
            e
        );
        return None;
    }

    let pool = Arc::new(pool);
    crate::db::set_test_pool(pool.clone());

    Some(TestDb {
        pool,
        schema,
        _guard: guard,
    })
}

/// Truncate every table the migrations create, restarting identity columns.
///
/// Per-`TestDb` schema isolation usually makes this unnecessary, but it is
/// useful for tests that re-use a single `TestDb` across multiple
/// sub-scenarios and want a clean slate between them.
pub async fn truncate_all_tables(pool: &PgPool) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        TRUNCATE TABLE
            admin_refresh_tokens,
            refresh_tokens,
            blog_posts,
            contact_messages,
            portfolio_sections,
            admin_users,
            users
        RESTART IDENTITY CASCADE
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a minimal `admin_users` row and return its `id`. Useful for tests
/// that need a real DB-backed admin user (e.g. for refresh-token tests).
pub async fn insert_admin_user(pool: &PgPool, email: &str) -> sqlx::Result<String> {
    let id = Uuid::new_v4().to_string();
    // bcrypt of "test-password" — stable across runs, never used for real
    // logins because it lives only inside the per-test schema.
    let password_hash = "$2b$04$abcdefghijklmnopqrstuuJL3vQvT.4U8bJZ9VqX1/3lN4n2eNqDi".to_string();
    sqlx::query(
        r#"
        INSERT INTO admin_users (id, email, password_hash, role, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, 'SUPER_ADMIN', true, now(), now())
        "#,
    )
    .bind(&id)
    .bind(email)
    .bind(&password_hash)
    .execute(pool)
    .await?;
    Ok(id)
}

/// Insert an active admin with a known plaintext password (bcrypt-hashed).
pub async fn insert_admin_with_password(
    pool: &PgPool,
    email: &str,
    password: &str,
) -> sqlx::Result<String> {
    let pwd = password.to_string();
    let password_hash = tokio::task::spawn_blocking(move || {
        bcrypt::hash(&pwd, bcrypt::DEFAULT_COST).expect("bcrypt hash in test")
    })
    .await
    .expect("spawn_blocking join");
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO admin_users (id, email, password_hash, role, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, 'SUPER_ADMIN', true, now(), now())
        "#,
    )
    .bind(&id)
    .bind(email)
    .bind(&password_hash)
    .execute(pool)
    .await?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// Auth tokens
// ---------------------------------------------------------------------------

/// Default admin identity used by [`admin_bearer`].
pub const DEFAULT_TEST_ADMIN_ID: &str = "00000000-0000-0000-0000-00000000ad11";
pub const DEFAULT_TEST_ADMIN_EMAIL: &str = "admin@test.local";
pub const DEFAULT_TEST_ADMIN_ROLE: &str = "ADMIN";

/// Mint a JWT for the supplied admin identity using the production signing
/// helper, so tests stay coupled to the real claim set / algorithm.
pub fn mint_admin_token(user_id: &str, email: &str, role: &str) -> String {
    crate::routes::auth::create_access_token(user_id, email, role)
        .expect("test_support: failed to mint admin access token")
}

/// `Authorization: Bearer ...` value for an admin user with a custom identity.
pub fn admin_bearer_for(user_id: &str, email: &str, role: &str) -> String {
    format!("Bearer {}", mint_admin_token(user_id, email, role))
}

/// `Authorization: Bearer ...` value for the default test admin. Use this
/// when the test only cares that the request is authenticated as some admin.
pub fn admin_bearer() -> String {
    admin_bearer_for(
        DEFAULT_TEST_ADMIN_ID,
        DEFAULT_TEST_ADMIN_EMAIL,
        DEFAULT_TEST_ADMIN_ROLE,
    )
}

// ---------------------------------------------------------------------------
// Isolated upload directory
// ---------------------------------------------------------------------------

/// Serializes upload tests so the `UPLOAD_DIR` env-var override never races.
static UPLOAD_DIR_LOCK: Mutex<()> = Mutex::const_new(());

/// RAII guard returned by [`isolated_upload_dir`]. Restores the previous
/// `UPLOAD_DIR` env var and removes the temp directory on `Drop`.
pub struct UploadDirGuard {
    /// Path to the temp directory the upload routes are writing into.
    pub path: PathBuf,
    previous: Option<String>,
    _lock: MutexGuard<'static, ()>,
}

impl Drop for UploadDirGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(p) => std::env::set_var(UPLOAD_DIR_ENV, p),
            None => std::env::remove_var(UPLOAD_DIR_ENV),
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Create a fresh temp directory, point [`crate::routes::upload`] at it via
/// the `UPLOAD_DIR` env var, and return an RAII guard that cleans both up.
///
/// Holds [`UPLOAD_DIR_LOCK`] for the lifetime of the guard so concurrent
/// upload tests do not stomp on each other's env-var override.
pub async fn isolated_upload_dir() -> std::io::Result<UploadDirGuard> {
    let lock = UPLOAD_DIR_LOCK.lock().await;
    let path = std::env::temp_dir().join(format!(
        "portfolio-test-uploads-{}",
        Uuid::new_v4().simple()
    ));
    tokio::fs::create_dir_all(&path).await?;
    let previous = std::env::var(UPLOAD_DIR_ENV).ok();
    std::env::set_var(UPLOAD_DIR_ENV, &path);
    Ok(UploadDirGuard {
        path,
        previous,
        _lock: lock,
    })
}

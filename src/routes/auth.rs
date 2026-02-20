/**
 * Authentication Routes
 * JWT-based authentication with login, verify, refresh, and logout
 */
use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

use crate::db;

// ============================================================================
// Configuration
// ============================================================================

lazy_static::lazy_static! {
    /// JWT secret key from environment
    pub static ref JWT_SECRET: String = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "default-jwt-secret-change-in-production".to_string());

    /// Refresh token secret (can be same as JWT_SECRET or different)
    pub static ref REFRESH_SECRET: String = std::env::var("REFRESH_TOKEN_SECRET")
        .unwrap_or_else(|_| JWT_SECRET.clone());

    /// Admin email from environment
    pub static ref ADMIN_EMAIL: String = std::env::var("ADMIN_EMAIL")
        .unwrap_or_else(|_| "admin@example.com".to_string());

    /// Admin password hash from environment (or plain password to hash)
    pub static ref ADMIN_PASSWORD_HASH: String = {
        // First try ADMIN_HASH_PASSWORD (already hashed)
        if let Ok(hash) = std::env::var("ADMIN_HASH_PASSWORD") {
            hash
        } else if let Ok(plain) = std::env::var("ADMIN_PASSWORD") {
            // Hash the plain password
            hash(&plain, DEFAULT_COST).unwrap_or_else(|_| "".to_string())
        } else {
            // Default password "admin123" hashed
            hash("admin123", DEFAULT_COST).unwrap_or_else(|_| "".to_string())
        }
    };

    /// Refresh token storage (in-memory)
    pub static ref REFRESH_TOKENS: Arc<RwLock<HashMap<String, RefreshTokenData>>> =
        Arc::new(RwLock::new(HashMap::new()));

    /// Rate limit storage (IP -> last request timestamp)
    pub static ref RATE_LIMIT: Arc<RwLock<HashMap<String, i64>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// Access token expiry in minutes
const ACCESS_TOKEN_EXPIRY_MINUTES: i64 = 15;

/// Refresh token expiry in days
const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 7;

/// Rate limit window in seconds (1 request per IP per 60 seconds for login)
#[allow(dead_code)]
const RATE_LIMIT_WINDOW_SECS: i64 = 60;

// ============================================================================
// Types
// ============================================================================

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,   // User ID
    pub email: String, // User email
    pub role: String,  // User role
    pub exp: i64,      // Expiry timestamp
    pub iat: i64,      // Issued at timestamp
}

/// Stored refresh token data
#[derive(Debug, Clone)]
pub struct RefreshTokenData {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub expires_at: i64,
    pub revoked: bool,
}

/// User info returned to frontend
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub user_id: String,
    pub email: String,
    pub role: String,
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub success: bool,
    pub user: Option<UserInfo>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub success: bool,
    pub user: Option<UserInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub success: bool,
    pub is_valid: bool, // For compatibility with SecureAuth
    pub user: Option<UserInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub success: bool,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LogoutResponse {
    pub success: bool,
}

// Re-export the shared ErrorResponse so existing code in this module still compiles.
pub use crate::routes::ErrorResponse;

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a random refresh token
fn generate_refresh_token() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 64)
}

/// Hash a refresh token for secure storage using SHA-256.
/// Using a cryptographic hash is important because the hash is stored
/// in the database and could be a target for pre-image attacks if a
/// non-cryptographic function (e.g. DefaultHasher) were used instead.
fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Create access token
fn create_access_token(
    user_id: &str,
    email: &str,
    role: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let exp = now + Duration::minutes(ACCESS_TOKEN_EXPIRY_MINUTES);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

/// Verify and decode access token
pub fn verify_access_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

/// Extract bearer token from Authorization header
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Check rate limit for an IP.
///
/// Also removes stale entries from the map on every write so the HashMap
/// does not grow without bound as unique IPs accumulate over time.
async fn check_rate_limit(ip: &str) -> bool {
    #[cfg(test)]
    {
        let _ = ip;
        return true; // Bypass in tests so validation and credentials are exercised
    }

    #[cfg(not(test))]
    {
        let now = Utc::now().timestamp();
        let mut limits = RATE_LIMIT.write().await;

        // Evict all entries whose window has already expired.
        // This keeps memory proportional to the number of *active* IPs rather
        // than the total number of unique IPs seen since startup.
        limits.retain(|_, last| now - *last < RATE_LIMIT_WINDOW_SECS);

        if let Some(last_request) = limits.get(ip) {
            if now - last_request < RATE_LIMIT_WINDOW_SECS {
                return false; // Rate limited
            }
        }

        limits.insert(ip.to_string(), now);
        true // Allowed
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /api/auth/register
/// Register the first admin user (only works if no admin exists)
pub async fn register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let ip = addr.ip().to_string();

    // Rate limit check
    if !check_rate_limit(&ip).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(RegisterResponse {
                success: false,
                user: None,
                error: Some("Too many requests. Please try again later.".to_string()),
            }),
        );
    }

    // Validate request
    if payload.email.is_empty() || payload.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterResponse {
                success: false,
                user: None,
                error: Some("Email and password are required".to_string()),
            }),
        );
    }

    // Basic email format validation
    if !payload.email.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterResponse {
                success: false,
                user: None,
                error: Some("Invalid email format".to_string()),
            }),
        );
    }

    // Password strength validation
    if payload.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterResponse {
                success: false,
                user: None,
                error: Some("Password must be at least 8 characters long".to_string()),
            }),
        );
    }

    // Get database pool
    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(RegisterResponse {
                    success: false,
                    user: None,
                    error: Some("Database not available".to_string()),
                }),
            );
        }
    };

    // Check if any admin user already exists
    let existing_count: (i64,) = match sqlx::query_as("SELECT COUNT(*) FROM admin_users")
        .fetch_one(pool.as_ref())
        .await
    {
        Ok(count) => count,
        Err(e) => {
            tracing::error!("Failed to check existing admin users: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegisterResponse {
                    success: false,
                    user: None,
                    error: Some("Database error".to_string()),
                }),
            );
        }
    };

    // If any admin exists, registration is closed
    if existing_count.0 > 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(RegisterResponse {
                success: false,
                user: None,
                error: Some("Registration is closed. An admin account already exists.".to_string()),
            }),
        );
    }

    // Hash password — bcrypt is intentionally CPU-intensive; run it outside
    // the async executor so it doesn't block other in-flight tasks.
    let password_hash =
        match tokio::task::spawn_blocking(move || hash(&payload.password, DEFAULT_COST)).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                tracing::error!("Failed to hash password: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RegisterResponse {
                        success: false,
                        user: None,
                        error: Some("Failed to process password".to_string()),
                    }),
                );
            }
            Err(e) => {
                tracing::error!("spawn_blocking panic during hash: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RegisterResponse {
                        success: false,
                        user: None,
                        error: Some("Failed to process password".to_string()),
                    }),
                );
            }
        };

    // Insert new admin user
    let user_id = uuid::Uuid::new_v4().to_string();
    match sqlx::query(
        r#"
        INSERT INTO admin_users (id, email, password_hash, first_name, last_name, role, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, 'SUPER_ADMIN', true, now(), now())
        "#,
    )
    .bind(&user_id)
    .bind(&payload.email)
    .bind(&password_hash)
    .bind(&payload.first_name)
    .bind(&payload.last_name)
    .execute(pool.as_ref())
    .await
    {
        Ok(_) => {
            tracing::info!("Admin user registered successfully: {}", payload.email);
            (
                StatusCode::CREATED,
                Json(RegisterResponse {
                    success: true,
                    user: Some(UserInfo {
                        user_id,
                        email: payload.email,
                        role: "SUPER_ADMIN".to_string(),
                    }),
                    error: None,
                }),
            )
        }
        Err(e) => {
            tracing::error!("Failed to create admin user: {}", e);
            let error_msg = if e.to_string().contains("unique") {
                "Email already registered".to_string()
            } else {
                "Failed to create account".to_string()
            };
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegisterResponse {
                    success: false,
                    user: None,
                    error: Some(error_msg),
                }),
            )
        }
    }
}

/// POST /api/auth/login
/// Authenticate user and return tokens
pub async fn login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let ip = addr.ip().to_string();

    // Rate limit check
    if !check_rate_limit(&ip).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(LoginResponse {
                success: false,
                user: None,
                access_token: None,
                refresh_token: None,
                error: Some("Too many requests. Please try again later.".to_string()),
            }),
        );
    }

    // Validate request
    if payload.email.is_empty() || payload.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(LoginResponse {
                success: false,
                user: None,
                access_token: None,
                refresh_token: None,
                error: Some("Email and password are required".to_string()),
            }),
        );
    }

    // Basic email format validation
    if !payload.email.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(LoginResponse {
                success: false,
                user: None,
                access_token: None,
                refresh_token: None,
                error: Some("Invalid email format".to_string()),
            }),
        );
    }

    // Authenticate: query admin_users in the DB first; fall back to env-var
    // credentials when no database is available (e.g. local dev without PG).
    let (user_id, authenticated_email, role): (String, String, String) = match crate::db::get_pool()
    {
        Some(pool) => {
            let row = sqlx::query_as::<
                _,
                (
                    String,
                    String,
                    String,
                    String,
                    bool,
                    Option<chrono::DateTime<Utc>>,
                ),
            >(
                r#"SELECT id, email, password_hash, role, is_active, locked_until
                       FROM admin_users
                       WHERE LOWER(email) = LOWER($1)"#,
            )
            .bind(&payload.email)
            .fetch_optional(pool.as_ref())
            .await;

            match row {
                Ok(Some((id, email, password_hash, role, is_active, locked_until))) => {
                    // Check account lock
                    if let Some(until) = locked_until {
                        if until > Utc::now() {
                            tracing::warn!("Login attempt on locked account: {}", email);
                            return (
                                StatusCode::UNAUTHORIZED,
                                Json(LoginResponse {
                                    success: false,
                                    user: None,
                                    access_token: None,
                                    refresh_token: None,
                                    error: Some(
                                        "Account is temporarily locked. Try again later."
                                            .to_string(),
                                    ),
                                }),
                            );
                        }
                    }

                    // Check account active
                    if !is_active {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(LoginResponse {
                                success: false,
                                user: None,
                                access_token: None,
                                refresh_token: None,
                                error: Some("Account is disabled.".to_string()),
                            }),
                        );
                    }

                    // Verify password — bcrypt is CPU-bound; keep the async executor free.
                    let pwd = payload.password.clone();
                    let hash_clone = password_hash.clone();
                    let password_ok = tokio::task::spawn_blocking(move || {
                        verify(&pwd, &hash_clone).unwrap_or(false)
                    })
                    .await
                    .unwrap_or(false);
                    if !password_ok {
                        let _ = sqlx::query(
                            "UPDATE admin_users \
                                 SET login_attempts = login_attempts + 1, updated_at = now() \
                                 WHERE id = $1",
                        )
                        .bind(&id)
                        .execute(pool.as_ref())
                        .await;
                        tracing::warn!("Failed login attempt for: {}", email);
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(LoginResponse {
                                success: false,
                                user: None,
                                access_token: None,
                                refresh_token: None,
                                error: Some("Invalid credentials".to_string()),
                            }),
                        );
                    }

                    // Update last login metadata
                    let _ = sqlx::query(
                        "UPDATE admin_users \
                             SET last_login_at = now(), last_login_ip = $1, \
                                 login_attempts = 0, updated_at = now() \
                             WHERE id = $2",
                    )
                    .bind(&ip)
                    .bind(&id)
                    .execute(pool.as_ref())
                    .await;

                    (id, email, role)
                }
                Ok(None) => {
                    tracing::warn!("Login attempt for unknown user: {}", payload.email);
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(LoginResponse {
                            success: false,
                            user: None,
                            access_token: None,
                            refresh_token: None,
                            error: Some("Invalid credentials".to_string()),
                        }),
                    );
                }
                Err(e) => {
                    tracing::error!("Database error during login: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(LoginResponse {
                            success: false,
                            user: None,
                            access_token: None,
                            refresh_token: None,
                            error: Some(
                                "Authentication service temporarily unavailable.".to_string(),
                            ),
                        }),
                    );
                }
            }
        }
        None => {
            // No DB — fall back to env-var credentials for dev/no-db mode
            let email_matches = payload.email.to_lowercase() == ADMIN_EMAIL.to_lowercase();
            let password_matches = verify(&payload.password, &ADMIN_PASSWORD_HASH).unwrap_or(false);
            if !email_matches || !password_matches {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(LoginResponse {
                        success: false,
                        user: None,
                        access_token: None,
                        refresh_token: None,
                        error: Some("Invalid credentials".to_string()),
                    }),
                );
            }
            (
                "admin-user-id".to_string(),
                payload.email.clone(),
                "SUPER_ADMIN".to_string(),
            )
        }
    };

    // Generate tokens
    let access_token = match create_access_token(&user_id, &authenticated_email, &role) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to create access token: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse {
                    success: false,
                    user: None,
                    access_token: None,
                    refresh_token: None,
                    error: Some("Failed to create token".to_string()),
                }),
            );
        }
    };

    let refresh_token = generate_refresh_token();
    let refresh_token_hash = hash_refresh_token(&refresh_token);
    let expires_at = Utc::now() + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS);

    // Persist refresh token to DB (admin_refresh_tokens) when available
    if let Some(pool) = crate::db::get_pool() {
        if let Err(e) = sqlx::query(
            r#"INSERT INTO admin_refresh_tokens (admin_user_id, token_hash, expires_at)
               VALUES ($1, $2, $3)"#,
        )
        .bind(&user_id)
        .bind(&refresh_token_hash)
        .bind(expires_at)
        .execute(pool.as_ref())
        .await
        {
            tracing::error!("Failed to persist refresh token to DB: {}", e);
        }
    }

    // Also cache in-memory for fast validation (survives until restart)
    {
        let mut tokens = REFRESH_TOKENS.write().await;
        tokens.insert(
            refresh_token_hash,
            RefreshTokenData {
                user_id: user_id.clone(),
                email: authenticated_email.clone(),
                role: role.clone(),
                expires_at: expires_at.timestamp(),
                revoked: false,
            },
        );
    }

    tracing::info!("Successful login for user: {}", authenticated_email);

    (
        StatusCode::OK,
        Json(LoginResponse {
            success: true,
            user: Some(UserInfo {
                user_id,
                email: authenticated_email,
                role,
            }),
            access_token: Some(access_token),
            refresh_token: Some(refresh_token),
            error: None,
        }),
    )
}

/// POST /api/auth/verify
/// Verify access token and return user info
pub async fn verify_token(headers: HeaderMap) -> impl IntoResponse {
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::OK,
                Json(VerifyResponse {
                    success: false,
                    is_valid: false,
                    user: None,
                    error: Some("No authorization token provided".to_string()),
                }),
            );
        }
    };

    match verify_access_token(&token) {
        Ok(claims) => (
            StatusCode::OK,
            Json(VerifyResponse {
                success: true,
                is_valid: true,
                user: Some(UserInfo {
                    user_id: claims.sub,
                    email: claims.email,
                    role: claims.role,
                }),
                error: None,
            }),
        ),
        Err(e) => {
            tracing::debug!("Token verification failed: {}", e);
            (
                StatusCode::OK,
                Json(VerifyResponse {
                    success: false,
                    is_valid: false,
                    user: None,
                    error: Some("Invalid or expired token".to_string()),
                }),
            )
        }
    }
}

/// POST /api/auth/refresh
/// Refresh access token using refresh token
pub async fn refresh(Json(payload): Json<RefreshRequest>) -> impl IntoResponse {
    if payload.refresh_token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(RefreshResponse {
                success: false,
                access_token: None,
                refresh_token: None,
                error: Some("Refresh token is required".to_string()),
            }),
        );
    }

    let token_hash = hash_refresh_token(&payload.refresh_token);
    let now = Utc::now();

    // Resolve the token owner from DB first, then fall back to in-memory.
    // This ensures refresh tokens persist across server restarts.
    let token_data: Option<RefreshTokenData> = {
        if let Some(pool) = crate::db::get_pool() {
            match sqlx::query_as::<_, (String, String, String, chrono::DateTime<Utc>, bool)>(
                r#"SELECT au.id, au.email, au.role, art.expires_at, art.revoked
                   FROM admin_refresh_tokens art
                   JOIN admin_users au ON au.id = art.admin_user_id
                   WHERE art.token_hash = $1"#,
            )
            .bind(&token_hash)
            .fetch_optional(pool.as_ref())
            .await
            {
                Ok(Some((user_id, email, role, expires_at, revoked))) => Some(RefreshTokenData {
                    user_id,
                    email,
                    role,
                    expires_at: expires_at.timestamp(),
                    revoked,
                }),
                Ok(None) => {
                    // Not in DB — check in-memory cache (e.g. no-DB mode)
                    let tokens = REFRESH_TOKENS.read().await;
                    tokens.get(&token_hash).cloned()
                }
                Err(e) => {
                    tracing::error!("DB error during token refresh lookup: {}", e);
                    // Degrade gracefully: try in-memory
                    let tokens = REFRESH_TOKENS.read().await;
                    tokens.get(&token_hash).cloned()
                }
            }
        } else {
            // No DB — use in-memory only
            let tokens = REFRESH_TOKENS.read().await;
            tokens.get(&token_hash).cloned()
        }
    };

    match token_data {
        Some(data) if !data.revoked && data.expires_at > now.timestamp() => {
            // Create new access token
            let access_token = match create_access_token(&data.user_id, &data.email, &data.role) {
                Ok(token) => token,
                Err(e) => {
                    tracing::error!("Failed to create access token: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(RefreshResponse {
                            success: false,
                            access_token: None,
                            refresh_token: None,
                            error: Some("Failed to create token".to_string()),
                        }),
                    );
                }
            };

            // Rotate refresh token
            let new_refresh_token = generate_refresh_token();
            let new_token_hash = hash_refresh_token(&new_refresh_token);
            let new_expires_at = now + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS);

            // Rotate in DB
            if let Some(pool) = crate::db::get_pool() {
                let _ = sqlx::query(
                    "UPDATE admin_refresh_tokens SET revoked = true WHERE token_hash = $1",
                )
                .bind(&token_hash)
                .execute(pool.as_ref())
                .await;

                let _ = sqlx::query(
                    r#"INSERT INTO admin_refresh_tokens (admin_user_id, token_hash, expires_at)
                       VALUES ($1, $2, $3)"#,
                )
                .bind(&data.user_id)
                .bind(&new_token_hash)
                .bind(new_expires_at)
                .execute(pool.as_ref())
                .await;
            }

            // Rotate in-memory cache
            {
                let mut tokens = REFRESH_TOKENS.write().await;
                if let Some(old_data) = tokens.get_mut(&token_hash) {
                    old_data.revoked = true;
                }
                tokens.insert(
                    new_token_hash,
                    RefreshTokenData {
                        user_id: data.user_id,
                        email: data.email,
                        role: data.role,
                        expires_at: new_expires_at.timestamp(),
                        revoked: false,
                    },
                );
            }

            (
                StatusCode::OK,
                Json(RefreshResponse {
                    success: true,
                    access_token: Some(access_token),
                    refresh_token: Some(new_refresh_token),
                    error: None,
                }),
            )
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(RefreshResponse {
                success: false,
                access_token: None,
                refresh_token: None,
                error: Some("Invalid or expired refresh token".to_string()),
            }),
        ),
    }
}

/// POST /api/auth/logout
/// Invalidate refresh token(s) in both the DB and the in-memory cache.
pub async fn logout(headers: HeaderMap, Json(payload): Json<LogoutRequest>) -> impl IntoResponse {
    let pool = crate::db::get_pool();

    // Revoke a specific refresh token if provided
    if let Some(refresh_token) = payload.refresh_token {
        let token_hash = hash_refresh_token(&refresh_token);

        // Revoke in DB
        if let Some(ref p) = pool {
            let _ =
                sqlx::query("UPDATE admin_refresh_tokens SET revoked = true WHERE token_hash = $1")
                    .bind(&token_hash)
                    .execute(p.as_ref())
                    .await;
        }

        // Revoke in in-memory cache
        let mut tokens = REFRESH_TOKENS.write().await;
        if let Some(data) = tokens.get_mut(&token_hash) {
            data.revoked = true;
        }
    }

    // If an access token is provided, revoke ALL refresh tokens for that user
    if let Some(access_token) = payload
        .access_token
        .or_else(|| extract_bearer_token(&headers))
    {
        if let Ok(claims) = verify_access_token(&access_token) {
            // Revoke all user's tokens in DB
            if let Some(ref p) = pool {
                let _ = sqlx::query(
                    "UPDATE admin_refresh_tokens SET revoked = true WHERE admin_user_id = $1",
                )
                .bind(&claims.sub)
                .execute(p.as_ref())
                .await;
            }

            // Revoke all user's tokens in in-memory cache
            let mut tokens = REFRESH_TOKENS.write().await;
            for data in tokens.values_mut() {
                if data.user_id == claims.sub {
                    data.revoked = true;
                }
            }
        }
    }

    // Logout is always idempotent — always return success
    (StatusCode::OK, Json(LogoutResponse { success: true }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use axum::Router;
    use tower::ServiceExt;

    fn auth_router() -> Router {
        use axum::extract::connect_info::MockConnectInfo;
        Router::new()
            .route("/api/auth/login", post(login))
            .route("/api/auth/verify", post(verify_token))
            .route("/api/auth/refresh", post(refresh))
            .route("/api/auth/logout", post(logout))
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))))
    }

    async fn post_json(
        app: Router,
        uri: &str,
        json: &impl serde::Serialize,
    ) -> (StatusCode, axum::body::Bytes) {
        let body = Body::from(serde_json::to_vec(json).unwrap());
        let req = Request::post(uri)
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, bytes)
    }

    async fn post_empty(app: Router, uri: &str) -> (StatusCode, axum::body::Bytes) {
        let req = Request::post(uri).body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, bytes)
    }

    #[test]
    fn test_verify_access_token_invalid_returns_err() {
        let result = verify_access_token("invalid.jwt.token");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_login_empty_email_returns_bad_request() {
        let (status, _) = post_json(
            auth_router(),
            "/api/auth/login",
            &LoginRequest {
                email: "".to_string(),
                password: "admin123".to_string(),
            },
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_login_invalid_email_format_returns_bad_request() {
        let (status, _) = post_json(
            auth_router(),
            "/api/auth/login",
            &LoginRequest {
                email: "no-at-sign".to_string(),
                password: "admin123".to_string(),
            },
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_login_wrong_credentials_returns_unauthorized() {
        let (status, _) = post_json(
            auth_router(),
            "/api/auth/login",
            &LoginRequest {
                email: "admin@example.com".to_string(),
                password: "wrongpassword".to_string(),
            },
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_verify_no_token_returns_error_in_body() {
        let (status, bytes) = post_empty(auth_router(), "/api/auth/verify").await;
        assert_eq!(status, StatusCode::OK);
        let body: VerifyResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!body.success);
        assert!(!body.is_valid);
    }

    #[tokio::test]
    async fn test_refresh_empty_token_returns_bad_request() {
        let (status, _) = post_json(
            auth_router(),
            "/api/auth/refresh",
            &RefreshRequest {
                refresh_token: "".to_string(),
            },
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_logout_returns_success() {
        let (status, bytes) = post_json(
            auth_router(),
            "/api/auth/logout",
            &LogoutRequest {
                access_token: None,
                refresh_token: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let body: LogoutResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(body.success);
    }
}

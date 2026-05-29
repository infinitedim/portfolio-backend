use axum::{
    extract::ConnectInfo,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

use crate::db;

/// Minimum length for production HMAC secrets. 32 bytes maps to a 256-bit key,
/// which matches HS256 strength.
const MIN_SECRET_LEN: usize = 32;

fn load_secret(var: &str) -> String {
    let value = std::env::var(var).unwrap_or_default();
    let is_production = std::env::var("ENVIRONMENT").as_deref() == Ok("production");

    if value.is_empty() {
        if is_production {
            panic!(
                "FATAL: {} must be set in production. Refusing to start without an explicit secret.",
                var
            );
        }
        tracing::warn!(
            "{} is not set. Using a randomly generated dev-only secret. \
             DO NOT rely on this in production.",
            var
        );
        return Alphanumeric.sample_string(&mut rand::rng(), 64);
    }

    if is_production && value.len() < MIN_SECRET_LEN {
        panic!(
            "FATAL: {} is shorter than {} characters. Refusing to start with a weak secret.",
            var, MIN_SECRET_LEN
        );
    }

    value
}

lazy_static::lazy_static! {

    pub static ref JWT_SECRET: String = load_secret("JWT_SECRET");

    pub static ref REFRESH_SECRET: String = load_secret("REFRESH_TOKEN_SECRET");

    pub static ref ADMIN_EMAIL: String = std::env::var("ADMIN_EMAIL")
        .unwrap_or_else(|_| "admin@example.com".to_string());


    pub static ref ADMIN_PASSWORD_HASH: String = {

        if let Ok(hash) = std::env::var("ADMIN_HASH_PASSWORD") {
            hash
        } else if let Ok(plain) = std::env::var("ADMIN_PASSWORD") {

            hash(&plain, DEFAULT_COST).unwrap_or_else(|_| "".to_string())
        } else {
            tracing::warn!(
                "SECURITY: Neither ADMIN_HASH_PASSWORD nor ADMIN_PASSWORD is set. \
                 Fallback login is disabled until one of these env vars is configured."
            );
            "".to_string()
        }
    };

    pub static ref JWT_ISSUER: String = std::env::var("JWT_ISSUER")
        .unwrap_or_else(|_| "portfolio-backend".to_string());

    pub static ref JWT_AUDIENCE: String = std::env::var("JWT_AUDIENCE")
        .unwrap_or_else(|_| "portfolio-frontend".to_string());
}

const ACCESS_TOKEN_EXPIRY_MINUTES: i64 = 15;

const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 7;

/// Name of the HttpOnly cookie that holds the refresh token. It is scoped to
/// `/api/auth` so it is only sent on auth endpoints (login, refresh, logout)
/// and never on other routes — minimising attack surface even on the same
/// origin.
const REFRESH_COOKIE_NAME: &str = "rt";
const REFRESH_COOKIE_PATH: &str = "/api/auth";

/// Whether the cookie should be marked `Secure`. Disabled in non-production
/// so local dev over HTTP still works. In production any value other than
/// "production" is treated as production by default to avoid accidental
/// downgrades.
fn cookie_secure_flag() -> bool {
    std::env::var("ENVIRONMENT")
        .map(|v| v != "development" && v != "test")
        .unwrap_or(true)
}

fn build_refresh_cookie(token: &str) -> String {
    let max_age = REFRESH_TOKEN_EXPIRY_DAYS * 24 * 3600;
    let mut parts = vec![
        format!("{}={}", REFRESH_COOKIE_NAME, token),
        format!("Max-Age={}", max_age),
        format!("Path={}", REFRESH_COOKIE_PATH),
        "HttpOnly".to_string(),
        "SameSite=Strict".to_string(),
    ];
    if cookie_secure_flag() {
        parts.push("Secure".to_string());
    }
    parts.join("; ")
}

fn clear_refresh_cookie() -> String {
    let mut parts = vec![
        format!("{}=", REFRESH_COOKIE_NAME),
        "Max-Age=0".to_string(),
        format!("Path={}", REFRESH_COOKIE_PATH),
        "HttpOnly".to_string(),
        "SameSite=Strict".to_string(),
    ];
    if cookie_secure_flag() {
        parts.push("Secure".to_string());
    }
    parts.join("; ")
}

fn extract_refresh_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{}=", REFRESH_COOKIE_NAME);
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix(&prefix) {
            return Some(value.to_string());
        }
    }
    None
}

/// Build a response that returns JSON and attaches the refresh-token cookie.
fn json_with_cookie<T: serde::Serialize>(
    status: StatusCode,
    body: T,
    cookie: Option<String>,
) -> Response {
    let mut response = (status, Json(body)).into_response();
    if let Some(c) = cookie {
        match HeaderValue::from_str(&c) {
            Ok(v) => {
                response.headers_mut().append(header::SET_COOKIE, v);
            }
            Err(e) => {
                tracing::error!("Failed to build refresh cookie header: {}", e);
            }
        }
    }
    response
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub aud: String,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenData {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub expires_at: i64,
    pub revoked: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub user_id: String,
    pub email: String,
    pub role: String,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub success: bool,
    pub user: Option<UserInfo>,
    pub access_token: Option<String>,
    /// Deprecated. The refresh token is now delivered as an HttpOnly cookie
    /// scoped to `/api/auth`. Field is kept (skipped when None) only to ease
    /// frontend rollout and will be removed in a future release.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// When true, no access/refresh tokens are issued — the client must
    /// post `challenge_token` + a TOTP code to `/api/auth/2fa/login` to
    /// finish authenticating.
    #[serde(default)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub requires2fa: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub success: bool,
    pub user: Option<UserInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub success: bool,
    pub is_valid: bool,
    pub user: Option<UserInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Request body for `/api/auth/refresh`. The refresh token is now read from
/// the HttpOnly cookie; this struct exists so the endpoint accepts an empty
/// body without erroring on missing JSON.
#[derive(Debug, Default, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    /// Deprecated — refresh token is read from the HttpOnly `rt` cookie.
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub success: bool,
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct LogoutResponse {
    pub success: bool,
}

pub use crate::routes::ErrorResponse;

fn generate_refresh_token() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 64)
}

fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub(crate) fn create_access_token(
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
        iss: JWT_ISSUER.clone(),
        aud: JWT_AUDIENCE.clone(),
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

/// Build a strict validation config: pin to HS256, require iss/aud/exp/sub/iat,
/// and disable any default tolerance for missing claims.
fn access_token_validation() -> Validation {
    let mut v = Validation::new(Algorithm::HS256);
    v.set_issuer(&[JWT_ISSUER.as_str()]);
    v.set_audience(&[JWT_AUDIENCE.as_str()]);
    v.set_required_spec_claims(&["exp", "iat", "sub", "iss", "aud"]);
    v.leeway = 30;
    v
}

pub fn verify_access_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &access_token_validation(),
    )?;
    Ok(token_data.claims)
}

/// Require a valid bearer token whose role is admin-equivalent. Returns the
/// verified claims on success and an `AppError` mapped to 401/403 otherwise.
pub fn require_admin(headers: &HeaderMap) -> Result<Claims, crate::routes::AppError> {
    let token = extract_bearer_token(headers).ok_or(crate::routes::AppError::Unauthorized)?;
    let claims = verify_access_token(&token).map_err(|_| crate::routes::AppError::Unauthorized)?;

    let role = claims.role.to_ascii_uppercase();
    let allowed = matches!(role.as_str(), "ADMIN" | "SUPER_ADMIN");
    if !allowed {
        return Err(crate::routes::AppError::Forbidden);
    }
    Ok(claims)
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

// Application-level rate limiting has moved to the `tower-governor`
// middleware wired up in `lib.rs::create_app`. The previous in-memory
// HashMap was unbounded, did not honour `X-Forwarded-For`, and was useless
// behind any reverse proxy or with multiple replicas.

#[utoipa::path(
    post,
    path = "/api/auth/register",
    tag = "Authentication",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Registration successful", body = RegisterResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 409, description = "Email already taken", body = ErrorResponse),
        (status = 429, description = "Too many attempts", body = ErrorResponse),
    ),
)]
pub async fn register(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
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

#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "Authentication",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful (or 2FA challenge issued — see `requiresTwoFa`)", body = LoginResponse),
        (status = 400, description = "Missing/invalid email or password", body = ErrorResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 429, description = "Too many attempts", body = ErrorResponse),
    ),
)]
pub async fn login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> Response {
    let ip = addr.ip().to_string();

    if payload.email.is_empty() || payload.password.is_empty() {
        return json_with_cookie(
            StatusCode::BAD_REQUEST,
            LoginResponse {
                success: false,
                user: None,
                access_token: None,
                refresh_token: None,
                requires2fa: false,
                challenge_token: None,
                error: Some("Email and password are required".to_string()),
            },
            None,
        );
    }

    if !payload.email.contains('@') {
        return json_with_cookie(
            StatusCode::BAD_REQUEST,
            LoginResponse {
                success: false,
                user: None,
                access_token: None,
                refresh_token: None,
                requires2fa: false,
                challenge_token: None,
                error: Some("Invalid email format".to_string()),
            },
            None,
        );
    }

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
                    if let Some(until) = locked_until {
                        if until > Utc::now() {
                            tracing::warn!("Login attempt on locked account: {}", email);
                            return json_with_cookie(
                                StatusCode::UNAUTHORIZED,
                                LoginResponse {
                                    success: false,
                                    user: None,
                                    access_token: None,
                                    refresh_token: None,
                                    requires2fa: false,
                                    challenge_token: None,
                                    error: Some(
                                        "Account is temporarily locked. Try again later."
                                            .to_string(),
                                    ),
                                },
                                None,
                            );
                        }
                    }

                    if !is_active {
                        return json_with_cookie(
                            StatusCode::FORBIDDEN,
                            LoginResponse {
                                success: false,
                                user: None,
                                access_token: None,
                                refresh_token: None,
                                requires2fa: false,
                                challenge_token: None,
                                error: Some("Account is disabled.".to_string()),
                            },
                            None,
                        );
                    }

                    let pwd = payload.password.clone();
                    let hash_clone = password_hash.clone();
                    let password_ok = tokio::task::spawn_blocking(move || {
                        verify(&pwd, &hash_clone).unwrap_or(false)
                    })
                    .await
                    .unwrap_or(false);
                    if !password_ok {
                        let _ = sqlx::query(
                            r#"UPDATE admin_users
                                 SET login_attempts = login_attempts + 1,
                                     locked_until   = CASE
                                         WHEN login_attempts + 1 >= 5
                                         THEN now() + INTERVAL '15 minutes'
                                         ELSE locked_until
                                     END,
                                     updated_at = now()
                                 WHERE id = $1"#,
                        )
                        .bind(&id)
                        .execute(pool.as_ref())
                        .await;
                        tracing::warn!("Failed login attempt for: {}", email);
                        return json_with_cookie(
                            StatusCode::UNAUTHORIZED,
                            LoginResponse {
                                success: false,
                                user: None,
                                access_token: None,
                                refresh_token: None,
                                requires2fa: false,
                                challenge_token: None,
                                error: Some("Invalid credentials".to_string()),
                            },
                            None,
                        );
                    }

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
                    return json_with_cookie(
                        StatusCode::UNAUTHORIZED,
                        LoginResponse {
                            success: false,
                            user: None,
                            access_token: None,
                            refresh_token: None,
                            requires2fa: false,
                            challenge_token: None,
                            error: Some("Invalid credentials".to_string()),
                        },
                        None,
                    );
                }
                Err(e) => {
                    tracing::error!("Database error during login: {}", e);
                    return json_with_cookie(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        LoginResponse {
                            success: false,
                            user: None,
                            access_token: None,
                            refresh_token: None,
                            requires2fa: false,
                            challenge_token: None,
                            error: Some(
                                "Authentication service temporarily unavailable.".to_string(),
                            ),
                        },
                        None,
                    );
                }
            }
        }
        None => {
            let email_matches = payload.email.to_lowercase() == ADMIN_EMAIL.to_lowercase();
            let password_matches = verify(&payload.password, &ADMIN_PASSWORD_HASH).unwrap_or(false);
            if !email_matches || !password_matches {
                return json_with_cookie(
                    StatusCode::UNAUTHORIZED,
                    LoginResponse {
                        success: false,
                        user: None,
                        access_token: None,
                        refresh_token: None,
                        requires2fa: false,
                        challenge_token: None,
                        error: Some("Invalid credentials".to_string()),
                    },
                    None,
                );
            }
            (
                "admin-user-id".to_string(),
                payload.email.clone(),
                "SUPER_ADMIN".to_string(),
            )
        }
    };

    // Branch on 2FA: if the admin has TOTP enabled, we don't issue any
    // tokens yet. Instead we mint a short-lived challenge token that the
    // client must exchange via `/api/auth/2fa/login` together with a valid
    // TOTP / backup code.
    let totp_required = if let Some(pool) = crate::db::get_pool() {
        match crate::routes::twofa::fetch_admin_totp_state_by_email(
            pool.as_ref(),
            &authenticated_email,
        )
        .await
        {
            Ok(Some((_id, enabled))) => enabled,
            Ok(None) => false,
            Err(e) => {
                tracing::error!("Failed to load 2FA state: {}", e);
                false
            }
        }
    } else {
        false
    };

    if totp_required {
        let challenge = match crate::routes::twofa::create_challenge_token(
            &user_id,
            &authenticated_email,
            &role,
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to mint 2FA challenge token: {}", e);
                return json_with_cookie(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    LoginResponse {
                        success: false,
                        error: Some("Failed to start 2FA challenge".to_string()),
                        ..Default::default()
                    },
                    None,
                );
            }
        };

        return json_with_cookie(
            StatusCode::OK,
            LoginResponse {
                success: true,
                requires2fa: true,
                challenge_token: Some(challenge),
                user: Some(UserInfo {
                    user_id,
                    email: authenticated_email,
                    role,
                }),
                ..Default::default()
            },
            None,
        );
    }

    issue_login_tokens(&user_id, &authenticated_email, &role, &HeaderMap::new()).await
}

/// Mint the access token + refresh-token cookie after the caller has been
/// authenticated. Reused by `login` (no 2FA) and by `twofa::login_challenge`
/// (post-TOTP). The `_headers` argument is unused for now but kept on the
/// signature so the helper can later attach IP/UA-bound metadata without a
/// breaking signature change.
pub async fn issue_login_tokens(
    user_id: &str,
    email: &str,
    role: &str,
    _headers: &HeaderMap,
) -> Response {
    let access_token = match create_access_token(user_id, email, role) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to create access token: {}", e);
            return json_with_cookie(
                StatusCode::INTERNAL_SERVER_ERROR,
                LoginResponse {
                    success: false,
                    error: Some("Failed to create token".to_string()),
                    ..Default::default()
                },
                None,
            );
        }
    };

    let refresh_token = generate_refresh_token();
    let refresh_token_hash = hash_refresh_token(&refresh_token);
    let expires_at = Utc::now() + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS);

    if let Some(pool) = crate::db::get_pool() {
        if let Err(e) = sqlx::query(
            r#"INSERT INTO admin_refresh_tokens (admin_user_id, token_hash, expires_at)
               VALUES ($1, $2, $3)"#,
        )
        .bind(user_id)
        .bind(&refresh_token_hash)
        .bind(expires_at)
        .execute(pool.as_ref())
        .await
        {
            tracing::error!("Failed to persist refresh token to DB: {}", e);
        }
    } else {
        tracing::warn!(
            "Issuing refresh token without DB persistence \
             (DATABASE_URL not set). The token will not survive across \
             restarts and cannot be revoked server-side."
        );
    }

    tracing::info!("Successful login for user: {}", email);

    let cookie = build_refresh_cookie(&refresh_token);
    json_with_cookie(
        StatusCode::OK,
        LoginResponse {
            success: true,
            user: Some(UserInfo {
                user_id: user_id.to_string(),
                email: email.to_string(),
                role: role.to_string(),
            }),
            access_token: Some(access_token),
            ..Default::default()
        },
        Some(cookie),
    )
}

#[utoipa::path(
    post,
    path = "/api/auth/verify",
    tag = "Authentication",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Access token is valid", body = VerifyResponse),
        (status = 401, description = "Missing or invalid token", body = ErrorResponse),
    ),
)]
pub async fn verify_token(headers: HeaderMap) -> impl IntoResponse {
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
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
                StatusCode::UNAUTHORIZED,
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

#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    tag = "Authentication",
    request_body(content = RefreshRequest, description = "Body is optional — refresh token is read from the HttpOnly `rt` cookie"),
    responses(
        (status = 200, description = "New access token issued", body = RefreshResponse),
        (status = 401, description = "Refresh cookie missing/expired", body = ErrorResponse),
    ),
)]
pub async fn refresh(headers: HeaderMap, body: Option<Json<RefreshRequest>>) -> Response {
    // Prefer the HttpOnly cookie. We still accept the legacy JSON-body
    // refresh token for one release cycle so existing clients keep working
    // through deployment, but new code paths should never rely on it.
    let cookie_token = extract_refresh_cookie(&headers);
    let body_token = body
        .and_then(|Json(req)| req.refresh_token)
        .filter(|t| !t.is_empty());
    let refresh_token = match cookie_token.or(body_token) {
        Some(t) if !t.is_empty() => t,
        _ => {
            return json_with_cookie(
                StatusCode::UNAUTHORIZED,
                RefreshResponse {
                    success: false,
                    access_token: None,
                    error: Some("Refresh token is required".to_string()),
                },
                None,
            );
        }
    };

    let token_hash = hash_refresh_token(&refresh_token);
    let now = Utc::now();

    // Refresh tokens live in Postgres only. The previous in-memory fallback
    // was a dual-source-of-truth bug: a token could be revoked in DB but
    // still accepted from RAM, or vice versa.
    let token_data: Option<RefreshTokenData> = match crate::db::get_pool() {
        Some(pool) => {
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
                Ok(None) => None,
                Err(e) => {
                    tracing::error!("DB error during token refresh lookup: {}", e);
                    None
                }
            }
        }
        None => {
            tracing::warn!("Refresh requested but DATABASE_URL is not set; cannot validate token.");
            None
        }
    };

    match token_data {
        Some(data) if !data.revoked && data.expires_at > now.timestamp() => {
            let access_token = match create_access_token(&data.user_id, &data.email, &data.role) {
                Ok(token) => token,
                Err(e) => {
                    tracing::error!("Failed to create access token: {}", e);
                    return json_with_cookie(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        RefreshResponse {
                            success: false,
                            access_token: None,
                            error: Some("Failed to create token".to_string()),
                        },
                        None,
                    );
                }
            };

            let new_refresh_token = generate_refresh_token();
            let new_token_hash = hash_refresh_token(&new_refresh_token);
            let new_expires_at = now + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS);

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
            let _ = new_token_hash;

            let cookie = build_refresh_cookie(&new_refresh_token);
            json_with_cookie(
                StatusCode::OK,
                RefreshResponse {
                    success: true,
                    access_token: Some(access_token),
                    error: None,
                },
                Some(cookie),
            )
        }
        _ => json_with_cookie(
            StatusCode::UNAUTHORIZED,
            RefreshResponse {
                success: false,
                access_token: None,
                error: Some("Invalid or expired refresh token".to_string()),
            },
            // Proactively clear a stale or invalid cookie on the client.
            Some(clear_refresh_cookie()),
        ),
    }
}

#[utoipa::path(
    post,
    path = "/api/auth/logout",
    tag = "Authentication",
    request_body(content = LogoutRequest, description = "Optional. Clears the refresh cookie and revokes the session."),
    responses(
        (status = 200, description = "Logout always returns success", body = LogoutResponse),
    ),
)]
pub async fn logout(headers: HeaderMap, body: Option<Json<LogoutRequest>>) -> Response {
    let pool = crate::db::get_pool();
    let payload = body.map(|Json(p)| p).unwrap_or_default();

    // Refresh token comes from the cookie first, JSON body only as legacy
    // fallback during rollout.
    let refresh_token = extract_refresh_cookie(&headers).or(payload.refresh_token);
    if let Some(refresh_token) = refresh_token {
        let token_hash = hash_refresh_token(&refresh_token);

        if let Some(ref p) = pool {
            let _ =
                sqlx::query("UPDATE admin_refresh_tokens SET revoked = true WHERE token_hash = $1")
                    .bind(&token_hash)
                    .execute(p.as_ref())
                    .await;
        }
    }

    if let Some(access_token) = payload
        .access_token
        .or_else(|| extract_bearer_token(&headers))
    {
        if let Ok(claims) = verify_access_token(&access_token) {
            if let Some(ref p) = pool {
                let _ = sqlx::query(
                    "UPDATE admin_refresh_tokens SET revoked = true WHERE admin_user_id = $1",
                )
                .bind(&claims.sub)
                .execute(p.as_ref())
                .await;
            }
        }
    }

    json_with_cookie(
        StatusCode::OK,
        LogoutResponse { success: true },
        // Always clear the cookie on logout, even if the request didn't carry
        // one — browsers will simply ignore the expiration of an absent cookie.
        Some(clear_refresh_cookie()),
    )
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
            .route("/api/auth/register", post(register))
            .route("/api/auth/login", post(login))
            .route("/api/auth/verify", post(verify_token))
            .route("/api/auth/refresh", post(refresh))
            .route("/api/auth/logout", post(logout))
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))))
    }

    fn auth_and_twofa_router() -> Router {
        use axum::extract::connect_info::MockConnectInfo;
        use axum::routing::get;
        Router::new()
            .route("/api/auth/register", post(register))
            .route("/api/auth/login", post(login))
            .route("/api/auth/verify", post(verify_token))
            .route("/api/auth/refresh", post(refresh))
            .route("/api/auth/logout", post(logout))
            .route("/api/auth/2fa/status", get(crate::routes::twofa::status))
            .route("/api/auth/2fa/setup", post(crate::routes::twofa::setup))
            .route(
                "/api/auth/2fa/verify",
                post(crate::routes::twofa::verify_setup),
            )
            .route("/api/auth/2fa/disable", post(crate::routes::twofa::disable))
            .route(
                "/api/auth/2fa/login",
                post(crate::routes::twofa::login_challenge),
            )
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
    async fn test_verify_no_token_returns_unauthorized() {
        let (status, bytes) = post_empty(auth_router(), "/api/auth/verify").await;
        // Hardened contract: missing/invalid token must surface as 401, not 200.
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let body: VerifyResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!body.success);
        assert!(!body.is_valid);
    }

    #[tokio::test]
    async fn test_refresh_without_cookie_or_body_returns_unauthorized() {
        // Refresh now reads the token from the HttpOnly `rt` cookie. With
        // neither cookie nor body the response must be 401, not 400 — the
        // request is simply unauthenticated.
        let (status, _) = post_json(
            auth_router(),
            "/api/auth/refresh",
            &RefreshRequest {
                refresh_token: Some(String::new()),
            },
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_refresh_with_invalid_cookie_clears_cookie_and_returns_401() {
        let req = Request::post("/api/auth/refresh")
            .header("cookie", "rt=this-is-not-a-real-token")
            .body(Body::empty())
            .unwrap();
        let res = auth_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Server should proactively clear the bogus cookie on the client.
        let set_cookie = res
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            set_cookie.contains("rt=") && set_cookie.contains("Max-Age=0"),
            "expected cookie clear, got: {}",
            set_cookie
        );
    }

    #[tokio::test]
    async fn test_logout_returns_success_and_clears_cookie() {
        let req = Request::post("/api/auth/logout")
            .header("content-type", "application/json")
            .body(Body::from(b"{}".as_slice()))
            .unwrap();
        let res = auth_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let set_cookie = res
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            set_cookie.contains("rt=") && set_cookie.contains("Max-Age=0"),
            "logout must clear the refresh cookie; got {}",
            set_cookie
        );

        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: LogoutResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(body.success);
    }

    #[test]
    fn test_extract_refresh_cookie_parses_simple_header() {
        let mut h = HeaderMap::new();
        h.insert("cookie", HeaderValue::from_static("rt=abc123"));
        assert_eq!(extract_refresh_cookie(&h).as_deref(), Some("abc123"));
    }

    #[test]
    fn test_extract_refresh_cookie_picks_correct_value_from_multiple() {
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            HeaderValue::from_static("foo=bar; rt=secret-value; baz=qux"),
        );
        assert_eq!(extract_refresh_cookie(&h).as_deref(), Some("secret-value"));
    }

    #[test]
    fn test_build_refresh_cookie_has_security_flags() {
        std::env::set_var("ENVIRONMENT", "production");
        let cookie = build_refresh_cookie("token-xyz");
        assert!(cookie.contains("rt=token-xyz"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("Path=/api/auth"));
        std::env::remove_var("ENVIRONMENT");
    }

    fn first_nonempty_rt_from_set_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
        for raw in headers.get_all(header::SET_COOKIE) {
            if let Ok(s) = raw.to_str() {
                for part in s.split(';') {
                    let p = part.trim();
                    if let Some(v) = p.strip_prefix("rt=") {
                        if !v.is_empty() {
                            return Some(v.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    #[tokio::test]
    async fn test_verify_valid_bearer_minted_via_test_support() {
        let bearer = crate::test_support::admin_bearer();
        let req = Request::post("/api/auth/verify")
            .header("authorization", bearer)
            .body(Body::empty())
            .unwrap();
        let res = auth_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: VerifyResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(body.success && body.is_valid);
        assert_eq!(
            body.user.as_ref().unwrap().email,
            crate::test_support::DEFAULT_TEST_ADMIN_EMAIL
        );
    }

    #[tokio::test]
    async fn test_register_password_too_short_returns_bad_request() {
        let (status, _) = post_json(
            auth_router(),
            "/api/auth/register",
            &RegisterRequest {
                email: "valid@example.com".to_string(),
                password: "short".to_string(),
                first_name: None,
                last_name: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn db_register_first_admin_then_second_closed() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = auth_router();
        let (st1, b1) = post_json(
            app.clone(),
            "/api/auth/register",
            &RegisterRequest {
                email: "first@admin.test".to_string(),
                password: "longenough".to_string(),
                first_name: Some("A".to_string()),
                last_name: Some("B".to_string()),
            },
        )
        .await;
        assert_eq!(st1, StatusCode::CREATED);
        let r1: RegisterResponse = serde_json::from_slice(&b1).unwrap();
        assert!(r1.success);

        let (st2, b2) = post_json(
            app,
            "/api/auth/register",
            &RegisterRequest {
                email: "second@admin.test".to_string(),
                password: "longenough2".to_string(),
                first_name: None,
                last_name: None,
            },
        )
        .await;
        assert_eq!(st2, StatusCode::FORBIDDEN);
        let r2: RegisterResponse = serde_json::from_slice(&b2).unwrap();
        assert!(!r2.success);
        assert!(r2.error.unwrap().contains("closed"));
    }

    #[tokio::test]
    async fn db_login_refresh_logout_revokes_refresh() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let email = "loginflow@admin.test";
        let password = "longenough!";
        let uid =
            crate::test_support::insert_admin_with_password(db.pool.as_ref(), email, password)
                .await
                .expect("seed admin");

        let app = auth_router();
        let login_http = Request::post("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&LoginRequest {
                    email: email.to_string(),
                    password: password.to_string(),
                })
                .unwrap(),
            ))
            .unwrap();
        let res_login = app.clone().oneshot(login_http).await.unwrap();
        assert_eq!(res_login.status(), StatusCode::OK);
        let rt = first_nonempty_rt_from_set_cookie(res_login.headers()).expect("rt cookie");
        let body_bytes = axum::body::to_bytes(res_login.into_body(), usize::MAX)
            .await
            .unwrap();
        let login_res: LoginResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(login_res.success);
        let access = login_res.access_token.expect("access token");

        let req_ref = Request::post("/api/auth/refresh")
            .header("cookie", format!("rt={}", rt))
            .body(Body::empty())
            .unwrap();
        let res_ref = app.clone().oneshot(req_ref).await.unwrap();
        assert_eq!(res_ref.status(), StatusCode::OK);
        let ref_body: RefreshResponse = serde_json::from_slice(
            &axum::body::to_bytes(res_ref.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(ref_body.success);
        assert!(ref_body.access_token.is_some());

        let req_out = Request::post("/api/auth/logout")
            .header("cookie", format!("rt={}", rt))
            .header("authorization", format!("Bearer {}", access))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let res_out = app.clone().oneshot(req_out).await.unwrap();
        assert_eq!(res_out.status(), StatusCode::OK);

        let req_ref2 = Request::post("/api/auth/refresh")
            .header("cookie", format!("rt={}", rt))
            .body(Body::empty())
            .unwrap();
        let res_ref2 = app.oneshot(req_ref2).await.unwrap();
        assert_eq!(res_ref2.status(), StatusCode::UNAUTHORIZED);

        let _ = uid;
    }

    #[tokio::test]
    async fn db_login_inactive_account_forbidden() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let email = "inactive@admin.test";
        let password = "longenough!";
        let uid =
            crate::test_support::insert_admin_with_password(db.pool.as_ref(), email, password)
                .await
                .expect("seed");
        sqlx::query("UPDATE admin_users SET is_active = false WHERE id = $1")
            .bind(&uid)
            .execute(db.pool.as_ref())
            .await
            .unwrap();

        let (st, bytes) = post_json(
            auth_router(),
            "/api/auth/login",
            &LoginRequest {
                email: email.to_string(),
                password: password.to_string(),
            },
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        let body: LoginResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(body.error.unwrap().contains("disabled"));
    }

    #[tokio::test]
    async fn db_login_locked_account_unauthorized() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let email = "locked@admin.test";
        let password = "longenough!";
        let uid =
            crate::test_support::insert_admin_with_password(db.pool.as_ref(), email, password)
                .await
                .expect("seed");
        sqlx::query(
            "UPDATE admin_users SET locked_until = now() + interval '1 hour' WHERE id = $1",
        )
        .bind(&uid)
        .execute(db.pool.as_ref())
        .await
        .unwrap();

        let (st, bytes) = post_json(
            auth_router(),
            "/api/auth/login",
            &LoginRequest {
                email: email.to_string(),
                password: password.to_string(),
            },
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let body: LoginResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(body.error.unwrap().to_lowercase().contains("locked"));
    }

    #[tokio::test]
    async fn db_login_with_totp_enabled_issues_challenge_then_exchanges() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let email = "twofa@admin.test";
        let password = "longenough!";
        let uid =
            crate::test_support::insert_admin_with_password(db.pool.as_ref(), email, password)
                .await
                .expect("seed");

        let bearer = crate::test_support::admin_bearer_for(&uid, email, "SUPER_ADMIN");
        let app = auth_and_twofa_router();

        let req_setup = Request::post("/api/auth/2fa/setup")
            .header("authorization", bearer.clone())
            .body(Body::empty())
            .unwrap();
        let res_setup = app.clone().oneshot(req_setup).await.unwrap();
        assert_eq!(res_setup.status(), StatusCode::OK);
        let setup_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res_setup.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let secret_b32 = setup_json["secret"].as_str().unwrap().to_string();

        let code = {
            use totp_rs::{Algorithm as TotpAlg, Secret, TOTP};
            let secret_bytes = Secret::Encoded(secret_b32.clone())
                .to_bytes()
                .expect("secret bytes");
            let issuer = std::env::var("TOTP_ISSUER")
                .unwrap_or_else(|_| "infinitedim.vercel.app".to_string());
            let totp = TOTP::new(
                TotpAlg::SHA1,
                6,
                1,
                30,
                secret_bytes,
                Some(issuer),
                email.to_string(),
            )
            .expect("totp");
            totp.generate_current().expect("code")
        };

        let req_verify = Request::post("/api/auth/2fa/verify")
            .header("authorization", bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "code": code }).to_string().into_bytes(),
            ))
            .unwrap();
        let res_verify = app.clone().oneshot(req_verify).await.unwrap();
        assert_eq!(res_verify.status(), StatusCode::OK);

        let (st_login, login_bytes) = post_json(
            app.clone(),
            "/api/auth/login",
            &LoginRequest {
                email: email.to_string(),
                password: password.to_string(),
            },
        )
        .await;
        assert_eq!(st_login, StatusCode::OK);
        let login_json: LoginResponse = serde_json::from_slice(&login_bytes).unwrap();
        assert!(login_json.requires2fa);
        let challenge = login_json.challenge_token.expect("challenge");

        let req_finish = Request::post("/api/auth/2fa/login")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "challengeToken": challenge,
                    "code": code,
                })
                .to_string()
                .into_bytes(),
            ))
            .unwrap();
        let res_finish = app.oneshot(req_finish).await.unwrap();
        assert_eq!(res_finish.status(), StatusCode::OK);
        let had_rt = first_nonempty_rt_from_set_cookie(res_finish.headers()).is_some();
        let finish: LoginResponse = serde_json::from_slice(
            &axum::body::to_bytes(res_finish.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(finish.success);
        assert!(!finish.requires2fa);
        assert!(finish.access_token.is_some());
        assert!(had_rt);
    }
}

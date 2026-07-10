//! TOTP 2FA flow for admin accounts.
//!
//! ## Wire-format / lifecycle
//!
//! 1. Admin calls `POST /api/auth/2fa/setup` (authed). Backend generates a
//!    new secret + 8 backup codes, stores them on the user, and returns
//!    the otpauth URI + plaintext backup codes (only chance to see them).
//!    `totp_enabled` is *not* yet flipped: setup is reversible at this
//!    point.
//! 2. Admin scans the QR (FE renders the URI) and calls
//!    `POST /api/auth/2fa/verify` with a 6-digit code. If correct, we
//!    flip `totp_enabled` to `true`. Backup codes remain hashed in
//!    `totp_backup_codes`.
//! 3. Admin can call `POST /api/auth/2fa/disable` with their password +
//!    a valid TOTP/backup code to wipe `totp_secret`/codes.
//!
//! When `totp_enabled` is true, [`login`](crate::routes::auth::login)
//! returns `requires2fa: true` + a short-lived challenge token rather
//! than the full access/refresh pair. The client then calls
//! `POST /api/auth/2fa/login` with the challenge token + 6-digit code
//! (or a backup code) to obtain real credentials.
//!
//! Backup codes are SHA-256 hashed at rest and consumed on use — we
//! delete the hash from the array as soon as it succeeds, so the same
//! code cannot be replayed.

use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::verify;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use totp_rs::{Algorithm as TotpAlg, Secret, TOTP};

use crate::db;
use crate::routes::auth::{require_admin, JWT_AUDIENCE, JWT_ISSUER, JWT_SECRET};
use crate::routes::{AppError, ErrorResponse};

/// Standard TOTP parameters: 30s step, 6-digit codes, SHA-1 (compat).
const TOTP_DIGITS: usize = 6;
const TOTP_STEP_SECS: u64 = 30;
const TOTP_SKEW: u8 = 1; // accept ±1 step for clock skew

/// 2FA challenge tokens are intentionally short-lived. The window only has
/// to cover "user fishes for their authenticator app and types six digits".
const CHALLENGE_TOKEN_EXPIRY_MINUTES: i64 = 5;
const CHALLENGE_AUDIENCE_SUFFIX: &str = "-2fa-challenge";

/// Issuer label baked into the otpauth URI. Configurable so the QR shows
/// e.g. "infinitedim.dev" in Authenticator apps instead of an opaque
/// default.
fn totp_issuer_label() -> String {
    std::env::var("TOTP_ISSUER").unwrap_or_else(|_| "infinitedim.dev".to_string())
}

fn challenge_audience() -> String {
    format!("{}{}", *JWT_AUDIENCE, CHALLENGE_AUDIENCE_SUFFIX)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChallengeClaims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: String,
}

pub fn create_challenge_token(
    user_id: &str,
    email: &str,
    role: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let exp = now + Duration::minutes(CHALLENGE_TOKEN_EXPIRY_MINUTES);
    let claims = ChallengeClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        iss: JWT_ISSUER.clone(),
        aud: challenge_audience(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

fn verify_challenge_token(token: &str) -> Result<ChallengeClaims, jsonwebtoken::errors::Error> {
    let mut v = Validation::new(Algorithm::HS256);
    v.set_issuer(&[JWT_ISSUER.as_str()]);
    let aud = challenge_audience();
    v.set_audience(&[aud.as_str()]);
    v.set_required_spec_claims(&["exp", "iat", "sub", "iss", "aud"]);
    v.leeway = 30;
    let data =
        decode::<ChallengeClaims>(token, &DecodingKey::from_secret(JWT_SECRET.as_bytes()), &v)?;
    Ok(data.claims)
}

fn build_totp(secret_b32: &str, account: &str) -> Result<TOTP, AppError> {
    let secret = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| AppError::Internal(format!("invalid totp secret: {:?}", e)))?;
    TOTP::new(
        TotpAlg::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP_SECS,
        secret,
        Some(totp_issuer_label()),
        account.to_string(),
    )
    .map_err(|e| AppError::Internal(format!("totp build failed: {}", e)))
}

fn verify_totp_code(secret_b32: &str, account: &str, code: &str) -> Result<bool, AppError> {
    let totp = build_totp(secret_b32, account)?;
    totp.check_current(code)
        .map_err(|e| AppError::Internal(format!("totp check failed: {}", e)))
}

fn generate_backup_codes() -> Vec<String> {
    // 8 codes, 10 chars each, alphanumeric. Plenty of entropy and easy
    // to read/transcribe. Stored hashed.
    (0..8)
        .map(|_| Alphanumeric.sample_string(&mut rand::rng(), 10))
        .collect()
}

fn hash_backup_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.trim().to_ascii_uppercase().as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
struct AdminTotpRow {
    id: String,
    email: String,
    role: String,
    password_hash: String,
    totp_secret: Option<String>,
    totp_enabled: bool,
    totp_backup_codes: Vec<String>,
}

async fn load_admin_by_id(pool: &sqlx::PgPool, id: &str) -> Result<AdminTotpRow, AppError> {
    sqlx::query_as::<_, AdminTotpRow>(
        r#"
        SELECT id, email, role, password_hash,
               totp_secret, totp_enabled, totp_backup_codes
        FROM admin_users
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::NotFound)
}

pub async fn fetch_admin_totp_state_by_email(
    pool: &sqlx::PgPool,
    email: &str,
) -> Result<Option<(String, bool)>, sqlx::Error> {
    let row: Option<(String, bool)> = sqlx::query_as(
        r#"
        SELECT id, totp_enabled FROM admin_users
        WHERE LOWER(email) = LOWER($1)
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

// ---------------------------------------------------------------------------
// Status (lightweight check used by the admin settings page)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorStatusResponse {
    pub enabled: bool,
    pub backup_codes_remaining: usize,
}

#[utoipa::path(
    get,
    path = "/api/auth/2fa/status",
    tag = "Two-Factor Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current 2FA enrolment status", body = TwoFactorStatusResponse),
        (status = 401, description = "Missing or invalid token", body = ErrorResponse),
    ),
)]
pub async fn status(headers: HeaderMap) -> Result<impl IntoResponse, AppError> {
    let claims = require_admin(&headers)?;
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let admin = load_admin_by_id(pool.as_ref(), &claims.sub).await?;
    Ok((
        StatusCode::OK,
        Json(TwoFactorStatusResponse {
            enabled: admin.totp_enabled,
            backup_codes_remaining: admin.totp_backup_codes.len(),
        }),
    ))
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorSetupResponse {
    pub success: bool,
    pub secret: String,
    pub otpauth_uri: String,
    pub backup_codes: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/api/auth/2fa/setup",
    tag = "Two-Factor Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Generates a TOTP secret + 8 backup codes (NOT enabled until /verify)", body = TwoFactorSetupResponse),
        (status = 400, description = "2FA already enabled — disable first", body = ErrorResponse),
        (status = 401, description = "Missing or invalid token", body = ErrorResponse),
    ),
)]
pub async fn setup(headers: HeaderMap) -> Result<impl IntoResponse, AppError> {
    let claims = require_admin(&headers)?;
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let admin = load_admin_by_id(pool.as_ref(), &claims.sub).await?;

    if admin.totp_enabled {
        return Err(AppError::BadRequest(
            "2FA already enabled — disable first".to_string(),
        ));
    }

    let secret = Secret::generate_secret().to_encoded().to_string();
    let totp = build_totp(&secret, &admin.email)?;
    let uri = totp.get_url();
    let backup_codes = generate_backup_codes();
    let hashed_codes: Vec<String> = backup_codes.iter().map(|c| hash_backup_code(c)).collect();

    sqlx::query(
        r#"
        UPDATE admin_users
        SET totp_secret = $1,
            totp_backup_codes = $2,
            totp_enabled = false,
            updated_at = now()
        WHERE id = $3
        "#,
    )
    .bind(&secret)
    .bind(&hashed_codes)
    .bind(&admin.id)
    .execute(pool.as_ref())
    .await?;

    Ok((
        StatusCode::OK,
        Json(TwoFactorSetupResponse {
            success: true,
            secret,
            otpauth_uri: uri,
            backup_codes,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Verify (post-setup activation)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifySetupRequest {
    pub code: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifySetupResponse {
    pub success: bool,
    pub enabled: bool,
}

#[utoipa::path(
    post,
    path = "/api/auth/2fa/verify",
    tag = "Two-Factor Auth",
    security(("bearer_auth" = [])),
    request_body = VerifySetupRequest,
    responses(
        (status = 200, description = "Code matched — 2FA is now enabled", body = VerifySetupResponse),
        (status = 400, description = "Setup not started — call /setup first", body = ErrorResponse),
        (status = 401, description = "Invalid TOTP code", body = ErrorResponse),
    ),
)]
pub async fn verify_setup(
    headers: HeaderMap,
    Json(payload): Json<VerifySetupRequest>,
) -> Result<impl IntoResponse, AppError> {
    let claims = require_admin(&headers)?;
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let admin = load_admin_by_id(pool.as_ref(), &claims.sub).await?;

    let secret = admin
        .totp_secret
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("call /setup first".to_string()))?;

    if !verify_totp_code(secret, &admin.email, &payload.code)? {
        return Err(AppError::Unauthorized);
    }

    sqlx::query(
        r#"
        UPDATE admin_users SET totp_enabled = true, updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(&admin.id)
    .execute(pool.as_ref())
    .await?;

    Ok((
        StatusCode::OK,
        Json(VerifySetupResponse {
            success: true,
            enabled: true,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Disable
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DisableRequest {
    pub password: String,
    /// Either a TOTP code or a backup code. Both are accepted so users with
    /// a lost phone can still disable the second factor.
    pub code: String,
}

#[utoipa::path(
    post,
    path = "/api/auth/2fa/disable",
    tag = "Two-Factor Auth",
    security(("bearer_auth" = [])),
    request_body = DisableRequest,
    responses(
        (status = 200, description = "2FA disabled and enrolment data wiped"),
        (status = 400, description = "2FA not configured", body = ErrorResponse),
        (status = 401, description = "Bad password or code", body = ErrorResponse),
    ),
)]
pub async fn disable(
    headers: HeaderMap,
    Json(payload): Json<DisableRequest>,
) -> Result<impl IntoResponse, AppError> {
    let claims = require_admin(&headers)?;
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let admin = load_admin_by_id(pool.as_ref(), &claims.sub).await?;

    let pwd = payload.password;
    let pw_hash = admin.password_hash.clone();
    let password_ok = tokio::task::spawn_blocking(move || verify(&pwd, &pw_hash).unwrap_or(false))
        .await
        .unwrap_or(false);
    if !password_ok {
        return Err(AppError::Unauthorized);
    }

    let secret = admin
        .totp_secret
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("2FA not configured".to_string()))?;

    let totp_ok = verify_totp_code(secret, &admin.email, &payload.code).unwrap_or(false);
    let mut consumed_backup_idx: Option<usize> = None;
    if !totp_ok {
        let h = hash_backup_code(&payload.code);
        if let Some(idx) = admin.totp_backup_codes.iter().position(|c| c == &h) {
            consumed_backup_idx = Some(idx);
        } else {
            return Err(AppError::Unauthorized);
        }
    }

    let mut codes = admin.totp_backup_codes.clone();
    if let Some(idx) = consumed_backup_idx {
        codes.remove(idx);
    }

    sqlx::query(
        r#"
        UPDATE admin_users
        SET totp_secret = NULL,
            totp_enabled = false,
            totp_backup_codes = '{}',
            updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(&admin.id)
    .execute(pool.as_ref())
    .await?;

    let _ = codes; // intentionally dropped: 2FA is disabled, codes wiped

    Ok((StatusCode::OK, Json(serde_json::json!({"success": true}))))
}

// ---------------------------------------------------------------------------
// Login challenge (post-password 2FA step)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    /// The challenge token returned by `/api/auth/login` when 2FA is on.
    pub challenge_token: String,
    pub code: String,
}

#[utoipa::path(
    post,
    path = "/api/auth/2fa/login",
    tag = "Two-Factor Auth",
    request_body = ChallengeRequest,
    responses(
        (status = 200, description = "Tokens issued — same shape as `/api/auth/login` success", body = crate::routes::auth::LoginResponse),
        (status = 401, description = "Invalid challenge or 2FA code", body = ErrorResponse),
        (status = 503, description = "Database unavailable", body = ErrorResponse),
    ),
)]
pub async fn login_challenge(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<ChallengeRequest>,
) -> Response {
    // We deliberately reuse the auth.rs `login` happy path: once we've
    // verified the challenge token + TOTP, we mint the same access/refresh
    // pair the regular login flow would have minted.
    let claims = match verify_challenge_token(&payload.challenge_token) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Invalid 2FA challenge token: {}", e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    serde_json::json!({"success": false, "error": "Invalid or expired challenge"}),
                ),
            )
                .into_response();
        }
    };

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"success": false, "error": "Database not available"})),
            )
                .into_response();
        }
    };

    let admin = match load_admin_by_id(pool.as_ref(), &claims.sub).await {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"success": false, "error": "Invalid challenge"})),
            )
                .into_response();
        }
    };

    if !admin.totp_enabled || admin.totp_secret.is_none() {
        // The user disabled 2FA between login and challenge — fall back
        // to issuing tokens directly so they don't get stuck.
        return crate::routes::auth::issue_login_tokens(
            &admin.id,
            &admin.email,
            &admin.role,
            &headers,
        )
        .await;
    }

    let secret = admin.totp_secret.as_deref().unwrap();
    let totp_ok = verify_totp_code(secret, &admin.email, &payload.code).unwrap_or(false);
    let mut new_backup_codes: Option<Vec<String>> = None;
    if !totp_ok {
        let h = hash_backup_code(&payload.code);
        if let Some(idx) = admin.totp_backup_codes.iter().position(|c| c == &h) {
            let mut updated = admin.totp_backup_codes.clone();
            updated.remove(idx);
            new_backup_codes = Some(updated);
        } else {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"success": false, "error": "Invalid 2FA code"})),
            )
                .into_response();
        }
    }

    if let Some(updated) = new_backup_codes {
        if let Err(e) = sqlx::query(
            r#"UPDATE admin_users SET totp_backup_codes = $1, updated_at = now() WHERE id = $2"#,
        )
        .bind(&updated)
        .bind(&admin.id)
        .execute(pool.as_ref())
        .await
        {
            tracing::error!("Failed to consume backup code: {}", e);
        }
    }

    crate::routes::auth::issue_login_tokens(&admin.id, &admin.email, &admin.role, &headers).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    #[test]
    fn backup_code_hash_is_case_insensitive() {
        let lower = hash_backup_code("abcd1234ef");
        let upper = hash_backup_code("ABCD1234EF");
        let mixed = hash_backup_code(" AbCd1234Ef ");
        assert_eq!(lower, upper);
        assert_eq!(lower, mixed);
    }

    #[test]
    fn challenge_token_round_trip() {
        let token = create_challenge_token("u1", "a@b.co", "ADMIN").expect("encode");
        let claims = verify_challenge_token(&token).expect("decode");
        assert_eq!(claims.sub, "u1");
        assert_eq!(claims.email, "a@b.co");
        assert_eq!(claims.role, "ADMIN");
        assert!(claims.aud.ends_with(CHALLENGE_AUDIENCE_SUFFIX));
    }

    #[test]
    fn challenge_token_rejected_with_wrong_audience() {
        let token = create_challenge_token("u1", "a@b.co", "ADMIN").expect("encode");
        // Decoding with the *access* token validation (no challenge audience)
        // must fail — proves the two token types don't cross-validate.
        let res = crate::routes::auth::verify_access_token(&token);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn status_returns_unauthorized_without_bearer() {
        let app = Router::new().route("/api/auth/2fa/status", get(status));
        let req = Request::get("/api/auth/2fa/status")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn status_returns_service_unavailable_when_pool_cleared_under_lock() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = Router::new().route("/api/auth/2fa/status", get(status));
        let bearer = crate::test_support::admin_bearer();
        crate::db::clear_test_pool();
        let req = Request::get("/api/auth/2fa/status")
            .header("authorization", bearer)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        crate::db::set_test_pool(db.pool.clone());
    }

    #[tokio::test]
    async fn login_challenge_rejects_malformed_challenge_without_db() {
        let app = Router::new()
            .route("/api/auth/2fa/login", post(login_challenge))
            .layer(crate::test_support::mock_connect_info());
        let req = Request::post("/api/auth/2fa/login")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"challengeToken":"not-a-jwt","code":"123456"}"#.as_bytes(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_challenge_returns_503_when_pool_cleared_under_lock() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let challenge = create_challenge_token("orphan-id", "orphan@test.local", "ADMIN").unwrap();
        crate::db::clear_test_pool();
        let app = Router::new()
            .route("/api/auth/2fa/login", post(login_challenge))
            .layer(crate::test_support::mock_connect_info());
        let req = Request::post("/api/auth/2fa/login")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "challengeToken": challenge,
                    "code": "123456"
                })
                .to_string(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        crate::db::set_test_pool(db.pool.clone());
    }

    #[tokio::test]
    async fn db_setup_rejected_when_totp_already_enabled() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let email = "twofa-setup-dup@test.local";
        let password = "longenough!";
        let uid =
            crate::test_support::insert_admin_with_password(db.pool.as_ref(), email, password)
                .await
                .expect("seed");
        let bearer = crate::test_support::admin_bearer_for(&uid, email, "SUPER_ADMIN");
        let app = Router::new()
            .route("/api/auth/2fa/setup", post(setup))
            .route("/api/auth/2fa/verify", post(verify_setup))
            .layer(crate::test_support::mock_connect_info());

        let res_s1 = app
            .clone()
            .oneshot(
                Request::post("/api/auth/2fa/setup")
                    .header("authorization", bearer.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_s1.status(), axum::http::StatusCode::OK);
        let setup: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res_s1.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let secret_b32 = setup["secret"].as_str().unwrap();
        let code = {
            use totp_rs::{Algorithm as TotpAlg, Secret, TOTP};
            let secret_bytes = Secret::Encoded(secret_b32.to_string())
                .to_bytes()
                .expect("bytes");
            let issuer =
                std::env::var("TOTP_ISSUER").unwrap_or_else(|_| "infinitedim.dev".to_string());
            TOTP::new(
                TotpAlg::SHA1,
                6,
                1,
                30,
                secret_bytes,
                Some(issuer),
                email.to_string(),
            )
            .expect("totp")
            .generate_current()
            .expect("code")
        };

        let res_v = app
            .clone()
            .oneshot(
                Request::post("/api/auth/2fa/verify")
                    .header("authorization", bearer.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "code": code }).to_string().into_bytes(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_v.status(), axum::http::StatusCode::OK);

        let res_s2 = app
            .oneshot(
                Request::post("/api/auth/2fa/setup")
                    .header("authorization", bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_s2.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn db_login_challenge_rejects_wrong_totp_code() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let email = "twofa-wrong@test.local";
        let password = "longenough!";
        let uid =
            crate::test_support::insert_admin_with_password(db.pool.as_ref(), email, password)
                .await
                .expect("seed");
        let bearer = crate::test_support::admin_bearer_for(&uid, email, "SUPER_ADMIN");
        let app = Router::new()
            .route("/api/auth/2fa/setup", post(setup))
            .route("/api/auth/2fa/verify", post(verify_setup))
            .route("/api/auth/2fa/login", post(login_challenge))
            .layer(crate::test_support::mock_connect_info());

        let res_s1 = app
            .clone()
            .oneshot(
                Request::post("/api/auth/2fa/setup")
                    .header("authorization", bearer.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let setup: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res_s1.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let secret_b32 = setup["secret"].as_str().unwrap();
        let code = {
            use totp_rs::{Algorithm as TotpAlg, Secret, TOTP};
            let secret_bytes = Secret::Encoded(secret_b32.to_string())
                .to_bytes()
                .expect("bytes");
            let issuer =
                std::env::var("TOTP_ISSUER").unwrap_or_else(|_| "infinitedim.dev".to_string());
            TOTP::new(
                TotpAlg::SHA1,
                6,
                1,
                30,
                secret_bytes,
                Some(issuer),
                email.to_string(),
            )
            .expect("totp")
            .generate_current()
            .expect("code")
        };

        let res_v = app
            .clone()
            .oneshot(
                Request::post("/api/auth/2fa/verify")
                    .header("authorization", bearer.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "code": code }).to_string().into_bytes(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_v.status(), axum::http::StatusCode::OK);

        let login_payload = crate::routes::auth::LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
        };
        // Obtain challenge via auth login — use crate routes auth::login
        use axum::extract::connect_info::MockConnectInfo;
        use std::net::SocketAddr;
        let auth_app = axum::Router::new()
            .route("/api/auth/login", post(crate::routes::auth::login))
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))));
        let res_login = auth_app
            .oneshot(
                Request::post("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&login_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_login.status(), axum::http::StatusCode::OK);
        let login_body: crate::routes::auth::LoginResponse = serde_json::from_slice(
            &axum::body::to_bytes(res_login.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let ch = login_body.challenge_token.expect("challenge");

        let res_bad = app
            .oneshot(
                Request::post("/api/auth/2fa/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "challengeToken": ch,
                            "code": "000000"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_bad.status(), axum::http::StatusCode::UNAUTHORIZED);
        let _ = uid;
    }

    #[tokio::test]
    async fn db_disable_2fa_flow() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };

        let email = "twofa-disable@test.local";
        let password = "supersecretpassword";
        let uid =
            crate::test_support::insert_admin_with_password(db.pool.as_ref(), email, password)
                .await
                .unwrap();
        let bearer = crate::test_support::admin_bearer_for(&uid, email, "SUPER_ADMIN");

        let app = axum::Router::new()
            .route("/api/auth/2fa/setup", post(setup))
            .route("/api/auth/2fa/verify", post(verify_setup))
            .route("/api/auth/2fa/disable", post(disable))
            .route("/api/auth/2fa/status", get(status));

        let res_status = app
            .clone()
            .oneshot(
                Request::get("/api/auth/2fa/status")
                    .header("authorization", bearer.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_status.status(), axum::http::StatusCode::OK);
        let body_status: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res_status.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body_status["enabled"], false);

        let res_dis_not_conf = app
            .clone()
            .oneshot(
                Request::post("/api/auth/2fa/disable")
                    .header("authorization", bearer.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "password": password,
                            "code": "123456"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res_dis_not_conf.status(),
            axum::http::StatusCode::BAD_REQUEST
        );

        let res_s = app
            .clone()
            .oneshot(
                Request::post("/api/auth/2fa/setup")
                    .header("authorization", bearer.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_s.status(), axum::http::StatusCode::OK);
        let setup_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res_s.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let secret_b32 = setup_body["secret"].as_str().unwrap();

        let code = {
            use totp_rs::{Algorithm as TotpAlg, Secret, TOTP};
            let secret_bytes = Secret::Encoded(secret_b32.to_string())
                .to_bytes()
                .expect("bytes");
            let issuer =
                std::env::var("TOTP_ISSUER").unwrap_or_else(|_| "infinitedim.dev".to_string());
            TOTP::new(
                TotpAlg::SHA1,
                6,
                1,
                30,
                secret_bytes,
                Some(issuer),
                email.to_string(),
            )
            .expect("totp")
            .generate_current()
            .expect("code")
        };

        let res_v = app
            .clone()
            .oneshot(
                Request::post("/api/auth/2fa/verify")
                    .header("authorization", bearer.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "code": code }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_v.status(), axum::http::StatusCode::OK);

        let res_dis_wrong_pw = app
            .clone()
            .oneshot(
                Request::post("/api/auth/2fa/disable")
                    .header("authorization", bearer.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "password": "wrongpassword",
                            "code": code
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res_dis_wrong_pw.status(),
            axum::http::StatusCode::UNAUTHORIZED
        );

        let res_dis_wrong_code = app
            .clone()
            .oneshot(
                Request::post("/api/auth/2fa/disable")
                    .header("authorization", bearer.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "password": password,
                            "code": "000000"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res_dis_wrong_code.status(),
            axum::http::StatusCode::UNAUTHORIZED
        );

        let res_dis_ok = app
            .clone()
            .oneshot(
                Request::post("/api/auth/2fa/disable")
                    .header("authorization", bearer.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "password": password,
                            "code": code
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_dis_ok.status(), axum::http::StatusCode::OK);

        let res_status2 = app
            .clone()
            .oneshot(
                Request::get("/api/auth/2fa/status")
                    .header("authorization", bearer.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body_status2: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res_status2.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body_status2["enabled"], false);
        let _ = uid;
    }
}

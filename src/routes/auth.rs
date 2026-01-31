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
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::RwLock;

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
const RATE_LIMIT_WINDOW_SECS: i64 = 60;

// ============================================================================
// Types
// ============================================================================

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,      // User ID
    pub email: String,    // User email
    pub role: String,     // User role
    pub exp: i64,         // Expiry timestamp
    pub iat: i64,         // Issued at timestamp
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub success: bool,
    pub is_valid: bool,  // For compatibility with SecureAuth
    pub user: Option<UserInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a random refresh token
fn generate_refresh_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

/// Hash a refresh token for storage
fn hash_refresh_token(token: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Create access token
fn create_access_token(user_id: &str, email: &str, role: &str) -> Result<String, jsonwebtoken::errors::Error> {
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

/// Check rate limit for an IP
async fn check_rate_limit(ip: &str) -> bool {
    let now = Utc::now().timestamp();
    let mut limits = RATE_LIMIT.write().await;
    
    if let Some(last_request) = limits.get(ip) {
        if now - last_request < RATE_LIMIT_WINDOW_SECS {
            return false; // Rate limited
        }
    }
    
    limits.insert(ip.to_string(), now);
    true // Allowed
}

// ============================================================================
// Handlers
// ============================================================================

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
    
    // Check credentials
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
    
    // Generate tokens
    let user_id = "admin-user-id"; // In production, this would come from DB
    let role = "admin";
    
    let access_token = match create_access_token(user_id, &payload.email, role) {
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
    
    // Store refresh token
    let expires_at = (Utc::now() + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS)).timestamp();
    {
        let mut tokens = REFRESH_TOKENS.write().await;
        tokens.insert(refresh_token_hash, RefreshTokenData {
            user_id: user_id.to_string(),
            email: payload.email.clone(),
            role: role.to_string(),
            expires_at,
            revoked: false,
        });
    }
    
    (
        StatusCode::OK,
        Json(LoginResponse {
            success: true,
            user: Some(UserInfo {
                user_id: user_id.to_string(),
                email: payload.email,
                role: role.to_string(),
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
    let now = Utc::now().timestamp();
    
    // Check if token exists and is valid
    let token_data = {
        let tokens = REFRESH_TOKENS.read().await;
        tokens.get(&token_hash).cloned()
    };
    
    match token_data {
        Some(data) if !data.revoked && data.expires_at > now => {
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
            
            // Optionally rotate refresh token
            let new_refresh_token = generate_refresh_token();
            let new_token_hash = hash_refresh_token(&new_refresh_token);
            let new_expires_at = (Utc::now() + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS)).timestamp();
            
            {
                let mut tokens = REFRESH_TOKENS.write().await;
                // Revoke old token
                if let Some(old_data) = tokens.get_mut(&token_hash) {
                    old_data.revoked = true;
                }
                // Store new token
                tokens.insert(new_token_hash, RefreshTokenData {
                    user_id: data.user_id,
                    email: data.email,
                    role: data.role,
                    expires_at: new_expires_at,
                    revoked: false,
                });
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
/// Invalidate refresh token
pub async fn logout(
    headers: HeaderMap,
    Json(payload): Json<LogoutRequest>,
) -> impl IntoResponse {
    // Try to get refresh token from body or revoke based on access token
    if let Some(refresh_token) = payload.refresh_token {
        let token_hash = hash_refresh_token(&refresh_token);
        let mut tokens = REFRESH_TOKENS.write().await;
        if let Some(data) = tokens.get_mut(&token_hash) {
            data.revoked = true;
        }
    }
    
    // If access token provided, try to find and revoke associated refresh tokens
    // For simplicity, we just return success as access token will expire anyway
    if let Some(access_token) = payload.access_token.or_else(|| extract_bearer_token(&headers)) {
        if let Ok(claims) = verify_access_token(&access_token) {
            // Could revoke all refresh tokens for this user
            let mut tokens = REFRESH_TOKENS.write().await;
            for (_, data) in tokens.iter_mut() {
                if data.user_id == claims.sub {
                    data.revoked = true;
                }
            }
        }
    }
    
    // Logout always succeeds (idempotent)
    (StatusCode::OK, Json(LogoutResponse { success: true }))
}

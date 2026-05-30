use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Instant,
};
use uuid::Uuid;

use crate::routes::AppError;

const PROGRESS_COOKIE: &str = "gate_progress";
const UNLOCK_COOKIE: &str = "portfolio_gate";
const L1_USERNAME: &str = "yourbloo0";
const L2_USERNAME: &str = "yourbloo1";
const GATE_TOKEN_ISSUER: &str = "portfolio-gate";
const GATE_TOKEN_AUDIENCE: &str = "terminal";

#[derive(Clone)]
pub struct GateConfig {
    pub l1_answer: String,
    pub l2_answer: String,
    pub token_secret: String,
    #[allow(dead_code)]
    // Frontend-only bypass consumed by Next.js proxy.ts (X-Gate-Bypass).
    // Rust gate handlers intentionally ignore this value.
    pub bypass_secret: Option<String>,
    pub cookie_max_age_days: i64,
    pub session_ttl_hours: i64,
    pub site_url: String,
}

impl GateConfig {
    pub fn from_env() -> Self {
        let site_url = std::env::var("SITE_URL")
            .or_else(|_| std::env::var("FRONTEND_ORIGIN"))
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        Self {
            l1_answer: std::env::var("GATE_L1_ANSWER").unwrap_or_default(),
            l2_answer: std::env::var("GATE_L2_ANSWER").unwrap_or_default(),
            token_secret: std::env::var("GATE_TOKEN_SECRET").unwrap_or_default(),
            bypass_secret: std::env::var("GATE_BYPASS_SECRET")
                .ok()
                .filter(|s| !s.is_empty()),
            cookie_max_age_days: std::env::var("GATE_COOKIE_MAX_AGE_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7),
            session_ttl_hours: std::env::var("GATE_SESSION_TTL_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(24),
            site_url,
        }
    }
}

#[derive(Debug, Clone)]
struct GateSession {
    completed_levels: HashSet<u8>,
    failed_attempts: HashMap<u8, u32>,
    #[allow(dead_code)]
    created_at: Instant,
}

#[derive(Clone)]
pub struct GateState {
    config: GateConfig,
    sessions: Arc<RwLock<HashMap<String, GateSession>>>,
}

impl GateState {
    pub fn new(config: GateConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct GateTokenClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GateStatusResponse {
    pub unlocked: bool,
    pub current_level: u8,
    pub completed_levels: Vec<u8>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub level: u8,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CompleteLevel3Response {
    pub passed: bool,
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{name}=");
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix(&prefix) {
            return Some(value.to_string());
        }
    }
    None
}

fn build_set_cookie(name: &str, value: &str, max_age_secs: i64, secure: bool) -> String {
    let mut parts = vec![
        format!("{name}={value}"),
        "Path=/".to_string(),
        "HttpOnly".to_string(),
        "SameSite=Strict".to_string(),
        format!("Max-Age={max_age_secs}"),
    ];
    if secure {
        parts.push("Secure".to_string());
    }
    parts.join("; ")
}

fn cookie_secure() -> bool {
    !matches!(
        std::env::var("ENVIRONMENT").as_deref(),
        Ok("development") | Ok("test")
    )
}

fn session_id_from_headers(headers: &HeaderMap) -> String {
    extract_cookie(headers, PROGRESS_COOKIE).unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn get_or_create_session(state: &GateState, session_id: &str) -> GateSession {
    let mut sessions = state.sessions.write().expect("gate sessions lock");
    sessions
        .entry(session_id.to_string())
        .or_insert_with(|| GateSession {
            completed_levels: HashSet::new(),
            failed_attempts: HashMap::new(),
            created_at: Instant::now(),
        })
        .clone()
}

fn save_session(state: &GateState, session_id: &str, session: GateSession) {
    let mut sessions = state.sessions.write().expect("gate sessions lock");
    sessions.insert(session_id.to_string(), session);
}

fn gate_token_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[GATE_TOKEN_ISSUER]);
    validation.set_audience(&[GATE_TOKEN_AUDIENCE]);
    validation
}

fn is_unlocked(headers: &HeaderMap, config: &GateConfig) -> bool {
    let Some(token) = extract_cookie(headers, UNLOCK_COOKIE) else {
        return false;
    };
    if config.token_secret.is_empty() {
        return false;
    }

    decode::<GateTokenClaims>(
        &token,
        &DecodingKey::from_secret(config.token_secret.as_bytes()),
        &gate_token_validation(),
    )
    .is_ok()
}

fn hint_for_level(level: u8, attempts: u32) -> Option<String> {
    match (level, attempts) {
        (1, a) if a >= 6 => Some("Credentials are shown above the login form.".into()),
        (1, a) if a >= 3 => Some("Username and password are the same.".into()),
        (2, a) if a >= 10 => Some("https://overthewire.org/wargames/natas/natas3.html".into()),
        (2, a) if a >= 6 => Some("Try exploring hidden directories on this site.".into()),
        (2, a) if a >= 3 => Some("What lives under /s3cr3t/ ?".into()),
        (3, a) if a >= 6 => Some("Visit /terminal first, then follow the link.".into()),
        (3, a) if a >= 3 => Some("This page checks the Referer HTTP header.".into()),
        _ => None,
    }
}

fn expected_username(level: u8) -> Option<&'static str> {
    match level {
        1 => Some(L1_USERNAME),
        2 => Some(L2_USERNAME),
        _ => None,
    }
}

fn expected_password(config: &GateConfig, level: u8) -> &str {
    match level {
        1 => &config.l1_answer,
        2 => &config.l2_answer,
        _ => "",
    }
}

pub fn is_valid_terminal_referer(referer: &str, site_url: &str) -> bool {
    let base = site_url.trim_end_matches('/');
    let expected = format!("{base}/terminal");
    let referer_trimmed = referer.trim();
    referer_trimmed == expected
        || referer_trimmed.starts_with(&format!("{expected}/"))
        || referer_trimmed.starts_with(&format!("{expected}?"))
}

fn attach_progress_cookie(response: &mut Response, session_id: &str, config: &GateConfig) {
    let max_age = config.session_ttl_hours * 3600;
    let cookie = build_set_cookie(PROGRESS_COOKIE, session_id, max_age, cookie_secure());
    if let Ok(v) = header::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
}

fn record_login_attempt(session: &mut GateSession, level: u8, passed: bool) -> u32 {
    if passed {
        session.failed_attempts.get(&level).copied().unwrap_or(0)
    } else {
        let count = session.failed_attempts.entry(level).or_insert(0);
        *count += 1;
        *count
    }
}

#[utoipa::path(
    get,
    path = "/api/gate/status",
    tag = "Gate",
    responses(
        (status = 200, description = "Gate progress status", body = GateStatusResponse),
    )
)]
pub async fn status(
    State(state): State<GateState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let unlocked = is_unlocked(&headers, &state.config);
    let session_id = session_id_from_headers(&headers);
    let session = get_or_create_session(&state, &session_id);

    let mut completed: Vec<u8> = session.completed_levels.iter().copied().collect();
    completed.sort_unstable();

    let current_level = if unlocked || completed.contains(&3) {
        4
    } else if completed.contains(&2) {
        3
    } else if completed.contains(&1) {
        2
    } else {
        1
    };

    let mut response = Json(GateStatusResponse {
        unlocked,
        current_level,
        completed_levels: completed,
    })
    .into_response();

    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
}

#[utoipa::path(
    post,
    path = "/api/gate/login",
    tag = "Gate",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login result", body = LoginResponse),
    )
)]
pub async fn login(
    State(state): State<GateState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.level != 1 && body.level != 2 {
        return Err(AppError::BadRequest("Invalid level".into()));
    }

    let session_id = session_id_from_headers(&headers);
    let mut session = get_or_create_session(&state, &session_id);

    if body.level > 1 && !session.completed_levels.contains(&(body.level - 1)) {
        return Err(AppError::Forbidden);
    }

    let Some(expected_user) = expected_username(body.level) else {
        return Err(AppError::BadRequest("Invalid level".into()));
    };

    let expected_pass = expected_password(&state.config, body.level);
    if expected_pass.is_empty() {
        return Err(AppError::Internal(format!(
            "Gate L{} not configured",
            body.level
        )));
    }

    let username_ok = constant_time_eq(expected_user, body.username.trim());
    let password_ok = constant_time_eq(expected_pass, body.password.trim());
    let passed = username_ok && password_ok;

    let attempts = record_login_attempt(&mut session, body.level, passed);
    let hint = if passed {
        None
    } else {
        hint_for_level(body.level, attempts)
    };

    if passed {
        session.completed_levels.insert(body.level);
    }

    save_session(&state, &session_id, session);

    let next_level = if passed && body.level < 3 {
        Some(body.level + 1)
    } else {
        None
    };

    let mut response = Json(LoginResponse {
        passed,
        next_level,
        attempts: if passed { None } else { Some(attempts) },
        hint,
    })
    .into_response();

    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
}

#[utoipa::path(
    post,
    path = "/api/gate/complete/3",
    tag = "Gate",
    responses(
        (status = 200, description = "Level 3 completed", body = CompleteLevel3Response),
        (status = 403, description = "Level 2 not completed"),
    )
)]
pub async fn complete_level_3(
    State(state): State<GateState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let session_id = session_id_from_headers(&headers);
    let mut session = get_or_create_session(&state, &session_id);

    if !session.completed_levels.contains(&2) {
        return Err(AppError::Forbidden);
    }

    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Forbidden)?;
    if !is_valid_terminal_referer(referer, &state.config.site_url) {
        return Err(AppError::Forbidden);
    }

    session.completed_levels.insert(3);
    save_session(&state, &session_id, session);

    let mut response = Json(CompleteLevel3Response { passed: true }).into_response();
    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
}

#[utoipa::path(
    post,
    path = "/api/gate/unlock",
    tag = "Gate",
    responses(
        (status = 200, description = "Terminal unlocked"),
        (status = 403, description = "Levels incomplete"),
    )
)]
pub async fn unlock(
    State(state): State<GateState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let session_id = session_id_from_headers(&headers);
    let session = get_or_create_session(&state, &session_id);

    if !(session.completed_levels.contains(&1)
        && session.completed_levels.contains(&2)
        && session.completed_levels.contains(&3))
    {
        return Err(AppError::Forbidden);
    }

    if state.config.token_secret.is_empty() {
        return Err(AppError::Internal("Gate not configured".into()));
    }

    let now = Utc::now();
    let exp = now + Duration::days(state.config.cookie_max_age_days);
    let claims = GateTokenClaims {
        sub: "gate".into(),
        iss: GATE_TOKEN_ISSUER.into(),
        aud: GATE_TOKEN_AUDIENCE.into(),
        iat: now.timestamp(),
        exp: exp.timestamp(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(state.config.token_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let max_age = state.config.cookie_max_age_days * 86400;
    let unlock_cookie = build_set_cookie(UNLOCK_COOKIE, &token, max_age, cookie_secure());

    crate::metrics::record_gate_unlock();

    let mut response = Json(serde_json::json!({ "unlocked": true })).into_response();
    if let Ok(v) = header::HeaderValue::from_str(&unlock_cookie) {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
}

#[utoipa::path(
    get,
    path = "/api/gate/challenge/2/users.txt",
    tag = "Gate",
    responses(
        (status = 200, description = "users.txt for level 2"),
        (status = 403, description = "Level 1 not completed"),
    )
)]
pub async fn challenge_2_users_txt(
    State(state): State<GateState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let session_id = session_id_from_headers(&headers);
    let session = get_or_create_session(&state, &session_id);
    if !session.completed_levels.contains(&1) {
        return Err(AppError::Forbidden);
    }

    let password = &state.config.l2_answer;
    if password.is_empty() {
        return Err(AppError::Internal("Gate L2 not configured".into()));
    }

    let body = format!("{L2_USERNAME}:{password}\n");
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response();
    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    fn config() -> GateConfig {
        GateConfig {
            l1_answer: "yourbloo0".into(),
            l2_answer: "secret-l2".into(),
            token_secret: "this_is_a_very_long_gate_token_secret_123456".into(),
            bypass_secret: None,
            cookie_max_age_days: 7,
            session_ttl_hours: 24,
            site_url: "https://example.com".into(),
        }
    }

    fn headers(cookie: &str, referer: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("gate_progress={cookie}").parse().unwrap(),
        );
        if let Some(referer) = referer {
            headers.insert(header::REFERER, referer.parse().unwrap());
        }
        headers
    }

    async fn login_level(
        state: GateState,
        cookie: &str,
        level: u8,
        username: &str,
        password: &str,
    ) {
        let _ = login(
            State(state),
            headers(cookie, None),
            Json(LoginRequest {
                level,
                username: username.into(),
                password: password.into(),
            }),
        )
        .await
        .expect("login should succeed");
    }

    #[tokio::test]
    async fn complete_level_3_requires_valid_referer() {
        let state = GateState::new(config());
        let cookie = "session-1";

        login_level(state.clone(), cookie, 1, "yourbloo0", "yourbloo0").await;
        login_level(state.clone(), cookie, 2, "yourbloo1", "secret-l2").await;

        let valid = complete_level_3(
            State(state.clone()),
            headers(cookie, Some("https://example.com/terminal")),
        )
        .await
        .expect("valid referer should pass")
        .into_response();
        assert_eq!(valid.status(), StatusCode::OK);

        let invalid = complete_level_3(
            State(state.clone()),
            headers(cookie, Some("https://example.com/gate/3")),
        )
        .await;
        assert!(matches!(invalid, Err(AppError::Forbidden)));

        let missing = complete_level_3(State(state), headers(cookie, None)).await;
        assert!(matches!(missing, Err(AppError::Forbidden)));
    }

    #[tokio::test]
    async fn challenge_users_txt_requires_level_1() {
        let state = GateState::new(config());
        let cookie = "session-2";

        let before_login = challenge_2_users_txt(State(state.clone()), headers(cookie, None)).await;
        assert!(matches!(before_login, Err(AppError::Forbidden)));

        login_level(state.clone(), cookie, 1, "yourbloo0", "yourbloo0").await;

        let response = challenge_2_users_txt(State(state), headers(cookie, None))
            .await
            .expect("level 1 should unlock users.txt")
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body_text = String::from_utf8(body.to_vec()).expect("utf8");
        assert_eq!(body_text, "yourbloo1:secret-l2\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }

    #[test]
    fn hint_escalates_with_attempts() {
        assert!(hint_for_level(1, 2).is_none());
        assert!(hint_for_level(1, 3).is_some());
        assert!(hint_for_level(2, 3).is_some());
    }

    #[test]
    fn referer_validation_accepts_terminal_url() {
        assert!(is_valid_terminal_referer(
            "https://infinitedim.vercel.app/terminal",
            "https://infinitedim.vercel.app"
        ));
        assert!(is_valid_terminal_referer(
            "https://infinitedim.vercel.app/terminal/",
            "https://infinitedim.vercel.app/"
        ));
        assert!(!is_valid_terminal_referer(
            "https://infinitedim.vercel.app/gate/3",
            "https://infinitedim.vercel.app"
        ));
    }
}

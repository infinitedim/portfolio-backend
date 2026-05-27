use axum::{
    extract::State,
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Instant,
};
use uuid::Uuid;

use crate::routes::AppError;

const PROGRESS_COOKIE: &str = "gate_progress";
const UNLOCK_COOKIE: &str = "portfolio_gate";

#[derive(Clone)]
pub struct GateConfig {
    pub l1_answer: String,
    pub l2_answer: String,
    pub l3_answer: String,
    pub l2_stub_md5: Option<String>,
    pub l3_offset: usize,
    pub l3_ret_addr: String,
    pub l3_shellcode_hash: Option<String>,
    pub token_secret: String,
    pub bypass_secret: Option<String>,
    pub cookie_max_age_days: i64,
    pub session_ttl_hours: i64,
}

impl GateConfig {
    pub fn from_env() -> Self {
        Self {
            l1_answer: std::env::var("GATE_L1_ANSWER").unwrap_or_default(),
            l2_answer: std::env::var("GATE_L2_ANSWER").unwrap_or_default(),
            l3_answer: std::env::var("GATE_L3_ANSWER").unwrap_or_default(),
            l2_stub_md5: std::env::var("GATE_L2_STUB_MD5").ok().filter(|s| !s.is_empty()),
            l3_offset: std::env::var("GATE_L3_OFFSET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(528),
            l3_ret_addr: std::env::var("GATE_L3_RET_ADDR")
                .unwrap_or_else(|_| "e0d7ffff".to_string()),
            l3_shellcode_hash: std::env::var("GATE_L3_SHELLCODE_HASH")
                .ok()
                .filter(|s| !s.is_empty()),
            token_secret: std::env::var("GATE_TOKEN_SECRET").unwrap_or_default(),
            bypass_secret: std::env::var("GATE_BYPASS_SECRET").ok().filter(|s| !s.is_empty()),
            cookie_max_age_days: std::env::var("GATE_COOKIE_MAX_AGE_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7),
            session_ttl_hours: std::env::var("GATE_SESSION_TTL_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(24),
        }
    }
}

#[derive(Debug, Clone)]
struct L2Manifest {
    filename: String,
    signature: String,
}

#[derive(Debug, Clone)]
struct GateSession {
    completed_levels: HashSet<u8>,
    failed_attempts: HashMap<u8, u32>,
    l2_manifest: Option<L2Manifest>,
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
pub struct VerifyRequest {
    pub level: u8,
    pub answer: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct StubRequest {
    pub content: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StubResponse {
    pub md5: String,
    pub suggested_filename: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestRequest {
    pub filename: String,
    pub signature: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct TriggerRequest {
    pub filename: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TriggerResponse {
    pub token: String,
    pub message: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CrashRequest {
    pub input: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CrashResponse {
    pub eip_offset: usize,
    pub message: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RunRequest {
    pub payload: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RunResponse {
    pub password: String,
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

fn md5_hex(content: &str) -> String {
    format!("{:x}", md5::compute(content.as_bytes()))
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
            l2_manifest: None,
            created_at: Instant::now(),
        })
        .clone()
}

fn save_session(state: &GateState, session_id: &str, session: GateSession) {
    let mut sessions = state.sessions.write().expect("gate sessions lock");
    sessions.insert(session_id.to_string(), session);
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
        &Validation::default(),
    )
    .is_ok()
}

fn hint_for_level(level: u8, attempts: u32) -> Option<String> {
    match (level, attempts) {
        (1, a) if a >= 10 => Some("https://overthewire.org/wargames/bandit/bandit32.html".into()),
        (1, a) if a >= 6 => Some("What does $0 expand to in a shell?".into()),
        (1, a) if a >= 3 => Some("Variables in this shell are UPPERCASE.".into()),
        (2, a) if a >= 10 => Some("https://overthewire.org/wargames/natas/natas33.html".into()),
        (2, a) if a >= 6 => Some("Metadata in Phar archives can be deserialized.".into()),
        (2, a) if a >= 3 => Some("What does md5_file do with phar files?".into()),
        (3, a) if a >= 10 => Some("https://overthewire.org/wargames/behemoth/behemoth7.html".into()),
        (3, a) if a >= 6 => Some("528 bytes before the return address.".into()),
        (3, a) if a >= 3 => Some("Find where EIP becomes 0x42424242.".into()),
        _ => None,
    }
}

fn expected_answer(config: &GateConfig, level: u8) -> &str {
    match level {
        1 => &config.l1_answer,
        2 => &config.l2_answer,
        3 => &config.l3_answer,
        _ => "",
    }
}

fn attach_progress_cookie(response: &mut Response, session_id: &str, config: &GateConfig) {
    let max_age = config.session_ttl_hours * 3600;
    let cookie = build_set_cookie(PROGRESS_COOKIE, session_id, max_age, cookie_secure());
    if let Ok(v) = header::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, v);
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

    let current_level = if unlocked {
        4
    } else if completed.contains(&3) {
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
    path = "/api/gate/verify",
    tag = "Gate",
    request_body = VerifyRequest,
    responses(
        (status = 200, description = "Verification result", body = VerifyResponse),
    )
)]
pub async fn verify(
    State(state): State<GateState>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.level < 1 || body.level > 3 {
        return Err(AppError::BadRequest("Invalid level".into()));
    }

    let session_id = session_id_from_headers(&headers);
    let mut session = get_or_create_session(&state, &session_id);

    if body.level > 1 && !session.completed_levels.contains(&(body.level - 1)) {
        return Err(AppError::Forbidden);
    }

    let expected = expected_answer(&state.config, body.level);
    let passed = !expected.is_empty() && constant_time_eq(expected, body.answer.trim());

    let attempts = if passed {
        session.failed_attempts.get(&body.level).copied().unwrap_or(0)
    } else {
        let count = session.failed_attempts.entry(body.level).or_insert(0);
        *count += 1;
        *count
    };

    let hint = if passed {
        None
    } else {
        hint_for_level(body.level, attempts)
    };

    if passed {
        session.completed_levels.insert(body.level);
    }

    save_session(&state, &session_id, session.clone());

    let next_level = if passed && body.level < 3 {
        Some(body.level + 1)
    } else {
        None
    };

    let mut response = Json(VerifyResponse {
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
        iat: now.timestamp(),
        exp: exp.timestamp(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.token_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let max_age = state.config.cookie_max_age_days * 86400;
    let unlock_cookie = build_set_cookie(UNLOCK_COOKIE, &token, max_age, cookie_secure());

    let mut response = Json(serde_json::json!({ "unlocked": true })).into_response();
    if let Ok(v) = header::HeaderValue::from_str(&unlock_cookie) {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
}

pub async fn challenge_2_stub(
    State(state): State<GateState>,
    headers: HeaderMap,
    Json(body): Json<StubRequest>,
) -> Result<impl IntoResponse, AppError> {
    let session_id = session_id_from_headers(&headers);
    let session = get_or_create_session(&state, &session_id);
    if !session.completed_levels.contains(&1) {
        return Err(AppError::Forbidden);
    }

    let hash = md5_hex(&body.content);
    let mut response = Json(StubResponse {
        md5: hash,
        suggested_filename: "shell.php".into(),
    })
    .into_response();
    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
}

pub async fn challenge_2_manifest(
    State(state): State<GateState>,
    headers: HeaderMap,
    Json(body): Json<ManifestRequest>,
) -> Result<impl IntoResponse, AppError> {
    let session_id = session_id_from_headers(&headers);
    let mut session = get_or_create_session(&state, &session_id);
    if !session.completed_levels.contains(&1) {
        return Err(AppError::Forbidden);
    }

    session.l2_manifest = Some(L2Manifest {
        filename: body.filename,
        signature: body.signature,
    });
    save_session(&state, &session_id, session);

    let mut response = Json(serde_json::json!({ "stored": true })).into_response();
    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
}

pub async fn challenge_2_trigger(
    State(state): State<GateState>,
    headers: HeaderMap,
    Json(body): Json<TriggerRequest>,
) -> Result<impl IntoResponse, AppError> {
    let session_id = session_id_from_headers(&headers);
    let session = get_or_create_session(&state, &session_id);
    if !session.completed_levels.contains(&1) {
        return Err(AppError::Forbidden);
    }

    let Some(manifest) = session.l2_manifest else {
        return Err(AppError::BadRequest("Manifest not stored".into()));
    };

    if !body.filename.starts_with("phar://") {
        return Err(AppError::BadRequest("Invalid trigger path".into()));
    }

    if manifest.filename.is_empty() || manifest.signature.is_empty() {
        return Err(AppError::BadRequest("Invalid manifest".into()));
    }

    let token = state.config.l2_answer.clone();
    if token.is_empty() {
        return Err(AppError::Internal("Gate L2 not configured".into()));
    }

    let mut response = Json(TriggerResponse {
        token: token.clone(),
        message: "Congratulations! Running firmware update...".into(),
    })
    .into_response();
    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
}

pub async fn challenge_3_crash(
    State(state): State<GateState>,
    headers: HeaderMap,
    Json(body): Json<CrashRequest>,
) -> Result<impl IntoResponse, AppError> {
    let session_id = session_id_from_headers(&headers);
    let session = get_or_create_session(&state, &session_id);
    if !session.completed_levels.contains(&2) {
        return Err(AppError::Forbidden);
    }

    if body.input.len() < state.config.l3_offset + 4 {
        return Err(AppError::BadRequest("Input too short".into()));
    }

    let slice = &body.input.as_bytes()[state.config.l3_offset..state.config.l3_offset + 4];
    if slice != b"BBBB" {
        return Err(AppError::BadRequest("Pattern not found".into()));
    }

    let mut response = Json(CrashResponse {
        eip_offset: state.config.l3_offset,
        message: "Segmentation fault at 0x42424242".into(),
    })
    .into_response();
    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
}

pub async fn challenge_3_run(
    State(state): State<GateState>,
    headers: HeaderMap,
    Json(body): Json<RunRequest>,
) -> Result<impl IntoResponse, AppError> {
    let session_id = session_id_from_headers(&headers);
    let session = get_or_create_session(&state, &session_id);
    if !session.completed_levels.contains(&2) {
        return Err(AppError::Forbidden);
    }

    let payload = body.payload.as_bytes();
    let min_len = state.config.l3_offset + 4 + 200;
    if payload.len() < min_len {
        return Err(AppError::BadRequest("Payload too short".into()));
    }

    let ret_slice = &payload[state.config.l3_offset..state.config.l3_offset + 4];
    let ret_hex: String = ret_slice.iter().map(|b| format!("{b:02x}")).collect();
    if ret_hex != state.config.l3_ret_addr.to_lowercase() {
        return Err(AppError::BadRequest("Invalid return address".into()));
    }

    let nop_region = &payload[state.config.l3_offset + 4..state.config.l3_offset + 4 + 200];
    if !nop_region.iter().all(|&b| b == 0x90) {
        return Err(AppError::BadRequest("NOP sled invalid".into()));
    }

    if let Some(expected_hash) = &state.config.l3_shellcode_hash {
        let shellcode = &payload[state.config.l3_offset + 4 + 200..];
        let mut hasher = Sha256::new();
        hasher.update(shellcode);
        let hash = hex::encode(hasher.finalize());
        if hash != expected_hash.to_lowercase() {
            return Err(AppError::BadRequest("Shellcode mismatch".into()));
        }
    }

    let password = state.config.l3_answer.clone();
    if password.is_empty() {
        return Err(AppError::Internal("Gate L3 not configured".into()));
    }

    let mut response = Json(RunResponse { password }).into_response();
    attach_progress_cookie(&mut response, &session_id, &state.config);
    Ok(response)
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
    fn md5_hex_known_value() {
        assert_eq!(
            md5_hex("<?php /* gate-stub */ ?>"),
            md5_hex("<?php /* gate-stub */ ?>")
        );
    }

    #[test]
    fn hint_escalates_with_attempts() {
        assert!(hint_for_level(1, 2).is_none());
        assert!(hint_for_level(1, 3).is_some());
    }
}

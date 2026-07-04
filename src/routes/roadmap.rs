use axum::{http::StatusCode, response::IntoResponse, Json};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const ROADMAP_BASE: &str = "https://roadmap.sh/api";
const CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const STALE_TTL: Duration = Duration::from_secs(15 * 60);

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("failed to build roadmap HTTP client")
});

struct CacheEntry {
    data: Value,
    fetched_at: Instant,
}

struct RoadmapState {
    auth_token: Option<String>,
    cache: std::collections::HashMap<String, CacheEntry>,
}

impl RoadmapState {
    fn cache_get(&self, key: &str) -> Option<(&Value, bool)> {
        let entry = self.cache.get(key)?;
        let age = entry.fetched_at.elapsed();
        if age < STALE_TTL {
            let is_fresh = age < CACHE_TTL;
            Some((&entry.data, is_fresh))
        } else {
            None
        }
    }

    fn cache_set(&mut self, key: String, data: Value) {
        self.cache.insert(
            key,
            CacheEntry {
                data,
                fetched_at: Instant::now(),
            },
        );
    }
}

static STATE: Lazy<Arc<Mutex<RoadmapState>>> = Lazy::new(|| {
    Arc::new(Mutex::new(RoadmapState {
        auth_token: None,
        cache: std::collections::HashMap::new(),
    }))
});

fn credentials_from_env() -> Option<(String, String)> {
    let email = std::env::var("ROADMAP_EMAIL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())?;
    let password = std::env::var("ROADMAP_PASSWORD")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())?;
    Some((email, password))
}

#[derive(Serialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
}

async fn login() -> Result<String, String> {
    let Some((email, password)) = credentials_from_env() else {
        return Err("ROADMAP_EMAIL/PASSWORD not configured".to_string());
    };

    let response = HTTP_CLIENT
        .post(format!("{}/v1-login", ROADMAP_BASE))
        .json(&LoginRequest { email, password })
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("login request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("login rejected: {}", response.status()));
    }

    let body: LoginResponse = response
        .json()
        .await
        .map_err(|e| format!("login parse failed: {e}"))?;
    Ok(body.token)
}

async fn get_token() -> Result<String, String> {
    let mut state = STATE.lock().await;
    if let Some(token) = state.auth_token.clone() {
        return Ok(token);
    }
    let token = login().await?;
    state.auth_token = Some(token.clone());
    Ok(token)
}

async fn invalidate_token() {
    let mut state = STATE.lock().await;
    state.auth_token = None;
}

async fn fetch_upstream(path: &str) -> Result<Value, String> {
    let token = get_token().await?;
    let url = format!("{}/{}", ROADMAP_BASE, path);

    let response = HTTP_CLIENT
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("upstream request failed: {e}"))?;

    if response.status() == StatusCode::UNAUTHORIZED {
        invalidate_token().await;
        let token = get_token().await?;
        let response = HTTP_CLIENT
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("retry request failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!("upstream error after retry: {}", response.status()));
        }
        return response
            .json()
            .await
            .map_err(|e| format!("parse failed: {e}"));
    }

    if !response.status().is_success() {
        return Err(format!("upstream error: {}", response.status()));
    }

    response
        .json()
        .await
        .map_err(|e| format!("parse failed: {e}"))
}

async fn cached_fetch(path: &str) -> Result<Value, (StatusCode, Json<Value>)> {
    {
        let state = STATE.lock().await;
        if let Some((data, is_fresh)) = state.cache_get(path) {
            let data = data.clone();
            if !is_fresh {
                let path_owned = path.to_string();
                tokio::spawn(async move {
                    if let Ok(fresh) = fetch_upstream(&path_owned).await {
                        let mut state = STATE.lock().await;
                        state.cache_set(path_owned, fresh);
                    }
                });
            }
            return Ok(data);
        }
    }

    match fetch_upstream(path).await {
        Ok(data) => {
            let mut state = STATE.lock().await;
            state.cache_set(path.to_string(), data.clone());
            Ok(data)
        }
        Err(e) => {
            tracing::error!(path = %path, error = %e, "roadmap fetch failed");
            Err((
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e })),
            ))
        }
    }
}

/// GET /api/roadmap/streak
/// Proxies `roadmap.sh/api/v1-streak`
#[utoipa::path(
    get,
    path = "/api/roadmap/streak",
    tag = "Roadmap",
    responses((status = 200, description = "Roadmap streak data"))
)]
pub async fn get_streak() -> impl IntoResponse {
    match cached_fetch("v1-streak").await {
        Ok(data) => (StatusCode::OK, Json(data)).into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/roadmap/dashboard
/// Proxies `roadmap.sh/api/v1-user-dashboard`
#[utoipa::path(
    get,
    path = "/api/roadmap/dashboard",
    tag = "Roadmap",
    responses((status = 200, description = "Roadmap dashboard data"))
)]
pub async fn get_dashboard() -> impl IntoResponse {
    match cached_fetch("v1-user-dashboard").await {
        Ok(data) => (StatusCode::OK, Json(data)).into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/roadmap/teams
/// Proxies `roadmap.sh/api/v1-get-user-teams`
#[utoipa::path(
    get,
    path = "/api/roadmap/teams",
    tag = "Roadmap",
    responses((status = 200, description = "Roadmap teams data"))
)]
pub async fn get_teams() -> impl IntoResponse {
    match cached_fetch("v1-get-user-teams").await {
        Ok(data) => (StatusCode::OK, Json(data)).into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/roadmap/favourites
/// Proxies `roadmap.sh/api/v1-list-favorite-roadmaps`
#[utoipa::path(
    get,
    path = "/api/roadmap/favourites",
    tag = "Roadmap",
    responses((status = 200, description = "Favourite roadmaps"))
)]
pub async fn get_favourites() -> impl IntoResponse {
    match cached_fetch("v1-list-favorite-roadmaps").await {
        Ok(data) => (StatusCode::OK, Json(data)).into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/roadmap/progress/{techstack}
/// Proxies `roadmap.sh/api/v1-get-user-resource-progress`
#[utoipa::path(
    get,
    path = "/api/roadmap/progress/{techstack}",
    tag = "Roadmap",
    params(
        ("techstack" = String, Path, description = "The technology stack/roadmap name")
    ),
    responses(
        (status = 200, description = "Roadmap progress data"),
        (status = 502, description = "Upstream error or unreachable")
    )
)]
pub async fn get_resource_progress(
    axum::extract::Path(techstack): axum::extract::Path<String>,
) -> impl IntoResponse {
    let path = format!(
        "v1-get-user-resource-progress?resourceId={}&resourceType=roadmap",
        techstack
    );
    match cached_fetch(&path).await {
        Ok(data) => (StatusCode::OK, Json(data)).into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

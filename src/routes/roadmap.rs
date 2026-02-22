use axum::{http::StatusCode, response::IntoResponse, Json};
use once_cell::sync::Lazy;
use serde_json::Value;

const ROADMAP_BASE: &str = "https://roadmap.sh/api";

static ROADMAP_TOKEN: Lazy<String> =
    Lazy::new(|| std::env::var("ROADMAP_AUTH_TOKEN").unwrap_or_default());

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(reqwest::Client::new);

async fn fetch(path: &str) -> Result<Value, (StatusCode, Json<Value>)> {
    let url = format!("{}/{}", ROADMAP_BASE, path);

    let response = HTTP_CLIENT
        .get(&url)
        .header("Authorization", ROADMAP_TOKEN.as_str())
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            tracing::error!(path = %path, error = %e, "roadmap upstream request failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "upstream request failed" })),
            )
        })?;

    let status = response.status();
    if !status.is_success() {
        tracing::warn!(path = %path, status = %status, "roadmap upstream returned error");
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(serde_json::json!({
                "error": "roadmap upstream error",
                "status": status.as_u16()
            })),
        ));
    }

    response.json::<Value>().await.map_err(|e| {
        tracing::error!(path = %path, error = %e, "failed to parse roadmap response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "failed to parse upstream response" })),
        )
    })
}

/// GET /api/roadmap/streak
/// Proxies `roadmap.sh/api/v-streak`
pub async fn get_streak() -> impl IntoResponse {
    match fetch("v-streak").await {
        Ok(data) => (StatusCode::OK, Json(data)).into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/roadmap/dashboard
/// Proxies `roadmap.sh/api/v1/user-dashboard`
pub async fn get_dashboard() -> impl IntoResponse {
    match fetch("v1/user-dashboard").await {
        Ok(data) => (StatusCode::OK, Json(data)).into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/roadmap/teams
/// Proxies `roadmap.sh/api/v1/get-user-teams`
pub async fn get_teams() -> impl IntoResponse {
    match fetch("v1/get-user-teams").await {
        Ok(data) => (StatusCode::OK, Json(data)).into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/roadmap/favourites
/// Proxies `roadmap.sh/api/v1/list-favourite-roadmaps`
pub async fn get_favourites() -> impl IntoResponse {
    match fetch("v1/list-favourite-roadmaps").await {
        Ok(data) => (StatusCode::OK, Json(data)).into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

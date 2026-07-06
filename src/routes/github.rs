//! GitHub API proxy with in-memory caching and optional `GH_TOKEN` auth.

use axum::{extract::Path, http::StatusCode, response::IntoResponse, Json};
use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use utoipa::ToSchema;

const GITHUB_API: &str = "https://api.github.com";
const CACHE_FRESH_TTL: Duration = Duration::from_secs(15 * 60);
const CACHE_STALE_TTL: Duration = Duration::from_secs(60 * 60);

static GH_TOKEN: Lazy<String> = Lazy::new(|| std::env::var("GH_TOKEN").unwrap_or_default());

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(reqwest::Client::new);

struct CacheEntry {
    body: serde_json::Value,
    fetched_at: Instant,
}

static CACHE: Lazy<Mutex<HashMap<String, CacheEntry>>> = Lazy::new(|| Mutex::new(HashMap::new()));

enum CacheHit {
    Fresh(serde_json::Value),
    Stale(serde_json::Value),
}

fn cache_get(key: &str) -> Option<CacheHit> {
    let cache = CACHE.lock().expect("github cache poisoned");
    let entry = cache.get(key)?;
    let age = entry.fetched_at.elapsed();
    if age < CACHE_FRESH_TTL {
        Some(CacheHit::Fresh(entry.body.clone()))
    } else if age < CACHE_STALE_TTL {
        Some(CacheHit::Stale(entry.body.clone()))
    } else {
        None
    }
}

fn cache_set(key: impl Into<String>, body: serde_json::Value) {
    let mut cache = CACHE.lock().expect("github cache poisoned");
    cache.insert(
        key.into(),
        CacheEntry {
            body,
            fetched_at: Instant::now(),
        },
    );
}

fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 39
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

async fn github_fetch_raw(path: &str) -> Result<serde_json::Value, String> {
    let url = format!("{GITHUB_API}{path}");
    let mut request = HTTP_CLIENT
        .get(&url)
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "portfolio-backend");

    if !GH_TOKEN.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", GH_TOKEN.as_str()));
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("upstream request failed: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("upstream error: {status}"));
    }

    response
        .json()
        .await
        .map_err(|e| format!("parse failed: {e}"))
}

async fn github_get(
    path: &str,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    match cache_get(path) {
        Some(CacheHit::Fresh(data)) => return Ok(data),
        Some(CacheHit::Stale(data)) => {
            let path_owned = path.to_string();
            tokio::spawn(async move {
                if let Ok(fresh) = github_fetch_raw(&path_owned).await {
                    cache_set(path_owned, fresh);
                }
            });
            return Ok(data);
        }
        None => {}
    }

    let body = github_fetch_raw(path).await.map_err(|e| {
        tracing::error!(path = %path, error = %e, "github fetch failed");
        if e.contains("404") {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "GitHub resource not found" })),
            )
        } else {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e })),
            )
        }
    })?;

    cache_set(path, body.clone());
    Ok(body)
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubUserResponse {
    pub login: String,
    pub name: Option<String>,
    pub avatar_url: String,
    pub bio: Option<String>,
    pub public_repos: u64,
    pub followers: u64,
    pub following: u64,
    pub html_url: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubRepoSummary {
    pub name: String,
    pub description: Option<String>,
    pub stars: u64,
    pub forks: u64,
    pub language: Option<String>,
    pub updated_at: String,
    pub html_url: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubStatsResponse {
    pub profile: GitHubProfileStats,
    pub repositories: Vec<GitHubRepoSummary>,
    pub total_stars: u64,
    pub languages: HashMap<String, u64>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubProfileStats {
    pub followers: u64,
    pub following: u64,
    pub public_repos: u64,
}

/// GET /api/github/user/:username
#[utoipa::path(
    get,
    path = "/api/github/user/{username}",
    tag = "GitHub",
    params(("username" = String, Path, description = "GitHub username")),
    responses(
        (status = 200, description = "GitHub user profile", body = GitHubUserResponse),
        (status = 400, description = "Invalid username", body = crate::routes::ErrorResponse),
        (status = 404, description = "User not found", body = crate::routes::ErrorResponse),
    )
)]
pub async fn get_user(Path(username): Path<String>) -> impl IntoResponse {
    let username = username.trim();
    if !is_valid_username(username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid username" })),
        )
            .into_response();
    }

    match github_get(&format!("/users/{username}")).await {
        Ok(raw) => {
            let user = GitHubUserResponse {
                login: raw["login"].as_str().unwrap_or(username).to_string(),
                name: raw["name"].as_str().map(str::to_string),
                avatar_url: raw["avatar_url"].as_str().unwrap_or_default().to_string(),
                bio: raw["bio"].as_str().map(str::to_string),
                public_repos: raw["public_repos"].as_u64().unwrap_or(0),
                followers: raw["followers"].as_u64().unwrap_or(0),
                following: raw["following"].as_u64().unwrap_or(0),
                html_url: raw["html_url"].as_str().unwrap_or_default().to_string(),
                created_at: raw["created_at"].as_str().unwrap_or_default().to_string(),
            };
            (StatusCode::OK, Json(user)).into_response()
        }
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/github/stats/:username
#[utoipa::path(
    get,
    path = "/api/github/stats/{username}",
    tag = "GitHub",
    params(("username" = String, Path, description = "GitHub username")),
    responses(
        (status = 200, description = "Aggregated GitHub stats", body = GitHubStatsResponse),
        (status = 400, description = "Invalid username", body = crate::routes::ErrorResponse),
        (status = 404, description = "User not found", body = crate::routes::ErrorResponse),
    )
)]
pub async fn get_stats(Path(username): Path<String>) -> impl IntoResponse {
    let username = username.trim();
    if !is_valid_username(username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid username" })),
        )
            .into_response();
    }

    let user_path = format!("/users/{username}");
    let repos_path = format!("/users/{username}/repos?sort=updated&per_page=100");

    let user = match github_get(&user_path).await {
        Ok(data) => data,
        Err((status, json)) => return (status, json).into_response(),
    };

    let repos_raw = match github_get(&repos_path).await {
        Ok(data) => data,
        Err((status, json)) => return (status, json).into_response(),
    };

    let repos_array = repos_raw.as_array().cloned().unwrap_or_default();
    let mut repositories = Vec::with_capacity(repos_array.len());
    let mut total_stars = 0u64;
    let mut languages: HashMap<String, u64> = HashMap::new();

    for repo in repos_array {
        let stars = repo["stargazers_count"].as_u64().unwrap_or(0);
        total_stars += stars;

        if let Some(lang) = repo["language"].as_str() {
            *languages.entry(lang.to_string()).or_insert(0) += 1;
        }

        repositories.push(GitHubRepoSummary {
            name: repo["name"].as_str().unwrap_or_default().to_string(),
            description: repo["description"].as_str().map(str::to_string),
            stars,
            forks: repo["forks_count"].as_u64().unwrap_or(0),
            language: repo["language"].as_str().map(str::to_string),
            updated_at: repo["updated_at"].as_str().unwrap_or_default().to_string(),
            html_url: repo["html_url"].as_str().unwrap_or_default().to_string(),
        });
    }

    let stats = GitHubStatsResponse {
        profile: GitHubProfileStats {
            followers: user["followers"].as_u64().unwrap_or(0),
            following: user["following"].as_u64().unwrap_or(0),
            public_repos: user["public_repos"].as_u64().unwrap_or(0),
        },
        repositories,
        total_stars,
        languages,
    };

    (StatusCode::OK, Json(stats)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_usernames_accept_alphanumeric_dash_underscore() {
        assert!(is_valid_username("infinitedim"));
        assert!(is_valid_username("user-name_1"));
    }

    #[test]
    fn invalid_usernames_rejected() {
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("bad/user"));
        assert!(!is_valid_username("has space"));
        assert!(!is_valid_username(&"x".repeat(40)));
    }

    #[tokio::test]
    async fn get_user_rejects_invalid_username_without_network() {
        let response = get_user(Path("bad/user".into())).await.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_stats_rejects_invalid_username_without_network() {
        let response = get_stats(Path("".into())).await.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_user_cached_happy_path() {
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert(
                "/users/infinitedim".to_string(),
                CacheEntry {
                    body: serde_json::json!({
                        "login": "infinitedim",
                        "name": "Dimas Saputra",
                        "avatar_url": "https://avatar.url",
                        "bio": "Developer",
                        "public_repos": 10,
                        "followers": 5,
                        "following": 5,
                        "html_url": "https://github.com/infinitedim",
                        "created_at": "2024-01-01T00:00:00Z"
                    }),
                    fetched_at: Instant::now(),
                },
            );
        }

        let response = get_user(Path("infinitedim".into())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(val["login"], "infinitedim");
        assert_eq!(val["name"], "Dimas Saputra");
    }

    #[tokio::test]
    async fn get_stats_cached_happy_path() {
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert(
                "/users/infinitedim".to_string(),
                CacheEntry {
                    body: serde_json::json!({
                        "followers": 5,
                        "following": 5,
                        "public_repos": 10
                    }),
                    fetched_at: Instant::now(),
                },
            );
            cache.insert(
                "/users/infinitedim/repos?sort=updated&per_page=100".to_string(),
                CacheEntry {
                    body: serde_json::json!([
                        {
                            "name": "repo1",
                            "description": "desc1",
                            "stargazers_count": 2,
                            "forks_count": 1,
                            "language": "Rust",
                            "updated_at": "2024-01-02T00:00:00Z",
                            "html_url": "https://github.com/infinitedim/repo1"
                        }
                    ]),
                    fetched_at: Instant::now(),
                },
            );
        }

        let response = get_stats(Path("infinitedim".into())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(val["totalStars"], 2);
        assert_eq!(val["repositories"][0]["name"], "repo1");
    }
}

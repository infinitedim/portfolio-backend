use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
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

fn is_valid_repo_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

async fn github_fetch_raw(path: &str) -> Result<serde_json::Value, String> {
    let url = format!("{GITHUB_API}{path}");
    let has_token = !GH_TOKEN.is_empty();

    let mut request = HTTP_CLIENT
        .get(&url)
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "portfolio-backend");

    if has_token {
        request = request.header("Authorization", format!("Bearer {}", GH_TOKEN.as_str()));
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("upstream request failed: {e}"))?;

    let status = response.status();

    // If 401 Unauthorized occurred and a token was sent, retry unauthenticated for public repos
    if status == reqwest::StatusCode::UNAUTHORIZED && has_token {
        tracing::warn!(
            path = %path,
            "GH_TOKEN returned 401 Unauthorized; retrying unauthenticated for public repo"
        );
        let unauth_response = HTTP_CLIENT
            .get(&url)
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "portfolio-backend")
            .send()
            .await
            .map_err(|e| format!("upstream unauthenticated retry failed: {e}"))?;

        let unauth_status = unauth_response.status();
        if !unauth_status.is_success() {
            return Err(format!("upstream error: {unauth_status}"));
        }

        return unauth_response
            .json()
            .await
            .map_err(|e| format!("parse failed: {e}"));
    }

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

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CommitQuery {
    pub sha: Option<String>,
    pub per_page: Option<u32>,
    pub page: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct GitHubCommitParent {
    pub sha: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubCommitSummary {
    pub sha: String,
    pub short_sha: String,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
    pub author_date: String,
    pub author_avatar: Option<String>,
    pub author_login: Option<String>,
    pub author_url: Option<String>,
    pub html_url: String,
    pub status_state: Option<String>,
    pub parents: Vec<GitHubCommitParent>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubCommitStats {
    pub additions: u32,
    pub deletions: u32,
    pub total: u32,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubCommitFile {
    pub filename: String,
    pub status: String,
    pub additions: u32,
    pub deletions: u32,
    pub changes: u32,
    pub patch: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubCommitDetail {
    pub sha: String,
    pub short_sha: String,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
    pub author_date: String,
    pub author_avatar: Option<String>,
    pub author_login: Option<String>,
    pub author_url: Option<String>,
    pub html_url: String,
    pub status_state: Option<String>,
    pub parents: Vec<GitHubCommitParent>,
    pub stats: Option<GitHubCommitStats>,
    pub files: Option<Vec<GitHubCommitFile>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubBranchResponse {
    pub name: String,
    pub commit_sha: String,
    pub protected: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubCheckApp {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubCheckRun {
    pub id: u64,
    pub name: String,
    pub head_sha: String,
    pub status: String,
    pub conclusion: Option<String>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub html_url: String,
    pub app: GitHubCheckApp,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitHubCheckRunsResponse {
    pub total_count: u32,
    pub combined_state: String,
    pub check_runs: Vec<GitHubCheckRun>,
}

#[derive(Debug, Deserialize)]
pub struct CheckRunsQueryParams {
    pub force: Option<bool>,
}

async fn get_commit_combined_status(owner: &str, repo: &str, ref_id: &str) -> String {
    let path = format!("/repos/{owner}/{repo}/commits/{ref_id}/check-runs");
    match github_get(&path).await {
        Ok(raw) => {
            let total_count = raw["total_count"].as_u64().unwrap_or(0) as u32;
            if total_count == 0 {
                return "unconfigured".to_string();
            }

            let check_runs = match raw["check_runs"].as_array() {
                Some(arr) => arr,
                None => return "unconfigured".to_string(),
            };

            if check_runs.is_empty() {
                return "unconfigured".to_string();
            }

            // Check if any check run has failed or timed out
            let has_failure = check_runs.iter().any(|item| {
                let c = item["conclusion"].as_str().unwrap_or_default();
                c == "failure" || c == "timed_out" || c == "action_required"
            });
            if has_failure {
                return "failure".to_string();
            }

            // Check if ANY check run is still queued or in progress or missing conclusion
            let is_running = check_runs.iter().any(|item| {
                let s = item["status"].as_str().unwrap_or_default();
                s == "in_progress"
                    || s == "queued"
                    || item.get("conclusion").is_none_or(|c| c.is_null())
            });
            if is_running {
                return "running".to_string();
            }

            // Check if all check runs were cancelled
            let all_cancelled = check_runs
                .iter()
                .all(|item| item["conclusion"].as_str().unwrap_or_default() == "cancelled");
            if all_cancelled {
                return "cancelled".to_string();
            }

            "success".to_string()
        }
        Err(_) => "unconfigured".to_string(),
    }
}

/// GET /api/github/repos/:owner/:repo/commits
#[utoipa::path(
    get,
    path = "/api/github/repos/{owner}/{repo}/commits",
    tag = "GitHub",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        CommitQuery
    ),
    responses(
        (status = 200, description = "List of repository commits", body = [GitHubCommitSummary]),
        (status = 400, description = "Invalid owner or repo name", body = crate::routes::ErrorResponse),
        (status = 404, description = "Repository not found", body = crate::routes::ErrorResponse),
    )
)]
pub async fn get_repo_commits(
    Path((owner, repo)): Path<(String, String)>,
    Query(params): Query<CommitQuery>,
) -> impl IntoResponse {
    let owner = owner.trim();
    let repo = repo.trim();
    if !is_valid_username(owner) || !is_valid_repo_identifier(repo) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid owner or repository name" })),
        )
            .into_response();
    }

    let per_page = params.per_page.unwrap_or(20).min(100);
    let page = params.page.unwrap_or(1);

    let (path, is_compare) = if let Some(ref sha) = params.sha {
        if sha.contains("...")
            && sha
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/')
        {
            (format!("/repos/{owner}/{repo}/compare/{sha}"), true)
        } else if !sha.is_empty()
            && sha
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/')
        {
            (
                format!("/repos/{owner}/{repo}/commits?per_page={per_page}&page={page}&sha={sha}"),
                false,
            )
        } else {
            (
                format!("/repos/{owner}/{repo}/commits?per_page={per_page}&page={page}"),
                false,
            )
        }
    } else {
        (
            format!("/repos/{owner}/{repo}/commits?per_page={per_page}&page={page}"),
            false,
        )
    };

    match github_get(&path).await {
        Ok(raw) => {
            let items_option = if is_compare {
                raw["commits"].as_array().cloned()
            } else {
                raw.as_array().cloned()
            };

            let items = items_option.unwrap_or_default();
            let mut summaries = Vec::with_capacity(items.len());

            for item in items {
                let sha = item["sha"].as_str().unwrap_or_default().to_string();
                let short_sha = if sha.len() >= 7 {
                    sha[..7].to_string()
                } else {
                    sha.clone()
                };
                let message = item["commit"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let author_name = item["commit"]["author"]["name"]
                    .as_str()
                    .unwrap_or("Unknown")
                    .to_string();
                let author_email = item["commit"]["author"]["email"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let author_date = item["commit"]["author"]["date"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let author_avatar = item["author"]["avatar_url"].as_str().map(str::to_string);
                let author_login = item["author"]["login"].as_str().map(str::to_string);
                let author_url = item["author"]["html_url"].as_str().map(str::to_string);
                let html_url = item["html_url"].as_str().unwrap_or_default().to_string();

                let status_state = Some(get_commit_combined_status(owner, repo, &sha).await);

                let parents = item["parents"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|p| {
                                Some(GitHubCommitParent {
                                    sha: p["sha"].as_str()?.to_string(),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                summaries.push(GitHubCommitSummary {
                    sha,
                    short_sha,
                    message,
                    author_name,
                    author_email,
                    author_date,
                    author_avatar,
                    author_login,
                    author_url,
                    html_url,
                    status_state,
                    parents,
                });
            }

            (StatusCode::OK, Json(summaries)).into_response()
        }
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/github/repos/:owner/:repo/commits/:ref_id
#[utoipa::path(
    get,
    path = "/api/github/repos/{owner}/{repo}/commits/{ref_id}",
    tag = "GitHub",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ref_id" = String, Path, description = "Commit SHA or ref"),
    ),
    responses(
        (status = 200, description = "Detailed commit information", body = GitHubCommitDetail),
        (status = 400, description = "Invalid parameters", body = crate::routes::ErrorResponse),
        (status = 404, description = "Commit not found", body = crate::routes::ErrorResponse),
    )
)]
pub async fn get_commit_detail(
    Path((owner, repo, ref_id)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let owner = owner.trim();
    let repo = repo.trim();
    let ref_id = ref_id.trim();

    if !is_valid_username(owner)
        || !is_valid_repo_identifier(repo)
        || !is_valid_repo_identifier(ref_id)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid owner, repo, or ref" })),
        )
            .into_response();
    }

    let path = format!("/repos/{owner}/{repo}/commits/{ref_id}");
    match github_get(&path).await {
        Ok(raw) => {
            let sha = raw["sha"].as_str().unwrap_or_default().to_string();
            let short_sha = if sha.len() >= 7 {
                sha[..7].to_string()
            } else {
                sha.clone()
            };
            let message = raw["commit"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let author_name = raw["commit"]["author"]["name"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string();
            let author_email = raw["commit"]["author"]["email"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let author_date = raw["commit"]["author"]["date"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let author_avatar = raw["author"]["avatar_url"].as_str().map(str::to_string);
            let author_login = raw["author"]["login"].as_str().map(str::to_string);
            let author_url = raw["author"]["html_url"].as_str().map(str::to_string);
            let html_url = raw["html_url"].as_str().unwrap_or_default().to_string();

            let status_state = raw
                .get("status")
                .and_then(|s| s["state"].as_str())
                .map(str::to_string)
                .or_else(|| Some("success".to_string()));

            let stats = raw.get("stats").map(|s| GitHubCommitStats {
                additions: s["additions"].as_u64().unwrap_or(0) as u32,
                deletions: s["deletions"].as_u64().unwrap_or(0) as u32,
                total: s["total"].as_u64().unwrap_or(0) as u32,
            });

            let files = raw.get("files").and_then(|f| f.as_array()).map(|arr| {
                arr.iter()
                    .map(|f| GitHubCommitFile {
                        filename: f["filename"].as_str().unwrap_or_default().to_string(),
                        status: f["status"].as_str().unwrap_or_default().to_string(),
                        additions: f["additions"].as_u64().unwrap_or(0) as u32,
                        deletions: f["deletions"].as_u64().unwrap_or(0) as u32,
                        changes: f["changes"].as_u64().unwrap_or(0) as u32,
                        patch: f["patch"].as_str().map(str::to_string),
                    })
                    .collect()
            });

            let parents = raw["parents"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|p| {
                            Some(GitHubCommitParent {
                                sha: p["sha"].as_str()?.to_string(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            let detail = GitHubCommitDetail {
                sha,
                short_sha,
                message,
                author_name,
                author_email,
                author_date,
                author_avatar,
                author_login,
                author_url,
                html_url,
                status_state,
                parents,
                stats,
                files,
            };

            (StatusCode::OK, Json(detail)).into_response()
        }
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/github/repos/:owner/:repo/commits/:ref_id/check-runs
#[utoipa::path(
    get,
    path = "/api/github/repos/{owner}/{repo}/commits/{ref_id}/check-runs",
    tag = "GitHub",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("ref_id" = String, Path, description = "Commit SHA or ref"),
        ("force" = Option<bool>, Query, description = "Bypass cache if true and cache age >= 10s"),
    ),
    responses(
        (status = 200, description = "Commit check runs and status", body = GitHubCheckRunsResponse),
        (status = 400, description = "Invalid parameters", body = crate::routes::ErrorResponse),
        (status = 404, description = "Commit not found", body = crate::routes::ErrorResponse),
    )
)]
pub async fn get_commit_check_runs(
    Path((owner, repo, ref_id)): Path<(String, String, String)>,
    Query(params): Query<CheckRunsQueryParams>,
) -> impl IntoResponse {
    let owner = owner.trim();
    let repo = repo.trim();
    let ref_id = ref_id.trim();

    if !is_valid_username(owner)
        || !is_valid_repo_identifier(repo)
        || !is_valid_repo_identifier(ref_id)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid owner, repo, or ref" })),
        )
            .into_response();
    }

    let path = format!("/repos/{owner}/{repo}/commits/{ref_id}/check-runs");

    // Check if force reload is requested
    let force_reload = params.force.unwrap_or(false);
    if force_reload {
        let cache_key = path.clone();
        let mut cache = CACHE.lock().expect("github cache poisoned");
        if let Some(entry) = cache.get(&cache_key) {
            if entry.fetched_at.elapsed() >= Duration::from_secs(10) {
                cache.remove(&cache_key);
            }
        }
    }

    match github_get(&path).await {
        Ok(raw) => {
            let total_count = raw["total_count"].as_u64().unwrap_or(0) as u32;
            let check_runs: Vec<GitHubCheckRun> = raw["check_runs"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .map(|item| GitHubCheckRun {
                            id: item["id"].as_u64().unwrap_or(0),
                            name: item["name"].as_str().unwrap_or_default().to_string(),
                            head_sha: item["head_sha"].as_str().unwrap_or_default().to_string(),
                            status: item["status"].as_str().unwrap_or_default().to_string(),
                            conclusion: item["conclusion"].as_str().map(str::to_string),
                            started_at: item["started_at"].as_str().unwrap_or_default().to_string(),
                            completed_at: item["completed_at"].as_str().map(str::to_string),
                            html_url: item["html_url"].as_str().unwrap_or_default().to_string(),
                            app: GitHubCheckApp {
                                name: item["app"]["name"]
                                    .as_str()
                                    .unwrap_or("GitHub Actions")
                                    .to_string(),
                            },
                        })
                        .collect()
                })
                .unwrap_or_default();

            let combined_state = if total_count == 0 {
                "unconfigured".to_string()
            } else if check_runs.iter().any(|c| {
                c.conclusion == Some("failure".to_string())
                    || c.conclusion == Some("timed_out".to_string())
            }) {
                "failure".to_string()
            } else if check_runs
                .iter()
                .any(|c| c.status == "in_progress" || c.status == "queued")
            {
                "running".to_string()
            } else if check_runs
                .iter()
                .all(|c| c.conclusion == Some("cancelled".to_string()))
            {
                "cancelled".to_string()
            } else {
                "success".to_string()
            };

            let response = GitHubCheckRunsResponse {
                total_count,
                combined_state,
                check_runs,
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        Err((status, json)) => (status, json).into_response(),
    }
}

/// GET /api/github/repos/:owner/:repo/branches
#[utoipa::path(
    get,
    path = "/api/github/repos/{owner}/{repo}/branches",
    tag = "GitHub",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "List of repository branches", body = [GitHubBranchResponse]),
        (status = 400, description = "Invalid owner or repo", body = crate::routes::ErrorResponse),
        (status = 404, description = "Repository not found", body = crate::routes::ErrorResponse),
    )
)]
pub async fn get_repo_branches(Path((owner, repo)): Path<(String, String)>) -> impl IntoResponse {
    let owner = owner.trim();
    let repo = repo.trim();

    if !is_valid_username(owner) || !is_valid_repo_identifier(repo) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid owner or repository name" })),
        )
            .into_response();
    }

    let path = format!("/repos/{owner}/{repo}/branches?per_page=100");
    match github_get(&path).await {
        Ok(raw) => {
            let items = raw.as_array().cloned().unwrap_or_default();
            let branches: Vec<GitHubBranchResponse> = items
                .iter()
                .map(|b| GitHubBranchResponse {
                    name: b["name"].as_str().unwrap_or_default().to_string(),
                    commit_sha: b["commit"]["sha"].as_str().unwrap_or_default().to_string(),
                    protected: b["protected"].as_bool().unwrap_or(false),
                })
                .collect();

            (StatusCode::OK, Json(branches)).into_response()
        }
        Err((status, json)) => (status, json).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_repo_identifiers_accept_valid_characters() {
        assert!(is_valid_repo_identifier("portfolio-backend"));
        assert!(is_valid_repo_identifier("medmind.app_v1"));
        assert!(!is_valid_repo_identifier(""));
        assert!(!is_valid_repo_identifier("bad repo name"));
        assert!(!is_valid_repo_identifier("bad/path"));
    }

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
                "/users/user-cached-test".to_string(),
                CacheEntry {
                    body: serde_json::json!({
                        "login": "user-cached-test",
                        "name": "Dimas Saputra",
                        "avatar_url": "https://avatar.url",
                        "bio": "Developer",
                        "public_repos": 10,
                        "followers": 5,
                        "following": 5,
                        "html_url": "https://github.com/user-cached-test",
                        "created_at": "2024-01-01T00:00:00Z"
                    }),
                    fetched_at: Instant::now(),
                },
            );
        }

        let response = get_user(Path("user-cached-test".into()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(val["login"], "user-cached-test");
        assert_eq!(val["name"], "Dimas Saputra");
    }

    #[tokio::test]
    async fn get_stats_cached_happy_path() {
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert(
                "/users/stats-cached-test".to_string(),
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
                "/users/stats-cached-test/repos?sort=updated&per_page=100".to_string(),
                CacheEntry {
                    body: serde_json::json!([
                        {
                            "name": "repo1",
                            "description": "desc1",
                            "stargazers_count": 2,
                            "forks_count": 1,
                            "language": "Rust",
                            "updated_at": "2024-01-02T00:00:00Z",
                            "html_url": "https://github.com/stats-cached-test/repo1"
                        }
                    ]),
                    fetched_at: Instant::now(),
                },
            );
        }

        let response = get_stats(Path("stats-cached-test".into()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(val["totalStars"], 2);
        assert_eq!(val["repositories"][0]["name"], "repo1");
    }

    #[tokio::test]
    async fn test_github_stale_cache_hit() {
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert(
                "/users/stale-cached-test".to_string(),
                CacheEntry {
                    body: serde_json::json!({
                        "login": "stale-cached-test",
                        "name": "Dimas Saputra",
                        "avatar_url": "https://avatar.url",
                        "bio": "Developer",
                        "public_repos": 10,
                        "followers": 5,
                        "following": 5,
                        "html_url": "https://github.com/stale-cached-test",
                        "created_at": "2024-01-01T00:00:00Z"
                    }),
                    fetched_at: Instant::now() - Duration::from_secs(30 * 60),
                },
            );
        }

        let response = get_user(Path("stale-cached-test".into()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_commits_cached_happy_path() {
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert(
                "/repos/infinitedim/portfolio-backend/commits?per_page=20&page=1".to_string(),
                CacheEntry {
                    body: serde_json::json!([
                        {
                            "sha": "1234567890abcdef",
                            "commit": {
                                "message": "feat: add feature\n\nbody message",
                                "author": {
                                    "name": "Dimas Saputra",
                                    "email": "test@example.com",
                                    "date": "2024-01-01T00:00:00Z"
                                }
                            },
                            "html_url": "https://github.com/infinitedim/portfolio-backend/commit/123456",
                            "author": {
                                "login": "infinitedim",
                                "avatar_url": "https://avatar.url"
                            }
                        }
                    ]),
                    fetched_at: Instant::now(),
                },
            );
            cache.insert(
                "/repos/infinitedim/portfolio-backend/commits/1234567890abcdef/check-runs"
                    .to_string(),
                CacheEntry {
                    body: serde_json::json!({
                        "total_count": 1,
                        "check_runs": [
                            {
                                "id": 1,
                                "name": "build",
                                "status": "completed",
                                "conclusion": "success",
                                "html_url": "https://github.com/check"
                            }
                        ]
                    }),
                    fetched_at: Instant::now(),
                },
            );
        }

        let response = get_repo_commits(
            Path(("infinitedim".into(), "portfolio-backend".into())),
            Query(CommitQuery {
                per_page: Some(20),
                page: None,
                sha: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_branches_cached_happy_path() {
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert(
                "/repos/infinitedim/portfolio-backend/branches?per_page=100".to_string(),
                CacheEntry {
                    body: serde_json::json!([
                        {
                            "name": "main",
                            "commit": { "sha": "abc12345" },
                            "protected": true
                        }
                    ]),
                    fetched_at: Instant::now(),
                },
            );
        }

        let response = get_repo_branches(Path(("infinitedim".into(), "portfolio-backend".into())))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_check_runs_cached_happy_path() {
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert(
                "/repos/infinitedim/portfolio-backend/commits/main/check-runs".to_string(),
                CacheEntry {
                    body: serde_json::json!({
                        "total_count": 1,
                        "check_runs": [
                            {
                                "id": 1,
                                "name": "build",
                                "status": "completed",
                                "conclusion": "success",
                                "html_url": "https://github.com/check"
                            }
                        ]
                    }),
                    fetched_at: Instant::now(),
                },
            );
        }

        let response = get_commit_check_runs(
            Path((
                "infinitedim".into(),
                "portfolio-backend".into(),
                "main".into(),
            )),
            Query(CheckRunsQueryParams { force: Some(false) }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_commit_detail_cached_happy_path() {
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert(
                "/repos/infinitedim/portfolio-backend/commits/abc123456789".to_string(),
                CacheEntry {
                    body: serde_json::json!({
                        "sha": "abc123456789",
                        "commit": {
                            "message": "feat: commit detail",
                            "author": { "name": "Author", "email": "a@example.com", "date": "2026-08-01T00:00:00Z" }
                        },
                        "author": { "avatar_url": "https://avatar.url", "login": "infinitedim", "html_url": "https://gh.com/user" },
                        "html_url": "https://github.com/commit/abc123456789",
                        "status": { "state": "success" },
                        "stats": { "additions": 10, "deletions": 2, "total": 12 },
                        "files": [{ "filename": "src/main.rs", "status": "modified", "additions": 10, "deletions": 2, "changes": 12, "patch": "@@ -1 +1 @@" }],
                        "parents": [{ "sha": "parent123456" }]
                    }),
                    fetched_at: Instant::now(),
                },
            );
        }
        let res = get_commit_detail(Path((
            "infinitedim".into(),
            "portfolio-backend".into(),
            "abc123456789".into(),
        )))
        .await
        .into_response();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_commit_detail_invalid_params_returns_400() {
        let res = get_commit_detail(Path((
            "invalid/user".into(),
            "portfolio-backend".into(),
            "main".into(),
        )))
        .await
        .into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_cache_get_expired_returns_none() {
        let mut cache = CACHE.lock().unwrap();
        cache.insert(
            "test-expired-key".to_string(),
            CacheEntry {
                body: serde_json::json!({"test": 1}),
                fetched_at: Instant::now() - Duration::from_secs(3601),
            },
        );
        drop(cache);
        assert!(cache_get("test-expired-key").is_none());
    }

    #[tokio::test]
    async fn test_get_commit_combined_status_matrix() {
        let mut cache = CACHE.lock().unwrap();
        // total_count == 0 -> unconfigured
        cache.insert(
            "/repos/owner/repo/commits/sha-empty/check-runs".into(),
            CacheEntry {
                body: serde_json::json!({ "total_count": 0, "check_runs": [] }),
                fetched_at: Instant::now(),
            },
        );
        // failure
        cache.insert(
            "/repos/owner/repo/commits/sha-fail/check-runs".into(),
            CacheEntry {
                body: serde_json::json!({ "total_count": 1, "check_runs": [{ "conclusion": "failure", "status": "completed" }] }),
                fetched_at: Instant::now(),
            },
        );
        // in_progress -> running
        cache.insert(
            "/repos/owner/repo/commits/sha-running/check-runs".into(),
            CacheEntry {
                body: serde_json::json!({ "total_count": 1, "check_runs": [{ "status": "in_progress", "conclusion": null }] }),
                fetched_at: Instant::now(),
            },
        );
        // all cancelled -> cancelled
        cache.insert(
            "/repos/owner/repo/commits/sha-cancelled/check-runs".into(),
            CacheEntry {
                body: serde_json::json!({ "total_count": 1, "check_runs": [{ "status": "completed", "conclusion": "cancelled" }] }),
                fetched_at: Instant::now(),
            },
        );
        drop(cache);

        assert_eq!(
            get_commit_combined_status("owner", "repo", "sha-empty").await,
            "unconfigured"
        );
        assert_eq!(
            get_commit_combined_status("owner", "repo", "sha-fail").await,
            "failure"
        );
        assert_eq!(
            get_commit_combined_status("owner", "repo", "sha-running").await,
            "running"
        );
        assert_eq!(
            get_commit_combined_status("owner", "repo", "sha-cancelled").await,
            "cancelled"
        );
    }

    #[tokio::test]
    async fn test_get_repo_commits_compare_mode() {
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert(
                "/repos/owner/repo/compare/main...feat".to_string(),
                CacheEntry {
                    body: serde_json::json!({
                        "commits": [{
                            "sha": "1234",
                            "commit": { "message": "feat", "author": { "name": null, "email": "a@a.com", "date": "2026-08-01" } },
                            "html_url": "https://gh.com/commit/1234",
                            "parents": []
                        }]
                    }),
                    fetched_at: Instant::now(),
                },
            );
        }
        let res = get_repo_commits(
            Path(("owner".into(), "repo".into())),
            Query(CommitQuery {
                sha: Some("main...feat".into()),
                per_page: Some(10),
                page: Some(1),
            }),
        )
        .await
        .into_response();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_commit_check_runs_force_reload_cache_eviction() {
        let key = "/repos/owner/repo/commits/head-sha/check-runs".to_string();
        {
            let mut cache = CACHE.lock().unwrap();
            cache.insert(
                key.clone(),
                CacheEntry {
                    body: serde_json::json!({ "total_count": 1, "check_runs": [{ "id": 1, "name": "ci", "status": "completed", "conclusion": "success", "html_url": "url", "app": { "name": "GH" } }] }),
                    fetched_at: Instant::now() - Duration::from_secs(15),
                },
            );
        }
        let _ = get_commit_check_runs(
            Path(("owner".into(), "repo".into(), "head-sha".into())),
            Query(CheckRunsQueryParams { force: Some(true) }),
        )
        .await;
        let cache = CACHE.lock().unwrap();
        assert!(cache.get(&key).is_none());
    }

    #[tokio::test]
    async fn test_github_handlers_reject_invalid_identifiers() {
        assert_eq!(
            get_repo_commits(
                Path(("bad/owner".into(), "repo".into())),
                Query(CommitQuery {
                    sha: None,
                    per_page: None,
                    page: None
                })
            )
            .await
            .into_response()
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get_repo_branches(Path(("owner".into(), "bad repo name".into())))
                .await
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get_commit_check_runs(
                Path(("owner".into(), "repo".into(), "bad/ref/".into())),
                Query(CheckRunsQueryParams { force: None })
            )
            .await
            .into_response()
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
}

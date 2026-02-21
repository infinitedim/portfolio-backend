use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::{self, models::PortfolioSection};
use crate::routes::auth::verify_access_token;

#[derive(Debug, Deserialize)]
pub struct PortfolioQuery {
    #[serde(default)]
    pub section: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PortfolioResponse {
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdatePortfolioRequest {
    pub section: String,
    pub data: Value,
}

#[derive(Debug, Serialize)]
pub struct UpdatePortfolioResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub const VALID_SECTIONS: &[&str] = &["skills", "projects", "experience", "about"];

pub fn is_valid_section(section: &str) -> bool {
    VALID_SECTIONS.contains(&section.to_lowercase().as_str())
}

static STATIC_PROJECTS: Lazy<Value> = Lazy::new(|| {
    serde_json::json!([
        {
            "id": "portfolio-website",
            "name": "Portfolio Website",
            "description": "A modern portfolio website built with Next.js and Rust",
            "technologies": ["Next.js", "React", "TypeScript", "Rust", "Axum"],
            "status": "active",
            "featured": true
        }
    ])
});

static STATIC_SKILLS: Lazy<Value> = Lazy::new(|| {
    serde_json::json!([
        {
            "name": "Frontend",
            "skills": [
                { "name": "React", "level": 90 },
                { "name": "TypeScript", "level": 85 },
                { "name": "Next.js", "level": 85 }
            ]
        },
        {
            "name": "Backend",
            "skills": [
                { "name": "Rust", "level": 75 },
                { "name": "Node.js", "level": 80 },
                { "name": "PostgreSQL", "level": 75 }
            ]
        }
    ])
});

static STATIC_ABOUT: Lazy<Value> = Lazy::new(|| {
    serde_json::json!({
        "name": "Developer",
        "title": "Full Stack Developer",
        "bio": "A passionate developer building modern web applications.",
        "location": "Remote",
        "contact": {
            "email": "dev@example.com",
            "github": "https://github.com/developer"
        }
    })
});

pub fn get_static_data(section: &str) -> Option<Value> {
    match section.to_lowercase().as_str() {
        "projects" => Some(STATIC_PROJECTS.clone()),
        "skills" => Some(STATIC_SKILLS.clone()),
        "experience" => Some(serde_json::json!([])),
        "about" => Some(STATIC_ABOUT.clone()),
        _ => None,
    }
}

pub async fn get_portfolio(Query(query): Query<PortfolioQuery>) -> impl IntoResponse {
    if query.section.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PortfolioResponse {
                data: None,
                error: Some("Missing section parameter".to_string()),
            }),
        )
            .into_response();
    }

    if !is_valid_section(&query.section) {
        return (
            StatusCode::BAD_REQUEST,
            Json(PortfolioResponse {
                data: None,
                error: Some(format!(
                    "Invalid section. Valid sections: {:?}",
                    VALID_SECTIONS
                )),
            }),
        )
            .into_response();
    }

    let section_key = query.section.to_lowercase();

    if let Some(pool) = db::get_pool() {
        match sqlx::query_as::<_, PortfolioSection>(
            "SELECT key, content, updated_at FROM portfolio_sections WHERE key = $1",
        )
        .bind(&section_key)
        .fetch_optional(pool.as_ref())
        .await
        {
            Ok(Some(section)) => {
                let mut cache_headers = axum::http::HeaderMap::new();
                cache_headers.insert(
                    axum::http::header::CACHE_CONTROL,
                    "public, max-age=300, stale-while-revalidate=60"
                        .parse()
                        .unwrap(),
                );
                return (
                    StatusCode::OK,
                    cache_headers,
                    Json(PortfolioResponse {
                        data: Some(section.content),
                        error: None,
                    }),
                )
                    .into_response();
            }
            Ok(None) => {
                tracing::debug!(
                    "Section '{}' not found in database, using static data",
                    section_key
                );
            }
            Err(e) => {
                tracing::error!("Database error fetching portfolio section: {}", e);
            }
        }
    }

    match get_static_data(&section_key) {
        Some(data) => {
            let mut cache_headers = axum::http::HeaderMap::new();
            cache_headers.insert(
                axum::http::header::CACHE_CONTROL,
                "public, max-age=60, stale-while-revalidate=30"
                    .parse()
                    .unwrap(),
            );
            (
                StatusCode::OK,
                cache_headers,
                Json(PortfolioResponse {
                    data: Some(data),
                    error: None,
                }),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            axum::http::HeaderMap::new(),
            Json(PortfolioResponse {
                data: None,
                error: Some("Section not found".to_string()),
            }),
        )
            .into_response(),
    }
}

pub async fn update_portfolio(
    headers: HeaderMap,
    Json(payload): Json<UpdatePortfolioRequest>,
) -> impl IntoResponse {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match token {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(UpdatePortfolioResponse {
                    success: false,
                    message: None,
                    error: Some("Authorization required".to_string()),
                }),
            );
        }
    };

    if verify_access_token(token).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(UpdatePortfolioResponse {
                success: false,
                message: None,
                error: Some("Invalid or expired token".to_string()),
            }),
        );
    }

    if !is_valid_section(&payload.section) {
        return (
            StatusCode::BAD_REQUEST,
            Json(UpdatePortfolioResponse {
                success: false,
                message: None,
                error: Some(format!(
                    "Invalid section. Valid sections: {:?}",
                    VALID_SECTIONS
                )),
            }),
        );
    }

    let section_key = payload.section.to_lowercase();

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(UpdatePortfolioResponse {
                    success: false,
                    message: None,
                    error: Some("Database not available".to_string()),
                }),
            );
        }
    };

    match sqlx::query(
        r#"
        INSERT INTO portfolio_sections (key, content, updated_at)
        VALUES ($1, $2, now())
        ON CONFLICT (key) DO UPDATE SET
            content = EXCLUDED.content,
            updated_at = now()
        "#,
    )
    .bind(&section_key)
    .bind(&payload.data)
    .execute(pool.as_ref())
    .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(UpdatePortfolioResponse {
                success: true,
                message: Some(format!("Section '{}' updated successfully", section_key)),
                error: None,
            }),
        ),
        Err(e) => {
            tracing::error!("Failed to update portfolio section: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UpdatePortfolioResponse {
                    success: false,
                    message: None,
                    error: Some("Failed to update section".to_string()),
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    #[allow(unused_imports)]
    use axum::routing::{get, patch};
    use axum::Router;
    use tower::ServiceExt;

    fn portfolio_router() -> Router {
        Router::new().route("/api/portfolio", get(get_portfolio).patch(update_portfolio))
    }

    async fn get_json<T: serde::de::DeserializeOwned>(app: Router, uri: &str) -> (StatusCode, T) {
        let req = Request::get(uri).body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: T = serde_json::from_slice(&bytes).unwrap();
        (status, value)
    }

    async fn patch_json(app: Router, uri: &str, json: &impl serde::Serialize) -> StatusCode {
        let body = Body::from(serde_json::to_vec(json).unwrap());
        let req = Request::patch(uri)
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        res.status()
    }

    #[test]
    fn test_is_valid_section() {
        assert!(is_valid_section("skills"));
        assert!(is_valid_section("Skills"));
        assert!(is_valid_section("projects"));
        assert!(is_valid_section("experience"));
        assert!(is_valid_section("about"));
        assert!(!is_valid_section("invalid"));
        assert!(!is_valid_section(""));
    }

    #[test]
    fn test_get_static_data() {
        assert!(get_static_data("skills").is_some());
        assert!(get_static_data("projects").is_some());
        assert!(get_static_data("experience").is_some());
        assert!(get_static_data("about").is_some());
        assert!(get_static_data("invalid").is_none());
    }

    #[tokio::test]
    async fn test_get_portfolio_missing_section_returns_bad_request() {
        let (status, _) = get_json::<PortfolioResponse>(portfolio_router(), "/api/portfolio").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_portfolio_invalid_section_returns_bad_request() {
        let (status, _) =
            get_json::<PortfolioResponse>(portfolio_router(), "/api/portfolio?section=invalid")
                .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_portfolio_skills_returns_ok_with_data() {
        let (status, body) =
            get_json::<PortfolioResponse>(portfolio_router(), "/api/portfolio?section=skills")
                .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.data.is_some());
        assert!(body.error.is_none());
    }

    #[tokio::test]
    async fn test_update_portfolio_no_auth_returns_unauthorized() {
        let status = patch_json(
            portfolio_router(),
            "/api/portfolio",
            &UpdatePortfolioRequest {
                section: "skills".to_string(),
                data: serde_json::json!({"test": true}),
            },
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

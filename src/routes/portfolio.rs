use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::db::{self, models::PortfolioSection};
use crate::routes::auth::require_admin;
use crate::routes::ErrorResponse;

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortfolioQuery {
    #[serde(default)]
    pub section: String,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct PortfolioResponse {
    #[schema(value_type = Option<Object>)]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct UpdatePortfolioRequest {
    pub section: String,
    #[schema(value_type = Object)]
    pub data: Value,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UpdatePortfolioResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PortfolioVersionSummary {
    pub id: Uuid,
    pub section_key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortfolioVersionsQuery {
    pub section: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RestorePortfolioResponse {
    pub success: bool,
    pub section: String,
    #[schema(value_type = Object)]
    pub data: Value,
}

pub const VALID_SECTIONS: &[&str] = &["projects", "experience", "about"];

pub fn is_valid_section(section: &str) -> bool {
    VALID_SECTIONS.contains(&section.to_lowercase().as_str())
}

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
        "projects" => Some(serde_json::json!([])),
        "experience" => Some(serde_json::json!([])),
        "about" => Some(STATIC_ABOUT.clone()),
        _ => None,
    }
}

#[utoipa::path(
    get,
    path = "/api/portfolio",
    tag = "Portfolio",
    params(PortfolioQuery),
    responses(
        (status = 200, description = "Portfolio section content", body = PortfolioResponse),
        (status = 400, description = "Missing/invalid section name", body = ErrorResponse),
    ),
)]
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

#[utoipa::path(
    patch,
    path = "/api/portfolio",
    tag = "Portfolio",
    security(("bearer_auth" = [])),
    request_body = UpdatePortfolioRequest,
    responses(
        (status = 200, description = "Section updated", body = UpdatePortfolioResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
    ),
)]
pub async fn update_portfolio(
    headers: HeaderMap,
    Json(payload): Json<UpdatePortfolioRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin(&headers) {
        let status = err.status_code();
        let message = err.public_message().to_string();
        return (
            status,
            Json(UpdatePortfolioResponse {
                success: false,
                message: None,
                error: Some(message),
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

    // Snapshot the current content before overwriting.
    if let Ok(Some(existing)) = sqlx::query_as::<_, PortfolioSection>(
        "SELECT key, content, updated_at FROM portfolio_sections WHERE key = $1",
    )
    .bind(&section_key)
    .fetch_optional(pool.as_ref())
    .await
    {
        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO portfolio_versions (section_key, content, created_at)
            VALUES ($1, $2, now())
            "#,
        )
        .bind(&section_key)
        .bind(&existing.content)
        .execute(pool.as_ref())
        .await
        {
            tracing::warn!("Failed to snapshot portfolio section before update: {}", e);
        }
    }

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

#[utoipa::path(
    get,
    path = "/api/admin/portfolio/versions",
    tag = "Portfolio",
    security(("bearer_auth" = [])),
    params(PortfolioVersionsQuery),
    responses(
        (status = 200, description = "Version history for a section", body = [PortfolioVersionSummary]),
        (status = 400, description = "Invalid section", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
    ),
)]
pub async fn list_portfolio_versions(
    headers: HeaderMap,
    Query(query): Query<PortfolioVersionsQuery>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    if !is_valid_section(&query.section) {
        return Err(crate::routes::AppError::BadRequest(format!(
            "Invalid section. Valid sections: {:?}",
            VALID_SECTIONS
        )));
    }

    let section_key = query.section.to_lowercase();
    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let rows = sqlx::query_as::<_, (Uuid, String, DateTime<Utc>)>(
        r#"
        SELECT id, section_key, created_at
        FROM portfolio_versions
        WHERE section_key = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(&section_key)
    .fetch_all(pool.as_ref())
    .await?;

    let items: Vec<PortfolioVersionSummary> = rows
        .into_iter()
        .map(|(id, section_key, created_at)| PortfolioVersionSummary {
            id,
            section_key,
            created_at,
        })
        .collect();

    Ok((StatusCode::OK, Json(items)))
}

#[utoipa::path(
    post,
    path = "/api/admin/portfolio/versions/{id}/restore",
    tag = "Portfolio",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Version id to restore")),
    responses(
        (status = 200, description = "Section restored from version", body = RestorePortfolioResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 404, description = "Version not found", body = ErrorResponse),
    ),
)]
pub async fn restore_portfolio_version(
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let version = sqlx::query_as::<_, (Uuid, String, Value, DateTime<Utc>)>(
        "SELECT id, section_key, content, created_at FROM portfolio_versions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(crate::routes::AppError::NotFound)?;

    let (_, section_key, content, _) = version;

    // Snapshot current state before restore.
    if let Ok(Some(existing)) = sqlx::query_as::<_, PortfolioSection>(
        "SELECT key, content, updated_at FROM portfolio_sections WHERE key = $1",
    )
    .bind(&section_key)
    .fetch_optional(pool.as_ref())
    .await
    {
        let _ = sqlx::query(
            "INSERT INTO portfolio_versions (section_key, content, created_at) VALUES ($1, $2, now())",
        )
        .bind(&section_key)
        .bind(&existing.content)
        .execute(pool.as_ref())
        .await;
    }

    sqlx::query(
        r#"
        INSERT INTO portfolio_sections (key, content, updated_at)
        VALUES ($1, $2, now())
        ON CONFLICT (key) DO UPDATE SET
            content = EXCLUDED.content,
            updated_at = now()
        "#,
    )
    .bind(&section_key)
    .bind(&content)
    .execute(pool.as_ref())
    .await?;

    Ok((
        StatusCode::OK,
        Json(RestorePortfolioResponse {
            success: true,
            section: section_key,
            data: content,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    #[allow(unused_imports)]
    use axum::routing::{get, patch, post};
    use axum::Router;
    use tower::ServiceExt;

    fn portfolio_router() -> Router {
        Router::new()
            .route("/api/portfolio", get(get_portfolio).patch(update_portfolio))
            .route(
                "/api/admin/portfolio/versions",
                get(list_portfolio_versions),
            )
            .route(
                "/api/admin/portfolio/versions/{id}/restore",
                post(restore_portfolio_version),
            )
            .layer(crate::test_support::mock_connect_info())
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
        assert!(!is_valid_section("skills"));
        assert!(!is_valid_section("Skills"));
        assert!(is_valid_section("projects"));
        assert!(is_valid_section("experience"));
        assert!(is_valid_section("about"));
        assert!(!is_valid_section("invalid"));
        assert!(!is_valid_section(""));
    }

    #[test]
    fn test_get_static_data() {
        assert!(get_static_data("skills").is_none());
        assert_eq!(get_static_data("projects"), Some(serde_json::json!([])));
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
    async fn test_get_portfolio_projects_returns_ok_with_data() {
        let (status, body) =
            get_json::<PortfolioResponse>(portfolio_router(), "/api/portfolio?section=projects")
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
                section: "projects".to_string(),
                data: serde_json::json!({"test": true}),
            },
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn db_portfolio_update_creates_version_and_restore() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = portfolio_router();
        let bearer = crate::test_support::admin_bearer();
        let v1 = serde_json::json!([{"name": "Rust", "level": 80}]);
        let v2 = serde_json::json!([{"name": "Rust", "level": 90}]);

        let patch_body = |data: serde_json::Value| {
            Body::from(
                serde_json::to_vec(&UpdatePortfolioRequest {
                    section: "about".to_string(),
                    data,
                })
                .unwrap(),
            )
        };

        let req = Request::patch("/api/portfolio")
            .header("content-type", "application/json")
            .header(axum::http::header::AUTHORIZATION, bearer.clone())
            .body(patch_body(v1.clone()))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let req = Request::patch("/api/portfolio")
            .header("content-type", "application/json")
            .header(axum::http::header::AUTHORIZATION, bearer.clone())
            .body(patch_body(v2.clone()))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let req = Request::get("/api/admin/portfolio/versions?section=about")
            .header(axum::http::header::AUTHORIZATION, bearer.clone())
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let versions: Vec<PortfolioVersionSummary> = serde_json::from_slice(&bytes).unwrap();
        assert!(!versions.is_empty());

        let version_id = versions[0].id;
        let req = Request::post(format!(
            "/api/admin/portfolio/versions/{version_id}/restore"
        ))
        .header(axum::http::header::AUTHORIZATION, bearer)
        .body(Body::empty())
        .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let (_, body) = get_json::<PortfolioResponse>(app, "/api/portfolio?section=about").await;
        assert_eq!(body.data, Some(v1));
    }
}

use axum::{
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{self, models::BlogSeries};
use crate::routes::auth::require_admin;
use crate::routes::blog::{is_valid_slug, BlogPostSummary, ErrorResponse};
use crate::routes::AppError;

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SeriesResponse {
    pub id: Uuid,
    pub title: String,
    pub slug: String,
    pub description: Option<String>,
    pub post_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SeriesDetailResponse {
    pub id: Uuid,
    pub title: String,
    pub slug: String,
    pub description: Option<String>,
    pub posts: Vec<BlogPostSummary>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateSeriesRequest {
    pub title: String,
    pub slug: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSeriesRequest {
    pub title: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SuccessResponse {
    pub success: bool,
}

fn series_to_response(series: BlogSeries, post_count: i64) -> SeriesResponse {
    SeriesResponse {
        id: series.id,
        title: series.title,
        slug: series.slug,
        description: series.description,
        post_count,
        created_at: series.created_at,
        updated_at: series.updated_at,
    }
}

async fn count_series_posts(pool: &sqlx::PgPool, series_id: Uuid, public_only: bool) -> Result<i64, sqlx::Error> {
    let sql = if public_only {
        r#"
        SELECT COUNT(*) FROM blog_posts
        WHERE series_id = $1
          AND ((publish_at IS NOT NULL AND publish_at <= now())
               OR (publish_at IS NULL AND published = true))
        "#
    } else {
        "SELECT COUNT(*) FROM blog_posts WHERE series_id = $1"
    };
    let (count,): (i64,) = sqlx::query_as(sql).bind(series_id).fetch_one(pool).await?;
    Ok(count)
}

#[utoipa::path(
    get,
    path = "/api/blog/series",
    tag = "Blog Series",
    responses(
        (status = 200, description = "List of blog series", body = [SeriesResponse]),
        (status = 503, description = "Database unavailable", body = ErrorResponse),
    ),
)]
pub async fn list_series_public() -> Result<impl IntoResponse, AppError> {
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let rows = sqlx::query_as::<_, BlogSeries>(
        "SELECT id, title, slug, description, created_at, updated_at FROM blog_series ORDER BY title ASC",
    )
    .fetch_all(pool.as_ref())
    .await?;

    let mut items = Vec::with_capacity(rows.len());
    for series in rows {
        let post_count = count_series_posts(pool.as_ref(), series.id, true).await?;
        items.push(series_to_response(series, post_count));
    }

    Ok((StatusCode::OK, Json(items)))
}

#[utoipa::path(
    get,
    path = "/api/blog/series/{slug}",
    tag = "Blog Series",
    params(("slug" = String, Path, description = "Series slug")),
    responses(
        (status = 200, description = "Series with ordered published posts", body = SeriesDetailResponse),
        (status = 404, description = "Series not found", body = ErrorResponse),
        (status = 503, description = "Database unavailable", body = ErrorResponse),
    ),
)]
pub async fn get_series_public(Path(slug): Path<String>) -> Result<impl IntoResponse, AppError> {
    if !is_valid_slug(&slug) {
        return Err(AppError::BadRequest(
            "Slug must contain only lowercase letters, numbers, and hyphens".to_string(),
        ));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let series = sqlx::query_as::<_, BlogSeries>(
        "SELECT id, title, slug, description, created_at, updated_at FROM blog_series WHERE slug = $1",
    )
    .bind(&slug)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(AppError::NotFound)?;

    let posts = sqlx::query_as::<_, crate::db::models::BlogPost>(
        r#"
        SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
               published, tags, reading_time_minutes, view_count, publish_at,
               series_id, series_order, locale, translation_group_id, created_at, updated_at
        FROM blog_posts
        WHERE series_id = $1
          AND ((publish_at IS NOT NULL AND publish_at <= now())
               OR (publish_at IS NULL AND published = true))
        ORDER BY series_order ASC NULLS LAST, created_at ASC
        "#,
    )
    .bind(series.id)
    .fetch_all(pool.as_ref())
    .await?;

    let post_summaries: Vec<BlogPostSummary> = posts
        .into_iter()
        .map(|p| {
            let status = p.status();
            BlogPostSummary {
                id: p.id,
                title: p.title,
                slug: p.slug,
                summary: p.summary,
                published: p.published,
                tags: p.tags,
                reading_time_minutes: p.reading_time_minutes,
                publish_at: p.publish_at,
                status,
                locale: p.locale,
                series_id: p.series_id,
                series_order: p.series_order,
                created_at: p.created_at,
                updated_at: p.updated_at,
            }
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(SeriesDetailResponse {
            id: series.id,
            title: series.title,
            slug: series.slug,
            description: series.description,
            posts: post_summaries,
            created_at: series.created_at,
            updated_at: series.updated_at,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/admin/series",
    tag = "Blog Series",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "All blog series (admin)", body = [SeriesResponse]),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 503, description = "Database unavailable", body = ErrorResponse),
    ),
)]
pub async fn list_series_admin(headers: HeaderMap) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let rows = sqlx::query_as::<_, BlogSeries>(
        "SELECT id, title, slug, description, created_at, updated_at FROM blog_series ORDER BY updated_at DESC",
    )
    .fetch_all(pool.as_ref())
    .await?;

    let mut items = Vec::with_capacity(rows.len());
    for series in rows {
        let post_count = count_series_posts(pool.as_ref(), series.id, false).await?;
        items.push(series_to_response(series, post_count));
    }

    Ok((StatusCode::OK, Json(items)))
}

#[utoipa::path(
    post,
    path = "/api/admin/series",
    tag = "Blog Series",
    security(("bearer_auth" = [])),
    request_body = CreateSeriesRequest,
    responses(
        (status = 201, description = "Series created", body = SeriesResponse),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 409, description = "Slug already exists", body = ErrorResponse),
    ),
)]
pub async fn create_series(
    headers: HeaderMap,
    Json(payload): Json<CreateSeriesRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;

    if payload.title.trim().is_empty() {
        return Err(AppError::BadRequest("Title is required".to_string()));
    }
    if payload.slug.trim().is_empty() || !is_valid_slug(&payload.slug) {
        return Err(AppError::BadRequest(
            "Slug must contain only lowercase letters, numbers, and hyphens".to_string(),
        ));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let series = sqlx::query_as::<_, BlogSeries>(
        r#"
        INSERT INTO blog_series (title, slug, description, created_at, updated_at)
        VALUES ($1, $2, $3, now(), now())
        RETURNING id, title, slug, description, created_at, updated_at
        "#,
    )
    .bind(payload.title.trim())
    .bind(payload.slug.trim())
    .bind(payload.description.as_deref().map(str::trim))
    .fetch_one(pool.as_ref())
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") || e.to_string().contains("unique constraint") {
            AppError::BadRequest("Slug already exists".to_string())
        } else {
            AppError::Db(e)
        }
    })?;

    Ok((
        StatusCode::CREATED,
        Json(series_to_response(series, 0)),
    ))
}

#[utoipa::path(
    get,
    path = "/api/admin/series/{slug}",
    tag = "Blog Series",
    security(("bearer_auth" = [])),
    params(("slug" = String, Path, description = "Series slug")),
    responses(
        (status = 200, description = "Series detail (admin)", body = SeriesResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 404, description = "Series not found", body = ErrorResponse),
    ),
)]
pub async fn get_series_admin(
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;

    if !is_valid_slug(&slug) {
        return Err(AppError::BadRequest(
            "Slug must contain only lowercase letters, numbers, and hyphens".to_string(),
        ));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let series = sqlx::query_as::<_, BlogSeries>(
        "SELECT id, title, slug, description, created_at, updated_at FROM blog_series WHERE slug = $1",
    )
    .bind(&slug)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(AppError::NotFound)?;

    let post_count = count_series_posts(pool.as_ref(), series.id, false).await?;

    Ok((StatusCode::OK, Json(series_to_response(series, post_count))))
}

#[utoipa::path(
    patch,
    path = "/api/admin/series/{slug}",
    tag = "Blog Series",
    security(("bearer_auth" = [])),
    params(("slug" = String, Path, description = "Series slug")),
    request_body = UpdateSeriesRequest,
    responses(
        (status = 200, description = "Series updated", body = SeriesResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 404, description = "Series not found", body = ErrorResponse),
    ),
)]
pub async fn update_series(
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(payload): Json<UpdateSeriesRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;

    if !is_valid_slug(&slug) {
        return Err(AppError::BadRequest(
            "Slug must contain only lowercase letters, numbers, and hyphens".to_string(),
        ));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let series = sqlx::query_as::<_, BlogSeries>(
        r#"
        UPDATE blog_series
        SET title = COALESCE($1, title),
            description = COALESCE($2, description),
            updated_at = now()
        WHERE slug = $3
        RETURNING id, title, slug, description, created_at, updated_at
        "#,
    )
    .bind(payload.title.as_deref().map(str::trim))
    .bind(payload.description.as_deref().map(str::trim))
    .bind(&slug)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(AppError::NotFound)?;

    let post_count = count_series_posts(pool.as_ref(), series.id, false).await?;

    Ok((StatusCode::OK, Json(series_to_response(series, post_count))))
}

#[utoipa::path(
    delete,
    path = "/api/admin/series/{slug}",
    tag = "Blog Series",
    security(("bearer_auth" = [])),
    params(("slug" = String, Path, description = "Series slug")),
    responses(
        (status = 200, description = "Series deleted", body = SuccessResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 404, description = "Series not found", body = ErrorResponse),
    ),
)]
pub async fn delete_series(
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;

    if !is_valid_slug(&slug) {
        return Err(AppError::BadRequest(
            "Slug must contain only lowercase letters, numbers, and hyphens".to_string(),
        ));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let result = sqlx::query("DELETE FROM blog_series WHERE slug = $1")
        .bind(&slug)
        .execute(pool.as_ref())
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok((StatusCode::OK, Json(SuccessResponse { success: true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn series_router() -> Router {
        Router::new()
            .route("/api/blog/series", get(list_series_public))
            .route("/api/blog/series/{slug}", get(get_series_public))
            .route(
                "/api/admin/series",
                get(list_series_admin).post(create_series),
            )
            .route(
                "/api/admin/series/{slug}",
                get(get_series_admin)
                    .patch(update_series)
                    .delete(delete_series),
            )
            .layer(crate::test_support::mock_connect_info())
    }

    async fn post_json_auth(
        app: Router,
        uri: &str,
        bearer: &str,
        json: &impl serde::Serialize,
    ) -> (StatusCode, axum::body::Bytes) {
        let body = Body::from(serde_json::to_vec(json).unwrap());
        let req = Request::post(uri)
            .header("content-type", "application/json")
            .header(axum::http::header::AUTHORIZATION, bearer)
            .body(body)
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let st = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (st, bytes)
    }

    async fn get_status(app: Router, uri: &str) -> StatusCode {
        let req = Request::get(uri).body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        res.status()
    }

    #[tokio::test]
    async fn list_series_no_db_returns_503() {
        let status = get_status(series_router(), "/api/blog/series").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn admin_create_series_requires_auth() {
        let app = series_router();
        let body = Body::from(
            serde_json::to_vec(&CreateSeriesRequest {
                title: "Rust".to_string(),
                slug: "rust-series".to_string(),
                description: None,
            })
            .unwrap(),
        );
        let req = Request::post("/api/admin/series")
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn db_series_crud_and_public_list() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = series_router();
        let bearer = crate::test_support::admin_bearer();

        let (st, bytes) = post_json_auth(
            app.clone(),
            "/api/admin/series",
            &bearer,
            &CreateSeriesRequest {
                title: "Getting Started".to_string(),
                slug: "getting-started".to_string(),
                description: Some("Intro series".to_string()),
            },
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let created: SeriesResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(created.slug, "getting-started");

        let req = Request::get("/api/blog/series")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let list: Vec<SeriesResponse> =
            serde_json::from_slice(&axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert!(list.iter().any(|s| s.slug == "getting-started"));

        let req = Request::get("/api/blog/series/getting-started")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let req = Request::delete("/api/admin/series/getting-started")
            .header(axum::http::header::AUTHORIZATION, bearer)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}

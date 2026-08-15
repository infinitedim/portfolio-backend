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

async fn count_series_posts(
    pool: &sqlx::PgPool,
    series_id: Uuid,
    public_only: bool,
) -> Result<i64, sqlx::Error> {
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

pub fn get_static_series_list() -> Vec<SeriesResponse> {
    if std::env::var("ENVIRONMENT").as_deref() == Ok("production") {
        return Vec::new();
    }
    let now = Utc::now();
    vec![
        SeriesResponse {
            id: Uuid::parse_str("11111111-1111-4111-a111-111111111111").unwrap(),
            title: "Rust Systems & Axum Mastery".to_string(),
            slug: "rust-systems-mastery".to_string(),
            description: Some(
                "A comprehensive series on high-performance asynchronous Rust backend engineering, memory safety, and Axum 0.8 architecture."
                    .to_string(),
            ),
            post_count: 2,
            created_at: now,
            updated_at: now,
        },
        SeriesResponse {
            id: Uuid::parse_str("22222222-2222-4222-a222-222222222222").unwrap(),
            title: "Next.js 16 & Modern Web Architecture".to_string(),
            slug: "nextjs-16-architecture".to_string(),
            description: Some(
                "In-depth guide on Partial Prerendering (PPR), React Server Components, Web Vitals, and edge proxy design."
                    .to_string(),
            ),
            post_count: 2,
            created_at: now,
            updated_at: now,
        },
    ]
}

pub fn get_static_series_detail(slug: &str, locale: &str) -> Option<SeriesDetailResponse> {
    if std::env::var("ENVIRONMENT").as_deref() == Ok("production") {
        return None;
    }
    let list = get_static_series_list();
    let s = list
        .into_iter()
        .find(|item| item.slug == slug || item.id.to_string() == slug)?;
    let all_posts = crate::routes::blog::get_static_blog_posts(locale);
    let mut posts: Vec<BlogPostSummary> = all_posts
        .into_iter()
        .filter(|p| p.series_id == Some(s.id))
        .collect();
    posts.sort_by_key(|p| p.series_order.unwrap_or(999));

    Some(SeriesDetailResponse {
        id: s.id,
        title: s.title,
        slug: s.slug,
        description: s.description,
        posts,
        created_at: s.created_at,
        updated_at: s.updated_at,
    })
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
    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            let static_series = get_static_series_list();
            if !static_series.is_empty() {
                return Ok((StatusCode::OK, Json(static_series)));
            }
            return Err(AppError::DbUnavailable);
        }
    };

    let rows = sqlx::query_as::<_, BlogSeries>(
        "SELECT id, title, slug, description, created_at, updated_at FROM blog_series ORDER BY title ASC",
    )
    .fetch_all(pool.as_ref())
    .await?;

    if rows.is_empty() {
        let static_series = get_static_series_list();
        if !static_series.is_empty() {
            return Ok((StatusCode::OK, Json(static_series)));
        }
    }

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

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            if let Some(detail) = get_static_series_detail(&slug, "en") {
                return Ok((StatusCode::OK, Json(detail)));
            }
            return Err(AppError::DbUnavailable);
        }
    };

    let series = match sqlx::query_as::<_, BlogSeries>(
        "SELECT id, title, slug, description, created_at, updated_at FROM blog_series WHERE slug = $1",
    )
    .bind(&slug)
    .fetch_optional(pool.as_ref())
    .await? {
        Some(s) => s,
        None => {
            if let Some(detail) = get_static_series_detail(&slug, "en") {
                return Ok((StatusCode::OK, Json(detail)));
            }
            return Err(AppError::NotFound);
        }
    };

    let posts = sqlx::query_as::<_, crate::db::models::BlogPost>(
        r#"
        SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
               published, tags, reading_time_minutes, view_count, publish_at,
               series_id, series_order, locale, translation_group_id,
               translation_status, reviewed_at, reviewed_by, created_at, updated_at
        FROM blog_posts
        WHERE series_id = $1
          AND ((publish_at IS NOT NULL AND publish_at <= now())
               OR (publish_at IS NULL AND published = true))
          AND translation_status = 'published'
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
                translation_group_id: p.translation_group_id,
                translation_status: p.translation_status,
                reviewed_at: p.reviewed_at,
                reviewed_by: p.reviewed_by,
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

    Ok((StatusCode::CREATED, Json(series_to_response(series, 0))))
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

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn list_series_no_db_in_prod_returns_503() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("ENVIRONMENT", "production");
        let status = get_status(series_router(), "/api/blog/series").await;
        std::env::remove_var("ENVIRONMENT");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn list_series_no_db_in_dev_returns_ok() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::remove_var("ENVIRONMENT");
        let status = get_status(series_router(), "/api/blog/series").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[test]
    fn test_series_to_response_helper() {
        let series = BlogSeries {
            id: Uuid::nil(),
            title: "Title".to_string(),
            slug: "slug".to_string(),
            description: Some("desc".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let resp = series_to_response(series, 5);
        assert_eq!(resp.title, "Title");
        assert_eq!(resp.post_count, 5);
    }

    #[tokio::test]
    async fn test_series_unit_branches_without_db() {
        // 1. get_series_public invalid slug -> BadRequest
        let Err(err) = get_series_public(Path("INVALID_SLUG".to_string())).await else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::BadRequest(_)));

        // 2. get_series_public valid slug without DB -> DbUnavailable
        let Err(err) = get_series_public(Path("valid-slug".to_string())).await else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::DbUnavailable));

        // 3. list_series_admin without auth -> Unauthorized
        let Err(err) = list_series_admin(HeaderMap::new()).await else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::Unauthorized));

        // 4. list_series_admin with auth without DB -> DbUnavailable
        let bearer = crate::test_support::admin_bearer();
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, bearer.parse().unwrap());
        let Err(err) = list_series_admin(headers.clone()).await else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::DbUnavailable));

        // 5. create_series without auth -> Unauthorized
        let Err(err) = create_series(
            HeaderMap::new(),
            Json(CreateSeriesRequest {
                title: "T".to_string(),
                slug: "s".to_string(),
                description: None,
            }),
        )
        .await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::Unauthorized));

        // 6. create_series empty title -> BadRequest
        let Err(err) = create_series(
            headers.clone(),
            Json(CreateSeriesRequest {
                title: "   ".to_string(),
                slug: "valid-slug".to_string(),
                description: None,
            }),
        )
        .await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::BadRequest(_)));

        // 7. create_series invalid slug -> BadRequest
        let Err(err) = create_series(
            headers.clone(),
            Json(CreateSeriesRequest {
                title: "Title".to_string(),
                slug: "INVALID SLUG".to_string(),
                description: None,
            }),
        )
        .await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::BadRequest(_)));

        // 8. create_series valid request without DB -> DbUnavailable
        let Err(err) = create_series(
            headers.clone(),
            Json(CreateSeriesRequest {
                title: "Title".to_string(),
                slug: "valid-slug".to_string(),
                description: None,
            }),
        )
        .await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::DbUnavailable));

        // 9. get_series_admin without auth -> Unauthorized
        let Err(err) = get_series_admin(HeaderMap::new(), Path("valid-slug".to_string())).await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::Unauthorized));

        // 10. get_series_admin invalid slug -> BadRequest
        let Err(err) = get_series_admin(headers.clone(), Path("INVALID_SLUG".to_string())).await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::BadRequest(_)));

        // 11. get_series_admin valid slug without DB -> DbUnavailable
        let Err(err) = get_series_admin(headers.clone(), Path("valid-slug".to_string())).await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::DbUnavailable));

        // 12. update_series without auth -> Unauthorized
        let Err(err) = update_series(
            HeaderMap::new(),
            Path("valid-slug".to_string()),
            Json(UpdateSeriesRequest {
                title: None,
                description: None,
            }),
        )
        .await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::Unauthorized));

        // 13. update_series invalid slug -> BadRequest
        let Err(err) = update_series(
            headers.clone(),
            Path("INVALID_SLUG".to_string()),
            Json(UpdateSeriesRequest {
                title: None,
                description: None,
            }),
        )
        .await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::BadRequest(_)));

        // 14. update_series valid slug without DB -> DbUnavailable
        let Err(err) = update_series(
            headers.clone(),
            Path("valid-slug".to_string()),
            Json(UpdateSeriesRequest {
                title: Some("New Title".to_string()),
                description: None,
            }),
        )
        .await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::DbUnavailable));

        // 15. delete_series without auth -> Unauthorized
        let Err(err) = delete_series(HeaderMap::new(), Path("valid-slug".to_string())).await else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::Unauthorized));

        // 16. delete_series invalid slug -> BadRequest
        let Err(err) = delete_series(headers.clone(), Path("INVALID_SLUG".to_string())).await
        else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::BadRequest(_)));

        // 17. delete_series valid slug without DB -> DbUnavailable
        let Err(err) = delete_series(headers, Path("valid-slug".to_string())).await else {
            panic!("expected error");
        };
        assert!(matches!(err, AppError::DbUnavailable));
    }

    #[test]
    fn test_series_struct_serializations() {
        let detail = SeriesDetailResponse {
            id: Uuid::nil(),
            title: "Title".to_string(),
            slug: "slug".to_string(),
            description: Some("desc".to_string()),
            posts: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&detail).unwrap();
        assert!(json.contains("posts"));

        let succ = SuccessResponse { success: true };
        let json = serde_json::to_string(&succ).unwrap();
        assert!(json.contains("true"));
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
        let Some(db) = crate::test_support::acquire_test_pool().await else {
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

        // Call list_series_admin
        let req_list_admin = Request::get("/api/admin/series")
            .header(axum::http::header::AUTHORIZATION, &bearer)
            .body(Body::empty())
            .unwrap();
        let res_list_admin = app.clone().oneshot(req_list_admin).await.unwrap();
        assert_eq!(res_list_admin.status(), StatusCode::OK);

        // Call get_series_admin
        let req_get_admin = Request::get("/api/admin/series/getting-started")
            .header(axum::http::header::AUTHORIZATION, &bearer)
            .body(Body::empty())
            .unwrap();
        let res_get_admin = app.clone().oneshot(req_get_admin).await.unwrap();
        assert_eq!(res_get_admin.status(), StatusCode::OK);

        let req = Request::get("/api/blog/series")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let list: Vec<SeriesResponse> = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(list.iter().any(|s| s.slug == "getting-started"));

        let series_obj: SeriesResponse = serde_json::from_slice(&bytes).unwrap();

        // Create a blog post belonging to this series
        sqlx::query(
            r#"
            INSERT INTO blog_posts (id, title, slug, summary, content_md, published, series_id, series_order)
            VALUES ($1, 'Series Part 1', 'series-part-1', 'Summary', '# Content', true, $2, 1)
            "#,
        )
        .bind(uuid::Uuid::new_v4())
        .bind(series_obj.id)
        .execute(&*db.pool)
        .await
        .unwrap();

        let req = Request::get("/api/blog/series/getting-started")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Update series title and description
        let req_update = Request::patch("/api/admin/series/getting-started")
            .header(axum::http::header::AUTHORIZATION, &bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "title": "New Title",
                    "description": "New description"
                }))
                .unwrap(),
            ))
            .unwrap();
        let res_update = app.clone().oneshot(req_update).await.unwrap();
        assert_eq!(res_update.status(), StatusCode::OK);
        let updated: SeriesResponse = serde_json::from_slice(
            &axum::body::to_bytes(res_update.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(updated.title, "New Title");

        // Invalid slug validation on update
        let req_invalid = Request::patch("/api/admin/series/getting_started_invalid")
            .header(axum::http::header::AUTHORIZATION, &bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "title": "New Title",
                    "description": null
                }))
                .unwrap(),
            ))
            .unwrap();
        let res_invalid = app.clone().oneshot(req_invalid).await.unwrap();
        assert_eq!(res_invalid.status(), StatusCode::BAD_REQUEST);

        let req = Request::delete("/api/admin/series/getting-started")
            .header(axum::http::header::AUTHORIZATION, bearer)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}

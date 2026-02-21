use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{self, models::BlogPost};
use crate::routes::auth::verify_access_token;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlogListQuery {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_page_size")]
    pub page_size: i64,
    pub published: Option<bool>,
    pub search: Option<String>,
    pub tag: Option<String>,
    pub sort: Option<String>,
}

pub fn default_page() -> i64 {
    1
}

pub fn default_page_size() -> i64 {
    10
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlogListResponse {
    pub items: Vec<BlogPostSummary>,
    pub page: i64,
    pub page_size: i64,
    pub total: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlogPostSummary {
    pub id: Uuid,
    pub title: String,
    pub slug: String,
    pub summary: Option<String>,
    pub published: bool,
    pub tags: Vec<String>,
    pub reading_time_minutes: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlogPostResponse {
    pub id: Uuid,
    pub title: String,
    pub slug: String,
    pub summary: Option<String>,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub published: bool,
    pub tags: Vec<String>,
    pub reading_time_minutes: i32,
    pub view_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBlogRequest {
    pub title: String,
    pub slug: String,
    pub summary: Option<String>,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub published: Option<bool>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBlogRequest {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub published: Option<bool>,
    pub tags: Option<Vec<String>>,
}

pub use crate::routes::ErrorResponse;

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

lazy_static::lazy_static! {

    static ref SLUG_REGEX: Regex = Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap();
}

pub fn is_valid_slug(slug: &str) -> bool {
    SLUG_REGEX.is_match(slug)
}

pub fn sanitize_html(html: &str) -> String {
    ammonia::clean(html)
}

pub fn calculate_reading_time(content_md: Option<&str>) -> i32 {
    match content_md {
        Some(text) if !text.is_empty() => {
            let word_count = text.split_whitespace().count();
            ((word_count as f64 / 200.0).ceil() as i32).max(1)
        }
        _ => 0,
    }
}

fn verify_auth(headers: &HeaderMap) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match token {
        Some(t) => match verify_access_token(t) {
            Ok(_) => Ok(()),
            Err(_) => Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid or expired token".to_string(),
                    message: None,
                }),
            )),
        },
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Authorization required".to_string(),
                message: None,
            }),
        )),
    }
}

pub async fn list_posts(Query(query): Query<BlogListQuery>) -> impl IntoResponse {
    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(BlogListResponse {
                    items: vec![],
                    page: query.page,
                    page_size: query.page_size,
                    total: 0,
                }),
            )
                .into_response();
        }
    };

    let page_size = query.page_size.clamp(1, 100);
    let page = query.page.max(1);
    let offset = (page - 1) * page_size;

    let search_pattern = query
        .search
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| format!("%{}%", s.to_lowercase()));

    let tag_filter = query
        .tag
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let order_clause = match query.sort.as_deref() {
        Some("updated") => "ORDER BY updated_at DESC",
        Some("views") => "ORDER BY view_count DESC",
        _ => "ORDER BY created_at DESC",
    };

    let (posts, total): (Vec<BlogPost>, i64) = match (query.published, &search_pattern, &tag_filter)
    {
        (Some(pub_filter), Some(search), Some(tag)) => {
            let sql = format!(
                r#"SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
                       published, tags, reading_time_minutes, view_count, created_at, updated_at
                   FROM blog_posts
                   WHERE published = $1
                     AND (lower(title) LIKE $2 OR lower(summary) LIKE $2)
                     AND $3 = ANY(tags)
                   {} LIMIT $4 OFFSET $5"#,
                order_clause
            );
            let posts = sqlx::query_as::<_, BlogPost>(&sql)
                .bind(pub_filter)
                .bind(search)
                .bind(tag)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool.as_ref())
                .await
                .unwrap_or_default();
            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM blog_posts WHERE published = $1 AND (lower(title) LIKE $2 OR lower(summary) LIKE $2) AND $3 = ANY(tags)"
            )
            .bind(pub_filter).bind(search).bind(tag)
            .fetch_one(pool.as_ref()).await.unwrap_or((0,));
            (posts, total.0)
        }
        (Some(pub_filter), Some(search), None) => {
            let sql = format!(
                r#"SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
                       published, tags, reading_time_minutes, view_count, created_at, updated_at
                   FROM blog_posts
                   WHERE published = $1
                     AND (lower(title) LIKE $2 OR lower(summary) LIKE $2)
                   {} LIMIT $3 OFFSET $4"#,
                order_clause
            );
            let posts = sqlx::query_as::<_, BlogPost>(&sql)
                .bind(pub_filter)
                .bind(search)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool.as_ref())
                .await
                .unwrap_or_default();
            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM blog_posts WHERE published = $1 AND (lower(title) LIKE $2 OR lower(summary) LIKE $2)"
            )
            .bind(pub_filter).bind(search)
            .fetch_one(pool.as_ref()).await.unwrap_or((0,));
            (posts, total.0)
        }
        (Some(pub_filter), None, Some(tag)) => {
            let sql = format!(
                r#"SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
                       published, tags, reading_time_minutes, view_count, created_at, updated_at
                   FROM blog_posts
                   WHERE published = $1 AND $2 = ANY(tags)
                   {} LIMIT $3 OFFSET $4"#,
                order_clause
            );
            let posts = sqlx::query_as::<_, BlogPost>(&sql)
                .bind(pub_filter)
                .bind(tag)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool.as_ref())
                .await
                .unwrap_or_default();
            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM blog_posts WHERE published = $1 AND $2 = ANY(tags)",
            )
            .bind(pub_filter)
            .bind(tag)
            .fetch_one(pool.as_ref())
            .await
            .unwrap_or((0,));
            (posts, total.0)
        }
        (Some(pub_filter), None, None) => {
            let sql = format!(
                r#"SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
                       published, tags, reading_time_minutes, view_count, created_at, updated_at
                   FROM blog_posts WHERE published = $1 {} LIMIT $2 OFFSET $3"#,
                order_clause
            );
            let posts = sqlx::query_as::<_, BlogPost>(&sql)
                .bind(pub_filter)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool.as_ref())
                .await
                .unwrap_or_default();
            let total: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM blog_posts WHERE published = $1")
                    .bind(pub_filter)
                    .fetch_one(pool.as_ref())
                    .await
                    .unwrap_or((0,));
            (posts, total.0)
        }
        (None, Some(search), Some(tag)) => {
            let sql = format!(
                r#"SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
                       published, tags, reading_time_minutes, view_count, created_at, updated_at
                   FROM blog_posts
                   WHERE (lower(title) LIKE $1 OR lower(summary) LIKE $1) AND $2 = ANY(tags)
                   {} LIMIT $3 OFFSET $4"#,
                order_clause
            );
            let posts = sqlx::query_as::<_, BlogPost>(&sql)
                .bind(search)
                .bind(tag)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool.as_ref())
                .await
                .unwrap_or_default();
            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM blog_posts WHERE (lower(title) LIKE $1 OR lower(summary) LIKE $1) AND $2 = ANY(tags)"
            )
            .bind(search).bind(tag)
            .fetch_one(pool.as_ref()).await.unwrap_or((0,));
            (posts, total.0)
        }
        (None, Some(search), None) => {
            let sql = format!(
                r#"SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
                       published, tags, reading_time_minutes, view_count, created_at, updated_at
                   FROM blog_posts
                   WHERE lower(title) LIKE $1 OR lower(summary) LIKE $1
                   {} LIMIT $2 OFFSET $3"#,
                order_clause
            );
            let posts = sqlx::query_as::<_, BlogPost>(&sql)
                .bind(search)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool.as_ref())
                .await
                .unwrap_or_default();
            let total: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM blog_posts WHERE lower(title) LIKE $1 OR lower(summary) LIKE $1"
            )
            .bind(search)
            .fetch_one(pool.as_ref()).await.unwrap_or((0,));
            (posts, total.0)
        }
        (None, None, Some(tag)) => {
            let sql = format!(
                r#"SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
                       published, tags, reading_time_minutes, view_count, created_at, updated_at
                   FROM blog_posts WHERE $1 = ANY(tags) {} LIMIT $2 OFFSET $3"#,
                order_clause
            );
            let posts = sqlx::query_as::<_, BlogPost>(&sql)
                .bind(tag)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool.as_ref())
                .await
                .unwrap_or_default();
            let total: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM blog_posts WHERE $1 = ANY(tags)")
                    .bind(tag)
                    .fetch_one(pool.as_ref())
                    .await
                    .unwrap_or((0,));
            (posts, total.0)
        }
        (None, None, None) => {
            let sql = format!(
                r#"SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
                       published, tags, reading_time_minutes, view_count, created_at, updated_at
                   FROM blog_posts {} LIMIT $1 OFFSET $2"#,
                order_clause
            );
            let posts = sqlx::query_as::<_, BlogPost>(&sql)
                .bind(page_size)
                .bind(offset)
                .fetch_all(pool.as_ref())
                .await
                .unwrap_or_default();
            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blog_posts")
                .fetch_one(pool.as_ref())
                .await
                .unwrap_or((0,));
            (posts, total.0)
        }
    };

    let items: Vec<BlogPostSummary> = posts
        .into_iter()
        .map(|p| BlogPostSummary {
            id: p.id,
            title: p.title,
            slug: p.slug,
            summary: p.summary,
            published: p.published,
            tags: p.tags,
            reading_time_minutes: p.reading_time_minutes,
            created_at: p.created_at,
            updated_at: p.updated_at,
        })
        .collect();

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        "public, max-age=60, stale-while-revalidate=30"
            .parse()
            .unwrap(),
    );

    (
        StatusCode::OK,
        headers,
        Json(BlogListResponse {
            items,
            page,
            page_size,
            total,
        }),
    )
        .into_response()
}

pub async fn get_post(Path(slug): Path<String>) -> impl IntoResponse {
    if !is_valid_slug(&slug) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid slug".to_string(),
                message: Some(
                    "Slug must contain only lowercase letters, numbers, and hyphens".to_string(),
                ),
            }),
        )
            .into_response();
    }

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Database not available".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    match sqlx::query_as::<_, BlogPost>(
        r#"
        UPDATE blog_posts SET view_count = view_count + 1, updated_at = updated_at
        WHERE slug = $1
        RETURNING id, title, slug, summary, content_md, content_html, published, tags, reading_time_minutes, view_count, created_at, updated_at
        "#,
    )
    .bind(&slug)
    .fetch_optional(pool.as_ref())
    .await
    {
        Ok(Some(post)) => {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::CACHE_CONTROL,
                "public, max-age=300, stale-while-revalidate=60"
                    .parse()
                    .unwrap(),
            );
            let response = BlogPostResponse {
                id: post.id,
                title: post.title,
                slug: post.slug,
                summary: post.summary,
                content_md: post.content_md,
                content_html: post.content_html,
                published: post.published,
                tags: post.tags,
                reading_time_minutes: post.reading_time_minutes,
                view_count: post.view_count,
                created_at: post.created_at,
                updated_at: post.updated_at,
            };
            (StatusCode::OK, headers, Json(response)).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Not found".to_string(),
                message: None,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Database error fetching blog post: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    message: None,
                }),
            )
                .into_response()
        }
    }
}

pub async fn create_post(
    headers: HeaderMap,
    Json(payload): Json<CreateBlogRequest>,
) -> impl IntoResponse {
    if let Err(err_response) = verify_auth(&headers) {
        return err_response.into_response();
    }

    if payload.title.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Title is required".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    if payload.slug.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Slug is required".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    if !is_valid_slug(&payload.slug) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid slug".to_string(),
                message: Some(
                    "Slug must contain only lowercase letters, numbers, and hyphens".to_string(),
                ),
            }),
        )
            .into_response();
    }

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Database not available".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    let content_html = if let Some(h) = payload.content_html {
        Some(
            tokio::task::spawn_blocking(move || sanitize_html(&h))
                .await
                .unwrap_or_default(),
        )
    } else {
        None
    };

    let tags: Vec<String> = payload
        .tags
        .unwrap_or_default()
        .into_iter()
        .map(|t| {
            let trimmed = t.trim().to_string();
            let mut chars = trimmed.chars();
            match chars.next() {
                None => trimmed,
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .filter(|t| !t.is_empty())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let reading_time = calculate_reading_time(payload.content_md.as_deref());

    match sqlx::query_as::<_, BlogPost>(
        r#"
        INSERT INTO blog_posts (title, slug, summary, content_md, content_html, published, tags, reading_time_minutes, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())
        RETURNING id, title, slug, summary, content_md, content_html, published, tags, reading_time_minutes, view_count, created_at, updated_at
        "#
    )
    .bind(&payload.title)
    .bind(&payload.slug)
    .bind(&payload.summary)
    .bind(&payload.content_md)
    .bind(&content_html)
    .bind(payload.published.unwrap_or(false))
    .bind(&tags)
    .bind(reading_time)
    .fetch_one(pool.as_ref())
    .await
    {
        Ok(post) => {
            let response = BlogPostResponse {
                id: post.id,
                title: post.title,
                slug: post.slug,
                summary: post.summary,
                content_md: post.content_md,
                content_html: post.content_html,
                published: post.published,
                tags: post.tags,
                reading_time_minutes: post.reading_time_minutes,
                view_count: post.view_count,
                created_at: post.created_at,
                updated_at: post.updated_at,
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {

            if e.to_string().contains("duplicate key") || e.to_string().contains("unique constraint") {
                return (
                    StatusCode::CONFLICT,
                    Json(ErrorResponse {
                        error: "Slug already exists".to_string(),
                        message: None,
                    }),
                ).into_response();
            }

            tracing::error!("Database error creating blog post: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create post".to_string(),
                    message: None,
                }),
            ).into_response()
        }
    }
}

pub async fn update_post(
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(payload): Json<UpdateBlogRequest>,
) -> impl IntoResponse {
    if let Err(err_response) = verify_auth(&headers) {
        return err_response.into_response();
    }

    if !is_valid_slug(&slug) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid slug".to_string(),
                message: Some(
                    "Slug must contain only lowercase letters, numbers, and hyphens".to_string(),
                ),
            }),
        )
            .into_response();
    }

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Database not available".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    let content_html_opt = if let Some(h) = payload.content_html {
        Some(
            tokio::task::spawn_blocking(move || sanitize_html(&h))
                .await
                .unwrap_or_default(),
        )
    } else {
        None
    };

    let normalized_tags = payload.tags.map(|tags| {
        tags.into_iter()
            .map(|t| {
                let trimmed = t.trim().to_string();
                let mut chars = trimmed.chars();
                match chars.next() {
                    None => trimmed,
                    Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                }
            })
            .filter(|t| !t.is_empty())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect::<Vec<String>>()
    });

    let reading_time_opt = payload
        .content_md
        .as_deref()
        .map(|md| calculate_reading_time(Some(md)));

    match sqlx::query_as::<_, BlogPost>(
        r#"
        UPDATE blog_posts
        SET title                = COALESCE($1, title),
            summary              = COALESCE($2, summary),
            content_md           = COALESCE($3, content_md),
            content_html         = COALESCE($4, content_html),
            published            = COALESCE($5, published),
            tags                 = COALESCE($6::TEXT[], tags),
            reading_time_minutes = COALESCE($7, reading_time_minutes),
            updated_at           = now()
        WHERE slug = $8
        RETURNING id, title, slug, summary, content_md, content_html, published, tags, reading_time_minutes, view_count, created_at, updated_at
        "#
    )
    .bind(&payload.title)
    .bind(&payload.summary)
    .bind(&payload.content_md)
    .bind(&content_html_opt)
    .bind(payload.published)
    .bind(&normalized_tags)
    .bind(reading_time_opt)
    .bind(&slug)
    .fetch_optional(pool.as_ref())
    .await
    {
        Ok(Some(post)) => {
            let response = BlogPostResponse {
                id: post.id,
                title: post.title,
                slug: post.slug,
                summary: post.summary,
                content_md: post.content_md,
                content_html: post.content_html,
                published: post.published,
                tags: post.tags,
                reading_time_minutes: post.reading_time_minutes,
                view_count: post.view_count,
                created_at: post.created_at,
                updated_at: post.updated_at,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Not found".to_string(),
                message: None,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Database error updating blog post: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to update post".to_string(),
                    message: None,
                }),
            ).into_response()
        }
    }
}

pub async fn delete_post(headers: HeaderMap, Path(slug): Path<String>) -> impl IntoResponse {
    if let Err(err_response) = verify_auth(&headers) {
        return err_response.into_response();
    }

    if !is_valid_slug(&slug) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid slug".to_string(),
                message: Some(
                    "Slug must contain only lowercase letters, numbers, and hyphens".to_string(),
                ),
            }),
        )
            .into_response();
    }

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Database not available".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    match sqlx::query("DELETE FROM blog_posts WHERE slug = $1")
        .bind(&slug)
        .execute(pool.as_ref())
        .await
    {
        Ok(result) => {
            if result.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Not found".to_string(),
                        message: None,
                    }),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(SuccessResponse { success: true })).into_response()
        }
        Err(e) => {
            tracing::error!("Database error deleting blog post: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to delete post".to_string(),
                    message: None,
                }),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TagsResponse {
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct TagWithCount {
    pub name: String,
    pub slug: String,
    pub post_count: i64,
}

pub async fn list_tags() -> impl IntoResponse {
    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Database not available".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    match sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT tag AS name, COUNT(*) AS post_count
        FROM (
            SELECT unnest(tags) AS tag
            FROM blog_posts
            WHERE published = true AND array_length(tags, 1) > 0
        ) subq
        GROUP BY tag
        ORDER BY post_count DESC, tag ASC
        "#,
    )
    .fetch_all(pool.as_ref())
    .await
    {
        Ok(rows) => {
            let tags: Vec<TagWithCount> = rows
                .into_iter()
                .map(|(name, post_count)| {
                    let slug = name
                        .to_lowercase()
                        .replace(' ', "-")
                        .replace(|c: char| !c.is_alphanumeric() && c != '-', "");
                    TagWithCount {
                        name,
                        slug,
                        post_count,
                    }
                })
                .collect();
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::CACHE_CONTROL,
                "public, max-age=300, stale-while-revalidate=60"
                    .parse()
                    .unwrap(),
            );
            (StatusCode::OK, headers, Json(tags)).into_response()
        }
        Err(e) => {
            tracing::error!("Database error fetching tags: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to fetch tags".to_string(),
                    message: None,
                }),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    #[allow(unused_imports)]
    use axum::routing::{delete, get, patch, post};
    use axum::Router;
    use tower::ServiceExt;

    fn blog_router() -> Router {
        Router::new()
            .route("/api/blog", get(list_posts).post(create_post))
            .route(
                "/api/blog/{slug}",
                get(get_post).patch(update_post).delete(delete_post),
            )
    }

    async fn get_status(app: Router, uri: &str) -> StatusCode {
        let req = Request::get(uri).body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        res.status()
    }

    async fn post_json(app: Router, uri: &str, json: &impl serde::Serialize) -> StatusCode {
        let body = Body::from(serde_json::to_vec(json).unwrap());
        let req = Request::post(uri)
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        res.status()
    }

    #[test]
    fn test_is_valid_slug() {
        assert!(is_valid_slug("my-post"));
        assert!(is_valid_slug("post123"));
        assert!(is_valid_slug("a-b-c"));
        assert!(!is_valid_slug("Invalid"));
        assert!(!is_valid_slug("has space"));
        assert!(!is_valid_slug(""));
    }

    #[test]
    fn test_sanitize_html_removes_script() {
        let html = "<p>Hello</p><script>alert(1)</script>";
        let out = sanitize_html(html);
        assert!(!out.contains("<script>"));
        assert!(out.contains("Hello"));
    }

    #[test]
    fn test_default_page_and_page_size() {
        assert_eq!(default_page(), 1);
        assert_eq!(default_page_size(), 10);
    }

    #[tokio::test]
    async fn test_list_posts_no_db_returns_503() {
        let status = get_status(blog_router(), "/api/blog").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_get_post_invalid_slug_returns_bad_request() {
        let status = get_status(blog_router(), "/api/blog/Invalid_Slug").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_post_no_auth_returns_unauthorized() {
        let status = post_json(
            blog_router(),
            "/api/blog",
            &CreateBlogRequest {
                title: "Test".to_string(),
                slug: "test-post".to_string(),
                summary: None,
                content_md: None,
                content_html: None,
                published: Some(false),
                tags: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

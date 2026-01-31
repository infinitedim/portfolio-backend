/**
 * Blog Routes
 * CRUD API endpoints for blog posts
 */
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

// ============================================================================
// Request/Response Types
// ============================================================================

/// Query parameters for GET /api/blog (list)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlogListQuery {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_page_size")]
    pub page_size: i64,
    pub published: Option<bool>,
}

fn default_page() -> i64 {
    1
}

fn default_page_size() -> i64 {
    10
}

/// Response for GET /api/blog (list)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlogListResponse {
    pub items: Vec<BlogPostSummary>,
    pub page: i64,
    pub page_size: i64,
    pub total: i64,
}

/// Blog post summary (for list view)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlogPostSummary {
    pub id: Uuid,
    pub title: String,
    pub slug: String,
    pub summary: Option<String>,
    pub published: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Full blog post response
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request body for POST /api/blog (create)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBlogRequest {
    pub title: String,
    pub slug: String,
    pub summary: Option<String>,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub published: Option<bool>,
}

/// Request body for PATCH /api/blog/:slug (update)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBlogRequest {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub published: Option<bool>,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Success response (for delete)
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

// ============================================================================
// Validation
// ============================================================================

lazy_static::lazy_static! {
    /// Valid slug pattern: lowercase letters, numbers, and hyphens
    static ref SLUG_REGEX: Regex = Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap();
}

fn is_valid_slug(slug: &str) -> bool {
    SLUG_REGEX.is_match(slug)
}

/// Sanitize HTML content using ammonia
fn sanitize_html(html: &str) -> String {
    ammonia::clean(html)
}

// ============================================================================
// Helper: Extract and verify auth token
// ============================================================================

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

// ============================================================================
// Handlers
// ============================================================================

/// GET /api/blog - List blog posts with pagination
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

    // Clamp page_size to max 100
    let page_size = query.page_size.min(100).max(1);
    let page = query.page.max(1);
    let offset = (page - 1) * page_size;

    // Build query based on published filter
    let (posts, total): (Vec<BlogPost>, i64) = if let Some(published) = query.published {
        let posts = sqlx::query_as::<_, BlogPost>(
            r#"
            SELECT id, title, slug, summary, content_md, content_html, published, created_at, updated_at
            FROM blog_posts
            WHERE published = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#
        )
        .bind(published)
        .bind(page_size)
        .bind(offset)
        .fetch_all(pool.as_ref())
        .await
        .unwrap_or_default();

        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blog_posts WHERE published = $1")
            .bind(published)
            .fetch_one(pool.as_ref())
            .await
            .unwrap_or((0,));

        (posts, total.0)
    } else {
        let posts = sqlx::query_as::<_, BlogPost>(
            r#"
            SELECT id, title, slug, summary, content_md, content_html, published, created_at, updated_at
            FROM blog_posts
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#
        )
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
    };

    let items: Vec<BlogPostSummary> = posts
        .into_iter()
        .map(|p| BlogPostSummary {
            id: p.id,
            title: p.title,
            slug: p.slug,
            summary: p.summary,
            published: p.published,
            created_at: p.created_at,
            updated_at: p.updated_at,
        })
        .collect();

    (
        StatusCode::OK,
        Json(BlogListResponse {
            items,
            page,
            page_size,
            total,
        }),
    )
        .into_response()
}

/// GET /api/blog/:slug - Get single blog post by slug
pub async fn get_post(Path(slug): Path<String>) -> impl IntoResponse {
    // Validate slug
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
        SELECT id, title, slug, summary, content_md, content_html, published, created_at, updated_at
        FROM blog_posts
        WHERE slug = $1
        "#,
    )
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

/// POST /api/blog - Create new blog post (auth required)
pub async fn create_post(
    headers: HeaderMap,
    Json(payload): Json<CreateBlogRequest>,
) -> impl IntoResponse {
    // Verify auth
    if let Err(err_response) = verify_auth(&headers) {
        return err_response.into_response();
    }

    // Validate required fields
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

    // Validate slug format
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

    // Sanitize HTML content
    let content_html = payload.content_html.map(|h| sanitize_html(&h));

    // Insert new post
    match sqlx::query_as::<_, BlogPost>(
        r#"
        INSERT INTO blog_posts (title, slug, summary, content_md, content_html, published, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, now(), now())
        RETURNING id, title, slug, summary, content_md, content_html, published, created_at, updated_at
        "#
    )
    .bind(&payload.title)
    .bind(&payload.slug)
    .bind(&payload.summary)
    .bind(&payload.content_md)
    .bind(&content_html)
    .bind(payload.published.unwrap_or(false))
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
                created_at: post.created_at,
                updated_at: post.updated_at,
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            // Check for unique constraint violation (duplicate slug)
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

/// PATCH /api/blog/:slug - Update blog post (auth required)
pub async fn update_post(
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(payload): Json<UpdateBlogRequest>,
) -> impl IntoResponse {
    // Verify auth
    if let Err(err_response) = verify_auth(&headers) {
        return err_response.into_response();
    }

    // Validate slug
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

    // Check if post exists
    let existing = sqlx::query_as::<_, BlogPost>(
        "SELECT id, title, slug, summary, content_md, content_html, published, created_at, updated_at FROM blog_posts WHERE slug = $1"
    )
    .bind(&slug)
    .fetch_optional(pool.as_ref())
    .await;

    let existing = match existing {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Not found".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Database error fetching blog post: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    // Build update query with optional fields
    let title = payload.title.unwrap_or(existing.title);
    let summary = payload.summary.or(existing.summary);
    let content_md = payload.content_md.or(existing.content_md);
    let content_html = payload
        .content_html
        .map(|h| sanitize_html(&h))
        .or(existing.content_html);
    let published = payload.published.unwrap_or(existing.published);

    match sqlx::query_as::<_, BlogPost>(
        r#"
        UPDATE blog_posts
        SET title = $1, summary = $2, content_md = $3, content_html = $4, published = $5, updated_at = now()
        WHERE slug = $6
        RETURNING id, title, slug, summary, content_md, content_html, published, created_at, updated_at
        "#
    )
    .bind(&title)
    .bind(&summary)
    .bind(&content_md)
    .bind(&content_html)
    .bind(published)
    .bind(&slug)
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
                created_at: post.created_at,
                updated_at: post.updated_at,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
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

/// DELETE /api/blog/:slug - Delete blog post (auth required)
pub async fn delete_post(headers: HeaderMap, Path(slug): Path<String>) -> impl IntoResponse {
    // Verify auth
    if let Err(err_response) = verify_auth(&headers) {
        return err_response.into_response();
    }

    // Validate slug
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

    // Delete the post
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

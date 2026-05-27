//! Headless CMS API — scoped read/write via `X-Api-Key` when enabled.

use axum::{
    extract::{Extension, Path, Query, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::db::{self, models::BlogPost};
use crate::routes::newsletter::hash_api_key;
use crate::routes::AppError;

const API_KEY_HEADER: &str = "x-api-key";

#[derive(Clone)]
pub struct CmsState {
    pub enabled: bool,
}

impl CmsState {
    pub fn from_env() -> Self {
        let enabled = std::env::var("HEADLESS_CMS_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        Self { enabled }
    }
}

#[derive(Debug, Clone)]
pub struct ApiKeyContext {
    pub scope: String,
    pub key_id: Uuid,
}

pub fn cms_disabled_response() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "Headless CMS is not enabled" })),
    )
}

pub async fn require_api_key(
    State(state): State<CmsState>,
    mut req: Request,
    next: Next,
) -> Response {
    if !state.enabled {
        return cms_disabled_response().into_response();
    }

    let api_key = req
        .headers()
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let Some(raw_key) = api_key else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "X-Api-Key header required" })),
        )
            .into_response();
    };

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "Database not available" })),
            )
                .into_response();
        }
    };

    let key_hash = hash_api_key(raw_key);
    let row: Option<(Uuid, String)> = match sqlx::query_as(
        "SELECT id, scope FROM api_keys WHERE key_hash = $1",
    )
    .bind(&key_hash)
    .fetch_optional(pool.as_ref())
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "api key lookup failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response();
        }
    };

    let Some((key_id, scope)) = row else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid API key" })),
        )
            .into_response();
    };

    let _ = sqlx::query("UPDATE api_keys SET last_used_at = now() WHERE id = $1")
        .bind(key_id)
        .execute(pool.as_ref())
        .await;

    req.extensions_mut().insert(ApiKeyContext { scope, key_id });
    next.run(req).await
}

fn require_admin_scope(ctx: &ApiKeyContext) -> Result<(), AppError> {
    if ctx.scope.eq_ignore_ascii_case("admin") {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct CmsBlogQuery {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_page_size")]
    pub page_size: i64,
    pub locale: Option<String>,
}

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    20
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmsBlogListResponse {
    pub items: Vec<CmsBlogItem>,
    pub page: i64,
    pub page_size: i64,
    pub total: i64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmsBlogItem {
    pub id: Uuid,
    pub title: String,
    pub slug: String,
    pub summary: Option<String>,
    pub locale: String,
    pub published: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CmsBlogWriteRequest {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub published: Option<bool>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CmsPortfolioQuery {
    #[serde(default)]
    pub section: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/content/blog",
    tag = "Headless CMS",
    params(CmsBlogQuery),
    responses((status = 200, description = "Blog list", body = CmsBlogListResponse)),
)]
pub async fn list_blog(
    Query(query): Query<CmsBlogQuery>,
) -> Result<impl IntoResponse, AppError> {
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let page = query.page.max(1);
    let page_size = query.page_size.clamp(1, 100);
    let offset = (page - 1) * page_size;
    let locale = query.locale.as_deref().unwrap_or("en");

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM blog_posts WHERE locale = $1 AND published = true",
    )
    .bind(locale)
    .fetch_one(pool.as_ref())
    .await?;

    let rows = sqlx::query_as::<_, BlogPost>(
        r#"
        SELECT id, title, slug, summary, content_md, content_html, published,
               tags, reading_time_minutes, view_count, publish_at,
               series_id, series_order, locale, translation_group_id,
               created_at, updated_at
        FROM blog_posts
        WHERE locale = $1 AND published = true
        ORDER BY updated_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(locale)
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool.as_ref())
    .await?;

    let items = rows
        .into_iter()
        .map(|p| CmsBlogItem {
            id: p.id,
            title: p.title,
            slug: p.slug,
            summary: p.summary,
            locale: p.locale,
            published: p.published,
            updated_at: p.updated_at,
        })
        .collect();

    Ok(Json(CmsBlogListResponse {
        items,
        page,
        page_size,
        total,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/content/blog/{slug}",
    tag = "Headless CMS",
    responses((status = 200, description = "Blog post")),
)]
pub async fn get_blog_post(
    Path(slug): Path<String>,
    Query(query): Query<CmsBlogQuery>,
) -> Result<impl IntoResponse, AppError> {
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let locale = query.locale.as_deref().unwrap_or("en");

    let post = sqlx::query_as::<_, BlogPost>(
        r#"
        SELECT id, title, slug, summary, content_md, content_html, published,
               tags, reading_time_minutes, view_count, publish_at,
               series_id, series_order, locale, translation_group_id,
               created_at, updated_at
        FROM blog_posts
        WHERE slug = $1 AND locale = $2 AND published = true
        "#,
    )
    .bind(&slug)
    .bind(locale)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(AppError::NotFound)?;

    Ok(Json(json!({
        "id": post.id,
        "title": post.title,
        "slug": post.slug,
        "summary": post.summary,
        "contentMd": post.content_md,
        "contentHtml": post.content_html,
        "tags": post.tags,
        "locale": post.locale,
        "published": post.published,
        "updatedAt": post.updated_at,
    })))
}

#[utoipa::path(
    patch,
    path = "/api/v1/content/blog/{slug}",
    tag = "Headless CMS",
    request_body = CmsBlogWriteRequest,
    responses((status = 200, description = "Blog post updated")),
)]
pub async fn update_blog_post(
    Path(slug): Path<String>,
    Query(query): Query<CmsBlogQuery>,
    Extension(ctx): Extension<ApiKeyContext>,
    Json(payload): Json<CmsBlogWriteRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin_scope(&ctx)?;

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let locale = query.locale.as_deref().unwrap_or("en");

    let existing = sqlx::query_as::<_, BlogPost>(
        r#"
        SELECT id, title, slug, summary, content_md, content_html, published,
               tags, reading_time_minutes, view_count, publish_at,
               series_id, series_order, locale, translation_group_id,
               created_at, updated_at
        FROM blog_posts
        WHERE slug = $1 AND locale = $2
        "#,
    )
    .bind(&slug)
    .bind(locale)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(AppError::NotFound)?;

    let title = payload.title.as_deref().unwrap_or(&existing.title);
    let summary = payload.summary.as_ref().or(existing.summary.as_ref());
    let content_md = payload.content_md.as_ref().or(existing.content_md.as_ref());
    let content_html = payload
        .content_html
        .as_ref()
        .or(existing.content_html.as_ref());
    let published = payload.published.unwrap_or(existing.published);
    let tags = payload.tags.as_ref().unwrap_or(&existing.tags);

    sqlx::query(
        r#"
        UPDATE blog_posts
        SET title = $3,
            summary = $4,
            content_md = $5,
            content_html = $6,
            published = $7,
            tags = $8,
            updated_at = now()
        WHERE slug = $1 AND locale = $2
        "#,
    )
    .bind(&slug)
    .bind(locale)
    .bind(title)
    .bind(summary)
    .bind(content_md)
    .bind(content_html)
    .bind(published)
    .bind(tags)
    .execute(pool.as_ref())
    .await?;

    Ok(Json(json!({ "success": true, "slug": slug })))
}

#[utoipa::path(
    get,
    path = "/api/v1/content/portfolio",
    tag = "Headless CMS",
    params(CmsPortfolioQuery),
    responses((status = 200, description = "Portfolio sections")),
)]
pub async fn get_portfolio(Query(query): Query<CmsPortfolioQuery>) -> Result<impl IntoResponse, AppError> {
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    if query.section.trim().is_empty() {
        let rows: Vec<(String, Value)> =
            sqlx::query_as("SELECT key, content FROM portfolio_sections ORDER BY key")
                .fetch_all(pool.as_ref())
                .await?;
        let obj: serde_json::Map<String, Value> = rows.into_iter().collect();
        return Ok(Json(Value::Object(obj)));
    }

    let section = query.section.to_lowercase();
    let row: Option<(Value,)> =
        sqlx::query_as("SELECT content FROM portfolio_sections WHERE key = $1")
            .bind(&section)
            .fetch_optional(pool.as_ref())
            .await?;

    match row {
        Some((content,)) => Ok(Json(json!({ "section": section, "data": content }))),
        None => Err(AppError::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cms_disabled_by_default() {
        let _guard = std::env::remove_var("HEADLESS_CMS_ENABLED");
        let state = CmsState::from_env();
        assert!(!state.enabled);
    }

    #[test]
    fn cms_enabled_when_env_true() {
        std::env::set_var("HEADLESS_CMS_ENABLED", "true");
        let state = CmsState::from_env();
        assert!(state.enabled);
        std::env::remove_var("HEADLESS_CMS_ENABLED");
    }
}

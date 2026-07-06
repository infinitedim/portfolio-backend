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

use crate::db::{
    self,
    models::{BlogPost, BlogStatus},
};
use crate::routes::auth::require_admin;
use crate::routes::AppError;

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct BlogListQuery {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_page_size")]
    pub page_size: i64,
    pub published: Option<bool>,
    pub search: Option<String>,
    pub tag: Option<String>,
    pub sort: Option<String>,
    /// Filter posts belonging to a series (by series slug).
    pub series: Option<String>,
    /// BCP-47-ish locale code (defaults to `en` when omitted).
    pub locale: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct BlogSlugQuery {
    #[serde(default = "default_locale")]
    pub locale: String,
}

pub fn default_page() -> i64 {
    1
}

pub fn default_page_size() -> i64 {
    10
}

pub fn default_locale() -> String {
    "en".to_string()
}

pub fn is_valid_locale(locale: &str) -> bool {
    !locale.is_empty()
        && locale.len() <= 10
        && locale
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BlogListResponse {
    pub items: Vec<BlogPostSummary>,
    pub page: i64,
    pub page_size: i64,
    pub total: i64,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BlogPostSummary {
    pub id: Uuid,
    pub title: String,
    pub slug: String,
    pub summary: Option<String>,
    pub published: bool,
    pub tags: Vec<String>,
    pub reading_time_minutes: i32,
    pub publish_at: Option<DateTime<Utc>>,
    pub status: BlogStatus,
    pub locale: String,
    pub series_id: Option<Uuid>,
    pub series_order: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
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
    pub publish_at: Option<DateTime<Utc>>,
    pub status: BlogStatus,
    pub locale: String,
    pub series_id: Option<Uuid>,
    pub series_order: Option<i32>,
    pub translation_group_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateBlogRequest {
    pub title: String,
    pub slug: String,
    pub summary: Option<String>,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub published: Option<bool>,
    pub tags: Option<Vec<String>>,
    /// Optional ISO-8601 timestamp. If set and in the future, the post is
    /// in the `Scheduled` state and stays hidden from the public list
    /// until the timestamp passes (no background job needed — the public
    /// list filter handles it).
    pub publish_at: Option<DateTime<Utc>>,
    pub locale: Option<String>,
    pub series_id: Option<Uuid>,
    pub series_order: Option<i32>,
    pub translation_group_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBlogRequest {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub published: Option<bool>,
    pub tags: Option<Vec<String>>,
    /// `Some(Some(ts))` to schedule, `Some(None)` to clear, `None` to leave
    /// untouched. We rely on serde's default behaviour of mapping JSON
    /// `null` to `Some(None)` so the client can explicitly cancel a
    /// scheduled publish.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    #[schema(value_type = Option<DateTime<Utc>>, nullable, required = false)]
    pub publish_at: Option<Option<DateTime<Utc>>>,
    pub locale: Option<String>,
    pub series_id: Option<Uuid>,
    pub series_order: Option<i32>,
    pub translation_group_id: Option<Uuid>,
}

/// Distinguish "key absent" (`None`) from "key present but null" (`Some(None)`)
/// for `Option<Option<T>>`. Without this, serde collapses both into `None`
/// and we lose the ability to clear the schedule.
fn deserialize_optional_field<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

pub use crate::routes::ErrorResponse;

#[derive(Debug, Serialize, utoipa::ToSchema)]
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

fn verify_auth(headers: &HeaderMap) -> Result<(), AppError> {
    require_admin(headers).map(|_| ())
}

// Several knobs are currently passed individually rather than bundled into
// a query struct because each `bind` site needs strong types. Refactor when
// we add the next parameter; for now the structure is clearer this way.
#[allow(clippy::too_many_arguments)]
async fn fetch_blog_list(
    pool: &sqlx::PgPool,
    page: i64,
    page_size: i64,
    offset: i64,
    published: Option<bool>,
    search: Option<&str>,
    tag: Option<&str>,
    series_slug: Option<&str>,
    locale: Option<&str>,
    order_clause: &str,
) -> Result<(Vec<BlogPost>, i64), sqlx::Error> {
    // Build WHERE clause + bindings dynamically. Bind indices below match
    // the order in which we push to `binds`. We never interpolate user input
    // into the SQL string — the parameterised binds keep this safe.
    let mut where_clauses: Vec<String> = Vec::new();
    let mut idx = 1usize;

    // `published` is the *public-visibility* filter: scheduled posts whose
    // time has passed must be treated as published, and explicitly-published
    // posts with a future schedule (uncommon) must be hidden until the
    // schedule fires. We collapse the bool into a public/non-public split.
    if let Some(public) = published {
        if public {
            where_clauses.push(
                "((publish_at IS NOT NULL AND publish_at <= now()) \
                  OR (publish_at IS NULL AND published = true))"
                    .to_string(),
            );
        } else {
            where_clauses.push(
                "NOT ((publish_at IS NOT NULL AND publish_at <= now()) \
                       OR (publish_at IS NULL AND published = true))"
                    .to_string(),
            );
        }
    }
    if search.is_some() {
        where_clauses.push(format!(
            "(lower(title) LIKE ${idx} OR lower(summary) LIKE ${idx})",
            idx = idx
        ));
        idx += 1;
    }
    if tag.is_some() {
        where_clauses.push(format!("${} = ANY(tags)", idx));
        idx += 1;
    }
    if series_slug.is_some() {
        where_clauses.push(format!(
            "series_id = (SELECT id FROM blog_series WHERE slug = ${idx})",
            idx = idx
        ));
        idx += 1;
    }
    if locale.is_some() {
        where_clauses.push(format!("locale = ${idx}", idx = idx));
        idx += 1;
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let limit_idx = idx;
    let offset_idx = idx + 1;

    let select_sql = format!(
        r#"SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
                  published, tags, reading_time_minutes, view_count, publish_at,
                  series_id, series_order, locale, translation_group_id, created_at, updated_at
           FROM blog_posts {where} {order} LIMIT ${limit} OFFSET ${offset}"#,
        where = where_sql,
        order = order_clause,
        limit = limit_idx,
        offset = offset_idx,
    );

    let count_sql = format!("SELECT COUNT(*) FROM blog_posts {}", where_sql);

    // Build the two queries with the same dynamic binds.
    let mut select_q = sqlx::query_as::<_, BlogPost>(&select_sql);
    let mut count_q = sqlx::query_as::<_, (i64,)>(&count_sql);

    // The `published` filter is rendered inline (no bind) above, so we
    // skip binding it here.
    if let Some(s) = search {
        select_q = select_q.bind(s.to_string());
        count_q = count_q.bind(s.to_string());
    }
    if let Some(t) = tag {
        select_q = select_q.bind(t.to_string());
        count_q = count_q.bind(t.to_string());
    }
    if let Some(s) = series_slug {
        select_q = select_q.bind(s.to_string());
        count_q = count_q.bind(s.to_string());
    }
    if let Some(l) = locale {
        select_q = select_q.bind(l.to_string());
        count_q = count_q.bind(l.to_string());
    }
    select_q = select_q.bind(page_size).bind(offset);

    let _ = page;
    let posts = select_q.fetch_all(pool).await?;
    let total = count_q.fetch_one(pool).await?.0;

    Ok((posts, total))
}

#[utoipa::path(
    get,
    path = "/api/blog",
    tag = "Blog",
    params(BlogListQuery),
    responses(
        (status = 200, description = "Paginated list of blog posts", body = BlogListResponse),
        (status = 503, description = "Database unavailable", body = ErrorResponse),
    ),
)]
pub async fn list_posts(Query(query): Query<BlogListQuery>) -> Result<impl IntoResponse, AppError> {
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

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

    let series_filter = query
        .series
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let locale_filter = query
        .locale
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase());

    let order_clause = match query.sort.as_deref() {
        Some("updated") => "ORDER BY updated_at DESC",
        Some("views") => "ORDER BY view_count DESC",
        _ => "ORDER BY created_at DESC",
    };

    let (posts, total) = fetch_blog_list(
        pool.as_ref(),
        page,
        page_size,
        offset,
        query.published,
        search_pattern.as_deref(),
        tag_filter.as_deref(),
        series_filter.as_deref(),
        locale_filter.as_deref(),
        order_clause,
    )
    .await?;

    let items: Vec<BlogPostSummary> = posts
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

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        "public, max-age=60, stale-while-revalidate=30"
            .parse()
            .unwrap(),
    );

    Ok((
        StatusCode::OK,
        headers,
        Json(BlogListResponse {
            items,
            page,
            page_size,
            total,
        }),
    )
        .into_response())
}

fn post_to_response(post: BlogPost) -> BlogPostResponse {
    let status = post.status();
    BlogPostResponse {
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
        publish_at: post.publish_at,
        status,
        locale: post.locale,
        series_id: post.series_id,
        series_order: post.series_order,
        translation_group_id: post.translation_group_id,
        created_at: post.created_at,
        updated_at: post.updated_at,
    }
}

const BLOG_POST_RETURNING: &str = r#"
        id, title, slug, summary, content_md, content_html, published, tags,
        reading_time_minutes, view_count, publish_at, series_id, series_order,
        locale, translation_group_id, created_at, updated_at
"#;

#[utoipa::path(
    get,
    path = "/api/blog/{slug}",
    tag = "Blog",
    params(
        ("slug" = String, Path, description = "URL-friendly slug"),
        BlogSlugQuery,
    ),
    responses(
        (status = 200, description = "Single blog post", body = BlogPostResponse),
        (status = 404, description = "Slug not found", body = ErrorResponse),
        (status = 503, description = "Database unavailable", body = ErrorResponse),
    ),
)]
pub async fn get_post(
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<BlogSlugQuery>,
) -> impl IntoResponse {
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

    let locale = query.locale.to_lowercase();
    if !is_valid_locale(&locale) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid locale".to_string(),
                message: None,
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

    let is_admin = require_admin(&headers).is_ok();

    let sql = if is_admin {
        format!(
            r#"
        UPDATE blog_posts SET view_count = view_count + 1, updated_at = updated_at
        WHERE slug = $1 AND locale = $2
        RETURNING {BLOG_POST_RETURNING}
        "#
        )
    } else {
        format!(
            r#"
        UPDATE blog_posts SET view_count = view_count + 1, updated_at = updated_at
        WHERE slug = $1 AND locale = $2
          AND ((publish_at IS NOT NULL AND publish_at <= now())
               OR (publish_at IS NULL AND published = true))
        RETURNING {BLOG_POST_RETURNING}
        "#
        )
    };

    match sqlx::query_as::<_, BlogPost>(&sql)
        .bind(&slug)
        .bind(&locale)
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
            (StatusCode::OK, headers, Json(post_to_response(post))).into_response()
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

#[utoipa::path(
    post,
    path = "/api/blog",
    tag = "Blog",
    security(("bearer_auth" = [])),
    request_body = CreateBlogRequest,
    responses(
        (status = 201, description = "Post created", body = BlogPostResponse),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 409, description = "Slug already exists", body = ErrorResponse),
    ),
)]
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

    let locale = payload.locale.as_deref().unwrap_or("en").to_lowercase();
    if !is_valid_locale(&locale) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid locale".to_string(),
                message: None,
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

    let insert_sql = format!(
        r#"
        INSERT INTO blog_posts (
            title, slug, summary, content_md, content_html, published, tags,
            reading_time_minutes, publish_at, locale, series_id, series_order,
            translation_group_id, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now(), now())
        RETURNING {BLOG_POST_RETURNING}
        "#
    );

    match sqlx::query_as::<_, BlogPost>(&insert_sql)
        .bind(&payload.title)
        .bind(&payload.slug)
        .bind(&payload.summary)
        .bind(&payload.content_md)
        .bind(&content_html)
        .bind(payload.published.unwrap_or(false))
        .bind(&tags)
        .bind(reading_time)
        .bind(payload.publish_at)
        .bind(&locale)
        .bind(payload.series_id)
        .bind(payload.series_order)
        .bind(payload.translation_group_id)
        .fetch_one(pool.as_ref())
        .await
    {
        Ok(post) => (StatusCode::CREATED, Json(post_to_response(post))).into_response(),
        Err(e) => {
            if e.to_string().contains("duplicate key")
                || e.to_string().contains("unique constraint")
            {
                return (
                    StatusCode::CONFLICT,
                    Json(ErrorResponse {
                        error: "Slug already exists".to_string(),
                        message: None,
                    }),
                )
                    .into_response();
            }

            tracing::error!("Database error creating blog post: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create post".to_string(),
                    message: None,
                }),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    patch,
    path = "/api/blog/{slug}",
    tag = "Blog",
    security(("bearer_auth" = [])),
    params(
        ("slug" = String, Path, description = "URL-friendly slug"),
        BlogSlugQuery,
    ),
    request_body = UpdateBlogRequest,
    responses(
        (status = 200, description = "Post updated", body = BlogPostResponse),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 404, description = "Slug not found", body = ErrorResponse),
    ),
)]
pub async fn update_post(
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<BlogSlugQuery>,
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

    let locale = query.locale.to_lowercase();
    if !is_valid_locale(&locale) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid locale".to_string(),
                message: None,
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

    // Tri-state mapping for `publish_at` so the client can leave the field
    // alone, set a new schedule, or clear an existing one:
    //   - None              → leave column unchanged via $9::BOOLEAN = false
    //   - Some(None)        → clear column (NULL)
    //   - Some(Some(ts))    → set to `ts`
    let (publish_at_value, publish_at_present): (Option<DateTime<Utc>>, bool) =
        match payload.publish_at {
            None => (None, false),
            Some(None) => (None, true),
            Some(Some(ts)) => (Some(ts), true),
        };

    let update_sql = format!(
        r#"
        UPDATE blog_posts
        SET title                = COALESCE($1, title),
            summary              = COALESCE($2, summary),
            content_md           = COALESCE($3, content_md),
            content_html         = COALESCE($4, content_html),
            published            = COALESCE($5, published),
            tags                 = COALESCE($6::TEXT[], tags),
            reading_time_minutes = COALESCE($7, reading_time_minutes),
            publish_at           = CASE WHEN $9 THEN $8 ELSE publish_at END,
            series_id            = COALESCE($10, series_id),
            series_order         = COALESCE($11, series_order),
            translation_group_id = COALESCE($12, translation_group_id),
            updated_at           = now()
        WHERE slug = $13 AND locale = $14
        RETURNING {BLOG_POST_RETURNING}
        "#
    );

    match sqlx::query_as::<_, BlogPost>(&update_sql)
        .bind(&payload.title)
        .bind(&payload.summary)
        .bind(&payload.content_md)
        .bind(&content_html_opt)
        .bind(payload.published)
        .bind(&normalized_tags)
        .bind(reading_time_opt)
        .bind(publish_at_value)
        .bind(publish_at_present)
        .bind(payload.series_id)
        .bind(payload.series_order)
        .bind(payload.translation_group_id)
        .bind(&slug)
        .bind(&locale)
        .fetch_optional(pool.as_ref())
        .await
    {
        Ok(Some(post)) => (StatusCode::OK, Json(post_to_response(post))).into_response(),
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
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/api/blog/{slug}",
    tag = "Blog",
    security(("bearer_auth" = [])),
    params(
        ("slug" = String, Path, description = "URL-friendly slug"),
        BlogSlugQuery,
    ),
    responses(
        (status = 200, description = "Post deleted", body = SuccessResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 404, description = "Slug not found", body = ErrorResponse),
    ),
)]
pub async fn delete_post(
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<BlogSlugQuery>,
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

    let locale = query.locale.to_lowercase();
    if !is_valid_locale(&locale) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid locale".to_string(),
                message: None,
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

    match sqlx::query("DELETE FROM blog_posts WHERE slug = $1 AND locale = $2")
        .bind(&slug)
        .bind(&locale)
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

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LinkTranslationRequest {
    pub slug_a: String,
    #[serde(default = "default_locale")]
    pub locale_a: String,
    pub slug_b: String,
    #[serde(default = "default_locale")]
    pub locale_b: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TranslationGroupResponse {
    pub translation_group_id: Uuid,
    pub posts: Vec<BlogPostSummary>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct TranslationGroupQuery {
    pub group_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/admin/blog/translations/link",
    tag = "Blog",
    security(("bearer_auth" = [])),
    request_body = LinkTranslationRequest,
    responses(
        (status = 200, description = "Posts linked as translations", body = TranslationGroupResponse),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 404, description = "Post not found", body = ErrorResponse),
    ),
)]
pub async fn link_translations(
    headers: HeaderMap,
    Json(payload): Json<LinkTranslationRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;

    if !is_valid_slug(&payload.slug_a) || !is_valid_slug(&payload.slug_b) {
        return Err(AppError::BadRequest("Invalid slug format".to_string()));
    }

    let locale_a = payload.locale_a.to_lowercase();
    let locale_b = payload.locale_b.to_lowercase();
    if !is_valid_locale(&locale_a) || !is_valid_locale(&locale_b) {
        return Err(AppError::BadRequest("Invalid locale".to_string()));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let post_a = sqlx::query_as::<_, BlogPost>(&format!(
        "SELECT {BLOG_POST_RETURNING} FROM blog_posts WHERE slug = $1 AND locale = $2"
    ))
    .bind(&payload.slug_a)
    .bind(&locale_a)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(AppError::NotFound)?;

    let post_b = sqlx::query_as::<_, BlogPost>(&format!(
        "SELECT {BLOG_POST_RETURNING} FROM blog_posts WHERE slug = $1 AND locale = $2"
    ))
    .bind(&payload.slug_b)
    .bind(&locale_b)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(AppError::NotFound)?;

    let group_id = post_a
        .translation_group_id
        .or(post_b.translation_group_id)
        .unwrap_or_else(Uuid::new_v4);

    sqlx::query(
        "UPDATE blog_posts SET translation_group_id = $1, updated_at = now() WHERE id = ANY($2)",
    )
    .bind(group_id)
    .bind(&[post_a.id, post_b.id][..])
    .execute(pool.as_ref())
    .await?;

    let posts = sqlx::query_as::<_, BlogPost>(
        r#"
            SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
                   published, tags, reading_time_minutes, view_count, publish_at,
                   series_id, series_order, locale, translation_group_id, created_at, updated_at
            FROM blog_posts
            WHERE translation_group_id = $1
            ORDER BY locale ASC
            "#,
    )
    .bind(group_id)
    .fetch_all(pool.as_ref())
    .await?;

    let summaries: Vec<BlogPostSummary> = posts
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
        Json(TranslationGroupResponse {
            translation_group_id: group_id,
            posts: summaries,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/admin/blog/translations",
    tag = "Blog",
    security(("bearer_auth" = [])),
    params(TranslationGroupQuery),
    responses(
        (status = 200, description = "Posts in a translation group", body = TranslationGroupResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 404, description = "Group not found", body = ErrorResponse),
    ),
)]
pub async fn get_translation_group(
    headers: HeaderMap,
    Query(query): Query<TranslationGroupQuery>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let posts = sqlx::query_as::<_, BlogPost>(
        r#"
        SELECT id, title, slug, summary, NULL::TEXT AS content_md, NULL::TEXT AS content_html,
               published, tags, reading_time_minutes, view_count, publish_at,
               series_id, series_order, locale, translation_group_id, created_at, updated_at
        FROM blog_posts
        WHERE translation_group_id = $1
        ORDER BY locale ASC
        "#,
    )
    .bind(query.group_id)
    .fetch_all(pool.as_ref())
    .await?;

    if posts.is_empty() {
        return Err(AppError::NotFound);
    }

    let summaries: Vec<BlogPostSummary> = posts
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
        Json(TranslationGroupResponse {
            translation_group_id: query.group_id,
            posts: summaries,
        }),
    ))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TagsResponse {
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TagWithCount {
    pub name: String,
    pub slug: String,
    pub post_count: i64,
}

#[utoipa::path(
    get,
    path = "/api/blog/tags",
    tag = "Blog",
    responses(
        (status = 200, description = "List of tags with usage counts", body = [TagWithCount]),
        (status = 503, description = "Database unavailable", body = ErrorResponse),
    ),
)]
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
            WHERE ((publish_at IS NOT NULL AND publish_at <= now())
                   OR (publish_at IS NULL AND published = true))
              AND array_length(tags, 1) > 0
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
            .route("/api/blog/tags", get(list_tags))
            .route(
                "/api/blog/{slug}",
                get(get_post).patch(update_post).delete(delete_post),
            )
            .layer(crate::test_support::mock_connect_info())
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
                publish_at: None,
                locale: None,
                series_id: None,
                series_order: None,
                translation_group_id: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn blog_status_derivation() {
        let now = Utc::now();
        let mk = |published: bool, publish_at: Option<DateTime<Utc>>| BlogPost {
            id: Uuid::nil(),
            title: "t".into(),
            slug: "s".into(),
            summary: None,
            content_md: None,
            content_html: None,
            published,
            tags: vec![],
            reading_time_minutes: 0,
            view_count: 0,
            publish_at,
            series_id: None,
            series_order: None,
            locale: "en".into(),
            translation_group_id: None,
            created_at: now,
            updated_at: now,
        };
        let in_future = now + chrono::Duration::days(1);
        let in_past = now - chrono::Duration::days(1);

        assert_eq!(mk(false, None).status(), BlogStatus::Draft);
        assert_eq!(mk(true, None).status(), BlogStatus::Published);
        assert_eq!(mk(false, Some(in_future)).status(), BlogStatus::Scheduled);
        assert_eq!(mk(false, Some(in_past)).status(), BlogStatus::Published);
        // Future schedule trumps an ill-advised `published=true`.
        assert_eq!(mk(true, Some(in_future)).status(), BlogStatus::Scheduled);
    }

    #[test]
    fn update_request_distinguishes_unset_from_null_publish_at() {
        // Field absent ⇒ leave unchanged.
        let absent: UpdateBlogRequest = serde_json::from_str(r#"{}"#).unwrap();
        assert!(absent.publish_at.is_none());

        // Explicit null ⇒ clear schedule.
        let cleared: UpdateBlogRequest = serde_json::from_str(r#"{"publishAt": null}"#).unwrap();
        assert_eq!(cleared.publish_at, Some(None));

        // Explicit value ⇒ set schedule.
        let set: UpdateBlogRequest =
            serde_json::from_str(r#"{"publishAt": "2030-01-01T00:00:00Z"}"#).unwrap();
        assert!(matches!(set.publish_at, Some(Some(_))));
    }

    async fn get_status_body(app: Router, uri: &str) -> (StatusCode, axum::body::Bytes) {
        let req = Request::get(uri).body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        let st = res.status();
        let b = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (st, b)
    }

    async fn post_json_auth(
        app: Router,
        uri: &str,
        bearer: Option<&str>,
        json: &impl serde::Serialize,
    ) -> (StatusCode, axum::body::Bytes) {
        let body = Body::from(serde_json::to_vec(json).unwrap());
        let mut req = Request::post(uri)
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        if let Some(b) = bearer {
            req.headers_mut().insert(
                axum::http::header::AUTHORIZATION,
                b.parse().expect("bearer header"),
            );
        }
        let res = app.oneshot(req).await.unwrap();
        let st = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (st, bytes)
    }

    async fn patch_json_auth(
        app: Router,
        uri: &str,
        bearer: &str,
        json: &impl serde::Serialize,
    ) -> (StatusCode, axum::body::Bytes) {
        let body = Body::from(serde_json::to_vec(json).unwrap());
        let req = Request::patch(uri)
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

    async fn delete_auth(app: Router, uri: &str, bearer: &str) -> StatusCode {
        let req = Request::delete(uri)
            .header(axum::http::header::AUTHORIZATION, bearer)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        res.status()
    }

    #[tokio::test]
    async fn db_blog_create_list_get_update_delete_roundtrip() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = blog_router();
        let bearer = crate::test_support::admin_bearer();
        let (st, _) = post_json_auth(
            app.clone(),
            "/api/blog",
            Some(&bearer),
            &CreateBlogRequest {
                title: "Hello DB".to_string(),
                slug: "hello-db".to_string(),
                summary: Some("S".to_string()),
                content_md: Some("one two three four five".to_string()),
                content_html: None,
                published: Some(true),
                tags: Some(vec!["alpha".to_string(), "beta".to_string()]),
                publish_at: None,
                locale: None,
                series_id: None,
                series_order: None,
                translation_group_id: None,
            },
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);

        let (st_list, list_bytes) =
            get_status_body(app.clone(), "/api/blog?page=1&pageSize=10").await;
        assert_eq!(st_list, StatusCode::OK);
        let list: BlogListResponse = serde_json::from_slice(&list_bytes).unwrap();
        assert_eq!(list.total, 1);
        assert_eq!(list.items[0].slug, "hello-db");

        let (st_get, get_bytes) = get_status_body(app.clone(), "/api/blog/hello-db").await;
        assert_eq!(st_get, StatusCode::OK);
        let post: BlogPostResponse = serde_json::from_slice(&get_bytes).unwrap();
        assert_eq!(post.reading_time_minutes, 1);

        let (st_patch, patched) = patch_json_auth(
            app.clone(),
            "/api/blog/hello-db",
            &bearer,
            &serde_json::json!({ "title": "Updated" }),
        )
        .await;
        assert_eq!(st_patch, StatusCode::OK);
        let updated: BlogPostResponse = serde_json::from_slice(&patched).unwrap();
        assert_eq!(updated.title, "Updated");

        let st_del = delete_auth(app.clone(), "/api/blog/hello-db", &bearer).await;
        assert_eq!(st_del, StatusCode::OK);

        let (st_404, _) = get_status_body(app, "/api/blog/hello-db").await;
        assert_eq!(st_404, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn db_blog_duplicate_slug_returns_conflict() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = blog_router();
        let bearer = crate::test_support::admin_bearer();
        let body = CreateBlogRequest {
            title: "A".to_string(),
            slug: "dup-slug".to_string(),
            summary: None,
            content_md: None,
            content_html: None,
            published: Some(false),
            tags: None,
            publish_at: None,
            locale: None,
            series_id: None,
            series_order: None,
            translation_group_id: None,
        };
        let (st1, _) = post_json_auth(app.clone(), "/api/blog", Some(&bearer), &body).await;
        assert_eq!(st1, StatusCode::CREATED);
        let (st2, _) = post_json_auth(app, "/api/blog", Some(&bearer), &body).await;
        assert_eq!(st2, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn db_blog_invalid_slug_on_create_returns_bad_request() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = blog_router();
        let bearer = crate::test_support::admin_bearer();
        let (st, _) = post_json_auth(
            app,
            "/api/blog",
            Some(&bearer),
            &CreateBlogRequest {
                title: "T".to_string(),
                slug: "Bad_Slug".to_string(),
                summary: None,
                content_md: None,
                content_html: None,
                published: Some(false),
                tags: None,
                publish_at: None,
                locale: None,
                series_id: None,
                series_order: None,
                translation_group_id: None,
            },
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn db_blog_html_sanitized_on_create() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = blog_router();
        let bearer = crate::test_support::admin_bearer();
        let (st, _) = post_json_auth(
            app.clone(),
            "/api/blog",
            Some(&bearer),
            &CreateBlogRequest {
                title: "HTML".to_string(),
                slug: "html-safe".to_string(),
                summary: None,
                content_md: None,
                content_html: Some("<p>x</p><script>evil()</script>".to_string()),
                published: Some(true),
                tags: None,
                publish_at: None,
                locale: None,
                series_id: None,
                series_order: None,
                translation_group_id: None,
            },
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let (_, get_bytes) = get_status_body(app, "/api/blog/html-safe").await;
        let post: BlogPostResponse = serde_json::from_slice(&get_bytes).unwrap();
        let html = post.content_html.unwrap();
        assert!(!html.to_lowercase().contains("<script"));
        assert!(html.contains("x") || html.contains("<p"));
    }

    #[tokio::test]
    async fn db_blog_tags_normalized_and_deduped() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = blog_router();
        let bearer = crate::test_support::admin_bearer();
        let (st, _) = post_json_auth(
            app.clone(),
            "/api/blog",
            Some(&bearer),
            &CreateBlogRequest {
                title: "Tags".to_string(),
                slug: "tag-norm".to_string(),
                summary: None,
                content_md: None,
                content_html: None,
                published: Some(true),
                tags: Some(vec![
                    "rust".to_string(),
                    "Rust".to_string(),
                    "  go ".to_string(),
                ]),
                publish_at: None,
                locale: None,
                series_id: None,
                series_order: None,
                translation_group_id: None,
            },
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let (_, get_bytes) = get_status_body(app, "/api/blog/tag-norm").await;
        let post: BlogPostResponse = serde_json::from_slice(&get_bytes).unwrap();
        assert_eq!(post.tags.len(), 2);
        assert!(post.tags.contains(&"Rust".to_string()));
        assert!(post.tags.contains(&"Go".to_string()));
    }

    #[tokio::test]
    async fn db_blog_scheduled_future_hidden_from_public_list() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = blog_router();
        let bearer = crate::test_support::admin_bearer();
        let future = Utc::now() + chrono::Duration::days(7);
        let (st, _) = post_json_auth(
            app.clone(),
            "/api/blog",
            Some(&bearer),
            &CreateBlogRequest {
                title: "Future".to_string(),
                slug: "future-post".to_string(),
                summary: None,
                content_md: None,
                content_html: None,
                published: Some(false),
                tags: None,
                publish_at: Some(future),
                locale: None,
                series_id: None,
                series_order: None,
                translation_group_id: None,
            },
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);

        let (_, list_bytes) =
            get_status_body(app.clone(), "/api/blog?published=true&page=1&pageSize=10").await;
        let list: BlogListResponse = serde_json::from_slice(&list_bytes).unwrap();
        assert!(
            list.items.iter().all(|i| i.slug != "future-post"),
            "scheduled future post must not appear as published"
        );

        let (_, admin_list) = get_status_body(app, "/api/blog?published=false").await;
        let draftish: BlogListResponse = serde_json::from_slice(&admin_list).unwrap();
        assert!(draftish.items.iter().any(|i| i.slug == "future-post"));
    }

    #[tokio::test]
    async fn db_get_post_draft_returns_404_public() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = blog_router();
        let bearer = crate::test_support::admin_bearer();
        let (st, _) = post_json_auth(
            app.clone(),
            "/api/blog",
            Some(&bearer),
            &CreateBlogRequest {
                title: "Secret Draft".to_string(),
                slug: "secret-draft-leak-test".to_string(),
                summary: Some("hidden".to_string()),
                content_md: Some("draft body".to_string()),
                content_html: None,
                published: Some(false),
                tags: None,
                publish_at: None,
                locale: None,
                series_id: None,
                series_order: None,
                translation_group_id: None,
            },
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);

        let (st_public, _) = get_status_body(app.clone(), "/api/blog/secret-draft-leak-test").await;
        assert_eq!(st_public, StatusCode::NOT_FOUND);

        let req = Request::get("/api/blog/secret-draft-leak-test")
            .header(axum::http::header::AUTHORIZATION, bearer)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let post: BlogPostResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(post.slug, "secret-draft-leak-test");
    }

    #[tokio::test]
    async fn db_blog_list_tags_counts_published() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = blog_router();
        let bearer = crate::test_support::admin_bearer();
        let (st, _) = post_json_auth(
            app.clone(),
            "/api/blog",
            Some(&bearer),
            &CreateBlogRequest {
                title: "Tagged".to_string(),
                slug: "tagged-one".to_string(),
                summary: None,
                content_md: None,
                content_html: None,
                published: Some(true),
                tags: Some(vec!["News".to_string()]),
                publish_at: None,
                locale: None,
                series_id: None,
                series_order: None,
                translation_group_id: None,
            },
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);

        let (_, tags_bytes) = get_status_body(app, "/api/blog/tags").await;
        let tags: Vec<TagWithCount> = serde_json::from_slice(&tags_bytes).unwrap();
        let news = tags.iter().find(|t| t.name == "News");
        assert!(news.is_some());
        assert!(news.unwrap().post_count >= 1);
    }

    #[tokio::test]
    async fn db_blog_locale_filter_and_same_slug_different_locales() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = blog_router();
        let bearer = crate::test_support::admin_bearer();

        for (locale, title) in [("en", "English"), ("id", "Indonesian")] {
            let (st, _) = post_json_auth(
                app.clone(),
                "/api/blog",
                Some(&bearer),
                &CreateBlogRequest {
                    title: title.to_string(),
                    slug: "i18n-post".to_string(),
                    summary: None,
                    content_md: None,
                    content_html: None,
                    published: Some(true),
                    tags: None,
                    publish_at: None,
                    locale: Some(locale.to_string()),
                    series_id: None,
                    series_order: None,
                    translation_group_id: None,
                },
            )
            .await;
            assert_eq!(st, StatusCode::CREATED, "locale={locale}");
        }

        let (_, en_bytes) = get_status_body(app.clone(), "/api/blog/i18n-post?locale=en").await;
        let en: BlogPostResponse = serde_json::from_slice(&en_bytes).unwrap();
        assert_eq!(en.title, "English");

        let (_, id_bytes) = get_status_body(app.clone(), "/api/blog/i18n-post?locale=id").await;
        let id_post: BlogPostResponse = serde_json::from_slice(&id_bytes).unwrap();
        assert_eq!(id_post.title, "Indonesian");

        let (_, list_bytes) =
            get_status_body(app.clone(), "/api/blog?locale=id&published=true").await;
        let list: BlogListResponse = serde_json::from_slice(&list_bytes).unwrap();
        assert!(list.items.iter().all(|i| i.locale == "id"));
    }

    #[tokio::test]
    async fn db_blog_link_translations() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = Router::new()
            .route("/api/admin/blog/translations/link", post(link_translations))
            .route("/api/admin/blog/translations", get(get_translation_group))
            .route("/api/blog", post(create_post))
            .layer(crate::test_support::mock_connect_info());
        let bearer = crate::test_support::admin_bearer();

        for (locale, slug, title) in [("en", "link-en", "Link EN"), ("id", "link-id", "Link ID")] {
            let (st, _) = post_json_auth(
                app.clone(),
                "/api/blog",
                Some(&bearer),
                &CreateBlogRequest {
                    title: title.to_string(),
                    slug: slug.to_string(),
                    summary: None,
                    content_md: None,
                    content_html: None,
                    published: Some(true),
                    tags: None,
                    publish_at: None,
                    locale: Some(locale.to_string()),
                    series_id: None,
                    series_order: None,
                    translation_group_id: None,
                },
            )
            .await;
            assert_eq!(st, StatusCode::CREATED);
        }

        let body = Body::from(
            serde_json::to_vec(&LinkTranslationRequest {
                slug_a: "link-en".to_string(),
                locale_a: "en".to_string(),
                slug_b: "link-id".to_string(),
                locale_b: "id".to_string(),
            })
            .unwrap(),
        );
        let req = Request::post("/api/admin/blog/translations/link")
            .header("content-type", "application/json")
            .header(axum::http::header::AUTHORIZATION, bearer.clone())
            .body(body)
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let group: TranslationGroupResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(group.posts.len(), 2);
        assert!(group.translation_group_id != Uuid::nil());

        // Test fetching the translation group
        let req_get = Request::get(format!(
            "/api/admin/blog/translations?groupId={}",
            group.translation_group_id
        ))
        .header(axum::http::header::AUTHORIZATION, bearer.clone())
        .body(Body::empty())
        .unwrap();
        let res_get = app.clone().oneshot(req_get).await.unwrap();
        assert_eq!(res_get.status(), StatusCode::OK);
        let bytes_get = axum::body::to_bytes(res_get.into_body(), usize::MAX)
            .await
            .unwrap();
        let fetched_group: TranslationGroupResponse = serde_json::from_slice(&bytes_get).unwrap();
        assert_eq!(
            fetched_group.translation_group_id,
            group.translation_group_id
        );
        assert_eq!(fetched_group.posts.len(), 2);

        // Test fetching non-existent translation group -> 404
        let req_404 = Request::get(format!(
            "/api/admin/blog/translations?groupId={}",
            Uuid::new_v4()
        ))
        .header(axum::http::header::AUTHORIZATION, bearer)
        .body(Body::empty())
        .unwrap();
        let res_404 = app.oneshot(req_404).await.unwrap();
        assert_eq!(res_404.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn db_blog_list_filters() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = Router::new()
            .route("/api/blog", get(list_posts))
            .route("/api/blog", post(create_post))
            .layer(crate::test_support::mock_connect_info());
        let bearer = crate::test_support::admin_bearer();

        for (title, slug, tag, sort_views, locale) in [
            ("Alpha Post", "alpha", "rust", 10, "en"),
            ("Beta Post", "beta", "rust", 5, "en"),
            ("Gamma Post", "gamma", "typescript", 2, "id"),
        ] {
            let (st, bytes) = post_json_auth(
                app.clone(),
                "/api/blog",
                Some(&bearer),
                &CreateBlogRequest {
                    title: title.to_string(),
                    slug: slug.to_string(),
                    summary: None,
                    content_md: None,
                    content_html: None,
                    published: Some(true),
                    tags: Some(vec![tag.to_string()]),
                    publish_at: None,
                    locale: Some(locale.to_string()),
                    series_id: None,
                    series_order: None,
                    translation_group_id: None,
                },
            )
            .await;
            assert_eq!(st, StatusCode::CREATED);

            let created: BlogPostResponse = serde_json::from_slice(&bytes).unwrap();
            let pool = db::get_pool().unwrap();
            sqlx::query("UPDATE blog_posts SET view_count = $1 WHERE id = $2")
                .bind(sort_views)
                .bind(created.id)
                .execute(pool.as_ref())
                .await
                .unwrap();
        }

        let (_, bytes) = get_status_body(app.clone(), "/api/blog?tag=Rust&published=true").await;
        let res: BlogListResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(res.total, 2);

        let (_, bytes) =
            get_status_body(app.clone(), "/api/blog?search=Alpha&published=true").await;
        let res: BlogListResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(res.total, 1);
        assert_eq!(res.items[0].slug, "alpha");

        let (_, bytes) = get_status_body(app.clone(), "/api/blog?sort=views&published=true").await;
        let res: BlogListResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(res.items[0].slug, "alpha");
        assert_eq!(res.items[1].slug, "beta");

        let (_, bytes) =
            get_status_body(app.clone(), "/api/blog?sort=updated&published=true").await;
        let res: BlogListResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!res.items.is_empty());
    }
}

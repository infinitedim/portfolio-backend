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
use crate::routes::translation;
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

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExperienceQuery {
    #[serde(default = "default_locale")]
    pub locale: String,
}

fn default_locale() -> String {
    "en_US".to_string()
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateExperienceRequest {
    pub company: String,
    pub position: String,
    pub duration: String,
    pub description: Vec<String>,
    pub technologies: Vec<String>,
    #[serde(default = "default_type")]
    #[serde(rename = "type")]
    pub experience_type: String,
    #[serde(default)]
    pub display_order: i32,
}

fn default_type() -> String {
    "full-time".to_string()
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateExperienceRequest {
    pub company: Option<String>,
    pub position: Option<String>,
    pub duration: Option<String>,
    pub description: Option<Vec<String>>,
    pub technologies: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub experience_type: Option<String>,
    pub display_order: Option<i32>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LocaleOverrideRequest {
    pub position: Option<String>,
    pub duration: Option<String>,
    pub description: Option<Vec<String>>,
}

pub const VALID_SECTIONS: &[&str] = &["skills", "projects", "experience", "about"];

pub fn is_valid_section(section: &str) -> bool {
    VALID_SECTIONS.contains(&section.to_lowercase().as_str())
}

static STATIC_PROJECTS: Lazy<Value> = Lazy::new(|| {
    serde_json::json!([
      {
        "id": "terminal-portfolio",
        "name": "Terminal Portfolio",
        "description": "Portfolio interaktif bergaya terminal dengan Next.js 15, Rust/Axum backend, gate system berbasis OverTheWire Natas, dan observability stack lengkap (Grafana, Loki, Prometheus).",
        "technologies": ["Next.js", "TypeScript", "Rust", "Axum", "PostgreSQL", "Tailwind CSS"],
        "demoUrl": "https://infinitedim.dev",
        "githubUrl": "https://github.com/infinitedim/portfolio-frontend",
        "status": "active",
        "featured": true
      },
      {
        "id": "medmind",
        "name": "MedMind",
        "description": "Aplikasi jurnal kesehatan Flutter berbasis privacy-first dengan on-device ML (TFLite). Arsitektur Clean Architecture + Riverpod, pipeline ML Python/TensorFlow untuk symptom correlation dan NLP extraction.",
        "technologies": ["Flutter", "TensorFlow", "TFLite", "Python", "Riverpod", "Clean Architecture"],
        "githubUrl": "https://github.com/infinitedim/medmind",
        "status": "in-progress",
        "featured": true
      },
      {
        "id": "devix-store",
        "name": "Devix Digital Store",
        "description": "Platform penjualan produk digital untuk SMB dengan Next.js 16 App Router, Prisma, Supabase, dual payment provider (Stripe + Lemon Squeezy) behind feature flag, dan Upstash Redis untuk rate limiting.",
        "technologies": ["Next.js", "TypeScript", "Prisma", "Supabase", "Stripe", "Upstash Redis"],
        "status": "in-progress",
        "featured": false
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
        "bio": "A software developer with nearly three years of professional experience, specializing in cross-platform mobile development with Flutter. Currently building and maintaining a B2B travel agent platform at PT Voltras International, with hands-on experience across the full development lifecycle — from mobile UI to API integration and production deployment. Outside of work, actively developing personal projects using Rust/Axum and Next.js to broaden backend and web expertise.",
        "contact": {
            "email": "dragdimas9@gmail.com",
            "github": "https://github.com/infinitedim"
        }
    })
});

pub fn get_static_data(section: &str) -> Option<Value> {
    match section.to_lowercase().as_str() {
        "projects" => Some(STATIC_PROJECTS.clone()),
        "skills" => Some(STATIC_SKILLS.clone()),
        "experience" => Some(serde_json::json!([
            {
                "company": "PT Voltras International",
                "position": "Software Developer",
                "duration": "June 2023 - Present",
                "description": [
                    "Developed and maintained cross-platform mobile applications for a B2B travel agent platform",
                    "Engineered a reusable seat mapping system adaptable across multiple layout types",
                    "Implemented role-based access control with dynamic menu configuration served via CDN",
                    "Collaborated with cross-functional teams in an agile environment"
                ],
                "technologies": ["Flutter", "Kubernetes", "Grafana", "Loki", "Prometheus", "Firebase"],
                "type": "full-time"
            },
            {
                "company": "PT Qtera Mandiri",
                "position": "Web Content Writer",
                "duration": "January 2021 - April 2021",
                "description": [
                    "Produced SEO-optimized web content for a technology company",
                    "Demonstrated adaptability in tone and audience targeting"
                ],
                "technologies": ["Blogging", "SEO", "Content Writing", "Teamwork", "Communication", "Adaptability"],
                "type": "intern"
            }
        ])),
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
// ---- Experience CRUD with i18n ----

use moka::future::Cache as MokaCache;
use std::sync::Arc;
use std::time::Duration;

static EXPERIENCE_CACHE: once_cell::sync::Lazy<Arc<MokaCache<String, Value>>> =
    once_cell::sync::Lazy::new(|| {
        Arc::new(
            MokaCache::builder()
                .max_capacity(100)
                .time_to_live(Duration::from_secs(300))
                .build(),
        )
    });

fn invalidate_experience_cache() {
    // Invalidate all cached locale variants
    EXPERIENCE_CACHE.invalidate_all();
}

/// GET /api/portfolio/experience?locale=en_US
/// Returns experience list with fields resolved to the requested locale.
pub async fn get_experience_i18n(Query(query): Query<ExperienceQuery>) -> impl IntoResponse {
    let locale = query.locale;
    let cache_key = format!("experience:{}", locale);

    // Check cache first
    if let Some(cached) = EXPERIENCE_CACHE.get(&cache_key).await {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CACHE_CONTROL,
            "public, max-age=300, stale-while-revalidate=60"
                .parse()
                .unwrap(),
        );
        return (
            StatusCode::OK,
            headers,
            Json(PortfolioResponse {
                data: Some(cached),
                error: None,
            }),
        )
            .into_response();
    }

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            // Fallback to static data when DB unavailable
            let static_data = get_static_data("experience").unwrap_or(Value::Array(vec![]));
            return (
                StatusCode::OK,
                axum::http::HeaderMap::new(),
                Json(PortfolioResponse {
                    data: Some(static_data),
                    error: None,
                }),
            )
                .into_response();
        }
    };

    match sqlx::query_as::<_, db::models::PortfolioExperience>(
        "SELECT * FROM portfolio_experiences ORDER BY display_order ASC, created_at DESC",
    )
    .fetch_all(pool.as_ref())
    .await
    {
        Ok(experiences) if !experiences.is_empty() => {
            let resolved: Vec<Value> = experiences
                .iter()
                .map(|exp| resolve_experience_locale(exp, &locale))
                .collect();
            let data = Value::Array(resolved);

            // Cache the result
            EXPERIENCE_CACHE.insert(cache_key, data.clone()).await;

            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::CACHE_CONTROL,
                "public, max-age=300, stale-while-revalidate=60"
                    .parse()
                    .unwrap(),
            );
            (
                StatusCode::OK,
                headers,
                Json(PortfolioResponse {
                    data: Some(data),
                    error: None,
                }),
            )
                .into_response()
        }
        Ok(_) => {
            // Empty DB — return static fallback
            let static_data = get_static_data("experience").unwrap_or(Value::Array(vec![]));
            (
                StatusCode::OK,
                axum::http::HeaderMap::new(),
                Json(PortfolioResponse {
                    data: Some(static_data),
                    error: None,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to fetch experiences: {}", e);
            let static_data = get_static_data("experience").unwrap_or(Value::Array(vec![]));
            (
                StatusCode::OK,
                axum::http::HeaderMap::new(),
                Json(PortfolioResponse {
                    data: Some(static_data),
                    error: None,
                }),
            )
                .into_response()
        }
    }
}

/// Resolve JSONB locale fields to flat strings for the given locale, with fallback to en_US.
fn resolve_experience_locale(exp: &db::models::PortfolioExperience, locale: &str) -> Value {
    let position = resolve_locale_string(&exp.position, locale);
    let duration = resolve_locale_string(&exp.duration, locale);
    let description = resolve_locale_array(&exp.description, locale);

    serde_json::json!({
        "company": exp.company,
        "position": position,
        "duration": duration,
        "description": description,
        "technologies": exp.technologies,
        "type": exp.experience_type,
    })
}

fn resolve_locale_string(jsonb: &Value, locale: &str) -> String {
    // Try exact locale
    if let Some(s) = jsonb.get(locale).and_then(|v| v.as_str()) {
        return s.to_string();
    }
    // Fallback to en_US
    if let Some(s) = jsonb.get("en_US").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    // Fallback to first available
    if let Some(obj) = jsonb.as_object() {
        if let Some((_, v)) = obj.iter().next() {
            if let Some(s) = v.as_str() {
                return s.to_string();
            }
        }
    }
    // If the value itself is a plain string (non-JSONB migrated data)
    jsonb.as_str().unwrap_or_default().to_string()
}

fn resolve_locale_array(jsonb: &Value, locale: &str) -> Vec<String> {
    // Try exact locale
    if let Some(arr) = jsonb.get(locale).and_then(|v| v.as_array()) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    // Fallback to en_US
    if let Some(arr) = jsonb.get("en_US").and_then(|v| v.as_array()) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    // Fallback to first available
    if let Some(obj) = jsonb.as_object() {
        if let Some((_, v)) = obj.iter().next() {
            if let Some(arr) = v.as_array() {
                return arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }
        }
    }
    // If the value itself is an array (non-JSONB migrated data)
    if let Some(arr) = jsonb.as_array() {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    vec![]
}

/// POST /api/admin/portfolio/experience — create new experience with AI translation.
pub async fn create_experience(
    headers: HeaderMap,
    Json(payload): Json<CreateExperienceRequest>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    // Try AI translation if Gemini is available
    let (position_jsonb, duration_jsonb, description_jsonb) = match std::env::var("GEMINI_API_KEY")
        .ok()
        .filter(|k| !k.is_empty())
    {
        Some(api_key) => {
            let client = reqwest::Client::new();
            match translation::translate_experience(
                &client,
                &api_key,
                &payload.position,
                &payload.duration,
                &payload.description,
            )
            .await
            {
                Ok(translated) => (
                    translated.position,
                    translated.duration,
                    translated.description,
                ),
                Err(e) => {
                    tracing::warn!("AI translation failed, storing English only: {}", e);
                    (
                        serde_json::json!({ "en_US": payload.position }),
                        serde_json::json!({ "en_US": payload.duration }),
                        serde_json::json!({ "en_US": payload.description }),
                    )
                }
            }
        }
        None => {
            tracing::info!("GEMINI_API_KEY not set, storing English only");
            (
                serde_json::json!({ "en_US": payload.position }),
                serde_json::json!({ "en_US": payload.duration }),
                serde_json::json!({ "en_US": payload.description }),
            )
        }
    };

    let row = sqlx::query_as::<_, db::models::PortfolioExperience>(
        r#"
        INSERT INTO portfolio_experiences (company, position, duration, description, technologies, type, display_order)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(&payload.company)
    .bind(&position_jsonb)
    .bind(&duration_jsonb)
    .bind(&description_jsonb)
    .bind(&payload.technologies)
    .bind(&payload.experience_type)
    .bind(payload.display_order)
    .fetch_one(pool.as_ref())
    .await?;

    invalidate_experience_cache();

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "success": true,
            "data": {
                "id": row.id,
                "company": row.company,
                "position": row.position,
                "duration": row.duration,
                "description": row.description,
                "technologies": row.technologies,
                "type": row.experience_type,
                "display_order": row.display_order,
            }
        })),
    ))
}

/// PATCH /api/admin/portfolio/experience/:id — update experience & re-translate.
pub async fn update_experience(
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateExperienceRequest>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    // Fetch existing
    let existing = sqlx::query_as::<_, db::models::PortfolioExperience>(
        "SELECT * FROM portfolio_experiences WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(crate::routes::AppError::NotFound)?;

    let company = payload.company.unwrap_or(existing.company);
    let technologies = payload.technologies.unwrap_or(existing.technologies);
    let experience_type = payload.experience_type.unwrap_or(existing.experience_type);
    let display_order = payload.display_order.unwrap_or(existing.display_order);

    // If position/duration/description changed, re-translate
    let needs_retranslation =
        payload.position.is_some() || payload.duration.is_some() || payload.description.is_some();

    let position_en = payload
        .position
        .unwrap_or_else(|| resolve_locale_string(&existing.position, "en_US"));
    let duration_en = payload
        .duration
        .unwrap_or_else(|| resolve_locale_string(&existing.duration, "en_US"));
    let description_en = payload
        .description
        .unwrap_or_else(|| resolve_locale_array(&existing.description, "en_US"));

    let (position_jsonb, duration_jsonb, description_jsonb) = if needs_retranslation {
        match std::env::var("GEMINI_API_KEY")
            .ok()
            .filter(|k| !k.is_empty())
        {
            Some(api_key) => {
                let client = reqwest::Client::new();
                match translation::translate_experience(
                    &client,
                    &api_key,
                    &position_en,
                    &duration_en,
                    &description_en,
                )
                .await
                {
                    Ok(translated) => (
                        translated.position,
                        translated.duration,
                        translated.description,
                    ),
                    Err(e) => {
                        tracing::warn!("AI re-translation failed: {}", e);
                        (
                            serde_json::json!({ "en_US": position_en }),
                            serde_json::json!({ "en_US": duration_en }),
                            serde_json::json!({ "en_US": description_en }),
                        )
                    }
                }
            }
            None => (
                serde_json::json!({ "en_US": position_en }),
                serde_json::json!({ "en_US": duration_en }),
                serde_json::json!({ "en_US": description_en }),
            ),
        }
    } else {
        (existing.position, existing.duration, existing.description)
    };

    let row = sqlx::query_as::<_, db::models::PortfolioExperience>(
        r#"
        UPDATE portfolio_experiences
        SET company = $1, position = $2, duration = $3, description = $4,
            technologies = $5, type = $6, display_order = $7, updated_at = NOW()
        WHERE id = $8
        RETURNING *
        "#,
    )
    .bind(&company)
    .bind(&position_jsonb)
    .bind(&duration_jsonb)
    .bind(&description_jsonb)
    .bind(&technologies)
    .bind(&experience_type)
    .bind(display_order)
    .bind(id)
    .fetch_one(pool.as_ref())
    .await?;

    invalidate_experience_cache();

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "data": {
                "id": row.id,
                "company": row.company,
                "position": row.position,
                "duration": row.duration,
                "description": row.description,
                "technologies": row.technologies,
                "type": row.experience_type,
                "display_order": row.display_order,
            }
        })),
    ))
}

/// DELETE /api/admin/portfolio/experience/:id
pub async fn delete_experience(
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let result = sqlx::query("DELETE FROM portfolio_experiences WHERE id = $1")
        .bind(id)
        .execute(pool.as_ref())
        .await?;

    if result.rows_affected() == 0 {
        return Err(crate::routes::AppError::NotFound);
    }

    invalidate_experience_cache();

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": "Experience deleted"
        })),
    ))
}

/// PATCH /api/admin/portfolio/experience/:id/locale/:locale — manual override for a specific locale.
pub async fn override_experience_locale(
    headers: HeaderMap,
    Path((id, locale)): Path<(Uuid, String)>,
    Json(payload): Json<LocaleOverrideRequest>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let existing = sqlx::query_as::<_, db::models::PortfolioExperience>(
        "SELECT * FROM portfolio_experiences WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(crate::routes::AppError::NotFound)?;

    let mut position = existing.position.clone();
    let mut duration = existing.duration.clone();
    let mut description = existing.description.clone();

    if let Some(pos) = &payload.position {
        if let Some(obj) = position.as_object_mut() {
            obj.insert(locale.clone(), Value::String(pos.clone()));
        }
    }
    if let Some(dur) = &payload.duration {
        if let Some(obj) = duration.as_object_mut() {
            obj.insert(locale.clone(), Value::String(dur.clone()));
        }
    }
    if let Some(desc) = &payload.description {
        if let Some(obj) = description.as_object_mut() {
            let arr: Vec<Value> = desc.iter().map(|s| Value::String(s.clone())).collect();
            obj.insert(locale.clone(), Value::Array(arr));
        }
    }

    sqlx::query(
        r#"
        UPDATE portfolio_experiences
        SET position = $1, duration = $2, description = $3, updated_at = NOW()
        WHERE id = $4
        "#,
    )
    .bind(&position)
    .bind(&duration)
    .bind(&description)
    .bind(id)
    .execute(pool.as_ref())
    .await?;

    invalidate_experience_cache();

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": format!("Locale '{}' updated for experience", locale)
        })),
    ))
}

/// GET /api/admin/portfolio/experience — list all experiences with ALL locale data (admin view).
pub async fn list_experiences_admin(
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let experiences = sqlx::query_as::<_, db::models::PortfolioExperience>(
        "SELECT * FROM portfolio_experiences ORDER BY display_order ASC, created_at DESC",
    )
    .fetch_all(pool.as_ref())
    .await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "data": experiences
        })),
    ))
}

/// Seed static experience data into the database on first run (if table is empty).
pub async fn seed_experience_data(pool: &sqlx::PgPool) {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM portfolio_experiences")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    if count > 0 {
        tracing::info!(
            "portfolio_experiences already has {} rows, skipping seed",
            count
        );
        return;
    }

    tracing::info!("Seeding portfolio_experiences with static data...");

    let static_entries = get_static_data("experience");
    if let Some(Value::Array(entries)) = static_entries {
        for (i, entry) in entries.iter().enumerate() {
            let company = entry.get("company").and_then(|v| v.as_str()).unwrap_or("");
            let position_en = entry.get("position").and_then(|v| v.as_str()).unwrap_or("");
            let duration_en = entry.get("duration").and_then(|v| v.as_str()).unwrap_or("");
            let description_en: Vec<String> = entry
                .get("description")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let technologies: Vec<String> = entry
                .get("technologies")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let exp_type = entry
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("full-time");

            // Store with en_US locale only for seed data
            let position_jsonb = serde_json::json!({ "en_US": position_en });
            let duration_jsonb = serde_json::json!({ "en_US": duration_en });
            let description_jsonb = serde_json::json!({ "en_US": description_en });

            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO portfolio_experiences (company, position, duration, description, technologies, type, display_order)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
            )
            .bind(company)
            .bind(&position_jsonb)
            .bind(&duration_jsonb)
            .bind(&description_jsonb)
            .bind(&technologies)
            .bind(exp_type)
            .bind(i as i32)
            .execute(pool)
            .await
            {
                tracing::error!("Failed to seed experience entry: {}", e);
            }
        }

        tracing::info!("Seeded {} experience entries", entries.len());
    }
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
                    section: "skills".to_string(),
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

        let req = Request::get("/api/admin/portfolio/versions?section=skills")
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

        let (_, body) = get_json::<PortfolioResponse>(app, "/api/portfolio?section=skills").await;
        assert_eq!(body.data, Some(v1));
    }
}

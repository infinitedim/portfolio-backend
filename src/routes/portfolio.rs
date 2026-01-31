/**
 * Portfolio Routes
 * API endpoints for portfolio data (skills, projects, experience, about)
 */
use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::{self, models::PortfolioSection};
use crate::routes::auth::verify_access_token;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Query parameters for GET /api/portfolio
#[derive(Debug, Deserialize)]
pub struct PortfolioQuery {
    pub section: String,
}

/// Response for GET /api/portfolio
#[derive(Debug, Serialize)]
pub struct PortfolioResponse {
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Request body for PATCH /api/portfolio
#[derive(Debug, Deserialize)]
pub struct UpdatePortfolioRequest {
    pub section: String,
    pub data: Value,
}

/// Response for PATCH /api/portfolio
#[derive(Debug, Serialize)]
pub struct UpdatePortfolioResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// Validation
// ============================================================================

/// Valid section keys
const VALID_SECTIONS: &[&str] = &["skills", "projects", "experience", "about"];

fn is_valid_section(section: &str) -> bool {
    VALID_SECTIONS.contains(&section.to_lowercase().as_str())
}

// ============================================================================
// Static/Fallback Data
// ============================================================================

/// Get static/fallback data for a section
fn get_static_data(section: &str) -> Option<Value> {
    match section.to_lowercase().as_str() {
        "projects" => Some(serde_json::json!([
            {
                "id": "portfolio-website",
                "name": "Portfolio Website",
                "description": "A modern portfolio website built with Next.js and Rust",
                "technologies": ["Next.js", "React", "TypeScript", "Rust", "Axum"],
                "status": "active",
                "featured": true
            }
        ])),
        "skills" => Some(serde_json::json!([
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
        ])),
        "experience" => Some(serde_json::json!([])),
        "about" => Some(serde_json::json!({
            "name": "Developer",
            "title": "Full Stack Developer",
            "bio": "A passionate developer building modern web applications.",
            "location": "Remote",
            "contact": {
                "email": "dev@example.com",
                "github": "https://github.com/developer"
            }
        })),
        _ => None,
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /api/portfolio?section=...
/// Returns portfolio data for the specified section
pub async fn get_portfolio(Query(query): Query<PortfolioQuery>) -> impl IntoResponse {
    // Validate section
    if query.section.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PortfolioResponse {
                data: None,
                error: Some("Missing section parameter".to_string()),
            }),
        );
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
        );
    }

    let section_key = query.section.to_lowercase();

    // Try to get data from database
    if let Some(pool) = db::get_pool() {
        match sqlx::query_as::<_, PortfolioSection>(
            "SELECT key, content, updated_at FROM portfolio_sections WHERE key = $1",
        )
        .bind(&section_key)
        .fetch_optional(pool.as_ref())
        .await
        {
            Ok(Some(section)) => {
                return (
                    StatusCode::OK,
                    Json(PortfolioResponse {
                        data: Some(section.content),
                        error: None,
                    }),
                );
            }
            Ok(None) => {
                // Section not found in DB, return static data
                tracing::debug!(
                    "Section '{}' not found in database, using static data",
                    section_key
                );
            }
            Err(e) => {
                tracing::error!("Database error fetching portfolio section: {}", e);
                // Fall through to static data
            }
        }
    }

    // Return static/fallback data
    match get_static_data(&section_key) {
        Some(data) => (
            StatusCode::OK,
            Json(PortfolioResponse {
                data: Some(data),
                error: None,
            }),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(PortfolioResponse {
                data: None,
                error: Some("Section not found".to_string()),
            }),
        ),
    }
}

/// PATCH /api/portfolio
/// Updates portfolio data for the specified section (requires auth)
pub async fn update_portfolio(
    headers: HeaderMap,
    Json(payload): Json<UpdatePortfolioRequest>,
) -> impl IntoResponse {
    // Extract and verify token
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

    // Verify token
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

    // Validate section
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

    // Update in database
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

    // Upsert the section
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

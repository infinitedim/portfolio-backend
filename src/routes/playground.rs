//! Live coding playground — admin creates snippets, public reads by id.

use axum::{
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{self, models::PlaygroundSnippet};
use crate::routes::auth::require_admin;
use crate::routes::AppError;

const MAX_TITLE_LEN: usize = 200;
const MAX_LANGUAGE_LEN: usize = 50;
const MAX_CODE_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateSnippetRequest {
    pub title: String,
    #[serde(default = "default_language")]
    pub language: String,
    pub code: String,
}

fn default_language() -> String {
    "javascript".to_string()
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnippetResponse {
    pub id: Uuid,
    pub title: String,
    pub language: String,
    pub code: String,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

impl From<PlaygroundSnippet> for SnippetResponse {
    fn from(s: PlaygroundSnippet) -> Self {
        Self {
            id: s.id,
            title: s.title,
            language: s.language,
            code: s.code,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

fn validate_create(req: &CreateSnippetRequest) -> Result<(), AppError> {
    let title = req.title.trim();
    if title.is_empty() || title.len() > MAX_TITLE_LEN {
        return Err(AppError::BadRequest(format!(
            "title must be 1..={} characters",
            MAX_TITLE_LEN
        )));
    }
    let language = req.language.trim();
    if language.is_empty() || language.len() > MAX_LANGUAGE_LEN {
        return Err(AppError::BadRequest(format!(
            "language must be 1..={} characters",
            MAX_LANGUAGE_LEN
        )));
    }
    if req.code.len() > MAX_CODE_BYTES {
        return Err(AppError::BadRequest(format!(
            "code must be ≤ {} bytes",
            MAX_CODE_BYTES
        )));
    }
    if req.code.trim().is_empty() {
        return Err(AppError::BadRequest("code must not be empty".to_string()));
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/playground/snippets",
    tag = "Playground",
    security(("bearer_auth" = [])),
    request_body = CreateSnippetRequest,
    responses(
        (status = 201, description = "Snippet created", body = SnippetResponse),
        (status = 400, description = "Validation failed"),
        (status = 401, description = "Unauthorized"),
    ),
)]
pub async fn create_snippet(
    headers: HeaderMap,
    Json(payload): Json<CreateSnippetRequest>,
) -> Result<impl IntoResponse, AppError> {
    let _admin = require_admin(&headers)?;
    validate_create(&payload)?;

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let now = Utc::now();
    let id = Uuid::new_v4();

    let snippet = sqlx::query_as::<_, PlaygroundSnippet>(
        r#"
        INSERT INTO playground_snippets (id, title, language, code, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $5)
        RETURNING id, title, language, code, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(payload.title.trim())
    .bind(payload.language.trim())
    .bind(&payload.code)
    .bind(now)
    .fetch_one(pool.as_ref())
    .await?;

    Ok((StatusCode::CREATED, Json(SnippetResponse::from(snippet))))
}

#[utoipa::path(
    get,
    path = "/api/playground/snippets/{id}",
    tag = "Playground",
    params(("id" = Uuid, Path, description = "Snippet id")),
    responses(
        (status = 200, description = "Snippet found", body = SnippetResponse),
        (status = 404, description = "Not found"),
    ),
)]
pub async fn get_snippet(Path(id): Path<Uuid>) -> Result<impl IntoResponse, AppError> {
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let snippet = sqlx::query_as::<_, PlaygroundSnippet>(
        r#"
        SELECT id, title, language, code, created_at, updated_at
        FROM playground_snippets
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(AppError::NotFound)?;

    Ok(Json(SnippetResponse::from(snippet)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_oversized_code() {
        let req = CreateSnippetRequest {
            title: "Demo".to_string(),
            language: "rust".to_string(),
            code: "x".repeat(MAX_CODE_BYTES + 1),
        };
        assert!(validate_create(&req).is_err());
    }

    #[test]
    fn validate_accepts_reasonable_payload() {
        let req = CreateSnippetRequest {
            title: "Hello".to_string(),
            language: "javascript".to_string(),
            code: "console.log('hi')".to_string(),
        };
        assert!(validate_create(&req).is_ok());
    }
}

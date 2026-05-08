//! Public contact-form endpoint and admin inbox handlers.
//!
//! `POST /api/contact` is the *only* public-write endpoint in the backend
//! that doesn't require auth, so it gets aggressive validation, length
//! caps, and (separately, in `lib.rs`) a dedicated `tower-governor` rate
//! limit. The remaining endpoints (`GET/PATCH/DELETE /api/admin/messages`)
//! require admin role.
//!
//! Email delivery is best-effort — we *persist* the message regardless of
//! whether the operator notification succeeds, so admins never miss inbox
//! entries because of a transient mail outage.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::{self, models::ContactMessage};
use crate::email::Mailer;
use crate::routes::auth::require_admin;
use crate::routes::{AppError, ErrorResponse};

/// Field length caps. Mirrors the column definitions in `db::run_migrations`
/// and is enforced server-side regardless of what the client sends. We
/// intentionally keep these tighter than the columns allow so that any
/// future schema relaxation doesn't silently widen our attack surface.
const MAX_NAME_LEN: usize = 100;
const MAX_EMAIL_LEN: usize = 254; // RFC 5321
const MAX_SUBJECT_LEN: usize = 200;
const MIN_MESSAGE_LEN: usize = 10;
const MAX_MESSAGE_LEN: usize = 5000;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateContactMessage {
    pub name: String,
    pub email: String,
    #[serde(default)]
    pub subject: Option<String>,
    pub message: String,
    /// Honeypot field. Real browsers will never fill this; bots usually do.
    /// If non-empty we accept the request (so the bot doesn't retry) but
    /// drop the message silently.
    #[serde(default)]
    pub website: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContactMessageResponse {
    pub id: Uuid,
    pub success: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdminContactMessage {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub subject: Option<String>,
    pub message: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub read: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<ContactMessage> for AdminContactMessage {
    fn from(m: ContactMessage) -> Self {
        Self {
            id: m.id,
            name: m.name,
            email: m.email,
            subject: m.subject,
            message: m.message,
            ip_address: m.ip_address,
            user_agent: m.user_agent,
            read: m.read,
            created_at: m.created_at,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdminMessagesListResponse {
    pub items: Vec<AdminContactMessage>,
    pub page: i64,
    pub page_size: i64,
    pub total: i64,
    pub unread: i64,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct AdminMessagesQuery {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_page_size")]
    pub page_size: i64,
    pub unread_only: Option<bool>,
}

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    20
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMessageRequest {
    pub read: Option<bool>,
}

/// Cheap, RFC-5322-ish email check. We deliberately don't pull in a
/// dedicated email-validation crate: the goal here is to reject obvious
/// garbage at the boundary, not to verify deliverability — that responsibility
/// belongs to the mail provider.
fn is_plausible_email(email: &str) -> bool {
    let trimmed = email.trim();
    if trimmed.len() < 3 || trimmed.len() > MAX_EMAIL_LEN {
        return false;
    }
    let at_count = trimmed.matches('@').count();
    if at_count != 1 {
        return false;
    }
    let (local, domain) = trimmed.split_once('@').unwrap();
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if !domain.contains('.') {
        return false;
    }
    if trimmed
        .chars()
        .any(|c| c.is_whitespace() || c == '<' || c == '>' || c == ',')
    {
        return false;
    }
    true
}

fn validate_payload(p: &CreateContactMessage) -> Result<(), AppError> {
    let name = p.name.trim();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(AppError::BadRequest(format!(
            "name must be 1..={} characters",
            MAX_NAME_LEN
        )));
    }
    if !is_plausible_email(&p.email) {
        return Err(AppError::BadRequest("email is invalid".to_string()));
    }
    if let Some(s) = &p.subject {
        if s.len() > MAX_SUBJECT_LEN {
            return Err(AppError::BadRequest(format!(
                "subject must be ≤ {} characters",
                MAX_SUBJECT_LEN
            )));
        }
    }
    let message = p.message.trim();
    if message.len() < MIN_MESSAGE_LEN || message.len() > MAX_MESSAGE_LEN {
        return Err(AppError::BadRequest(format!(
            "message must be {}..={} characters",
            MIN_MESSAGE_LEN, MAX_MESSAGE_LEN
        )));
    }
    Ok(())
}

/// Strip control characters except newlines/tabs. We keep formatting,
/// but block characters that confuse log aggregators or terminals.
fn sanitize_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
        .collect::<String>()
        .trim()
        .to_string()
}

fn extract_ip(headers: &HeaderMap, addr: &SocketAddr) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| Some(addr.ip().to_string()))
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(255).collect())
}

#[utoipa::path(
    post,
    path = "/api/contact",
    tag = "Contact",
    request_body = CreateContactMessage,
    responses(
        (status = 201, description = "Message accepted", body = ContactMessageResponse),
        (status = 200, description = "Honeypot triggered (silent drop, no body persisted)", body = ContactMessageResponse),
        (status = 400, description = "Validation failed", body = ErrorResponse),
        (status = 429, description = "Rate-limited", body = ErrorResponse),
        (status = 503, description = "Database unavailable", body = ErrorResponse),
    ),
)]
pub async fn submit_contact_message(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(mailer): State<Arc<dyn Mailer>>,
    Json(payload): Json<CreateContactMessage>,
) -> Result<impl IntoResponse, AppError> {
    // Honeypot: if the field is non-empty we *pretend* to succeed without
    // persisting anything. Returning a normal 200 keeps the bot from
    // retrying.
    if let Some(w) = &payload.website {
        if !w.trim().is_empty() {
            tracing::info!("Contact honeypot triggered from {}", addr.ip());
            return Ok((
                StatusCode::OK,
                Json(ContactMessageResponse {
                    id: Uuid::nil(),
                    success: true,
                }),
            )
                .into_response());
        }
    }

    validate_payload(&payload)?;

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let name = sanitize_text(&payload.name);
    let email = payload.email.trim().to_lowercase();
    let subject = payload
        .subject
        .as_deref()
        .map(sanitize_text)
        .filter(|s| !s.is_empty());
    let message = sanitize_text(&payload.message);
    let ip = extract_ip(&headers, &addr);
    let ua = extract_user_agent(&headers);

    let stored: ContactMessage = sqlx::query_as::<_, ContactMessage>(
        r#"
        INSERT INTO contact_messages (name, email, subject, message, ip_address, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, name, email, subject, message, ip_address, user_agent, read, created_at
        "#,
    )
    .bind(&name)
    .bind(&email)
    .bind(&subject)
    .bind(&message)
    .bind(&ip)
    .bind(&ua)
    .fetch_one(pool.as_ref())
    .await?;

    // Email delivery is best-effort. We log failures but never fail the
    // request — the message is already persisted and the admin will see
    // it in the inbox.
    let mailer_clone = mailer.clone();
    let stored_for_mail = stored.clone();
    tokio::spawn(async move {
        if let Err(e) = mailer_clone
            .send_contact_notification(&stored_for_mail)
            .await
        {
            tracing::warn!(error = %e, "Failed to send contact notification email");
        }
    });

    tracing::info!(
        message_id = %stored.id,
        from = %email,
        "Stored new contact message"
    );

    Ok((
        StatusCode::CREATED,
        Json(ContactMessageResponse {
            id: stored.id,
            success: true,
        }),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Admin inbox handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/admin/messages",
    tag = "Contact",
    security(("bearer_auth" = [])),
    params(AdminMessagesQuery),
    responses(
        (status = 200, description = "Paginated list of contact messages", body = AdminMessagesListResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 403, description = "Admin role required", body = ErrorResponse),
    ),
)]
pub async fn list_messages(
    headers: HeaderMap,
    Query(query): Query<AdminMessagesQuery>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let page_size = query.page_size.clamp(1, 100);
    let page = query.page.max(1);
    let offset = (page - 1) * page_size;
    let unread_only = query.unread_only.unwrap_or(false);

    let where_clause = if unread_only {
        "WHERE read = false"
    } else {
        ""
    };

    let select_sql = format!(
        r#"
        SELECT id, name, email, subject, message, ip_address, user_agent, read, created_at
        FROM contact_messages
        {where}
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
        where = where_clause,
    );

    let count_sql = format!("SELECT COUNT(*) FROM contact_messages {}", where_clause);

    let items: Vec<ContactMessage> = sqlx::query_as::<_, ContactMessage>(&select_sql)
        .bind(page_size)
        .bind(offset)
        .fetch_all(pool.as_ref())
        .await?;

    let total: i64 = sqlx::query_scalar(&count_sql)
        .fetch_one(pool.as_ref())
        .await?;

    let unread: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM contact_messages WHERE read = false")
            .fetch_one(pool.as_ref())
            .await?;

    let response = AdminMessagesListResponse {
        items: items.into_iter().map(Into::into).collect(),
        page,
        page_size,
        total,
        unread,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
    get,
    path = "/api/admin/messages/{id}",
    tag = "Contact",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Message UUID")),
    responses(
        (status = 200, description = "Single message", body = AdminContactMessage),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 403, description = "Admin role required", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
pub async fn get_message(
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let row: Option<ContactMessage> = sqlx::query_as::<_, ContactMessage>(
        r#"
        SELECT id, name, email, subject, message, ip_address, user_agent, read, created_at
        FROM contact_messages
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool.as_ref())
    .await?;

    let msg = row.ok_or(AppError::NotFound)?;
    Ok((StatusCode::OK, Json(AdminContactMessage::from(msg))).into_response())
}

#[utoipa::path(
    patch,
    path = "/api/admin/messages/{id}",
    tag = "Contact",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Message UUID")),
    request_body = UpdateMessageRequest,
    responses(
        (status = 200, description = "Message updated", body = AdminContactMessage),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 403, description = "Admin role required", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
pub async fn update_message(
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let read = payload
        .read
        .ok_or_else(|| AppError::BadRequest("`read` is required".to_string()))?;

    let row: Option<ContactMessage> = sqlx::query_as::<_, ContactMessage>(
        r#"
        UPDATE contact_messages SET read = $1
        WHERE id = $2
        RETURNING id, name, email, subject, message, ip_address, user_agent, read, created_at
        "#,
    )
    .bind(read)
    .bind(id)
    .fetch_optional(pool.as_ref())
    .await?;

    let msg = row.ok_or(AppError::NotFound)?;
    Ok((StatusCode::OK, Json(AdminContactMessage::from(msg))).into_response())
}

#[utoipa::path(
    delete,
    path = "/api/admin/messages/{id}",
    tag = "Contact",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Message UUID")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 403, description = "Admin role required", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
)]
pub async fn delete_message(
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let result = sqlx::query("DELETE FROM contact_messages WHERE id = $1")
        .bind(id)
        .execute(pool.as_ref())
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_validator_accepts_normal_addresses() {
        assert!(is_plausible_email("a@b.co"));
        assert!(is_plausible_email("user+tag@example.com"));
        assert!(is_plausible_email("dev.ops@my-domain.io"));
    }

    #[test]
    fn email_validator_rejects_obvious_garbage() {
        assert!(!is_plausible_email(""));
        assert!(!is_plausible_email("not-an-email"));
        assert!(!is_plausible_email("a@b"));
        assert!(!is_plausible_email("a@@b.co"));
        assert!(!is_plausible_email("a b@c.co"));
        assert!(!is_plausible_email("a@b.co<script>"));
    }

    #[test]
    fn validate_payload_enforces_lengths() {
        let mut p = CreateContactMessage {
            name: "".to_string(),
            email: "ok@ok.com".to_string(),
            subject: None,
            message: "x".repeat(20),
            website: None,
        };
        assert!(validate_payload(&p).is_err(), "empty name should fail");
        p.name = "x".repeat(MAX_NAME_LEN + 1);
        assert!(validate_payload(&p).is_err(), "long name should fail");

        p.name = "Dimas".to_string();
        p.message = "x".repeat(MIN_MESSAGE_LEN - 1);
        assert!(validate_payload(&p).is_err(), "short message should fail");

        p.message = "x".repeat(MAX_MESSAGE_LEN + 1);
        assert!(validate_payload(&p).is_err(), "long message should fail");

        p.message = "x".repeat(MIN_MESSAGE_LEN + 5);
        assert!(validate_payload(&p).is_ok(), "valid payload should pass");
    }

    #[test]
    fn sanitize_text_strips_control_chars_but_keeps_newlines() {
        let cleaned = sanitize_text("hello\u{0007}\nworld\t!\u{0000}");
        assert_eq!(cleaned, "hello\nworld\t!");
    }
}

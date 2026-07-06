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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BulkMessageIdsRequest {
    pub ids: Vec<Uuid>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BulkMessageActionResponse {
    pub affected: u64,
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

    crate::metrics::record_contact_submission();

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

fn validate_bulk_ids(ids: &[Uuid]) -> Result<(), AppError> {
    if ids.is_empty() {
        return Err(AppError::BadRequest("ids must not be empty".to_string()));
    }
    if ids.len() > 100 {
        return Err(AppError::BadRequest(
            "ids must contain at most 100 items".to_string(),
        ));
    }
    Ok(())
}

#[utoipa::path(
    patch,
    path = "/api/admin/messages/bulk",
    tag = "Contact",
    security(("bearer_auth" = [])),
    request_body = BulkMessageIdsRequest,
    responses(
        (status = 200, description = "Messages updated", body = BulkMessageActionResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 403, description = "Admin role required", body = ErrorResponse),
    ),
)]
pub async fn bulk_mark_messages_read(
    headers: HeaderMap,
    Json(payload): Json<BulkMessageIdsRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;
    validate_bulk_ids(&payload.ids)?;
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let result = sqlx::query("UPDATE contact_messages SET read = true WHERE id = ANY($1::uuid[])")
        .bind(&payload.ids)
        .execute(pool.as_ref())
        .await?;

    Ok((
        StatusCode::OK,
        Json(BulkMessageActionResponse {
            affected: result.rows_affected(),
        }),
    )
        .into_response())
}

#[utoipa::path(
    delete,
    path = "/api/admin/messages/bulk",
    tag = "Contact",
    security(("bearer_auth" = [])),
    request_body = BulkMessageIdsRequest,
    responses(
        (status = 200, description = "Messages deleted", body = BulkMessageActionResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 403, description = "Admin role required", body = ErrorResponse),
    ),
)]
pub async fn bulk_delete_messages(
    headers: HeaderMap,
    Json(payload): Json<BulkMessageIdsRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&headers)?;
    validate_bulk_ids(&payload.ids)?;
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let result = sqlx::query("DELETE FROM contact_messages WHERE id = ANY($1::uuid[])")
        .bind(&payload.ids)
        .execute(pool.as_ref())
        .await?;

    Ok((
        StatusCode::OK,
        Json(BulkMessageActionResponse {
            affected: result.rows_affected(),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, patch, post};
    use axum::Router;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    use crate::email::{Mailer, MailerError};
    use crate::test_support;

    #[derive(Debug)]
    struct TestMailer {
        send_count: AtomicUsize,
        should_fail: bool,
    }

    impl TestMailer {
        fn ok() -> Arc<Self> {
            Arc::new(Self {
                send_count: AtomicUsize::new(0),
                should_fail: false,
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                send_count: AtomicUsize::new(0),
                should_fail: true,
            })
        }

        fn sent(&self) -> usize {
            self.send_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Mailer for TestMailer {
        async fn send_contact_notification(
            &self,
            _msg: &crate::db::models::ContactMessage,
        ) -> Result<(), MailerError> {
            self.send_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                Err(MailerError::Transport("forced test failure".to_string()))
            } else {
                Ok(())
            }
        }
    }

    fn contact_router(mailer: Arc<dyn Mailer>) -> Router {
        Router::new()
            .route("/api/contact", post(submit_contact_message))
            .route("/api/admin/messages", get(list_messages))
            .route(
                "/api/admin/messages/bulk",
                patch(bulk_mark_messages_read).delete(bulk_delete_messages),
            )
            .route(
                "/api/admin/messages/{id}",
                get(get_message)
                    .patch(update_message)
                    .delete(delete_message),
            )
            .with_state(mailer)
            .layer(test_support::mock_connect_info())
    }

    async fn call(app: Router, req: Request<Body>) -> (StatusCode, axum::body::Bytes) {
        let res = app.oneshot(req).await.expect("request should succeed");
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        (status, body)
    }

    fn valid_payload_json() -> serde_json::Value {
        serde_json::json!({
            "name": "Alice",
            "email": "alice@example.com",
            "subject": "Need help",
            "message": "Hello there from contact form",
            "website": null
        })
    }

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

    #[tokio::test]
    async fn submit_returns_service_unavailable_without_db() {
        let mailer = TestMailer::ok();
        let req = Request::post("/api/contact")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&valid_payload_json()).expect("json body"),
            ))
            .expect("request should build");
        let (status, _) = call(contact_router(mailer), req).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn honeypot_returns_ok_and_does_not_persist() {
        let Some(db) = test_support::acquire_test_pool().await else {
            return;
        };

        let mailer = TestMailer::ok();
        let mut payload = valid_payload_json();
        payload["website"] = serde_json::Value::String("https://spam-bot.invalid".to_string());
        let req = Request::post("/api/contact")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).expect("json body")))
            .expect("request should build");

        let (status, body) = call(contact_router(mailer.clone()), req).await;
        assert_eq!(status, StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&body).expect("valid response JSON");
        let nil = Uuid::nil().to_string();
        assert_eq!(response["id"].as_str(), Some(nil.as_str()));

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contact_messages")
            .fetch_one(db.pool.as_ref())
            .await
            .expect("count query should succeed");
        assert_eq!(count, 0);
        assert_eq!(mailer.sent(), 0);
    }

    #[tokio::test]
    async fn submit_and_admin_crud_roundtrip_with_non_fatal_mailer_error() {
        let Some(db) = test_support::acquire_test_pool().await else {
            return;
        };

        let mailer = TestMailer::failing();
        let payload = valid_payload_json();
        let submit_req = Request::post("/api/contact")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "203.0.113.7, 10.0.0.1")
            .header("user-agent", "integration-test-agent/1.0")
            .body(Body::from(serde_json::to_vec(&payload).expect("json body")))
            .expect("request should build");

        let (submit_status, submit_body) = call(contact_router(mailer.clone()), submit_req).await;
        assert_eq!(submit_status, StatusCode::CREATED);
        let created: serde_json::Value =
            serde_json::from_slice(&submit_body).expect("valid submit response JSON");
        let created_id = created["id"]
            .as_str()
            .expect("created id should be present")
            .to_string();
        assert_ne!(created_id, Uuid::nil().to_string());

        // The handler sends mail on a detached task. Give it a short moment so
        // we can assert that mail failures do not break persistence.
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(mailer.sent(), 1);

        let bearer = test_support::admin_bearer();
        let list_req = Request::get("/api/admin/messages?page=1&pageSize=10")
            .header("authorization", &bearer)
            .body(Body::empty())
            .expect("request should build");
        let (list_status, list_body) = call(contact_router(mailer.clone()), list_req).await;
        assert_eq!(list_status, StatusCode::OK);
        let list: serde_json::Value =
            serde_json::from_slice(&list_body).expect("valid list response");
        assert_eq!(list["total"].as_i64(), Some(1));
        assert_eq!(list["unread"].as_i64(), Some(1));
        assert_eq!(list["items"][0]["id"].as_str(), Some(created_id.as_str()));

        let get_req = Request::get(format!("/api/admin/messages/{}", created_id))
            .header("authorization", &bearer)
            .body(Body::empty())
            .expect("request should build");
        let (get_status, get_body) = call(contact_router(mailer.clone()), get_req).await;
        assert_eq!(get_status, StatusCode::OK);
        let fetched: serde_json::Value =
            serde_json::from_slice(&get_body).expect("valid get response");
        assert_eq!(fetched["email"].as_str(), Some("alice@example.com"));
        assert_eq!(fetched["ipAddress"].as_str(), Some("203.0.113.7"));

        let update_req = Request::patch(format!("/api/admin/messages/{}", created_id))
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(br#"{"read":true}"#.as_slice()))
            .expect("request should build");
        let (update_status, update_body) = call(contact_router(mailer.clone()), update_req).await;
        assert_eq!(update_status, StatusCode::OK);
        let updated: serde_json::Value =
            serde_json::from_slice(&update_body).expect("valid update response");
        assert_eq!(updated["read"].as_bool(), Some(true));

        let delete_req = Request::delete(format!("/api/admin/messages/{}", created_id))
            .header("authorization", &bearer)
            .body(Body::empty())
            .expect("request should build");
        let (delete_status, _) = call(contact_router(mailer), delete_req).await;
        assert_eq!(delete_status, StatusCode::NO_CONTENT);

        let db_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contact_messages")
            .fetch_one(db.pool.as_ref())
            .await
            .expect("count query should succeed");
        assert_eq!(db_count, 0);
    }
    #[tokio::test]
    async fn submit_and_admin_bulk_ops() {
        let Some(db) = test_support::acquire_test_pool().await else {
            return;
        };

        let mailer = TestMailer::ok();
        let payload = valid_payload_json();

        let mut msg_ids = Vec::new();
        for i in 0..2 {
            let mut p = payload.clone();
            p["subject"] = serde_json::json!(format!("Subject {}", i));
            let submit_req = Request::post("/api/contact")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&p).unwrap()))
                .unwrap();
            let (status, body) = call(contact_router(mailer.clone()), submit_req).await;
            assert_eq!(status, StatusCode::CREATED);
            let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
            msg_ids.push(Uuid::parse_str(val["id"].as_str().unwrap()).unwrap());
        }

        let bearer = test_support::admin_bearer();

        let req_empty = Request::patch("/api/admin/messages/bulk")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({ "ids": [] })).unwrap(),
            ))
            .unwrap();
        let (status_empty, _) = call(contact_router(mailer.clone()), req_empty).await;
        assert_eq!(status_empty, StatusCode::BAD_REQUEST);

        let req_read = Request::patch("/api/admin/messages/bulk")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({ "ids": msg_ids })).unwrap(),
            ))
            .unwrap();
        let (status_read, _) = call(contact_router(mailer.clone()), req_read).await;
        assert_eq!(status_read, StatusCode::OK);

        let list_req = Request::get("/api/admin/messages?page=1&pageSize=10")
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        let (_, list_body) = call(contact_router(mailer.clone()), list_req).await;
        let list: serde_json::Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(list["unread"].as_i64(), Some(0));

        let req_del = Request::delete("/api/admin/messages/bulk")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({ "ids": msg_ids })).unwrap(),
            ))
            .unwrap();
        let (status_del, body_del) = call(contact_router(mailer.clone()), req_del).await;
        assert_eq!(status_del, StatusCode::OK);
        let res_del: serde_json::Value = serde_json::from_slice(&body_del).unwrap();
        assert_eq!(res_del["affected"].as_i64(), Some(2));

        let db_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contact_messages")
            .fetch_one(db.pool.as_ref())
            .await
            .unwrap();
        assert_eq!(db_count, 0);
    }
}

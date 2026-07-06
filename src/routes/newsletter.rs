//! Newsletter subscription with double opt-in and admin broadcast.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::db::{self, models::NewsletterSubscriber};
use crate::email::Mailer;
use crate::routes::auth::require_admin;
use crate::routes::AppError;

const MAX_EMAIL_LEN: usize = 254;
const MAX_SUBJECT_LEN: usize = 200;
const MAX_BODY_LEN: usize = 50_000;
const TOKEN_BYTES: usize = 32;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeRequest {
    pub email: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub struct ConfirmQuery {
    pub token: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UnsubscribeRequest {
    pub token: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubscriberListItem {
    pub id: Uuid,
    pub email: String,
    pub confirmed: bool,
    pub subscribed_at: chrono::DateTime<Utc>,
    pub confirmed_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubscriberListResponse {
    pub items: Vec<SubscriberListItem>,
    pub total: i64,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastRequest {
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastResponse {
    pub sent: u64,
    pub failed: u64,
}

fn is_plausible_email(email: &str) -> bool {
    let trimmed = email.trim();
    if trimmed.len() < 3 || trimmed.len() > MAX_EMAIL_LEN {
        return false;
    }
    let parts: Vec<&str> = trimmed.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.')
}

fn random_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn site_base_url() -> String {
    std::env::var("SITE_URL")
        .or_else(|_| std::env::var("FRONTEND_ORIGIN"))
        .unwrap_or_else(|_| "http://localhost:3000".to_string())
}

#[utoipa::path(
    post,
    path = "/api/newsletter/subscribe",
    tag = "Newsletter",
    request_body = SubscribeRequest,
    responses(
        (status = 200, description = "Subscription initiated"),
        (status = 400, description = "Invalid email"),
    ),
)]
pub async fn subscribe(
    State(mailer): State<Arc<dyn Mailer>>,
    Json(payload): Json<SubscribeRequest>,
) -> Result<impl IntoResponse, AppError> {
    let email = payload.email.trim().to_ascii_lowercase();
    if !is_plausible_email(&email) {
        return Err(AppError::BadRequest("email is invalid".to_string()));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let confirm_token = random_token();
    let unsubscribe_token = random_token();
    let now = Utc::now();

    let existing: Option<(bool, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT confirmed, unsubscribed_at FROM newsletter_subscribers WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(pool.as_ref())
    .await?;

    if let Some((confirmed, unsubscribed_at)) = existing {
        if confirmed && unsubscribed_at.is_none() {
            return Ok(Json(SubscribeResponse {
                success: true,
                message: "You are already subscribed.".to_string(),
            }));
        }
        sqlx::query(
            r#"
            UPDATE newsletter_subscribers
            SET confirmed = false,
                confirm_token = $2,
                unsubscribe_token = $3,
                subscribed_at = $4,
                confirmed_at = NULL,
                unsubscribed_at = NULL
            WHERE email = $1
            "#,
        )
        .bind(&email)
        .bind(&confirm_token)
        .bind(&unsubscribe_token)
        .bind(now)
        .execute(pool.as_ref())
        .await?;
    } else {
        sqlx::query(
            r#"
            INSERT INTO newsletter_subscribers
                (email, confirm_token, unsubscribe_token, subscribed_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(&email)
        .bind(&confirm_token)
        .bind(&unsubscribe_token)
        .bind(now)
        .execute(pool.as_ref())
        .await?;
    }

    let confirm_url = format!(
        "{}/api/newsletter/confirm?token={}",
        site_base_url().trim_end_matches('/'),
        confirm_token
    );
    mailer
        .send_newsletter_confirmation(&email, &confirm_url)
        .await
        .ok();

    Ok(Json(SubscribeResponse {
        success: true,
        message: "Check your email to confirm your subscription.".to_string(),
    }))
}

#[utoipa::path(
    get,
    path = "/api/newsletter/confirm",
    tag = "Newsletter",
    params(ConfirmQuery),
    responses(
        (status = 200, description = "Subscription confirmed"),
        (status = 400, description = "Invalid token"),
    ),
)]
pub async fn confirm(Query(query): Query<ConfirmQuery>) -> Result<impl IntoResponse, AppError> {
    if query.token.trim().is_empty() {
        return Err(AppError::BadRequest("token is required".to_string()));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let now = Utc::now();

    let updated = sqlx::query(
        r#"
        UPDATE newsletter_subscribers
        SET confirmed = true,
            confirmed_at = $2,
            confirm_token = NULL
        WHERE confirm_token = $1
          AND unsubscribed_at IS NULL
        "#,
    )
    .bind(query.token.trim())
    .bind(now)
    .execute(pool.as_ref())
    .await?;

    if updated.rows_affected() == 0 {
        return Err(AppError::BadRequest("invalid or expired token".to_string()));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Subscription confirmed. Thank you!"
    })))
}

#[utoipa::path(
    post,
    path = "/api/newsletter/unsubscribe",
    tag = "Newsletter",
    request_body = UnsubscribeRequest,
    responses(
        (status = 200, description = "Unsubscribed"),
        (status = 400, description = "Invalid token"),
    ),
)]
pub async fn unsubscribe(
    Json(payload): Json<UnsubscribeRequest>,
) -> Result<impl IntoResponse, AppError> {
    if payload.token.trim().is_empty() {
        return Err(AppError::BadRequest("token is required".to_string()));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let now = Utc::now();

    let updated = sqlx::query(
        r#"
        UPDATE newsletter_subscribers
        SET confirmed = false,
            unsubscribed_at = $2
        WHERE unsubscribe_token = $1
        "#,
    )
    .bind(payload.token.trim())
    .bind(now)
    .execute(pool.as_ref())
    .await?;

    if updated.rows_affected() == 0 {
        return Err(AppError::BadRequest("invalid token".to_string()));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "You have been unsubscribed."
    })))
}

#[utoipa::path(
    get,
    path = "/api/admin/newsletter/subscribers",
    tag = "Newsletter",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Subscriber list", body = SubscriberListResponse),
    ),
)]
pub async fn list_subscribers(headers: HeaderMap) -> Result<impl IntoResponse, AppError> {
    let _admin = require_admin(&headers)?;
    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;

    let rows = sqlx::query_as::<_, NewsletterSubscriber>(
        r#"
        SELECT id, email, confirmed, confirm_token, unsubscribe_token,
               subscribed_at, confirmed_at, unsubscribed_at
        FROM newsletter_subscribers
        WHERE unsubscribed_at IS NULL
        ORDER BY subscribed_at DESC
        "#,
    )
    .fetch_all(pool.as_ref())
    .await?;

    let total = rows.len() as i64;
    let items = rows
        .into_iter()
        .map(|s| SubscriberListItem {
            id: s.id,
            email: s.email,
            confirmed: s.confirmed,
            subscribed_at: s.subscribed_at,
            confirmed_at: s.confirmed_at,
        })
        .collect();

    Ok(Json(SubscriberListResponse { items, total }))
}

#[utoipa::path(
    post,
    path = "/api/admin/newsletter/broadcast",
    tag = "Newsletter",
    security(("bearer_auth" = [])),
    request_body = BroadcastRequest,
    responses(
        (status = 200, description = "Broadcast sent", body = BroadcastResponse),
    ),
)]
pub async fn broadcast(
    headers: HeaderMap,
    State(mailer): State<Arc<dyn Mailer>>,
    Json(payload): Json<BroadcastRequest>,
) -> Result<impl IntoResponse, AppError> {
    let _admin = require_admin(&headers)?;

    let subject = payload.subject.trim();
    let body = payload.body.trim();
    if subject.is_empty() || subject.len() > MAX_SUBJECT_LEN {
        return Err(AppError::BadRequest(format!(
            "subject must be 1..={} characters",
            MAX_SUBJECT_LEN
        )));
    }
    if body.is_empty() || body.len() > MAX_BODY_LEN {
        return Err(AppError::BadRequest(format!(
            "body must be 1..={} characters",
            MAX_BODY_LEN
        )));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    let emails: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT email FROM newsletter_subscribers
        WHERE confirmed = true AND unsubscribed_at IS NULL
        "#,
    )
    .fetch_all(pool.as_ref())
    .await?;

    let mut sent = 0u64;
    let mut failed = 0u64;
    for email in emails {
        match mailer
            .send_newsletter_broadcast(&email, subject, body)
            .await
        {
            Ok(()) => sent += 1,
            Err(e) => {
                tracing::warn!(email = %email, error = %e, "newsletter broadcast failed for recipient");
                failed += 1;
            }
        }
    }

    Ok(Json(BroadcastResponse { sent, failed }))
}

/// Hash an API key for storage lookup (shared helper for CMS module).
pub fn hash_api_key(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use std::sync::Arc;

    #[test]
    fn plausible_email_validation() {
        assert!(is_plausible_email("user@example.com"));
        assert!(!is_plausible_email("not-an-email"));
    }

    #[test]
    fn hash_api_key_is_deterministic() {
        assert_eq!(hash_api_key("abc"), hash_api_key("abc"));
        assert_ne!(hash_api_key("abc"), hash_api_key("def"));
    }

    #[tokio::test]
    async fn test_newsletter_full_flow() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let mailer = Arc::new(crate::email::NoopMailer);

        // 1. Subscribe with invalid email -> BadRequest
        let req = SubscribeRequest {
            email: "invalid".to_string(),
        };
        let res = subscribe(State(mailer.clone()), Json(req)).await;
        assert!(res.is_err());

        // 2. Subscribe with valid email -> success
        let req = SubscribeRequest {
            email: "user@example.com".to_string(),
        };
        let res = subscribe(State(mailer.clone()), Json(req))
            .await
            .unwrap()
            .into_response();
        assert_eq!(res.status(), StatusCode::OK);

        // 3. Confirm subscription
        let sub: NewsletterSubscriber =
            sqlx::query_as("SELECT * FROM newsletter_subscribers WHERE email = 'user@example.com'")
                .fetch_one(&*db.pool)
                .await
                .unwrap();
        let token = sub.confirm_token.unwrap();
        let query = ConfirmQuery { token };
        let res = confirm(Query(query)).await.unwrap().into_response();
        assert_eq!(res.status(), StatusCode::OK);

        // 4. Admin list subscribers
        let token_header = crate::test_support::admin_bearer();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            token_header.parse().unwrap(),
        );

        let res_list = list_subscribers(headers.clone())
            .await
            .unwrap()
            .into_response();
        assert_eq!(res_list.status(), StatusCode::OK);

        // 5. Admin broadcast
        let req_broadcast = BroadcastRequest {
            subject: "Hello".to_string(),
            body: "World".to_string(),
        };
        let res_broadcast = broadcast(headers, State(mailer.clone()), Json(req_broadcast))
            .await
            .unwrap()
            .into_response();
        assert_eq!(res_broadcast.status(), StatusCode::OK);

        // 6. Unsubscribe
        let req_unsub = UnsubscribeRequest {
            token: sub.unsubscribe_token,
        };
        let res = unsubscribe(Json(req_unsub)).await.unwrap().into_response();
        assert_eq!(res.status(), StatusCode::OK);

        // 7. Negative cases
        let res_err = confirm(Query(ConfirmQuery {
            token: "".to_string(),
        }))
        .await;
        assert!(res_err.is_err());
        let res_err2 = confirm(Query(ConfirmQuery {
            token: "invalid-token".to_string(),
        }))
        .await;
        assert!(res_err2.is_err());

        let res_unsub_err = unsubscribe(Json(UnsubscribeRequest {
            token: "".to_string(),
        }))
        .await;
        assert!(res_unsub_err.is_err());
        let res_unsub_err2 = unsubscribe(Json(UnsubscribeRequest {
            token: "invalid-token".to_string(),
        }))
        .await;
        assert!(res_unsub_err2.is_err());

        let res_list_err = list_subscribers(HeaderMap::new()).await;
        assert!(res_list_err.is_err());
    }
}

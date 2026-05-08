#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar: Option<String>,
    pub role: String,
    pub is_active: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
    pub login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAdminUser {
    pub email: String,
    pub password_hash: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUser {
    pub email: String,
    pub password_hash: String,
    pub role: Option<String>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewRefreshToken {
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize, ToSchema)]
pub struct PortfolioSection {
    pub key: String,
    #[schema(value_type = Object)]
    pub content: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpsertPortfolioSection {
    pub key: String,
    #[schema(value_type = Object)]
    pub content: serde_json::Value,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BlogPost {
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
    /// Optional scheduled publish time. If set and in the future, the post
    /// is in the `Scheduled` state — visible only to admins. If set and in
    /// the past, the post is treated as published regardless of the
    /// `published` flag (so admins don't have to flip it manually).
    pub publish_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BlogPost {
    /// Derive the canonical lifecycle status of a post.
    ///
    /// Precedence: scheduled (publish_at in the future) > published
    /// (`published` flag OR publish_at <= now) > draft.
    pub fn status(&self) -> BlogStatus {
        let now = Utc::now();
        match self.publish_at {
            Some(ts) if ts > now => BlogStatus::Scheduled,
            Some(ts) if ts <= now => BlogStatus::Published,
            _ if self.published => BlogStatus::Published,
            _ => BlogStatus::Draft,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BlogStatus {
    Draft,
    Scheduled,
    Published,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NewBlogPost {
    pub title: String,
    pub slug: String,
    pub summary: Option<String>,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub published: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub publish_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBlogPost {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub published: Option<bool>,
    pub tags: Option<Vec<String>>,
    /// Use `Some(Some(ts))` to set, `Some(None)` to clear, `None` to leave
    /// unchanged. Serde's default behaviour for `Option<Option<T>>` collapses
    /// `null` into `Some(None)`, which is exactly what we want.
    #[schema(value_type = Option<DateTime<Utc>>, nullable, required = false)]
    pub publish_at: Option<Option<DateTime<Utc>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BlogListResponse {
    pub items: Vec<BlogPost>,
    pub page: i64,
    pub page_size: i64,
    pub total: i64,
}

/// Contact-form message persisted in `contact_messages`.
///
/// Inbound messages are stored as plain text. The `ip_address` column is best-
/// effort and only used for spam triage / rate-limit auditing; it is not
/// exposed to non-admin clients.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContactMessage {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub subject: Option<String>,
    pub message: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub read: bool,
    pub created_at: DateTime<Utc>,
}

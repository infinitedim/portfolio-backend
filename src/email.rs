//! Email delivery boundary.
//!
//! The portfolio doesn't actually require sending email at runtime — the
//! contact form persists messages to the database which the admin can read
//! from the inbox. Sending is *additionally* useful (instant notification
//! to the operator) but must never block the request path.
//!
//! This module defines a [`Mailer`] trait with two implementations:
//!
//! - [`NoopMailer`]: drops messages silently (used when no transport is
//!   configured). Default in dev/test.
//! - [`ResendMailer`]: posts to the Resend HTTP API. Picked when
//!   `RESEND_API_KEY` is set.
//!
//! SMTP support is intentionally not included to keep the dependency
//! footprint small. Adding `lettre` later is a straightforward additional
//! `Mailer` impl behind the same trait.
//!
//! All variants are best-effort: handlers should `.ok()` the result so that
//! a transient mail failure never causes an HTTP 500 on the public contact
//! endpoint.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;

use crate::db::models::ContactMessage;

/// Outcome of an attempted send. The error variant is informational only;
/// callers that don't care about delivery success should ignore it.
#[derive(Debug)]
#[allow(dead_code)]
pub enum MailerError {
    /// HTTP transport failed.
    Transport(String),
    /// The remote provider rejected the request.
    Provider { status: u16, body: String },
    /// Required configuration is missing at runtime.
    Misconfigured(&'static str),
}

impl std::fmt::Display for MailerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MailerError::Transport(e) => write!(f, "mailer transport error: {}", e),
            MailerError::Provider { status, body } => {
                write!(f, "mail provider rejected request: {} {}", status, body)
            }
            MailerError::Misconfigured(name) => {
                write!(f, "mailer misconfigured: missing {}", name)
            }
        }
    }
}

impl std::error::Error for MailerError {}

/// Email transport contract. All implementations must be `Send + Sync` so
/// they can sit behind an `Arc` in the Axum router state.
#[async_trait]
pub trait Mailer: Send + Sync {
    /// Notify the operator that a new contact-form message has arrived.
    /// Implementations may render their own subject/body — the message
    /// content is provided as plain fields for convenience.
    async fn send_contact_notification(&self, msg: &ContactMessage) -> Result<(), MailerError>;
}

/// No-op transport. Used when no provider is configured. Always returns Ok.
#[derive(Debug, Default, Clone)]
pub struct NoopMailer;

#[async_trait]
impl Mailer for NoopMailer {
    async fn send_contact_notification(&self, msg: &ContactMessage) -> Result<(), MailerError> {
        tracing::debug!(
            from = %msg.email,
            "NoopMailer: dropping contact notification (no transport configured)"
        );
        Ok(())
    }
}

/// Resend (resend.com) HTTP transport. Reuses the `reqwest` client that's
/// already in the dependency tree.
#[derive(Debug, Clone)]
pub struct ResendMailer {
    api_key: String,
    from: String,
    to: String,
    client: reqwest::Client,
}

impl ResendMailer {
    pub fn new(api_key: String, from: String, to: String) -> Self {
        Self {
            api_key,
            from,
            to,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl Mailer for ResendMailer {
    async fn send_contact_notification(&self, msg: &ContactMessage) -> Result<(), MailerError> {
        let subject = match msg.subject.as_deref() {
            Some(s) if !s.trim().is_empty() => format!("[Portfolio] {}", s.trim()),
            _ => "[Portfolio] New contact message".to_string(),
        };

        // Plain-text body; intentionally not rendering HTML to keep the
        // dependency surface minimal.
        let body = format!(
            "New contact message from your portfolio site.\n\n\
             From: {} <{}>\n\
             Subject: {}\n\n\
             Message:\n{}\n\n---\nSent at: {}\n",
            msg.name,
            msg.email,
            msg.subject.as_deref().unwrap_or("(none)"),
            msg.message,
            msg.created_at,
        );

        let payload = json!({
            "from": self.from,
            "to": [self.to],
            "reply_to": msg.email,
            "subject": subject,
            "text": body,
        });

        let res = self
            .client
            .post("https://api.resend.com/emails")
            .bearer_auth(&self.api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| MailerError::Transport(e.to_string()))?;

        let status = res.status();
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            return Err(MailerError::Provider {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }
}

/// Build a [`Mailer`] from environment variables. Falls back to
/// [`NoopMailer`] if no transport is configured. Logs which transport was
/// selected so operators can verify config at boot.
pub fn from_env() -> Arc<dyn Mailer> {
    if let Ok(api_key) = std::env::var("RESEND_API_KEY") {
        let from =
            std::env::var("RESEND_FROM").unwrap_or_else(|_| "noreply@example.com".to_string());
        let to = std::env::var("CONTACT_EMAIL").unwrap_or_else(|_| from.clone());
        tracing::info!(from = %from, to = %to, "Mailer: Resend transport enabled");
        return Arc::new(ResendMailer::new(api_key, from, to));
    }

    tracing::info!("Mailer: no transport configured, using NoopMailer");
    Arc::new(NoopMailer)
}

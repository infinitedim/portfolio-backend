/*!
 * Routes Module
 * API route handlers
 */
pub mod auth;
pub mod blog;
pub mod health;
pub mod logs;
pub mod portfolio;

use serde::Serialize;

/// Shared error response type used by all route modules.
/// Centralised here to avoid duplicate definitions in auth.rs and blog.rs.
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub mod auth;
pub mod blog;
pub mod health;
pub mod logs;
pub mod portfolio;
pub mod roadmap;
pub mod rss;
pub mod upload;

use serde::Serialize;

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

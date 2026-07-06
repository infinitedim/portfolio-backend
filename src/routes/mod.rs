pub mod ai;
pub mod auth;
pub mod blog;
pub mod cms;
pub mod contact;
pub mod gate;
pub mod github;
pub mod health;
pub mod logs;
pub mod newsletter;
pub mod playground;
pub mod portfolio;
pub mod presence;
pub mod roadmap;
pub mod rss;
pub mod series;
pub mod twofa;
pub mod upload;

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
#[allow(dead_code)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Application-level error type that maps cleanly onto HTTP responses.
///
/// Use this from handlers that previously swallowed DB errors with
/// `unwrap_or_default()`. The point: never return HTTP 200 for an
/// internal-server failure — orchestrators and dashboards depend on
/// accurate status codes.
#[derive(Debug)]
#[allow(dead_code)]
pub enum AppError {
    /// Database pool not initialised. Surfaces as 503.
    DbUnavailable,
    /// Database query failed. Surfaces as 500 (server) or 503 (transient).
    Db(sqlx::Error),
    /// Resource not found.
    NotFound,
    /// Invalid client input.
    BadRequest(String),
    /// Auth missing/invalid.
    Unauthorized,
    /// Auth present but lacks the required role.
    Forbidden,
    /// Catch-all internal error (use sparingly).
    Internal(String),
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::DbUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Db(e) => match e {
                sqlx::Error::PoolTimedOut | sqlx::Error::Io(_) => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn public_message(&self) -> &str {
        match self {
            AppError::DbUnavailable => "Database not available",
            AppError::Db(_) => "Database error",
            AppError::NotFound => "Not found",
            AppError::BadRequest(msg) => msg,
            AppError::Unauthorized => "Authorization required",
            AppError::Forbidden => "Forbidden",
            AppError::Internal(_) => "Internal server error",
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Db(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        // Log the full error server-side; only return a sanitised message
        // to the client so we don't leak schema/SQL details.
        if matches!(self, AppError::Db(_) | AppError::Internal(_)) {
            tracing::error!(error = ?self, "request failed with internal error");
        }

        let status = self.status_code();
        let body = Json(ErrorResponse {
            error: self.public_message().to_string(),
            message: None,
        });
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_error_conversion_and_responses() {
        let err1 = AppError::DbUnavailable;
        assert_eq!(err1.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err1.public_message(), "Database not available");

        let err_db_io = AppError::Db(sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "io error",
        )));
        assert_eq!(err_db_io.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err_db_io.public_message(), "Database error");

        let err_db_other = AppError::Db(sqlx::Error::RowNotFound);
        assert_eq!(
            err_db_other.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let sqlx_err = sqlx::Error::RowNotFound;
        let converted: AppError = sqlx_err.into();
        assert!(matches!(converted, AppError::Db(_)));

        let response = converted.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

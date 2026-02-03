/**
 * Health Routes
 * Endpoints for checking backend health status
 */
use axum::{http::StatusCode, response::IntoResponse, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Instant;

// Track server start time for uptime calculation
lazy_static::lazy_static! {
    static ref SERVER_START: Instant = Instant::now();
}

/// Initialize the server start time
pub fn init_start_time() {
    lazy_static::initialize(&SERVER_START);
}

/// Health status enum
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)] // Reserved for future health API responses
pub enum HealthStatus {
    Ok,
    Healthy,
    Unhealthy,
    Unknown,
    Ready,
    #[serde(rename = "not ready")]
    NotReady,
}

/// Single service check result
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceCheck {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Detailed health check response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailedHealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<u64>,
    pub checks: HealthChecks,
}

/// Health checks for all services
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthChecks {
    pub database: ServiceCheck,
    pub redis: ServiceCheck,
}

/// Ready check response
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadyResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<ReadyChecks>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Ready checks summary
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadyChecks {
    pub database: String,
    pub redis: String,
}

/// Simple health response
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleHealthResponse {
    pub status: String,
}

/// GET /health - Simple health ping
/// Returns "OK" or JSON { status: "ok" }
pub async fn health_ping() -> impl IntoResponse {
    Json(SimpleHealthResponse {
        status: "ok".to_string(),
    })
}

/// GET /health/detailed - Detailed health with all checks
pub async fn health_detailed() -> impl IntoResponse {
    let uptime = SERVER_START.elapsed().as_secs();

    // Check database health
    let database_check = match crate::db::health_check().await {
        Ok(duration) => ServiceCheck {
            status: "healthy".to_string(),
            response_time: Some(duration.as_millis() as u64),
            error: None,
        },
        Err(e) => ServiceCheck {
            status: "unhealthy".to_string(),
            response_time: None,
            error: Some(e.to_string()),
        },
    };

    // TODO: Implement actual Redis check when Redis is connected (Fase 4)
    let redis_check = ServiceCheck {
        status: "unhealthy".to_string(),
        response_time: None,
        error: Some("Redis not configured yet".to_string()),
    };

    // Overall status is "ok" even if DB/Redis are not configured
    // This allows frontend to know backend is running
    let overall_status = "ok".to_string();

    let response = DetailedHealthResponse {
        status: overall_status,
        timestamp: Utc::now(),
        uptime: Some(uptime),
        checks: HealthChecks {
            database: database_check,
            redis: redis_check,
        },
    };

    (StatusCode::OK, Json(response))
}

/// GET /health/database - Database health check
pub async fn health_database() -> impl IntoResponse {
    // Check if database pool is available
    match crate::db::health_check().await {
        Ok(duration) => {
            let check = ServiceCheck {
                status: "healthy".to_string(),
                response_time: Some(duration.as_millis() as u64),
                error: None,
            };
            (StatusCode::OK, Json(check))
        }
        Err(e) => {
            let check = ServiceCheck {
                status: "unhealthy".to_string(),
                response_time: None,
                error: Some(e.to_string()),
            };
            (StatusCode::OK, Json(check))
        }
    }
}

/// GET /health/redis - Redis health check
pub async fn health_redis() -> impl IntoResponse {
    // TODO: Implement actual Redis check when Redis is connected (Fase 4)
    // For now, return stub "unhealthy" status
    let check = ServiceCheck {
        status: "unhealthy".to_string(),
        response_time: None,
        error: Some("Redis not configured yet".to_string()),
    };

    (StatusCode::OK, Json(check))
}

/// GET /health/ready - Readiness check
pub async fn health_ready() -> impl IntoResponse {
    let uptime = SERVER_START.elapsed().as_secs();

    // Check database health
    let database_status = match crate::db::health_check().await {
        Ok(_) => "healthy".to_string(),
        Err(_) => "unhealthy".to_string(),
    };

    // TODO: Implement actual Redis check when Redis is connected (Fase 4)
    let redis_status = "unhealthy".to_string();

    // For MVP, we're "ready" if backend is running
    // Database is optional (will use in-memory fallback)
    let is_ready = true;

    let response = ReadyResponse {
        status: if is_ready {
            "ready".to_string()
        } else {
            "not ready".to_string()
        },
        timestamp: Utc::now(),
        uptime: Some(uptime),
        checks: Some(ReadyChecks {
            database: database_status,
            redis: redis_status,
        }),
        reason: if !is_ready {
            Some("Database or Redis is not healthy".to_string())
        } else {
            None
        },
    };

    (StatusCode::OK, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use axum::routing::get;
    use tower::ServiceExt;

    fn test_router() -> Router {
        Router::new()
            .route("/health", get(health_ping))
            .route("/health/detailed", get(health_detailed))
            .route("/health/database", get(health_database))
            .route("/health/redis", get(health_redis))
            .route("/health/ready", get(health_ready))
    }

    async fn get_json<T: serde::de::DeserializeOwned>(app: Router, uri: &str) -> (StatusCode, T) {
        let req = Request::get(uri).body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let value: T = serde_json::from_slice(&body).unwrap();
        (status, value)
    }

    #[test]
    fn test_health_status_serialization() {
        let status = HealthStatus::Ok;
        let s = serde_json::to_string(&status).unwrap();
        assert_eq!(s, "\"ok\"");
    }

    #[test]
    fn test_service_check_has_required_fields() {
        let check = ServiceCheck {
            status: "healthy".to_string(),
            response_time: Some(10),
            error: None,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("healthy"));
    }

    #[tokio::test]
    async fn test_health_ping_returns_ok() {
        init_start_time();
        let (status, body) = get_json::<SimpleHealthResponse>(test_router(), "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "ok");
    }

    #[tokio::test]
    async fn test_health_redis_returns_unhealthy() {
        let (status, body) = get_json::<ServiceCheck>(test_router(), "/health/redis").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "unhealthy");
    }

    #[tokio::test]
    async fn test_health_database_returns_when_no_pool() {
        let (status, body) = get_json::<ServiceCheck>(test_router(), "/health/database").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "unhealthy");
    }

    #[tokio::test]
    async fn test_health_detailed_returns_ok() {
        init_start_time();
        let (status, body) = get_json::<DetailedHealthResponse>(test_router(), "/health/detailed").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "ok");
        assert!(body.uptime.is_some());
    }

    #[tokio::test]
    async fn test_health_ready_returns_ready() {
        init_start_time();
        let (status, body) = get_json::<ReadyResponse>(test_router(), "/health/ready").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "ready");
    }
}

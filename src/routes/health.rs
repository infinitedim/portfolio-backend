/**
 * Health Routes
 * Endpoints for checking backend health status
 */

use axum::{
    Json,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
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
        status: if is_ready { "ready".to_string() } else { "not ready".to_string() },
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

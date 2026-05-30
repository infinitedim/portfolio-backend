use axum::{http::StatusCode, response::IntoResponse, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Instant;

lazy_static::lazy_static! {
    static ref SERVER_START: Instant = Instant::now();
}

pub fn init_start_time() {
    lazy_static::initialize(&SERVER_START);
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum HealthStatus {
    Ok,
    Healthy,
    Unhealthy,
    Unknown,
    Ready,
    #[serde(rename = "not ready")]
    NotReady,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceCheck {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DetailedHealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<u64>,
    pub checks: HealthChecks,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct HealthChecks {
    pub database: ServiceCheck,
    pub redis: ServiceCheck,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReadyChecks {
    pub database: String,
    pub redis: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SimpleHealthResponse {
    pub status: String,
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Liveness probe", body = SimpleHealthResponse),
    ),
)]
pub async fn health_ping() -> impl IntoResponse {
    Json(SimpleHealthResponse {
        status: "ok".to_string(),
    })
}

#[utoipa::path(
    get,
    path = "/health/detailed",
    tag = "Health",
    responses(
        (status = 200, description = "Detailed health status incl. db + redis checks", body = DetailedHealthResponse),
        (status = 503, description = "One or more checks failed", body = DetailedHealthResponse),
    ),
)]
pub async fn health_detailed() -> impl IntoResponse {
    let uptime = SERVER_START.elapsed().as_secs();

    let db_configured = std::env::var("DATABASE_URL").is_ok();
    let is_production = std::env::var("ENVIRONMENT")
        .map(|v| v == "production")
        .unwrap_or(false);

    let (database_check, redis_check) = tokio::join!(
        async {
            if !db_configured {
                return ServiceCheck {
                    status: "not_configured".to_string(),
                    response_time: None,
                    error: None,
                };
            }
            match crate::db::health_check().await {
                Ok(duration) => ServiceCheck {
                    status: "healthy".to_string(),
                    response_time: Some(duration.as_millis() as u64),
                    error: None,
                },
                Err(e) => ServiceCheck {
                    status: "unhealthy".to_string(),
                    response_time: None,
                    error: if is_production {
                        Some("database unreachable".to_string())
                    } else {
                        Some(e.to_string())
                    },
                },
            }
        },
        check_redis()
    );

    let db_required_and_failing = db_configured && database_check.status != "healthy";
    let overall_status = if db_required_and_failing {
        "unhealthy"
    } else {
        "ok"
    }
    .to_string();
    let status_code = if db_required_and_failing {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    let response = DetailedHealthResponse {
        status: overall_status,
        timestamp: Utc::now(),
        uptime: Some(uptime),
        checks: HealthChecks {
            database: database_check,
            redis: redis_check,
        },
    };

    (status_code, Json(response))
}

#[utoipa::path(
    get,
    path = "/health/database",
    tag = "Health",
    responses(
        (status = 200, description = "Database is healthy", body = ServiceCheck),
        (status = 503, description = "Database is unhealthy", body = ServiceCheck),
    ),
)]
pub async fn health_database() -> impl IntoResponse {
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
            // 503 — orchestrators rely on this signal to drain traffic.
            (StatusCode::SERVICE_UNAVAILABLE, Json(check))
        }
    }
}

#[utoipa::path(
    get,
    path = "/health/redis",
    tag = "Health",
    responses(
        (status = 200, description = "Redis is healthy", body = ServiceCheck),
        (status = 503, description = "Redis is unhealthy", body = ServiceCheck),
    ),
)]
pub async fn health_redis() -> impl IntoResponse {
    let check = check_redis().await;
    let status_code = match check.status.as_str() {
        "healthy" | "not_configured" => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };

    (status_code, Json(check))
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "Health",
    responses(
        (status = 200, description = "Service is ready to accept traffic", body = ReadyResponse),
        (status = 503, description = "Service is not ready", body = ReadyResponse),
    ),
)]
pub async fn health_ready() -> impl IntoResponse {
    let uptime = SERVER_START.elapsed().as_secs();

    let (database_status, redis_check) = tokio::join!(
        async {
            match crate::db::health_check().await {
                Ok(_) => "healthy".to_string(),
                Err(_) => "unhealthy".to_string(),
            }
        },
        check_redis()
    );
    let redis_status = redis_check.status.clone();

    let db_configured = std::env::var("DATABASE_URL").is_ok();
    let is_ready = !db_configured || database_status == "healthy";

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
            Some("Database is configured but not reachable".to_string())
        } else {
            None
        },
    };

    let status_code = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(response))
}

async fn check_redis() -> ServiceCheck {
    let url = match std::env::var("REDIS_URL") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            return ServiceCheck {
                status: "not_configured".to_string(),
                response_time: None,
                error: None,
            };
        }
    };

    let is_production = std::env::var("ENVIRONMENT")
        .map(|v| v == "production")
        .unwrap_or(false);

    let start = Instant::now();
    match redis_ping(&url).await {
        Ok(()) => ServiceCheck {
            status: "healthy".to_string(),
            response_time: Some(start.elapsed().as_millis() as u64),
            error: None,
        },
        Err(error) => ServiceCheck {
            status: "unhealthy".to_string(),
            response_time: None,
            error: if is_production {
                Some("redis unreachable".to_string())
            } else {
                Some(error)
            },
        },
    }
}

async fn redis_ping(url: &str) -> Result<(), String> {
    let client = redis::Client::open(url).map_err(|e| e.to_string())?;
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| e.to_string())?;
    let pong: String = redis::cmd("PING")
        .query_async(&mut conn)
        .await
        .map_err(|e| e.to_string())?;

    if pong.eq_ignore_ascii_case("PONG") {
        Ok(())
    } else {
        Err(format!("unexpected PING response: {pong}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
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
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
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
    async fn test_health_redis_reports_configuration_state() {
        let (status, body) = get_json::<ServiceCheck>(test_router(), "/health/redis").await;
        assert!(
            status == StatusCode::OK || status == StatusCode::SERVICE_UNAVAILABLE,
            "unexpected status: {status}"
        );
        assert!(
            ["not_configured", "healthy", "unhealthy"].contains(&body.status.as_str()),
            "unexpected redis status: {}",
            body.status
        );
    }

    #[tokio::test]
    async fn test_health_database_returns_503_when_no_pool() {
        let (status, body) = get_json::<ServiceCheck>(test_router(), "/health/database").await;
        // 503 is the contract: orchestrators rely on this to drain traffic.
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.status, "unhealthy");
    }

    #[tokio::test]
    async fn test_health_detailed_returns_ok() {
        init_start_time();
        let (status, body) =
            get_json::<DetailedHealthResponse>(test_router(), "/health/detailed").await;
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

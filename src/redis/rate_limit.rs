use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use redis::Script;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::redis::RedisPool;
use crate::routes::ErrorResponse;

#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub bucket: &'static str,
    pub max_requests: u32,
    pub window_secs: u64,
}

impl RateLimitConfig {
    pub const AUTH: Self = Self {
        bucket: "auth",
        max_requests: 5,
        window_secs: 60,
    };
    pub const GATE: Self = Self {
        bucket: "gate",
        max_requests: 20,
        window_secs: 1,
    };
    pub const CONTACT: Self = Self {
        bucket: "contact",
        max_requests: 3,
        window_secs: 60,
    };
    pub const LOGS: Self = Self {
        bucket: "logs",
        max_requests: 20,
        window_secs: 1,
    };
    pub const ANALYTICS: Self = Self {
        bucket: "analytics",
        max_requests: 30,
        window_secs: 1,
    };
    pub const GITHUB: Self = Self {
        bucket: "github",
        max_requests: 10,
        window_secs: 1,
    };
    pub const NEWSLETTER: Self = Self {
        bucket: "newsletter",
        max_requests: 5,
        window_secs: 10,
    };
    pub const NEWSLETTER_BROADCAST: Self = Self {
        bucket: "newsletter_broadcast",
        max_requests: 2,
        window_secs: 30,
    };
    pub const AI: Self = Self {
        bucket: "ai",
        max_requests: 10,
        window_secs: 1,
    };
}

#[derive(Clone)]
pub struct RedisRateLimitState {
    pub pool: RedisPool,
    pub config: RateLimitConfig,
}

pub fn extract_client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = forwarded.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    peer.map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

static RATE_LIMIT_SCRIPT: &str = r#"
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"#;

pub async fn check_rate_limit(
    pool: &RedisPool,
    config: &RateLimitConfig,
    client_ip: &str,
) -> Result<(), u64> {
    let key = format!("ratelimit:{}:{client_ip}", config.bucket);
    let mut conn = pool.connection();

    let count: u32 = Script::new(RATE_LIMIT_SCRIPT)
        .key(&key)
        .arg(config.window_secs)
        .invoke_async(&mut conn)
        .await
        .map_err(|_| config.window_secs)?;

    if count > config.max_requests {
        Err(config.window_secs)
    } else {
        Ok(())
    }
}

pub async fn redis_rate_limit_middleware(
    State(state): State<Arc<RedisRateLimitState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let client_ip = extract_client_ip(request.headers(), Some(peer));
    let key = format!("ratelimit:{}:{client_ip}", state.config.bucket);
    let mut conn = state.pool.connection();

    let count_result: Result<u32, redis::RedisError> = Script::new(RATE_LIMIT_SCRIPT)
        .key(&key)
        .arg(state.config.window_secs)
        .invoke_async(&mut conn)
        .await;

    match count_result {
        Ok(count) if count > state.config.max_requests => {
            crate::metrics::record_rate_limit_rejected(state.config.bucket);
            let body = axum::Json(ErrorResponse {
                error: "Too many requests".to_string(),
                message: Some("Rate limit exceeded".to_string()),
            });
            let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();
            if let Ok(value) = state.config.window_secs.to_string().parse() {
                response
                    .headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, value);
            }
            response
        }
        Ok(_) => next.run(request).await,
        Err(error) => {
            tracing::warn!(
                error = %error,
                bucket = state.config.bucket,
                "rate limit redis error; allowing request"
            );
            next.run(request).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_client_ip_prefers_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.1, 10.0.0.1".parse().unwrap());
        assert_eq!(extract_client_ip(&headers, None), "203.0.113.1".to_string());
    }

    #[test]
    fn extract_client_ip_real_ip_and_fallbacks() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "198.51.100.1".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, None),
            "198.51.100.1".to_string()
        );

        let headers_empty = HeaderMap::new();
        let peer_addr = "192.0.2.1:12345".parse::<SocketAddr>().ok();
        assert_eq!(
            extract_client_ip(&headers_empty, peer_addr),
            "192.0.2.1".to_string()
        );

        assert_eq!(
            extract_client_ip(&headers_empty, None),
            "unknown".to_string()
        );
    }

    #[tokio::test]
    async fn redis_rate_limit_blocks_after_max() {
        let Some(url) = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return;
        };

        let pool = RedisPool::connect(&url).await.expect("connect");
        let config = RateLimitConfig {
            bucket: "test",
            max_requests: 3,
            window_secs: 60,
        };
        let ip = format!("test-{}", uuid::Uuid::new_v4());

        for _ in 0..3 {
            check_rate_limit(&pool, &config, &ip)
                .await
                .expect("under limit");
        }

        let blocked = check_rate_limit(&pool, &config, &ip).await;
        assert!(blocked.is_err());
    }

    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_rate_limit_middleware_success_and_rejection() {
        let Some(url) = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return;
        };

        let pool = RedisPool::connect(&url).await.expect("connect");
        let limit_state = Arc::new(RedisRateLimitState {
            pool,
            config: RateLimitConfig {
                bucket: "test_mw",
                max_requests: 2,
                window_secs: 10,
            },
        });

        use axum::extract::connect_info::MockConnectInfo;
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(from_fn_with_state(
                limit_state.clone(),
                redis_rate_limit_middleware,
            ))
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))));

        let req = Request::get("/test").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let req = Request::get("/test").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let req = Request::get("/test").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_rate_limit_middleware_redis_error_fail_open() {
        let Some(url) = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return;
        };

        let pool = RedisPool::connect(&url).await.expect("connect");
        let limit_state = Arc::new(RedisRateLimitState {
            pool: pool.clone(),
            config: RateLimitConfig {
                bucket: "test_err",
                max_requests: 1,
                window_secs: 10,
            },
        });

        // Seed the key with a wrong type (HASH) to force a WRONGTYPE RedisError
        let mut conn = pool.connection();
        let key = "ratelimit:test_err:127.0.0.1";
        let _: () = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap();
        let _: () = redis::cmd("HSET")
            .arg(key)
            .arg("field")
            .arg("value")
            .query_async(&mut conn)
            .await
            .unwrap();

        use axum::extract::connect_info::MockConnectInfo;
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(from_fn_with_state(
                limit_state.clone(),
                redis_rate_limit_middleware,
            ))
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))));

        let req = Request::get("/test").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Clean up
        let _: () = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap();
    }
}

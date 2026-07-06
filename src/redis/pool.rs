use redis::aio::ConnectionManager;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct RedisPool {
    manager: ConnectionManager,
}

impl RedisPool {
    pub async fn connect(url: &str) -> Result<Self, String> {
        let connect = async {
            let client = redis::Client::open(url).map_err(|e| e.to_string())?;
            let manager = ConnectionManager::new(client)
                .await
                .map_err(|e| e.to_string())?;
            Ok(Self { manager })
        };

        tokio::time::timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| "redis connect timeout".to_string())?
    }

    pub async fn ping(&self) -> Result<u64, String> {
        let start = Instant::now();
        let mut conn = self.manager.clone();
        let pong: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        if pong.eq_ignore_ascii_case("PONG") {
            Ok(start.elapsed().as_millis() as u64)
        } else {
            Err(format!("unexpected PING response: {pong}"))
        }
    }

    pub fn connection(&self) -> ConnectionManager {
        self.manager.clone()
    }
}

#[derive(Clone)]
pub enum RedisMode {
    Connected(Arc<RedisPool>),
    Disabled,
}

impl RedisMode {
    pub async fn connect_from_env() -> Self {
        let url = std::env::var("REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());

        let Some(url) = url else {
            tracing::info!("redis mode=disabled (REDIS_URL not set)");
            return Self::Disabled;
        };

        match RedisPool::connect(&url).await {
            Ok(pool) => {
                tracing::info!("redis mode=connected");
                Self::Connected(Arc::new(pool))
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "redis connect failed; falling back to disabled mode"
                );
                Self::Disabled
            }
        }
    }

    pub fn pool(&self) -> Option<&RedisPool> {
        match self {
            Self::Connected(pool) => Some(pool.as_ref()),
            Self::Disabled => None,
        }
    }

    pub async fn ping(&self) -> Result<Option<u64>, String> {
        match self {
            Self::Connected(pool) => pool.ping().await.map(Some),
            Self::Disabled => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redis_test_url() -> Option<String> {
        std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }

    #[tokio::test]
    async fn pool_ping_when_redis_available() {
        let Some(url) = redis_test_url() else {
            return;
        };

        let pool = RedisPool::connect(&url).await.expect("connect");
        let ms = pool.ping().await.expect("ping");
        assert!(ms < 5_000);
    }

    #[tokio::test]
    async fn test_redis_connect_invalid_url() {
        let res = RedisPool::connect("redis://127.0.0.1:1234").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_redis_mode_connect_from_env() {
        let original_redis = std::env::var("REDIS_URL").ok();
        std::env::remove_var("REDIS_URL");
        let mode = RedisMode::connect_from_env().await;
        assert!(matches!(mode, RedisMode::Disabled));
        assert!(mode.pool().is_none());
        assert_eq!(mode.ping().await.unwrap(), None);

        std::env::set_var("REDIS_URL", "redis://127.0.0.1:1234");
        let mode2 = RedisMode::connect_from_env().await;
        assert!(matches!(mode2, RedisMode::Disabled));

        if let Some(val) = original_redis {
            std::env::set_var("REDIS_URL", val);
        } else {
            std::env::remove_var("REDIS_URL");
        }
    }
}

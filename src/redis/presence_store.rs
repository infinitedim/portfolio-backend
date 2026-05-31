use async_trait::async_trait;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::redis::RedisPool;

const CONN_TTL_SECS: u64 = 90;

#[async_trait]
pub trait PresenceBackend: Send + Sync {
    async fn join_room(&self, conn_id: &str, room: &str) -> Result<u32, String>;
    async fn leave_conn(&self, conn_id: &str) -> Result<(), String>;
    async fn refresh_conn(&self, conn_id: &str) -> Result<bool, String>;
    async fn total_connections(&self) -> Result<u32, String>;
}

#[derive(Default)]
pub struct InMemoryPresence {
    inner: Arc<RwLock<InMemoryInner>>,
}

#[derive(Default)]
struct InMemoryInner {
    rooms: HashMap<String, u32>,
    conns: HashMap<String, String>,
    total_connections: u32,
}

impl InMemoryPresence {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PresenceBackend for InMemoryPresence {
    async fn join_room(&self, conn_id: &str, room: &str) -> Result<u32, String> {
        let mut guard = self.inner.write().await;
        guard.conns.insert(conn_id.to_string(), room.to_string());
        guard.total_connections = guard.total_connections.saturating_add(1);
        let count = guard.rooms.entry(room.to_string()).or_insert(0);
        *count = count.saturating_add(1);
        Ok(*count)
    }

    async fn leave_conn(&self, conn_id: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        let Some(room) = guard.conns.remove(conn_id) else {
            return Ok(());
        };
        if guard.total_connections > 0 {
            guard.total_connections -= 1;
        }
        if let Some(count) = guard.rooms.get_mut(&room) {
            if *count > 0 {
                *count -= 1;
            }
            if *count == 0 {
                guard.rooms.remove(&room);
            }
        }
        Ok(())
    }

    async fn refresh_conn(&self, conn_id: &str) -> Result<bool, String> {
        let guard = self.inner.read().await;
        Ok(guard.conns.contains_key(conn_id))
    }

    async fn total_connections(&self) -> Result<u32, String> {
        Ok(self.inner.read().await.total_connections)
    }
}

#[derive(Clone)]
pub struct RedisPresence {
    pool: RedisPool,
}

impl RedisPresence {
    pub fn new(pool: RedisPool) -> Self {
        Self { pool }
    }

    fn room_key(room: &str) -> String {
        format!("presence:room:{room}")
    }

    fn conn_key(conn_id: &str) -> String {
        format!("presence:conn:{conn_id}")
    }
}

static DECR_CLAMP: &str = r#"
local val = redis.call('DECR', KEYS[1])
if val < 0 then
    redis.call('SET', KEYS[1], 0)
    return 0
end
return val
"#;

#[async_trait]
impl PresenceBackend for RedisPresence {
    async fn join_room(&self, conn_id: &str, room: &str) -> Result<u32, String> {
        let mut conn = self.pool.connection();
        let conn_key = Self::conn_key(conn_id);
        let room_key = Self::room_key(room);

        redis::cmd("SET")
            .arg(&conn_key)
            .arg(room)
            .arg("EX")
            .arg(CONN_TTL_SECS)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        conn.incr::<_, _, u32>(&room_key, 1)
            .await
            .map_err(|e| e.to_string())?;
        conn.incr::<_, _, u32>("presence:total", 1)
            .await
            .map_err(|e| e.to_string())?;

        conn.get(&room_key).await.map_err(|e| e.to_string())
    }

    async fn leave_conn(&self, conn_id: &str) -> Result<(), String> {
        let mut conn = self.pool.connection();
        let conn_key = Self::conn_key(conn_id);

        let room: Option<String> = conn.get(&conn_key).await.map_err(|e| e.to_string())?;
        let Some(room) = room else {
            return Ok(());
        };

        let _: () = conn.del(&conn_key).await.map_err(|e| e.to_string())?;

        let room_key = Self::room_key(&room);
        redis::Script::new(DECR_CLAMP)
            .key(&room_key)
            .invoke_async::<()>(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        redis::Script::new(DECR_CLAMP)
            .key("presence:total")
            .invoke_async::<()>(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    async fn refresh_conn(&self, conn_id: &str) -> Result<bool, String> {
        let mut conn = self.pool.connection();
        let conn_key = Self::conn_key(conn_id);
        let refreshed: bool = conn
            .expire(&conn_key, CONN_TTL_SECS as i64)
            .await
            .map_err(|e| e.to_string())?;
        Ok(refreshed)
    }

    async fn total_connections(&self) -> Result<u32, String> {
        let mut conn = self.pool.connection();
        let total: u32 = conn.get("presence:total").await.unwrap_or(0);
        Ok(total)
    }
}

pub fn build_presence_backend(redis: &crate::redis::RedisMode) -> Arc<dyn PresenceBackend> {
    match redis {
        crate::redis::RedisMode::Connected(pool) => Arc::new(RedisPresence::new((**pool).clone())),
        crate::redis::RedisMode::Disabled => Arc::new(InMemoryPresence::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_join_leave() {
        let backend = InMemoryPresence::new();
        let count = backend.join_room("c1", "site").await.expect("join");
        assert_eq!(count, 1);
        assert_eq!(backend.total_connections().await.expect("total"), 1);
        backend.leave_conn("c1").await.expect("leave");
        assert_eq!(backend.total_connections().await.expect("total"), 0);
    }

    #[tokio::test]
    async fn redis_join_leave_when_available() {
        let Some(url) = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return;
        };

        let pool = RedisPool::connect(&url).await.expect("connect");
        let backend = RedisPresence::new(pool);
        let conn = uuid::Uuid::new_v4().to_string();

        let count = backend.join_room(&conn, "site").await.expect("join");
        assert!(count >= 1);
        backend.leave_conn(&conn).await.expect("leave");
    }
}

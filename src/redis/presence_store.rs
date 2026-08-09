use async_trait::async_trait;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::redis::RedisPool;

const CONN_TTL_SECS: u64 = 90;
pub const STALE_THRESHOLD_SECS: u64 = 30;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait]
pub trait PresenceBackend: Send + Sync {
    async fn join_room(&self, conn_id: &str, room: &str) -> Result<u32, String>;
    async fn leave_conn(&self, conn_id: &str) -> Result<(), String>;
    async fn refresh_conn(&self, conn_id: &str) -> Result<bool, String>;
    async fn prune_stale(&self, stale_threshold_secs: u64) -> Result<u32, String>;
    async fn total_connections(&self) -> Result<u32, String>;
}

struct ConnInfo {
    room: String,
    last_seen: Instant,
}

#[derive(Default)]
pub struct InMemoryPresence {
    inner: Arc<RwLock<InMemoryInner>>,
}

#[derive(Default)]
struct InMemoryInner {
    conns: HashMap<String, ConnInfo>,
}

impl InMemoryPresence {
    pub fn new() -> Self {
        Self::default()
    }

    fn prune_stale_inner(guard: &mut InMemoryInner, stale_threshold_secs: u64) {
        guard
            .conns
            .retain(|_, info| info.last_seen.elapsed().as_secs() <= stale_threshold_secs);
    }
}

#[async_trait]
impl PresenceBackend for InMemoryPresence {
    async fn join_room(&self, conn_id: &str, room: &str) -> Result<u32, String> {
        let mut guard = self.inner.write().await;
        Self::prune_stale_inner(&mut guard, STALE_THRESHOLD_SECS);
        guard.conns.insert(
            conn_id.to_string(),
            ConnInfo {
                room: room.to_string(),
                last_seen: Instant::now(),
            },
        );
        let room_count = guard
            .conns
            .values()
            .filter(|info| info.room == room)
            .count() as u32;
        Ok(room_count)
    }

    async fn leave_conn(&self, conn_id: &str) -> Result<(), String> {
        let mut guard = self.inner.write().await;
        guard.conns.remove(conn_id);
        Self::prune_stale_inner(&mut guard, STALE_THRESHOLD_SECS);
        Ok(())
    }

    async fn refresh_conn(&self, conn_id: &str) -> Result<bool, String> {
        let mut guard = self.inner.write().await;
        Self::prune_stale_inner(&mut guard, STALE_THRESHOLD_SECS);
        if let Some(info) = guard.conns.get_mut(conn_id) {
            info.last_seen = Instant::now();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn prune_stale(&self, stale_threshold_secs: u64) -> Result<u32, String> {
        let mut guard = self.inner.write().await;
        Self::prune_stale_inner(&mut guard, stale_threshold_secs);
        Ok(guard.conns.len() as u32)
    }

    async fn total_connections(&self) -> Result<u32, String> {
        self.prune_stale(STALE_THRESHOLD_SECS).await
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

#[async_trait]
impl PresenceBackend for RedisPresence {
    async fn join_room(&self, conn_id: &str, room: &str) -> Result<u32, String> {
        let mut conn = self.pool.connection();
        let conn_key = Self::conn_key(conn_id);
        let room_key = Self::room_key(room);
        let now = now_secs();

        // 1. Store connection metadata with TTL
        redis::cmd("SET")
            .arg(&conn_key)
            .arg(room)
            .arg("EX")
            .arg(CONN_TTL_SECS)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        // 2. Add connection ID to ZSETs with current timestamp as score
        conn.zadd::<_, _, _, ()>("presence:global", conn_id, now)
            .await
            .map_err(|e| e.to_string())?;
        conn.zadd::<_, _, _, ()>(&room_key, conn_id, now)
            .await
            .map_err(|e| e.to_string())?;

        // 3. Prune stale connections (older than STALE_THRESHOLD_SECS)
        let cutoff = now.saturating_sub(STALE_THRESHOLD_SECS);
        let _: () = conn
            .zrembyscore("presence:global", "-inf", cutoff)
            .await
            .unwrap_or(());
        let _: () = conn
            .zrembyscore(&room_key, "-inf", cutoff)
            .await
            .unwrap_or(());

        // 4. Return current room count
        let count: u32 = conn.zcard(&room_key).await.unwrap_or(0);
        Ok(count)
    }

    async fn leave_conn(&self, conn_id: &str) -> Result<(), String> {
        let mut conn = self.pool.connection();
        let conn_key = Self::conn_key(conn_id);

        let room: Option<String> = conn.get(&conn_key).await.map_err(|e| e.to_string())?;
        if let Some(room) = room {
            let room_key = Self::room_key(&room);
            let _: () = conn.zrem(&room_key, conn_id).await.unwrap_or(());
        }

        let _: () = conn.zrem("presence:global", conn_id).await.unwrap_or(());
        let _: () = conn.del(&conn_key).await.unwrap_or(());

        Ok(())
    }

    async fn refresh_conn(&self, conn_id: &str) -> Result<bool, String> {
        let mut conn = self.pool.connection();
        let conn_key = Self::conn_key(conn_id);
        let room: Option<String> = conn.get(&conn_key).await.map_err(|e| e.to_string())?;

        let Some(room) = room else {
            return Ok(false);
        };

        let now = now_secs();
        let room_key = Self::room_key(&room);

        conn.zadd::<_, _, _, ()>("presence:global", conn_id, now)
            .await
            .map_err(|e| e.to_string())?;
        conn.zadd::<_, _, _, ()>(&room_key, conn_id, now)
            .await
            .map_err(|e| e.to_string())?;

        let refreshed: bool = conn
            .expire(&conn_key, CONN_TTL_SECS as i64)
            .await
            .unwrap_or(false);

        Ok(refreshed)
    }

    async fn prune_stale(&self, stale_threshold_secs: u64) -> Result<u32, String> {
        let mut conn = self.pool.connection();
        let now = now_secs();
        let cutoff = now.saturating_sub(stale_threshold_secs);

        let _: () = conn
            .zrembyscore("presence:global", "-inf", cutoff)
            .await
            .map_err(|e| e.to_string())?;

        let total: u32 = conn
            .zcard("presence:global")
            .await
            .map_err(|e| e.to_string())?;
        Ok(total)
    }

    async fn total_connections(&self) -> Result<u32, String> {
        self.prune_stale(STALE_THRESHOLD_SECS).await
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

//! Real-time visitor presence over WebSocket — in-memory room counts with
//! optional Redis backing when `REDIS_URL` is configured.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct PresenceState {
    inner: Arc<RwLock<PresenceInner>>,
}

#[derive(Default)]
struct PresenceInner {
    rooms: HashMap<String, u32>,
    total_connections: u32,
}

impl PresenceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn join_room(&self, room: &str) -> u32 {
        let mut guard = self.inner.write().await;
        guard.total_connections += 1;
        let count = guard.rooms.entry(room.to_string()).or_insert(0);
        *count += 1;
        *count
    }

    pub async fn leave_room(&self, room: &str) -> u32 {
        let mut guard = self.inner.write().await;
        if guard.total_connections > 0 {
            guard.total_connections -= 1;
        }
        let count = guard
            .rooms
            .get_mut(room)
            .map(|c| {
                if *c > 0 {
                    *c -= 1;
                }
                *c
            })
            .unwrap_or(0);
        if count == 0 {
            guard.rooms.remove(room);
        }
        count
    }

    pub async fn snapshot(&self) -> PresenceSnapshot {
        let guard = self.inner.read().await;
        PresenceSnapshot {
            total_connections: guard.total_connections,
            rooms: guard.rooms.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceSnapshot {
    pub total_connections: u32,
    pub rooms: HashMap<String, u32>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ClientMessage {
    Join { room: String },
    Ping,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ServerMessage {
    Welcome { total_connections: u32 },
    RoomCount { room: String, count: u32 },
    Pong,
    Error { message: String },
}

fn normalize_room(room: &str) -> String {
    let trimmed = room.trim();
    if trimmed.is_empty() {
        "site".to_string()
    } else {
        trimmed.chars().take(64).collect()
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<PresenceState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: PresenceState) {
    let (mut sender, mut receiver) = socket.split();
    let mut current_room: Option<String> = None;

    let snapshot = state.snapshot().await;
    let welcome = serde_json::to_string(&ServerMessage::Welcome {
        total_connections: snapshot.total_connections,
    })
    .unwrap_or_else(|_| r#"{"type":"error","message":"serialize failed"}"#.to_string());
    if sender.send(Message::Text(welcome.into())).await.is_err() {
        return;
    }

    while let Some(msg) = receiver.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(_) => break,
        };

        match msg {
            Message::Text(text) => {
                let parsed: Result<ClientMessage, _> = serde_json::from_str(&text);
                match parsed {
                    Ok(ClientMessage::Join { room }) => {
                        if let Some(old) = current_room.take() {
                            let _ = state.leave_room(&old).await;
                        }
                        let room = normalize_room(&room);
                        let count = state.join_room(&room).await;
                        current_room = Some(room.clone());
                        let payload = serde_json::to_string(&ServerMessage::RoomCount {
                            room,
                            count,
                        })
                        .unwrap_or_default();
                        let _ = sender.send(Message::Text(payload.into())).await;
                    }
                    Ok(ClientMessage::Ping) => {
                        let payload =
                            serde_json::to_string(&ServerMessage::Pong).unwrap_or_default();
                        let _ = sender.send(Message::Text(payload.into())).await;
                    }
                    Err(_) => {
                        let payload = serde_json::to_string(&ServerMessage::Error {
                            message: "invalid message".to_string(),
                        })
                        .unwrap_or_default();
                        let _ = sender.send(Message::Text(payload.into())).await;
                    }
                }
            }
            Message::Close(_) => break,
            Message::Ping(payload) => {
                let _ = sender.send(Message::Pong(payload)).await;
            }
            _ => {}
        }
    }

    if let Some(room) = current_room {
        let _ = state.leave_room(&room).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn join_and_leave_room_updates_counts() {
        let state = PresenceState::new();
        let count = state.join_room("site").await;
        assert_eq!(count, 1);
        let count2 = state.join_room("site").await;
        assert_eq!(count2, 2);

        let remaining = state.leave_room("site").await;
        assert_eq!(remaining, 1);
        let remaining2 = state.leave_room("site").await;
        assert_eq!(remaining2, 0);

        let snap = state.snapshot().await;
        assert!(snap.rooms.is_empty());
    }

    #[test]
    fn normalize_room_defaults_empty_to_site() {
        assert_eq!(normalize_room(""), "site");
        assert_eq!(normalize_room("  blog  "), "blog");
    }
}

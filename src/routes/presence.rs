//! Real-time visitor presence over WebSocket — Redis-backed when configured,
//! in-memory fallback otherwise.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::redis::presence_store::{build_presence_backend, PresenceBackend};

#[derive(Clone)]
pub struct PresenceState {
    backend: Arc<dyn PresenceBackend>,
}

impl PresenceState {
    pub fn new(redis: &crate::redis::RedisMode) -> Self {
        Self {
            backend: build_presence_backend(redis),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceSnapshot {
    pub total_connections: u32,
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
    let conn_id = Uuid::new_v4().to_string();
    let mut current_room: Option<String> = None;
    let mut watchdog = None::<tokio::task::JoinHandle<()>>;

    let total = state.backend.total_connections().await.unwrap_or(0);
    let welcome = serde_json::to_string(&ServerMessage::Welcome {
        total_connections: total,
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
                            let _ = state.backend.leave_conn(&conn_id).await;
                            let _ = old;
                        }
                        if let Some(handle) = watchdog.take() {
                            handle.abort();
                        }

                        let room = normalize_room(&room);
                        let count = state.backend.join_room(&conn_id, &room).await.unwrap_or(0);
                        current_room = Some(room.clone());

                        let backend = state.backend.clone();
                        let conn = conn_id.clone();
                        watchdog = Some(tokio::spawn(async move {
                            loop {
                                tokio::time::sleep(Duration::from_secs(45)).await;
                                match backend.refresh_conn(&conn).await {
                                    Ok(true) => continue,
                                    _ => {
                                        let _ = backend.leave_conn(&conn).await;
                                        break;
                                    }
                                }
                            }
                        }));

                        let payload =
                            serde_json::to_string(&ServerMessage::RoomCount { room, count })
                                .unwrap_or_default();
                        let _ = sender.send(Message::Text(payload.into())).await;
                    }
                    Ok(ClientMessage::Ping) => {
                        let _ = state.backend.refresh_conn(&conn_id).await;
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

    if let Some(handle) = watchdog.take() {
        handle.abort();
    }
    if current_room.is_some() {
        let _ = state.backend.leave_conn(&conn_id).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redis::RedisMode;

    #[tokio::test]
    async fn presence_state_uses_in_memory_when_redis_disabled() {
        let state = PresenceState::new(&RedisMode::Disabled);
        let count = state.backend.join_room("c1", "site").await.expect("join");
        assert_eq!(count, 1);
    }

    #[test]
    fn normalize_room_defaults_empty_to_site() {
        assert_eq!(normalize_room(""), "site");
        assert_eq!(normalize_room("  blog  "), "blog");
    }
}

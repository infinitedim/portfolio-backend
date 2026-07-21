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
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::redis::presence_store::{build_presence_backend, PresenceBackend};

#[derive(Clone)]
pub struct PresenceState {
    backend: Arc<dyn PresenceBackend>,
    broadcast_tx: broadcast::Sender<u32>,
}

impl PresenceState {
    pub fn new(redis: &crate::redis::RedisMode) -> Self {
        let (broadcast_tx, _) = broadcast::channel(64);
        Self {
            backend: build_presence_backend(redis),
            broadcast_tx,
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
    #[serde(rename_all = "camelCase")]
    Welcome {
        total_connections: u32,
    },
    RoomCount {
        room: String,
        count: u32,
    },
    Pong,
    Error {
        message: String,
    },
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

    let mut broadcast_rx = state.broadcast_tx.subscribe();

    let total = state.backend.total_connections().await.unwrap_or(0);
    let welcome = serde_json::to_string(&ServerMessage::Welcome {
        total_connections: total,
    })
    .unwrap_or_else(|_| r#"{"type":"error","message":"serialize failed"}"#.to_string());
    if sender.send(Message::Text(welcome.into())).await.is_err() {
        return;
    }

    let (tx_to_ws, mut rx_from_bcast) = tokio::sync::mpsc::channel::<String>(8);
    tokio::spawn(async move {
        while let Ok(total) = broadcast_rx.recv().await {
            let msg = serde_json::to_string(&ServerMessage::Welcome {
                total_connections: total,
            })
            .unwrap_or_default();
            if tx_to_ws.send(msg).await.is_err() {
                break;
            }
        }
    });

    let timeout_duration = Duration::from_secs(90);
    let mut last_activity = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(last_activity + timeout_duration) => {
                break;
            }
            msg = receiver.next() => {
                last_activity = tokio::time::Instant::now();
                let msg = match msg {
                    Some(Ok(m)) => m,
                    _ => break,
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

                                let room = normalize_room(&room);
                                let count = state.backend.join_room(&conn_id, &room).await.unwrap_or(0);
                                current_room = Some(room.clone());

                                let payload =
                                    serde_json::to_string(&ServerMessage::RoomCount { room, count })
                                        .unwrap_or_default();
                                let _ = sender.send(Message::Text(payload.into())).await;

                                let new_total = state.backend.total_connections().await.unwrap_or(0);
                                let _ = state.broadcast_tx.send(new_total);
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
            Some(msg) = rx_from_bcast.recv() => {
                if sender.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
        }
    }

    if current_room.is_some() {
        let _ = state.backend.leave_conn(&conn_id).await;
        let new_total = state.backend.total_connections().await.unwrap_or(0);
        let _ = state.broadcast_tx.send(new_total);
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

    #[tokio::test]
    async fn test_ws_presence_integration() {
        use axum::routing::get;
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let state = PresenceState::new(&RedisMode::Disabled);
        let app = axum::Router::new()
            .route("/ws", get(ws_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
        let (mut write, mut read) = ws_stream.split();

        async fn wait_for_msg(
            read: &mut futures_util::stream::SplitStream<
                tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >,
            >,
            contains: &str,
        ) -> String {
            loop {
                let msg = read.next().await.unwrap().unwrap();
                let text = msg.to_text().unwrap();
                if text.to_lowercase().contains(&contains.to_lowercase()) {
                    return text.to_string();
                }
            }
        }

        // 1. Should receive Welcome message first
        let text = wait_for_msg(&mut read, "welcome").await;
        assert!(text.contains("welcome"));

        // 2. Send join message
        let join_msg = serde_json::json!({
            "type": "join",
            "room": "lobby"
        })
        .to_string();
        write.send(WsMessage::Text(join_msg.into())).await.unwrap();

        // 3. Should receive roomCount message
        let text = wait_for_msg(&mut read, "roomCount").await;
        assert!(text.contains("roomCount"));
        assert!(text.contains("lobby"));

        // 4. Send ping message
        let ping_msg = serde_json::json!({
            "type": "ping"
        })
        .to_string();
        write.send(WsMessage::Text(ping_msg.into())).await.unwrap();

        // 5. Should receive pong message
        let text = wait_for_msg(&mut read, "pong").await;
        assert!(text.contains("pong") || text.contains("Pong"));

        // 6. Send invalid message -> Should receive error
        write
            .send(WsMessage::Text("invalid json".into()))
            .await
            .unwrap();
        let text = wait_for_msg(&mut read, "error").await;
        assert!(text.contains("error") || text.contains("Error"));

        // 7. Join another room while already in one -> Should succeed
        let join_msg2 = serde_json::json!({
            "type": "join",
            "room": "blog"
        })
        .to_string();
        write.send(WsMessage::Text(join_msg2.into())).await.unwrap();
        let text = wait_for_msg(&mut read, "roomCount").await;
        assert!(text.contains("roomCount"));
        assert!(text.contains("blog"));

        // 8. Send WS Ping frame -> Should receive Pong frame
        write
            .send(WsMessage::Ping(vec![1, 2, 3].into()))
            .await
            .unwrap();

        loop {
            let msg = read.next().await.unwrap().unwrap();
            if matches!(msg, WsMessage::Pong(_)) {
                break;
            }
        }
    }
}

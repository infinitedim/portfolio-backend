use axum::{
    extract::{ConnectInfo, Extension, Json},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::Value;
use std::net::SocketAddr;
use tower_http::request_id::RequestId;

use crate::logging::config::{ClientLogBatch, ClientLogEntry, LogResponse};

/// Hard upper bound on entries per batch — anything more is almost certainly
/// abuse (or a bug in the client logger), and accepting it would let an
/// attacker drown our log pipeline.
const MAX_BATCH_SIZE: usize = 50;

/// Truncate per-entry strings to this length so a single misbehaving client
/// can't blow out our retention budget.
const MAX_FIELD_LEN: usize = 2_048;

/// Keys whose values should never be persisted, regardless of source. Match is
/// case-insensitive and prefix-based to catch typical naming variants like
/// `accessToken`, `Authorization`, `secretKey`, `password_hash`, etc.
const REDACT_KEY_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "set-cookie",
    "api_key",
    "apikey",
    "session",
    "credit_card",
    "creditcard",
    "ssn",
    "private_key",
    "privatekey",
];

const REDACTED: &str = "[REDACTED]";

#[utoipa::path(
    post,
    path = "/api/logs",
    tag = "Logs",
    request_body = ClientLogBatch,
    responses(
        (status = 200, description = "Logs accepted", body = LogResponse),
        (status = 413, description = "Batch too large", body = LogResponse),
    )
)]
#[tracing::instrument(skip(logs, headers), fields(batch_size = logs.logs.len()))]
pub async fn receive_client_logs(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request_id: Option<Extension<RequestId>>,
    Json(mut logs): Json<ClientLogBatch>,
) -> impl IntoResponse {
    // Reject anything bigger than the cap before we spend cycles redacting it.
    if logs.logs.len() > MAX_BATCH_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(LogResponse {
                success: false,
                received: logs.logs.len(),
                processed: 0,
                error: Some(format!(
                    "Batch exceeds maximum of {} entries",
                    MAX_BATCH_SIZE
                )),
            }),
        );
    }

    // Use the real client IP when behind a proxy, otherwise the socket addr.
    // Rate limiting itself is now enforced by the `tower-governor` layer
    // wired up in `lib.rs::create_app`. We keep the resolution here purely
    // for the audit log line below.
    let client_ip = client_ip(&headers, &addr);

    let req_id = request_id
        .as_ref()
        .and_then(|ext| ext.header_value().to_str().ok())
        .unwrap_or("unknown");

    let received = logs.logs.len();
    tracing::info!(
        request_id = %req_id,
        batch_size = received,
        client_ip = %client_ip,
        "received client logs"
    );

    let mut processed = 0;

    for log in logs.logs.iter_mut() {
        sanitize_entry(log);

        if let Err(e) = process_client_log(log, req_id) {
            tracing::warn!(
                request_id = %req_id,
                error = %e,
                "failed to process client log"
            );
        } else {
            processed += 1;
        }
    }

    let response = LogResponse {
        success: true,
        received,
        processed,
        error: None,
    };

    (StatusCode::ACCEPTED, Json(response))
}

fn client_ip(headers: &HeaderMap, fallback: &SocketAddr) -> String {
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            // First IP in the chain is the originating client.
            if let Some(first) = value.split(',').next() {
                let trimmed = first.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    fallback.ip().to_string()
}

fn sanitize_entry(entry: &mut ClientLogEntry) {
    if entry.message.len() > MAX_FIELD_LEN {
        entry.message.truncate(MAX_FIELD_LEN);
    }
    if let Some(ctx) = entry.context.as_mut() {
        redact_value(ctx);
    }
    if let Some(meta) = entry.metadata.as_mut() {
        redact_value(meta);
    }
}

fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if should_redact_key(k) {
                    *v = Value::String(REDACTED.to_string());
                } else {
                    redact_value(v);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_value(v);
            }
        }
        Value::String(s) if s.len() > MAX_FIELD_LEN => {
            s.truncate(MAX_FIELD_LEN);
        }
        _ => {}
    }
}

fn should_redact_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    REDACT_KEY_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
}

fn process_client_log(log: &ClientLogEntry, request_id: &str) -> Result<(), String> {
    let level = log.level.as_str();

    let span = tracing::info_span!(
        "client_log",
        request_id = %request_id,
        timestamp = %log.timestamp,
        source = "client",
    );

    let _enter = span.enter();

    match level {
        "trace" => tracing::trace!(
            message = %log.message,
            context = ?log.context,
            metadata = ?log.metadata,
            "client log"
        ),
        "debug" => tracing::debug!(
            message = %log.message,
            context = ?log.context,
            metadata = ?log.metadata,
            "client log"
        ),
        "info" => tracing::info!(
            message = %log.message,
            context = ?log.context,
            metadata = ?log.metadata,
            "client log"
        ),
        "warn" => tracing::warn!(
            message = %log.message,
            context = ?log.context,
            metadata = ?log.metadata,
            "client log"
        ),
        "error" | "fatal" => tracing::error!(
            message = %log.message,
            context = ?log.context,
            metadata = ?log.metadata,
            "client log"
        ),
        _ => {
            return Err(format!("Unknown log level: {}", level));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_should_redact_key_matches_token_variants() {
        assert!(should_redact_key("token"));
        assert!(should_redact_key("accessToken"));
        assert!(should_redact_key("Authorization"));
        assert!(should_redact_key("api_key"));
        assert!(should_redact_key("password_hash"));
        assert!(!should_redact_key("user_id"));
        assert!(!should_redact_key("level"));
    }

    #[test]
    fn test_redact_nested_object() {
        let mut value = json!({
            "user": "alice",
            "credentials": { "password": "hunter2", "session_id": "abc" },
            "tokens": [{"accessToken": "..."}],
            "metadata": { "ok": true },
        });
        redact_value(&mut value);

        // When the key itself matches a sensitive fragment, the whole subtree
        // is replaced with [REDACTED]. This is intentional — a key called
        // `tokens` could contain anything and is not safe to descend into.
        assert_eq!(value["tokens"], json!("[REDACTED]"));

        // Children of innocuous keys are still recursively scanned.
        let creds = &value["credentials"];
        assert_eq!(creds["password"], json!("[REDACTED]"));
        assert_eq!(creds["session_id"], json!("[REDACTED]"));

        // Non-sensitive keys are preserved untouched.
        assert_eq!(value["user"], json!("alice"));
        assert_eq!(value["metadata"]["ok"], json!(true));
    }
    #[test]
    fn test_truncate_long_string_field() {
        let huge = "x".repeat(MAX_FIELD_LEN + 100);
        let mut value = json!({ "note": huge });
        redact_value(&mut value);
        let v = &value["note"];
        assert_eq!(v.as_str().unwrap().len(), MAX_FIELD_LEN);
    }

    #[tokio::test]
    async fn test_receive_client_logs_integration() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::post;
        use axum::Router;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/api/logs", post(receive_client_logs))
            .layer(crate::test_support::mock_connect_info());

        // 1. Send normal logs batch
        let batch = json!({
            "logs": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "level": "info",
                    "message": "hello world",
                    "context": { "user": "test" },
                    "metadata": { "api_key": "secret123" }
                },
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "level": "unknown", // will fail processing but process other
                    "message": "bad level",
                    "context": null,
                    "metadata": null
                }
            ]
        });
        let body = serde_json::to_vec(&batch).unwrap();
        let req = Request::post("/api/logs")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "127.0.0.1, 10.0.0.1")
            .body(Body::from(body))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(response_val["success"].as_bool().unwrap());
        assert_eq!(response_val["received"].as_u64().unwrap(), 2);
        assert_eq!(response_val["processed"].as_u64().unwrap(), 1); // 1 processed, 1 failed (unknown level)

        // 2. Batch too large
        let mut huge_logs = Vec::new();
        for _ in 0..55 {
            huge_logs.push(json!({
                "timestamp": "2024-01-01T00:00:00Z",
                "level": "info",
                "message": "log",
                "context": null,
                "metadata": null
            }));
        }
        let batch_huge = json!({ "logs": huge_logs });
        let body_huge = serde_json::to_vec(&batch_huge).unwrap();
        let req_huge = Request::post("/api/logs")
            .header("content-type", "application/json")
            .body(Body::from(body_huge))
            .unwrap();
        let res_huge = app.oneshot(req_huge).await.unwrap();
        assert_eq!(res_huge.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let bytes_huge = axum::body::to_bytes(res_huge.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_huge: serde_json::Value = serde_json::from_slice(&bytes_huge).unwrap();
        assert!(!response_huge["success"].as_bool().unwrap());
    }
}

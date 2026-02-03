use crate::logging::config::{ClientLogBatch, ClientLogEntry, LogLevel, LogResponse};
/**
 * Logs Route Handler
 * Endpoint for receiving client logs from frontend
 */
use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use tower_http::request_id::RequestId;

/// POST /api/logs - Receive client logs
#[tracing::instrument(skip(logs), fields(batch_size = logs.logs.len()))]
pub async fn receive_client_logs(
    request_id: Option<Extension<RequestId>>,
    Json(logs): Json<ClientLogBatch>,
) -> impl IntoResponse {
    let req_id = request_id
        .as_ref()
        .and_then(|ext| ext.0.header_value().to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %req_id,
        batch_size = logs.logs.len(),
        "received client logs"
    );

    let mut processed = 0;

    // Process each log entry
    for log in &logs.logs {
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
        received: logs.logs.len(),
        processed,
        error: None,
    };

    (StatusCode::ACCEPTED, Json(response))
}

/// Process a single client log entry
fn process_client_log(log: &ClientLogEntry, request_id: &str) -> Result<(), String> {
    // Create structured log entry
    let span = tracing::info_span!(
        "client_log",
        request_id = %request_id,
        timestamp = %log.timestamp,
        source = "client",
    );

    let _enter = span.enter();

    // Log based on level
    match log.level {
        LogLevel::Trace => tracing::trace!(
            message = %log.message,
            context = ?log.context,
            metadata = ?log.metadata,
            "client log"
        ),
        LogLevel::Debug => tracing::debug!(
            message = %log.message,
            context = ?log.context,
            metadata = ?log.metadata,
            "client log"
        ),
        LogLevel::Info => tracing::info!(
            message = %log.message,
            context = ?log.context,
            metadata = ?log.metadata,
            "client log"
        ),
        LogLevel::Warn => tracing::warn!(
            message = %log.message,
            context = ?log.context,
            metadata = ?log.metadata,
            "client log"
        ),
        LogLevel::Error => tracing::error!(
            message = %log.message,
            context = ?log.context,
            metadata = ?log.metadata,
            "client log"
        ),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::config::{ClientLogBatch, ClientLogEntry, LogLevel};
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use axum::routing::post;
    use tower::ServiceExt;

    fn logs_router() -> Router {
        Router::new().route("/api/logs", post(receive_client_logs))
    }

    async fn post_json(app: Router, uri: &str, json: &impl serde::Serialize) -> (axum::http::StatusCode, axum::body::Bytes) {
        let body = Body::from(serde_json::to_vec(json).unwrap());
        let req = Request::post(uri).header("content-type", "application/json").body(body).unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (status, bytes)
    }

    #[tokio::test]
    async fn test_receive_client_logs_accepts_batch() {
        let batch = ClientLogBatch {
            logs: vec![ClientLogEntry {
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                level: LogLevel::Info,
                message: "test message".to_string(),
                context: None,
                metadata: None,
            }],
        };
        let (status, bytes) = post_json(logs_router(), "/api/logs", &batch).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        let body: crate::logging::config::LogResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(body.success);
        assert_eq!(body.received, 1);
        assert_eq!(body.processed, 1);
    }

    #[tokio::test]
    async fn test_receive_client_logs_empty_batch() {
        let batch = ClientLogBatch { logs: vec![] };
        let (status, bytes) = post_json(logs_router(), "/api/logs", &batch).await;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        let body: crate::logging::config::LogResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(body.success);
        assert_eq!(body.received, 0);
    }
}

/**
 * Logs Route Handler
 * Endpoint for receiving client logs from frontend
 */

use axum::{
    extract::{Json, Extension},
    http::StatusCode,
    response::IntoResponse,
};
use tower_http::request_id::RequestId;
use crate::logging::config::{ClientLogBatch, ClientLogEntry, LogLevel, LogResponse};

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

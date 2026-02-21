use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use tower_http::request_id::RequestId;

use crate::logging::config::{ClientLogBatch, ClientLogEntry, LogResponse};

#[tracing::instrument(skip(logs), fields(batch_size = logs.logs.len()))]
pub async fn receive_client_logs(
    request_id: Option<Extension<RequestId>>,
    Json(logs): Json<ClientLogBatch>,
) -> impl IntoResponse {
    let req_id = request_id
        .as_ref()
        .and_then(|ext| ext.header_value().to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %req_id,
        batch_size = logs.logs.len(),
        "received client logs"
    );

    let mut processed = 0;

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

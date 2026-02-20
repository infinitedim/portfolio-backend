

use axum::{extract::Request, middleware::Next, response::Response};
use std::time::Instant;
use tower_http::request_id::{
    MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};

pub async fn log_request(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let version = request.version();

    let req_id: String = request
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    
    tracing::info!(
        request_id = %req_id,
        method = %method,
        uri = %uri,
        version = ?version,
        "incoming request"
    );

    
    let response = next.run(request).await;

    
    let duration = start.elapsed();
    let status = response.status();

    
    if status.is_server_error() {
        tracing::error!(
            request_id = %req_id,
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = %duration.as_millis(),
            "request completed with error"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            request_id = %req_id,
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = %duration.as_millis(),
            "request completed with client error"
        );
    } else {
        tracing::info!(
            request_id = %req_id,
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = %duration.as_millis(),
            "request completed successfully"
        );
    }

    response
}

pub fn request_id_layer() -> SetRequestIdLayer<MakeRequestUuid> {
    SetRequestIdLayer::x_request_id(MakeRequestUuid)
}

pub fn propagate_request_id_layer() -> PropagateRequestIdLayer {
    PropagateRequestIdLayer::x_request_id()
}

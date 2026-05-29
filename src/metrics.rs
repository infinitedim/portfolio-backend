//! Prometheus metrics: HTTP middleware, business counters, and scrape endpoint.

use axum::{
    extract::MatchedPath,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use metrics::{counter, describe_counter, describe_histogram, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use once_cell::sync::OnceCell;
use serde::Deserialize;
use std::time::{Duration, Instant};
use utoipa::ToSchema;

static PROMETHEUS_HANDLE: OnceCell<PrometheusHandle> = OnceCell::new();

const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
const HTTP_REQUEST_DURATION_SECONDS: &str = "http_request_duration_seconds";
const BLOG_POST_VIEWS_TOTAL: &str = "blog_post_views_total";
const CONTACT_SUBMISSIONS_TOTAL: &str = "contact_submissions_total";
const GATE_UNLOCKS_TOTAL: &str = "gate_unlocks_total";

const LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Install the global Prometheus recorder once and return a clone of its handle.
pub fn init() -> PrometheusHandle {
    PROMETHEUS_HANDLE
        .get_or_init(|| {
            describe_counter!(
                HTTP_REQUESTS_TOTAL,
                "Total HTTP requests handled by the API"
            );
            describe_histogram!(
                HTTP_REQUEST_DURATION_SECONDS,
                "HTTP request latency in seconds"
            );
            describe_counter!(
                BLOG_POST_VIEWS_TOTAL,
                "Blog post page views reported via analytics endpoint"
            );
            describe_counter!(
                CONTACT_SUBMISSIONS_TOTAL,
                "Successful contact form submissions persisted"
            );
            describe_counter!(GATE_UNLOCKS_TOTAL, "Successful terminal gate unlocks");

            let handle = PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Full(HTTP_REQUEST_DURATION_SECONDS.to_string()),
                    LATENCY_BUCKETS,
                )
                .expect("valid latency histogram buckets")
                .install_recorder()
                .expect("failed to install prometheus metrics recorder");

            let upkeep = handle.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        upkeep.run_upkeep();
                    }
                });
            }

            handle
        })
        .clone()
}

pub fn prometheus_handle() -> PrometheusHandle {
    init()
}

/// Axum middleware that records request count and latency histograms.
pub async fn track_http_metrics(request: axum::extract::Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().to_string();
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    let response = next.run(request).await;

    let status = response.status().as_u16().to_string();
    let elapsed = start.elapsed().as_secs_f64();

    counter!(
        HTTP_REQUESTS_TOTAL,
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status
    )
    .increment(1);
    histogram!(
        HTTP_REQUEST_DURATION_SECONDS,
        "method" => method,
        "path" => path
    )
    .record(elapsed);

    response
}

pub fn record_blog_post_view(slug: &str) {
    counter!(BLOG_POST_VIEWS_TOTAL, "slug" => slug.to_string()).increment(1);
}

pub fn record_contact_submission() {
    counter!(CONTACT_SUBMISSIONS_TOTAL).increment(1);
}

pub fn record_gate_unlock() {
    counter!(GATE_UNLOCKS_TOTAL).increment(1);
}

/// GET /metrics — Prometheus scrape endpoint.
pub async fn metrics_handler() -> impl IntoResponse {
    let body = prometheus_handle().render();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PageviewRequest {
    /// Page path, e.g. `/blog/my-post` or `/`.
    pub path: String,
    /// Optional blog slug when the view is for a post detail page.
    #[serde(default)]
    pub slug: Option<String>,
}

#[derive(Debug, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PageviewResponse {
    pub recorded: bool,
}

const MAX_PAGEVIEW_PATH_LEN: usize = 512;
const MAX_PAGEVIEW_SLUG_LEN: usize = 200;

/// POST /api/analytics/pageview — lightweight client-side page view beacon.
#[utoipa::path(
    post,
    path = "/api/analytics/pageview",
    tag = "Analytics",
    request_body = PageviewRequest,
    responses(
        (status = 202, description = "Page view recorded", body = PageviewResponse),
        (status = 400, description = "Invalid payload", body = crate::routes::ErrorResponse),
    )
)]
pub async fn record_pageview(Json(body): Json<PageviewRequest>) -> impl IntoResponse {
    let path = body.path.trim();
    if path.is_empty() || path.len() > MAX_PAGEVIEW_PATH_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(crate::routes::ErrorResponse {
                error: "Invalid path".into(),
                message: None,
            }),
        )
            .into_response();
    }

    if let Some(slug) = body.slug.as_deref() {
        let slug = slug.trim();
        if slug.is_empty() || slug.len() > MAX_PAGEVIEW_SLUG_LEN {
            return (
                StatusCode::BAD_REQUEST,
                Json(crate::routes::ErrorResponse {
                    error: "Invalid slug".into(),
                    message: None,
                }),
            )
                .into_response();
        }
        record_blog_post_view(slug);
    } else if path.starts_with("/blog/") {
        let slug = path.trim_start_matches("/blog/").trim_matches('/');
        if !slug.is_empty() && slug.len() <= MAX_PAGEVIEW_SLUG_LEN && !slug.contains('/') {
            record_blog_post_view(slug);
        }
    }

    (
        StatusCode::ACCEPTED,
        Json(PageviewResponse { recorded: true }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use std::sync::{Mutex, OnceLock};
    use tower::util::ServiceExt;

    fn metrics_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn init_installs_prometheus_recorder_once() {
        let _guard = metrics_test_lock().lock().expect("metrics test lock");
        let _ = init();
        let _ = init();
    }

    #[tokio::test]
    async fn metrics_handler_returns_prometheus_text() {
        init();
        counter!(HTTP_REQUESTS_TOTAL, "method" => "GET", "path" => "/health", "status" => "200")
            .increment(1);

        let response = metrics_handler().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(content_type.contains("text/plain"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body readable");
        let text = String::from_utf8(body.to_vec()).expect("utf8 body");
        assert!(text.contains("http_requests_total"));
    }

    #[tokio::test]
    async fn pageview_rejects_empty_path() {
        let response = record_pageview(Json(PageviewRequest {
            path: "   ".into(),
            slug: None,
        }))
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn pageview_records_slug_and_returns_accepted() {
        init();
        let before = prometheus_handle().render();

        let response = record_pageview(Json(PageviewRequest {
            path: "/blog/hello-world".into(),
            slug: Some("hello-world".into()),
        }))
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let after = prometheus_handle().render();
        assert!(after.contains("blog_post_views_total"));
        assert!(after.len() >= before.len());
    }

    #[tokio::test]
    async fn track_http_metrics_middleware_records_request() {
        init();
        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn(track_http_metrics));

        app.oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

        let rendered = prometheus_handle().render();
        assert!(rendered.contains("http_requests_total"));
        assert!(rendered.contains("http_request_duration_seconds"));
    }
}

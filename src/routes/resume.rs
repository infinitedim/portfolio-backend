use axum::{
    extract::Multipart,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use object_store::{
    gcp::GoogleCloudStorageBuilder, path::Path as GcsPath, ObjectStore, ObjectStoreExt, PutPayload,
};
use once_cell::sync::OnceCell;
use std::sync::Arc;

use crate::routes::auth::require_admin;
use crate::routes::upload::UploadResponse;
use crate::routes::ErrorResponse;

const MAX_RESUME_SIZE: usize = 10 * 1024 * 1024; // 10MB
const GCS_RESUME_PATH: &str = "resume/resume.pdf";

static GCS_CLIENT: OnceCell<Option<Arc<dyn ObjectStore>>> = OnceCell::new();

fn gcs_bucket_name() -> Option<String> {
    std::env::var("GCS_BUCKET").ok().filter(|s| !s.is_empty())
}

fn gcs_client() -> Option<Arc<dyn ObjectStore>> {
    GCS_CLIENT
        .get_or_init(|| {
            let bucket = gcs_bucket_name()?;
            match GoogleCloudStorageBuilder::from_env()
                .with_bucket_name(&bucket)
                .build()
            {
                Ok(store) => {
                    tracing::info!("GCS client initialised for resume bucket: {}", bucket);
                    Some(Arc::new(store) as Arc<dyn ObjectStore>)
                }
                Err(e) => {
                    tracing::warn!("Failed to build GCS client for resume: {}", e);
                    None
                }
            }
        })
        .clone()
}

/// GET /api/resume/raw
/// Returns the raw PDF bytes of the resume from GCS (`resume/resume.pdf`).
#[utoipa::path(
    get,
    path = "/api/resume/raw",
    tag = "Resume",
    responses(
        (status = 200, description = "Raw resume PDF bytes", content_type = "application/pdf"),
        (status = 404, description = "Resume not found", body = ErrorResponse),
    )
)]
pub async fn get_raw_resume() -> impl IntoResponse {
    let client = match gcs_client() {
        Some(client) => client,
        None => {
            tracing::warn!("GCS client not configured for resume");
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Resume PDF not found".to_string(),
                    message: Some("Cloud storage not configured".to_string()),
                }),
            )
                .into_response();
        }
    };

    let gcs_path = GcsPath::from(GCS_RESUME_PATH);
    match client.get(&gcs_path).await {
        Ok(result) => match result.bytes().await {
            Ok(bytes) => {
                tracing::info!("Resume PDF served from GCS ({} bytes)", bytes.len());
                (
                    StatusCode::OK,
                    [
                        ("content-type", "application/pdf"),
                        (
                            "content-disposition",
                            "attachment; filename=\"Dimas_Saputra_Resume.pdf\"",
                        ),
                        ("cache-control", "private, no-store, max-age=0"),
                    ],
                    bytes,
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!("Failed to read GCS resume bytes: {}", e);
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Resume PDF not found".to_string(),
                        message: None,
                    }),
                )
                    .into_response()
            }
        },
        Err(e) => {
            tracing::warn!("GCS resume object not found: {}", e);
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Resume PDF not found".to_string(),
                    message: None,
                }),
            )
                .into_response()
        }
    }
}

/// POST /api/upload/resume (Admin only)
/// Uploads a new resume PDF to GCS (`resume/resume.pdf`).
#[utoipa::path(
    post,
    path = "/api/upload/resume",
    tag = "Upload",
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "Resume PDF uploaded", body = UploadResponse),
        (status = 400, description = "Invalid file", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 503, description = "Storage not configured", body = ErrorResponse),
    )
)]
pub async fn upload_resume(headers: HeaderMap, mut multipart: Multipart) -> impl IntoResponse {
    if let Err(err_response) = require_admin(&headers) {
        return err_response.into_response();
    }

    let field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "No file provided".to_string(),
                    message: None,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Multipart error on resume upload: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid multipart data".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    let bytes = match field.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to read resume bytes: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Failed to read file data".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    if bytes.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Empty file".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    if bytes.len() > MAX_RESUME_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "File too large. Maximum size for resume is 10MB.".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    // Validate PDF magic bytes: %PDF- (0x25, 0x50, 0x44, 0x46)
    if bytes.len() < 4 || &bytes[0..4] != b"%PDF" {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid file format. Only PDF files are allowed for resume.".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    let client = match gcs_client() {
        Some(c) => c,
        None => {
            tracing::error!("GCS client not configured for resume upload");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Cloud storage not configured".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    let size = bytes.len();

    let gcs_path = GcsPath::from(GCS_RESUME_PATH);
    let payload = PutPayload::from_bytes(bytes);
    let put_opts = object_store::PutOptions {
        attributes: {
            let mut attrs = object_store::Attributes::new();
            attrs.insert(
                object_store::Attribute::ContentType,
                object_store::AttributeValue::from("application/pdf"),
            );
            attrs.insert(
                object_store::Attribute::CacheControl,
                "private, no-store, max-age=0".into(),
            );
            attrs
        },
        ..Default::default()
    };

    if let Err(e) = client.put_opts(&gcs_path, payload, put_opts).await {
        tracing::error!("Failed to upload resume to GCS: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to upload resume to cloud storage".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    let bucket = gcs_bucket_name().unwrap_or_default();
    let url = format!(
        "https://storage.googleapis.com/{}/{}",
        bucket, GCS_RESUME_PATH
    );
    tracing::info!("Resume uploaded to GCS: {} ({} bytes)", url, size);

    (
        StatusCode::CREATED,
        Json(UploadResponse {
            url,
            filename: "Dimas_Saputra_Resume.pdf".to_string(),
            size,
            mime_type: "application/pdf".to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    use crate::test_support;

    fn resume_router() -> Router {
        Router::new()
            .route("/api/resume/raw", get(get_raw_resume))
            .route("/api/upload/resume", post(upload_resume))
            .layer(test_support::mock_connect_info())
    }

    fn multipart_pdf_body(boundary: &str, bytes: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"resume.pdf\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/pdf\r\n\r\n");
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
        body
    }

    #[tokio::test]
    async fn upload_resume_requires_admin_auth() {
        let boundary = "resume-boundary";
        let pdf = b"%PDF-1.4 sample content";
        let req = Request::post("/api/upload/resume")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_pdf_body(boundary, pdf)))
            .expect("request should build");

        let res = resume_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upload_resume_rejects_non_pdf() {
        let boundary = "resume-boundary";
        let invalid = b"NOT_A_PDF_FILE";
        let req = Request::post("/api/upload/resume")
            .header("authorization", test_support::admin_bearer())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_pdf_body(boundary, invalid)))
            .expect("request should build");

        let res = resume_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_resume_without_gcs_returns_not_found() {
        let req = Request::get("/api/resume/raw")
            .body(Body::empty())
            .expect("request should build");
        let res = resume_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_gcs_bucket_name_env_parsing() {
        std::env::set_var("GCS_BUCKET", "test-bucket");
        assert_eq!(gcs_bucket_name(), Some("test-bucket".to_string()));
        std::env::remove_var("GCS_BUCKET");
        assert_eq!(gcs_bucket_name(), None);
    }

    #[tokio::test]
    async fn upload_resume_rejects_empty_file() {
        let boundary = "empty-boundary";
        let req = Request::post("/api/upload/resume")
            .header("authorization", test_support::admin_bearer())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_pdf_body(boundary, b"")))
            .expect("request should build");

        let res = resume_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_resume_rejects_file_too_large() {
        let boundary = "large-boundary";
        // Create >10MB dummy %PDF bytes
        let mut large_pdf = vec![0u8; MAX_RESUME_SIZE + 10];
        large_pdf[0..4].copy_from_slice(b"%PDF");

        let req = Request::post("/api/upload/resume")
            .header("authorization", test_support::admin_bearer())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_pdf_body(boundary, &large_pdf)))
            .expect("request should build");

        let res = resume_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_resume_service_unavailable_without_gcs() {
        let boundary = "valid-boundary";
        let valid_pdf = b"%PDF-1.4 valid pdf content";

        let req = Request::post("/api/upload/resume")
            .header("authorization", test_support::admin_bearer())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_pdf_body(boundary, valid_pdf)))
            .expect("request should build");

        let res = resume_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_gcs_bucket_name_empty_string_filtered() {
        std::env::set_var("GCS_BUCKET", "");
        assert_eq!(gcs_bucket_name(), None);
        std::env::remove_var("GCS_BUCKET");
    }

    #[tokio::test]
    async fn upload_resume_no_fields_returns_bad_request() {
        let boundary = "empty-boundary";
        let req = Request::post("/api/upload/resume")
            .header("authorization", test_support::admin_bearer())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(format!("--{}--\r\n", boundary)))
            .expect("request should build");

        let res = resume_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_resume_malformed_multipart_returns_bad_request() {
        let req = Request::post("/api/upload/resume")
            .header("authorization", test_support::admin_bearer())
            .header("content-type", "multipart/form-data; boundary=test")
            .body(Body::from(b"invalid-truncated-multipart-data".as_slice()))
            .expect("request should build");

        let res = resume_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_resume_rejects_short_payload_under_4_bytes() {
        let boundary = "short-boundary";
        let req = Request::post("/api/upload/resume")
            .header("authorization", test_support::admin_bearer())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_pdf_body(boundary, b"%PD")))
            .expect("request should build");

        let res = resume_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_resume_invalid_token_returns_unauthorized() {
        let req = Request::post("/api/upload/resume")
            .header("authorization", "Bearer invalid.jwt.token")
            .header("content-type", "multipart/form-data; boundary=test")
            .body(Body::empty())
            .expect("request should build");

        let res = resume_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
}

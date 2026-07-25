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
const GCS_RESUME_PATH: &str = "resume/dimas_saputra_resume.pdf";
const DISK_FALLBACK_PATH: &str = "uploads/resume/resume.pdf";

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
/// Returns the raw PDF bytes of the resume.
/// Fetches from GCS (`resume/dimas_saputra_resume.pdf`) if `GCS_BUCKET` is configured,
/// or falls back to local disk (`uploads/resume/resume.pdf`) in local dev mode.
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
    if let Some(client) = gcs_client() {
        let gcs_path = GcsPath::from(GCS_RESUME_PATH);
        match client.get(&gcs_path).await {
            Ok(result) => match result.bytes().await {
                Ok(bytes) => {
                    tracing::info!("Resume PDF served from GCS ({} bytes)", bytes.len());
                    return (
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
                        .into_response();
                }
                Err(e) => {
                    tracing::error!("Failed to read GCS resume bytes: {}", e);
                }
            },
            Err(e) => {
                tracing::warn!("GCS resume object not found: {}", e);
            }
        }
    }

    // Disk fallback (local dev)
    let fallback_path = std::path::PathBuf::from(DISK_FALLBACK_PATH);
    match tokio::fs::read(&fallback_path).await {
        Ok(bytes) => {
            tracing::info!(
                "Resume PDF served from local disk fallback ({} bytes)",
                bytes.len()
            );
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
            tracing::warn!("Resume file not found on disk fallback: {}", e);
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
/// Uploads a new resume PDF to GCS or disk fallback.
#[utoipa::path(
    post,
    path = "/api/upload/resume",
    tag = "Upload",
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "Resume PDF uploaded", body = UploadResponse),
        (status = 400, description = "Invalid file", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
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

    let size = bytes.len();

    if let Some(client) = gcs_client() {
        let gcs_path = GcsPath::from(GCS_RESUME_PATH);
        let payload = PutPayload::from_bytes(bytes.clone());
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

        return (
            StatusCode::CREATED,
            Json(UploadResponse {
                url,
                filename: "Dimas_Saputra_Resume.pdf".to_string(),
                size,
                mime_type: "application/pdf".to_string(),
            }),
        )
            .into_response();
    }

    // Disk fallback
    let fallback_dir = std::path::PathBuf::from("uploads/resume");
    if let Err(e) = tokio::fs::create_dir_all(&fallback_dir).await {
        tracing::error!("Failed to create resume directory: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to initialize upload directory".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    let file_path = fallback_dir.join("resume.pdf");
    if let Err(e) = tokio::fs::write(&file_path, &bytes).await {
        tracing::error!("Failed to write resume file: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to save file".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    tracing::info!(
        "Resume saved to disk fallback: {} ({} bytes)",
        file_path.display(),
        size
    );

    (
        StatusCode::CREATED,
        Json(UploadResponse {
            url: "/uploads/resume/resume.pdf".to_string(),
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
    async fn upload_and_get_resume_roundtrip() {
        let boundary = "resume-boundary";
        let pdf = b"%PDF-1.4 sample resume content for testing";
        let upload_req = Request::post("/api/upload/resume")
            .header("authorization", test_support::admin_bearer())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_pdf_body(boundary, pdf)))
            .expect("request should build");

        let app = resume_router();
        let upload_res = app.clone().oneshot(upload_req).await.unwrap();
        assert_eq!(upload_res.status(), StatusCode::CREATED);

        let get_req = Request::get("/api/resume/raw")
            .body(Body::empty())
            .expect("request should build");
        let get_res = app.oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        assert_eq!(
            get_res.headers().get("content-type").unwrap(),
            "application/pdf"
        );
    }
}

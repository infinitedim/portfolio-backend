use axum::{
    extract::{Multipart, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use std::path::PathBuf;
use uuid::Uuid;

use crate::routes::auth::require_admin;
use crate::routes::ErrorResponse;

/// Default on-disk location for uploaded blog images. Used when the
/// `UPLOAD_DIR` env var is unset — overriding it lets tests redirect writes
/// into an isolated temp directory without touching the real `uploads/blog`
/// tree (see `crate::test_support::isolated_upload_dir`).
const DEFAULT_UPLOAD_DIR: &str = "uploads/blog";
const MAX_FILE_SIZE: usize = 5 * 1024 * 1024; // 5MB
const ALLOWED_EXTENSIONS: &[&str] = &["jpg", "jpeg", "png", "webp", "gif"];

/// Resolve the on-disk upload directory. Reads `UPLOAD_DIR` at call time so
/// tests can override it per-test via [`std::env::set_var`] without forcing
/// a process restart. Production builds simply fall through to
/// [`DEFAULT_UPLOAD_DIR`].
fn upload_dir() -> PathBuf {
    PathBuf::from(std::env::var("UPLOAD_DIR").unwrap_or_else(|_| DEFAULT_UPLOAD_DIR.to_string()))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadResponse {
    pub url: String,
    pub filename: String,
    pub size: usize,
    pub mime_type: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageInfo {
    pub filename: String,
    pub url: String,
    pub size: u64,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageListResponse {
    pub images: Vec<ImageInfo>,
    pub total: usize,
}

fn verify_auth(headers: &HeaderMap) -> Result<(), crate::routes::AppError> {
    require_admin(headers).map(|_| ())
}

fn validate_image_magic_bytes(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 4 {
        return None;
    }
    match bytes {
        // JPEG: FF D8 FF
        [0xFF, 0xD8, 0xFF, ..] => Some("image/jpeg"),
        // PNG: 89 50 4E 47
        [0x89, 0x50, 0x4E, 0x47, ..] => Some("image/png"),
        // GIF: 47 49 46 38
        [0x47, 0x49, 0x46, 0x38, ..] => Some("image/gif"),
        // WebP: 52 49 46 46 ... 57 45 42 50
        [0x52, 0x49, 0x46, 0x46, _, _, _, _, 0x57, 0x45, 0x42, 0x50, ..] => Some("image/webp"),
        _ => None,
    }
}

fn get_extension_from_mime(mime: &str) -> &str {
    match mime {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        _ => "bin",
    }
}

fn sanitize_filename(filename: &str) -> bool {
    // Reject path traversal and special characters
    !filename.contains("..")
        && !filename.contains('/')
        && !filename.contains('\\')
        && !filename.contains('\0')
}

pub async fn upload_image(headers: HeaderMap, mut multipart: Multipart) -> impl IntoResponse {
    if let Err(err_response) = verify_auth(&headers) {
        return err_response.into_response();
    }

    // Ensure upload directory exists
    let upload_path = upload_dir();
    if let Err(e) = tokio::fs::create_dir_all(&upload_path).await {
        tracing::error!("Failed to create upload directory: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to initialize upload directory".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    // Extract file from multipart
    let field = match multipart.next_field().await {
        Ok(Some(field)) => field,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "No file provided".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Multipart error: {}", e);
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

    // Get original filename for extension validation
    let original_name = field.file_name().unwrap_or("unknown").to_string();
    let original_ext = original_name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_lowercase();

    // Validate extension
    if !ALLOWED_EXTENSIONS.contains(&original_ext.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Unsupported file type. Allowed: JPEG, PNG, WebP, GIF.".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    // Read file bytes
    let bytes = match field.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to read upload bytes: {}", e);
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

    // Validate file size
    if bytes.len() > MAX_FILE_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "File too large. Maximum size is 5MB.".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

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

    // Validate magic bytes
    let mime_type = match validate_image_magic_bytes(&bytes) {
        Some(mime) => mime,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "File content does not match an allowed image type.".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    // Generate unique filename
    let ext = get_extension_from_mime(mime_type);
    let filename = format!("{}.{}", Uuid::new_v4(), ext);
    let file_path = upload_path.join(&filename);

    // Write file to disk
    if let Err(e) = tokio::fs::write(&file_path, &bytes).await {
        tracing::error!("Failed to write upload file: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to save file".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    let url = format!("/uploads/blog/{}", filename);
    tracing::info!("Image uploaded: {} ({} bytes)", filename, bytes.len());

    (
        StatusCode::CREATED,
        Json(UploadResponse {
            url,
            filename,
            size: bytes.len(),
            mime_type: mime_type.to_string(),
        }),
    )
        .into_response()
}

pub async fn delete_image(headers: HeaderMap, Path(filename): Path<String>) -> impl IntoResponse {
    if let Err(err_response) = verify_auth(&headers) {
        return err_response.into_response();
    }

    // Path traversal protection
    if !sanitize_filename(&filename) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid filename".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    let file_path = upload_dir().join(&filename);

    // Use the async metadata + remove pair instead of the blocking
    // `PathBuf::exists()` check, which would stall the executor on
    // slow filesystems.
    match tokio::fs::remove_file(&file_path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "File not found".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to delete file {}: {}", filename, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to delete file".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    }

    tracing::info!("Image deleted: {}", filename);
    StatusCode::NO_CONTENT.into_response()
}

pub async fn list_images(headers: HeaderMap) -> impl IntoResponse {
    if let Err(err_response) = verify_auth(&headers) {
        return err_response.into_response();
    }

    let upload_path = upload_dir();
    let mut images = Vec::new();

    // Async open instead of `PathBuf::exists()` (which is blocking).
    let mut entries = match tokio::fs::read_dir(&upload_path).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (
                StatusCode::OK,
                Json(ImageListResponse {
                    images: vec![],
                    total: 0,
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to read upload directory: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to list images".to_string(),
                    message: None,
                }),
            )
                .into_response();
        }
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        // Only list image files
        let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
        if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }

        let metadata = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };

        let created_at = metadata
            .created()
            .or_else(|_| metadata.modified())
            .map(|t| {
                let dt: chrono::DateTime<chrono::Utc> = t.into();
                dt.to_rfc3339()
            })
            .unwrap_or_default();

        images.push(ImageInfo {
            url: format!("/uploads/blog/{}", filename),
            filename,
            size: metadata.len(),
            created_at,
        });
    }

    // Sort by created_at descending
    images.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let total = images.len();
    (StatusCode::OK, Json(ImageListResponse { images, total })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{delete, get, post};
    use axum::Router;
    use tower::ServiceExt;

    use crate::test_support;

    fn upload_router() -> Router {
        Router::new()
            .route("/api/upload/image", post(upload_image))
            .route("/api/upload/image/{filename}", delete(delete_image))
            .route("/api/upload/images", get(list_images))
            .layer(test_support::mock_connect_info())
    }

    fn auth_header() -> String {
        test_support::admin_bearer()
    }

    async fn call(
        app: Router,
        req: Request<Body>,
    ) -> (StatusCode, axum::body::Bytes, axum::http::HeaderMap) {
        let res = app.oneshot(req).await.expect("request should succeed");
        let status = res.status();
        let headers = res.headers().clone();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        (status, body, headers)
    }

    fn multipart_body(boundary: &str, filename: &str, bytes: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
                filename
            )
            .as_bytes(),
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
        body
    }

    #[tokio::test]
    async fn upload_requires_admin_auth() {
        let boundary = "upload-test-boundary";
        let png = [0x89, 0x50, 0x4E, 0x47, 0, 1, 2, 3];
        let req = Request::post("/api/upload/image")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_body(boundary, "image.png", &png)))
            .expect("request should build");

        let (status, _, _) = call(upload_router(), req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_and_delete_require_admin_auth() {
        let list_req = Request::get("/api/upload/images")
            .body(Body::empty())
            .expect("request should build");
        let (list_status, _, _) = call(upload_router(), list_req).await;
        assert_eq!(list_status, StatusCode::UNAUTHORIZED);

        let delete_req = Request::delete("/api/upload/image/file.png")
            .body(Body::empty())
            .expect("request should build");
        let (delete_status, _, _) = call(upload_router(), delete_req).await;
        assert_eq!(delete_status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upload_rejects_unsupported_extension() {
        let _dir = test_support::isolated_upload_dir()
            .await
            .expect("isolated upload dir should be created");
        let boundary = "upload-test-boundary";
        let png = [0x89, 0x50, 0x4E, 0x47, 0, 1, 2, 3];
        let req = Request::post("/api/upload/image")
            .header("authorization", auth_header())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_body(boundary, "payload.txt", &png)))
            .expect("request should build");

        let (status, _, _) = call(upload_router(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_rejects_invalid_magic_bytes() {
        let _dir = test_support::isolated_upload_dir()
            .await
            .expect("isolated upload dir should be created");
        let boundary = "upload-test-boundary";
        let junk = b"not-an-image-at-all";
        let req = Request::post("/api/upload/image")
            .header("authorization", auth_header())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_body(boundary, "image.png", junk)))
            .expect("request should build");

        let (status, _, _) = call(upload_router(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_list_and_delete_roundtrip_with_isolated_dir() {
        let dir = test_support::isolated_upload_dir()
            .await
            .expect("isolated upload dir should be created");
        let boundary = "upload-test-boundary";
        let png = [0x89, 0x50, 0x4E, 0x47, 0, 1, 2, 3, 4, 5];
        let upload_req = Request::post("/api/upload/image")
            .header("authorization", auth_header())
            .header(
                "content-type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(multipart_body(boundary, "photo.png", &png)))
            .expect("request should build");
        let (upload_status, upload_body, _) = call(upload_router(), upload_req).await;
        assert_eq!(upload_status, StatusCode::CREATED);

        let uploaded: serde_json::Value =
            serde_json::from_slice(&upload_body).expect("valid upload response JSON");
        let filename = uploaded["filename"]
            .as_str()
            .expect("filename should be present")
            .to_string();
        assert!(dir.path.join(&filename).exists());
        assert_eq!(
            uploaded["mimeType"].as_str(),
            Some("image/png"),
            "mime type should be detected from magic bytes"
        );

        let list_req = Request::get("/api/upload/images")
            .header("authorization", auth_header())
            .body(Body::empty())
            .expect("request should build");
        let (list_status, list_body, _) = call(upload_router(), list_req).await;
        assert_eq!(list_status, StatusCode::OK);
        let listed: serde_json::Value =
            serde_json::from_slice(&list_body).expect("valid list JSON");
        assert_eq!(listed["total"].as_u64(), Some(1));
        assert_eq!(
            listed["images"][0]["filename"].as_str(),
            Some(filename.as_str())
        );

        let delete_req = Request::delete(format!("/api/upload/image/{}", filename))
            .header("authorization", auth_header())
            .body(Body::empty())
            .expect("request should build");
        let (delete_status, _, _) = call(upload_router(), delete_req).await;
        assert_eq!(delete_status, StatusCode::NO_CONTENT);
        assert!(!dir.path.join(&filename).exists());
    }

    #[tokio::test]
    async fn delete_rejects_path_traversal_filename() {
        let _dir = test_support::isolated_upload_dir()
            .await
            .expect("isolated upload dir should be created");
        let req = Request::delete("/api/upload/image/..evil.png")
            .header("authorization", auth_header())
            .body(Body::empty())
            .expect("request should build");
        let (status, _, _) = call(upload_router(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

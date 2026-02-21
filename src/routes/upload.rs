use axum::{
    extract::{Multipart, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use std::path::PathBuf;
use uuid::Uuid;

use crate::routes::auth::verify_access_token;
use crate::routes::ErrorResponse;

const UPLOAD_DIR: &str = "uploads/blog";
const MAX_FILE_SIZE: usize = 5 * 1024 * 1024; // 5MB
const ALLOWED_EXTENSIONS: &[&str] = &["jpg", "jpeg", "png", "webp", "gif"];

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

fn verify_auth(headers: &HeaderMap) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match token {
        Some(t) => match verify_access_token(t) {
            Ok(_) => Ok(()),
            Err(_) => Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid or expired token".to_string(),
                    message: None,
                }),
            )),
        },
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Authorization required".to_string(),
                message: None,
            }),
        )),
    }
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
    let upload_path = PathBuf::from(UPLOAD_DIR);
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

    let file_path = PathBuf::from(UPLOAD_DIR).join(&filename);

    if !file_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "File not found".to_string(),
                message: None,
            }),
        )
            .into_response();
    }

    if let Err(e) = tokio::fs::remove_file(&file_path).await {
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

    tracing::info!("Image deleted: {}", filename);
    StatusCode::NO_CONTENT.into_response()
}

pub async fn list_images(headers: HeaderMap) -> impl IntoResponse {
    if let Err(err_response) = verify_auth(&headers) {
        return err_response.into_response();
    }

    let upload_path = PathBuf::from(UPLOAD_DIR);
    if !upload_path.exists() {
        return (
            StatusCode::OK,
            Json(ImageListResponse {
                images: vec![],
                total: 0,
            }),
        )
            .into_response();
    }

    let mut images = Vec::new();

    let mut entries = match tokio::fs::read_dir(&upload_path).await {
        Ok(entries) => entries,
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

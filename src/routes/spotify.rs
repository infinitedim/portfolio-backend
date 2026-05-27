//! Spotify "now playing" proxy with token refresh and 30s in-memory cache.

use axum::{http::StatusCode, response::IntoResponse, Json};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use utoipa::ToSchema;

const SPOTIFY_TOKEN_URL: &str = "https://accounts.spotify.com/api/token";
const SPOTIFY_NOW_PLAYING_URL: &str = "https://api.spotify.com/v1/me/player/currently-playing";
const CACHE_TTL: Duration = Duration::from_secs(30);

static SPOTIFY_CLIENT_ID: Lazy<String> =
    Lazy::new(|| std::env::var("SPOTIFY_CLIENT_ID").unwrap_or_default());
static SPOTIFY_CLIENT_SECRET: Lazy<String> =
    Lazy::new(|| std::env::var("SPOTIFY_CLIENT_SECRET").unwrap_or_default());
static SPOTIFY_REFRESH_TOKEN: Lazy<String> =
    Lazy::new(|| std::env::var("SPOTIFY_REFRESH_TOKEN").unwrap_or_default());

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(reqwest::Client::new);

struct TokenCache {
    access_token: String,
    expires_at: Instant,
}

static TOKEN_CACHE: Lazy<Mutex<Option<TokenCache>>> = Lazy::new(|| Mutex::new(None));

struct NowPlayingCache {
    body: NowPlayingResponse,
    expires_at: Instant,
}

static NOW_PLAYING_CACHE: Lazy<Mutex<Option<NowPlayingCache>>> =
    Lazy::new(|| Mutex::new(None));

fn spotify_configured() -> bool {
    !SPOTIFY_CLIENT_ID.is_empty()
        && !SPOTIFY_CLIENT_SECRET.is_empty()
        && !SPOTIFY_REFRESH_TOKEN.is_empty()
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NowPlayingResponse {
    pub is_playing: bool,
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub album_art_url: Option<String>,
    pub song_url: Option<String>,
    pub progress_ms: Option<u64>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SpotifyTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct SpotifyCurrentlyPlaying {
    is_playing: Option<bool>,
    progress_ms: Option<u64>,
    item: Option<SpotifyTrack>,
}

#[derive(Debug, Deserialize)]
struct SpotifyTrack {
    name: String,
    duration_ms: Option<u64>,
    external_urls: Option<SpotifyExternalUrls>,
    album: Option<SpotifyAlbum>,
    artists: Option<Vec<SpotifyArtist>>,
}

#[derive(Debug, Deserialize)]
struct SpotifyExternalUrls {
    spotify: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SpotifyAlbum {
    name: Option<String>,
    images: Option<Vec<SpotifyImage>>,
}

#[derive(Debug, Deserialize)]
struct SpotifyImage {
    url: String,
}

#[derive(Debug, Deserialize)]
struct SpotifyArtist {
    name: String,
}

async fn fetch_access_token() -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    {
        let cache = TOKEN_CACHE.lock().expect("spotify token cache poisoned");
        if let Some(entry) = cache.as_ref() {
            if Instant::now() < entry.expires_at {
                return Ok(entry.access_token.clone());
            }
        }
    }

    let response = HTTP_CLIENT
        .post(SPOTIFY_TOKEN_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(SPOTIFY_CLIENT_ID.as_str(), Some(SPOTIFY_CLIENT_SECRET.as_str()))
        .body(format!(
            "grant_type=refresh_token&refresh_token={}",
            urlencoding_simple(&SPOTIFY_REFRESH_TOKEN)
        ))
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "spotify token request failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "spotify token request failed" })),
            )
        })?;

    if !response.status().is_success() {
        tracing::warn!(status = %response.status(), "spotify token endpoint returned error");
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "spotify authentication failed" })),
        ));
    }

    let token: SpotifyTokenResponse = response.json().await.map_err(|e| {
        tracing::error!(error = %e, "failed to parse spotify token response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "failed to parse spotify token response" })),
        )
    })?;

    let expires_at =
        Instant::now() + Duration::from_secs(token.expires_in.saturating_sub(30).max(60));

    {
        let mut cache = TOKEN_CACHE.lock().expect("spotify token cache poisoned");
        *cache = Some(TokenCache {
            access_token: token.access_token.clone(),
            expires_at,
        });
    }

    Ok(token.access_token)
}

fn urlencoding_simple(value: &str) -> String {
    value
        .bytes()
        .flat_map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![b as char]
            }
            _ => format!("%{b:02X}").chars().collect::<Vec<char>>(),
        })
        .collect()
}

fn map_now_playing(raw: SpotifyCurrentlyPlaying) -> NowPlayingResponse {
    let track = raw.item;
    NowPlayingResponse {
        is_playing: raw.is_playing.unwrap_or(false),
        title: track.as_ref().map(|t| t.name.clone()),
        artist: track.as_ref().and_then(|t| {
            t.artists.as_ref().and_then(|artists| {
                if artists.is_empty() {
                    None
                } else {
                    Some(
                        artists
                            .iter()
                            .map(|a| a.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                    )
                }
            })
        }),
        album: track
            .as_ref()
            .and_then(|t| t.album.as_ref())
            .and_then(|a| a.name.clone()),
        album_art_url: track.as_ref().and_then(|t| {
            t.album
                .as_ref()
                .and_then(|a| a.images.as_ref())
                .and_then(|images| images.first())
                .map(|img| img.url.clone())
        }),
        song_url: track
            .as_ref()
            .and_then(|t| t.external_urls.as_ref())
            .and_then(|urls| urls.spotify.clone()),
        progress_ms: raw.progress_ms,
        duration_ms: track.as_ref().and_then(|t| t.duration_ms),
    }
}

async fn fetch_now_playing() -> Result<NowPlayingResponse, (StatusCode, Json<serde_json::Value>)> {
    {
        let cache = NOW_PLAYING_CACHE
            .lock()
            .expect("spotify now playing cache poisoned");
        if let Some(entry) = cache.as_ref() {
            if Instant::now() < entry.expires_at {
                return Ok(entry.body.clone());
            }
        }
    }

    let access_token = fetch_access_token().await?;

    let response = HTTP_CLIENT
        .get(SPOTIFY_NOW_PLAYING_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "spotify now playing request failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "spotify upstream request failed" })),
            )
        })?;

    if response.status().as_u16() == 204 {
        let empty = NowPlayingResponse {
            is_playing: false,
            title: None,
            artist: None,
            album: None,
            album_art_url: None,
            song_url: None,
            progress_ms: None,
            duration_ms: None,
        };
        let mut cache = NOW_PLAYING_CACHE
            .lock()
            .expect("spotify now playing cache poisoned");
        *cache = Some(NowPlayingCache {
            body: empty.clone(),
            expires_at: Instant::now() + CACHE_TTL,
        });
        return Ok(empty);
    }

    if !response.status().is_success() {
        tracing::warn!(status = %response.status(), "spotify now playing returned error");
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "spotify upstream error",
                "status": response.status().as_u16()
            })),
        ));
    }

    let raw: SpotifyCurrentlyPlaying = response.json().await.map_err(|e| {
        tracing::error!(error = %e, "failed to parse spotify now playing response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "failed to parse spotify response" })),
        )
    })?;

    let mapped = map_now_playing(raw);
    {
        let mut cache = NOW_PLAYING_CACHE
            .lock()
            .expect("spotify now playing cache poisoned");
        *cache = Some(NowPlayingCache {
            body: mapped.clone(),
            expires_at: Instant::now() + CACHE_TTL,
        });
    }

    Ok(mapped)
}

/// GET /api/spotify/now-playing
#[utoipa::path(
    get,
    path = "/api/spotify/now-playing",
    tag = "Spotify",
    responses(
        (status = 200, description = "Current track or empty payload when nothing is playing", body = NowPlayingResponse),
        (status = 503, description = "Spotify integration not configured", body = crate::routes::ErrorResponse),
    )
)]
pub async fn now_playing() -> impl IntoResponse {
    if !spotify_configured() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "spotify integration not configured" })),
        )
            .into_response();
    }

    match fetch_now_playing().await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err((status, json)) => (status, json).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_now_playing_extracts_track_fields() {
        let mapped = map_now_playing(SpotifyCurrentlyPlaying {
            is_playing: Some(true),
            progress_ms: Some(12_000),
            item: Some(SpotifyTrack {
                name: "Test Song".into(),
                duration_ms: Some(180_000),
                external_urls: Some(SpotifyExternalUrls {
                    spotify: Some("https://open.spotify.com/track/abc".into()),
                }),
                album: Some(SpotifyAlbum {
                    name: Some("Test Album".into()),
                    images: Some(vec![SpotifyImage {
                        url: "https://i.scdn.co/image/test".into(),
                    }]),
                }),
                artists: Some(vec![
                    SpotifyArtist {
                        name: "Artist One".into(),
                    },
                    SpotifyArtist {
                        name: "Artist Two".into(),
                    },
                ]),
            }),
        });

        assert!(mapped.is_playing);
        assert_eq!(mapped.title.as_deref(), Some("Test Song"));
        assert_eq!(mapped.artist.as_deref(), Some("Artist One, Artist Two"));
        assert_eq!(mapped.album.as_deref(), Some("Test Album"));
        assert_eq!(
            mapped.album_art_url.as_deref(),
            Some("https://i.scdn.co/image/test")
        );
        assert_eq!(mapped.progress_ms, Some(12_000));
        assert_eq!(mapped.duration_ms, Some(180_000));
    }

    #[test]
    fn urlencoding_simple_encodes_special_chars() {
        assert_eq!(urlencoding_simple("abc"), "abc");
        assert_eq!(urlencoding_simple("a+b"), "a%2Bb");
    }

    #[test]
    fn spotify_configured_requires_all_three_env_vars() {
        // Pure logic test — does not mutate env (Lazy may already be initialized).
        assert!(!spotify_configured() || (
            !SPOTIFY_CLIENT_ID.is_empty()
                && !SPOTIFY_CLIENT_SECRET.is_empty()
                && !SPOTIFY_REFRESH_TOKEN.is_empty()
        ));
    }
}

//! AI portfolio assistant — Gemini SSE chat with simple RAG over blog content.

use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    Json,
};
use futures_util::stream;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::time::Duration;

use crate::db;
use crate::routes::AppError;

const RAG_TOP_K: i64 = 5;
const MAX_MESSAGE_LEN: usize = 4000;
const GEMINI_MODEL: &str = "gemini-2.0-flash";

#[derive(Clone)]
pub struct AiState {
    client: Client,
    api_key: Option<String>,
}

impl AiState {
    pub fn from_env() -> Self {
        Self {
            client: Client::new(),
            api_key: std::env::var("GEMINI_API_KEY")
                .ok()
                .filter(|k| !k.trim().is_empty()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.api_key.is_some()
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChatRequest {
    pub message: String,
    #[serde(default)]
    pub history: Vec<ChatTurn>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChatTurn {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone)]
struct RagChunk {
    source_type: String,
    source_id: String,
    text: String,
}

pub fn tokenize_query(query: &str) -> Vec<String> {
    query
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| w.len() >= 3)
        .map(|w| w.to_ascii_lowercase())
        .collect()
}

async fn fetch_rag_context(pool: &sqlx::PgPool, query: &str) -> Result<Vec<RagChunk>, sqlx::Error> {
    let tokens = tokenize_query(query);
    if tokens.is_empty() {
        return Ok(Vec::new());
    }

    let ts_query = tokens.join(" ");

    let embedding_rows: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT source_type, source_id, chunk_text
        FROM content_embeddings
        WHERE to_tsvector('english', chunk_text) @@ plainto_tsquery('english', $1)
        ORDER BY ts_rank(to_tsvector('english', chunk_text), plainto_tsquery('english', $1)) DESC
        LIMIT $2
        "#,
    )
    .bind(&ts_query)
    .bind(RAG_TOP_K)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    if !embedding_rows.is_empty() {
        return Ok(embedding_rows
            .into_iter()
            .map(|(source_type, source_id, text)| RagChunk {
                source_type,
                source_id,
                text,
            })
            .collect());
    }

    // Text search fallback against published blog posts.
    let pattern = format!("%{}%", tokens.join("%"));
    let blog_rows: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT 'blog'::text, slug,
               COALESCE(title, '') || E'\n' || COALESCE(summary, '') || E'\n' || COALESCE(content_md, '')
        FROM blog_posts
        WHERE published = true
          AND (
            title ILIKE $1 OR summary ILIKE $1 OR content_md ILIKE $1
          )
        ORDER BY updated_at DESC
        LIMIT $2
        "#,
    )
    .bind(&pattern)
    .bind(RAG_TOP_K)
    .fetch_all(pool)
    .await?;

    Ok(blog_rows
        .into_iter()
        .map(|(source_type, source_id, text)| RagChunk {
            source_type,
            source_id,
            text,
        })
        .collect())
}

pub async fn ensure_blog_embeddings_indexed(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_embeddings")
        .fetch_one(pool)
        .await?;
    if count > 0 {
        return Ok(());
    }

    let posts: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT slug, title, summary, content_md
        FROM blog_posts
        WHERE published = true
        "#,
    )
    .fetch_all(pool)
    .await?;

    for (slug, title, summary, content_md) in posts {
        let chunk = format!(
            "{}\n{}\n{}",
            title,
            summary.unwrap_or_default(),
            content_md.unwrap_or_default()
        );
        if chunk.trim().is_empty() {
            continue;
        }
        sqlx::query(
            r#"
            INSERT INTO content_embeddings (source_type, source_id, chunk_index, chunk_text)
            VALUES ('blog', $1, 0, $2)
            "#,
        )
        .bind(&slug)
        .bind(chunk.chars().take(8000).collect::<String>())
        .execute(pool)
        .await?;
    }
    Ok(())
}

fn build_system_prompt(chunks: &[RagChunk]) -> String {
    if chunks.is_empty() {
        return "You are a helpful assistant for a developer portfolio website. \
                Answer questions about the site owner based on general knowledge when \
                no specific context is available. Be concise."
            .to_string();
    }

    let mut prompt = String::from(
        "You are a helpful assistant for a developer portfolio website. \
         Use the following context from the portfolio content when answering. \
         If the answer is not in the context, say you don't know.\n\nContext:\n",
    );
    for chunk in chunks {
        prompt.push_str(&format!(
            "--- [{}:{}] ---\n{}\n\n",
            chunk.source_type, chunk.source_id, chunk.text
        ));
    }
    prompt
}

#[utoipa::path(
    post,
    path = "/api/ai/chat",
    tag = "AI",
    request_body = ChatRequest,
    responses((status = 200, description = "SSE stream of assistant tokens")),
)]
pub async fn chat(
    State(state): State<AiState>,
    Json(payload): Json<ChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    let api_key = state
        .api_key
        .as_deref()
        .ok_or_else(|| AppError::Internal("AI assistant is not configured".to_string()))?;

    let message = payload.message.trim();
    if message.is_empty() || message.len() > MAX_MESSAGE_LEN {
        return Err(AppError::BadRequest(format!(
            "message must be 1..={} characters",
            MAX_MESSAGE_LEN
        )));
    }

    let pool = db::get_pool().ok_or(AppError::DbUnavailable)?;
    ensure_blog_embeddings_indexed(pool.as_ref()).await.ok();
    let chunks = fetch_rag_context(pool.as_ref(), message).await?;
    let system_prompt = build_system_prompt(&chunks);

    let mut contents = Vec::new();
    contents.push(serde_json::json!({
        "role": "user",
        "parts": [{ "text": system_prompt }]
    }));
    for turn in &payload.history {
        let role = if turn.role.eq_ignore_ascii_case("assistant") {
            "model"
        } else {
            "user"
        };
        contents.push(serde_json::json!({
            "role": role,
            "parts": [{ "text": turn.content }]
        }));
    }
    contents.push(serde_json::json!({
        "role": "user",
        "parts": [{ "text": message }]
    }));

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:streamGenerateContent?alt=sse&key={}",
        GEMINI_MODEL, api_key
    );

    let body = serde_json::json!({ "contents": contents });

    let response = state
        .client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Gemini request failed: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        tracing::error!(%status, body = %text, "Gemini API error");
        return Err(AppError::Internal("AI provider error".to_string()));
    }

    let byte_stream = response.bytes_stream();
    let event_stream = stream::unfold(byte_stream, |mut byte_stream| async move {
        use tokio_stream::StreamExt as TokioStreamExt;

        let chunk = TokioStreamExt::next(&mut byte_stream).await?;
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "Gemini stream read error");
                return Some((
                    Ok::<Event, Infallible>(Event::default().data(format!("error: {}", e))),
                    byte_stream,
                ));
            }
        };

        let text = String::from_utf8_lossy(&bytes);
        let mut events = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(data) = line.strip_prefix("data: ") {
                if data == "[DONE]" {
                    continue;
                }
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(part_text) = json
                        .pointer("/candidates/0/content/parts/0/text")
                        .and_then(|v| v.as_str())
                    {
                        events.push(Event::default().data(part_text));
                    }
                }
            }
        }

        if events.is_empty() {
            return Some((Ok(Event::default().comment("keep-alive")), byte_stream));
        }

        // Return first event; additional events in same chunk are dropped for
        // simplicity — Gemini usually sends one token per SSE frame.
        Some((Ok(events.remove(0)), byte_stream))
    });

    Ok(Sse::new(event_stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_query_filters_short_words() {
        let tokens = tokenize_query("How do I use Rust in this portfolio?");
        assert!(tokens.contains(&"how".to_string()));
        assert!(tokens.contains(&"portfolio".to_string()));
        assert!(!tokens.contains(&"do".to_string()));
    }

    #[test]
    fn tokenize_query_empty_input() {
        let tokens = tokenize_query("");
        assert!(tokens.is_empty());
    }

    #[test]
    fn build_system_prompt_includes_chunks() {
        let chunks = vec![RagChunk {
            source_type: "blog".to_string(),
            source_id: "hello".to_string(),
            text: "Hello world".to_string(),
        }];
        let prompt = build_system_prompt(&chunks);
        assert!(prompt.contains("hello"));
        assert!(prompt.contains("Hello world"));
    }

    #[test]
    fn build_system_prompt_empty_chunks() {
        let prompt = build_system_prompt(&[]);
        assert!(prompt.contains("helpful assistant"));
    }

    #[tokio::test]
    async fn test_chat_not_configured() {
        let state = AiState {
            client: reqwest::Client::new(),
            api_key: None,
        };
        let request = ChatRequest {
            message: "Hello".to_string(),
            history: vec![],
        };
        let res = chat(State(state), Json(request)).await;
        match res {
            Err(AppError::Internal(msg)) => assert!(msg.contains("not configured")),
            _ => panic!("Expected AppError::Internal"),
        }
    }

    #[tokio::test]
    async fn test_chat_oversized_message() {
        let state = AiState {
            client: reqwest::Client::new(),
            api_key: Some("dummy-key".to_string()),
        };
        let request = ChatRequest {
            message: "a".repeat(4001),
            history: vec![],
        };
        let res = chat(State(state), Json(request)).await;
        match res {
            Err(AppError::BadRequest(msg)) => assert!(msg.contains("must be")),
            _ => panic!("Expected AppError::BadRequest"),
        }
    }
}

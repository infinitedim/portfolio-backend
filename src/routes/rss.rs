use axum::{body::Body, http::header, response::Response};
use chrono::DateTime;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::time::Instant;

use crate::db;

struct RssCache {
    xml: String,
    generated_at: Instant,
}

static RSS_CACHE: Lazy<Mutex<Option<RssCache>>> = Lazy::new(|| Mutex::new(None));
const RSS_CACHE_TTL_SECS: u64 = 60;

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn rfc822(dt: &DateTime<chrono::Utc>) -> String {
    dt.format("%a, %d %b %Y %H:%M:%S +0000").to_string()
}

#[utoipa::path(
    get,
    path = "/api/rss",
    tag = "RSS",
    responses(
        (status = 200, description = "RSS 2.0 feed of published posts", content_type = "application/rss+xml"),
    ),
)]
pub async fn rss_feed() -> Response {
    if let Ok(guard) = RSS_CACHE.lock() {
        if let Some(cached) = guard.as_ref() {
            if cached.generated_at.elapsed().as_secs() < RSS_CACHE_TTL_SECS {
                return Response::builder()
                    .status(200)
                    .header(header::CONTENT_TYPE, "application/rss+xml; charset=utf-8")
                    .header(
                        header::CACHE_CONTROL,
                        "public, max-age=3600, stale-while-revalidate=600",
                    )
                    .body(Body::from(cached.xml.clone()))
                    .unwrap();
            }
        }
    }

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return Response::builder()
                .status(503)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("Service unavailable"))
                .unwrap();
        }
    };

    let base_url =
        std::env::var("SITE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let site_title =
        std::env::var("SITE_TITLE").unwrap_or_else(|_| "Terminal Portfolio Blog".to_string());
    let site_description = std::env::var("SITE_DESCRIPTION")
        .unwrap_or_else(|_| "Latest articles and insights".to_string());

    let rows: Vec<(String, String, Option<String>, DateTime<chrono::Utc>)> = match sqlx::query_as(
        r#"
            SELECT title, slug, summary, created_at
            FROM blog_posts
            WHERE (publish_at IS NOT NULL AND publish_at <= now())
               OR (publish_at IS NULL AND published = true)
            ORDER BY created_at DESC
            LIMIT 50
            "#,
    )
    .fetch_all(pool.as_ref())
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("Failed to fetch blog posts for RSS feed: {}", e);
            return Response::builder()
                .status(502)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from("Bad Gateway: failed to fetch posts"))
                .unwrap();
        }
    };

    let mut items = String::new();
    for (title, slug, summary, created_at) in &rows {
        let post_url = format!("{}/blog/{}", base_url, slug);
        let desc = summary.as_deref().unwrap_or("");
        items.push_str(&format!(
            "    <item>\n\
                   <title>{}</title>\n\
                   <link>{}</link>\n\
                   <description>{}</description>\n\
                   <pubDate>{}</pubDate>\n\
                   <guid isPermaLink=\"true\">{}</guid>\n\
                 </item>\n",
            escape_xml(title),
            escape_xml(&post_url),
            escape_xml(desc),
            rfc822(created_at),
            escape_xml(&post_url),
        ));
    }

    let feed_url = format!("{}/rss.xml", base_url);
    let blog_url = format!("{}/blog", base_url);

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>{}</title>
    <link>{}</link>
    <description>{}</description>
    <language>en-us</language>
    <atom:link href="{}" rel="self" type="application/rss+xml"/>
    <lastBuildDate>{}</lastBuildDate>
{}  </channel>
</rss>"#,
        escape_xml(&site_title),
        escape_xml(&blog_url),
        escape_xml(&site_description),
        escape_xml(&feed_url),
        rows.first()
            .map(|(_, _, _, dt)| rfc822(dt))
            .unwrap_or_default(),
        items,
    );

    if let Ok(mut guard) = RSS_CACHE.lock() {
        *guard = Some(RssCache {
            xml: xml.clone(),
            generated_at: Instant::now(),
        });
    }

    Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "application/rss+xml; charset=utf-8")
        .header(
            header::CACHE_CONTROL,
            "public, max-age=3600, stale-while-revalidate=600",
        )
        .body(Body::from(xml))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use std::time::Instant;

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("a & b"), "a &amp; b");
        assert_eq!(escape_xml("<title>"), "&lt;title&gt;");
        assert_eq!(escape_xml("\"quote\""), "&quot;quote&quot;");
    }

    #[test]
    fn test_rfc822_format() {
        use chrono::TimeZone;
        let dt = chrono::Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        assert!(rfc822(&dt).contains("2024"));
    }

    #[tokio::test]
    async fn test_rss_feed_cached() {
        {
            let mut guard = RSS_CACHE.lock().unwrap();
            *guard = Some(RssCache {
                xml: "test-cached-xml".to_string(),
                generated_at: Instant::now(),
            });
        }
        let response = rss_feed().await;
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, "test-cached-xml");
    }

    #[tokio::test]
    async fn test_rss_feed_no_db() {
        let _db = crate::test_support::acquire_test_pool().await;
        crate::db::clear_test_pool();

        {
            let mut guard = RSS_CACHE.lock().unwrap();
            *guard = None;
        }
        let response = rss_feed().await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_rss_feed_with_db() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };

        {
            let mut guard = RSS_CACHE.lock().unwrap();
            *guard = None;
        }

        sqlx::query(
            r#"
            INSERT INTO blog_posts (id, title, slug, summary, content_md, published, locale, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
            "#,
        )
        .bind(uuid::Uuid::new_v4())
        .bind("Test Blog Post")
        .bind("test-blog-post")
        .bind("This is a test summary.")
        .bind("This is a test content.")
        .bind(true)
        .bind("en")
        .bind(chrono::Utc::now())
        .execute(db.pool.as_ref())
        .await
        .unwrap();

        let response = rss_feed().await;
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("Test Blog Post"));
        assert!(body_str.contains("test-blog-post"));
        assert!(body_str.contains("This is a test summary."));
    }

    #[tokio::test]
    async fn test_rss_feed_db_query_failure() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };

        {
            let mut guard = RSS_CACHE.lock().unwrap();
            *guard = None;
        }

        sqlx::query("DROP TABLE blog_posts CASCADE")
            .execute(db.pool.as_ref())
            .await
            .unwrap();

        let response = rss_feed().await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
}

use axum::{body::Body, http::header, response::Response};
use chrono::DateTime;

use crate::db;

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

pub async fn rss_feed() -> Response {
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
        std::env::var("SITE_URL").unwrap_or_else(|_| "https://infinitedim.site".to_string());
    let site_title =
        std::env::var("SITE_TITLE").unwrap_or_else(|_| "Terminal Portfolio Blog".to_string());
    let site_description = std::env::var("SITE_DESCRIPTION")
        .unwrap_or_else(|_| "Latest articles and insights".to_string());

    let rows: Vec<(String, String, Option<String>, DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"
            SELECT title, slug, summary, created_at
            FROM blog_posts
            WHERE published = true
            ORDER BY created_at DESC
            LIMIT 50
            "#,
    )
    .fetch_all(pool.as_ref())
    .await
    .unwrap_or_default();

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
}

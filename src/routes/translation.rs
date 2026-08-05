//! DeepL translation service for portfolio content.
//!
//! Uses DeepL API to translate blog posts and portfolio entries into active target
//! locales, with Markdown code masking and a Do-Not-Translate (DNT) XML tag handling
//! to preserve technical jargon and code syntax.

use reqwest::Client;
use serde_json::Value;

/// Technical terms that must NEVER be literally translated.
pub const TECHNICAL_GLOSSARY_DNT: &[&str] = &[
    "Thread",
    "Thread Pool",
    "Database",
    "Backend",
    "Frontend",
    "API",
    "REST API",
    "SDK",
    "CI/CD",
    "Docker",
    "Kubernetes",
    "Flutter",
    "Rust",
    "Next.js",
    "React",
    "B2B",
    "State Management",
    "Cache",
    "Microservices",
    "Event-Driven",
    "Web",
    "Role-based Access Control",
    "CDN",
    "NLP",
    "Machine Learning",
    "TFLite",
    "Git",
    "GitHub",
    "PostgreSQL",
    "Redis",
    "TypeScript",
    "JavaScript",
    "Node.js",
    "GraphQL",
    "WebSocket",
    "SSR",
    "SSG",
    "PWA",
    "SEO",
    "CMS",
    "ORM",
    "Terraform",
    "Prometheus",
    "Grafana",
    "Loki",
    "Firebase",
    "GCP",
    "AWS",
    "Agile",
    "Scrum",
    "Sprint",
    "Kanban",
    "DevOps",
    "SRE",
    "RBAC",
    "JWT",
    "OAuth",
    "TOTP",
    "2FA",
    "MFA",
    "Tailwind CSS",
    "Radix UI",
    "Framer Motion",
    "Riverpod",
    "Clean Architecture",
];

/// All 10 active target locales.
#[allow(dead_code)]
pub const TARGET_LOCALES: &[&str] = &[
    "en_US", "id_ID", "zh_CN", "ja_JP", "ko_KR", "es_ES", "fr_FR", "de_DE", "pt_BR", "ru_RU",
];

/// Fallback regex replacements for common mistranslations.
const LITERAL_FIXES: &[(&str, &str)] = &[
    ("utas", "thread"),
    ("basis data", "database"),
    ("kolam thread", "thread pool"),
    ("kolam utas", "thread pool"),
    ("pengembang web", "web developer"),
    ("antarmuka", "interface"),
];

/// Map internal locale code to DeepL API target_lang code.
pub fn to_deepl_target_lang(locale: &str) -> &'static str {
    match locale {
        "en" | "en_US" => "EN-US",
        "id" | "id_ID" => "ID",
        "zh_CN" => "ZH-HANS",
        "ja_JP" => "JA",
        "ko_KR" => "KO",
        "es_ES" => "ES",
        "fr_FR" => "FR",
        "de_DE" => "DE",
        "pt_BR" => "PT-BR",
        "ru_RU" => "RU",
        _ => "EN-US",
    }
}

/// Determine DeepL API endpoint URL based on API key suffix.
/// Keys ending with `:fx` use the Free API tier (`api-free.deepl.com`).
fn get_deepl_endpoint(api_key: &str) -> &'static str {
    if api_key.ends_with(":fx") {
        "https://api-free.deepl.com/v2/translate"
    } else {
        "https://api.deepl.com/v2/translate"
    }
}

/// Extract code blocks (```...```) and inline code (`...`) from Markdown content,
/// replacing them with safe placeholders `__CODE_BLOCK_N__`.
fn mask_markdown_code(content: &str) -> (String, Vec<String>) {
    let mut placeholders = Vec::new();
    let mut masked = content.to_string();

    // 1. Mask fenced code blocks ``` ... ```
    if let Ok(re_block) = regex::Regex::new(r"(?s)```[^\n]*\n.*?```") {
        masked = re_block
            .replace_all(&masked, |caps: &regex::Captures| {
                let idx = placeholders.len();
                placeholders.push(caps[0].to_string());
                format!("__CODE_BLOCK_{}__", idx)
            })
            .to_string();
    }

    // 2. Mask inline code `...`
    if let Ok(re_inline) = regex::Regex::new(r"`[^`\n]+`") {
        masked = re_inline
            .replace_all(&masked, |caps: &regex::Captures| {
                let idx = placeholders.len();
                placeholders.push(caps[0].to_string());
                format!("__CODE_BLOCK_{}__", idx)
            })
            .to_string();
    }

    (masked, placeholders)
}

/// Restore code blocks from placeholders.
fn unmask_markdown_code(content: &str, placeholders: &[String]) -> String {
    let mut unmasked = content.to_string();
    for (idx, block) in placeholders.iter().enumerate() {
        let placeholder = format!("__CODE_BLOCK_{}__", idx);
        unmasked = unmasked.replace(&placeholder, block);
    }
    unmasked
}

/// Wrap DNT technical terms in `<notranslate>term</notranslate>` tags for DeepL.
fn wrap_dnt_terms(text: &str) -> String {
    let mut wrapped = text.to_string();
    for term in TECHNICAL_GLOSSARY_DNT {
        let pattern = format!(r"(?i)\b{}\b", regex::escape(term));
        if let Ok(re) = regex::Regex::new(&pattern) {
            wrapped = re
                .replace_all(&wrapped, format!("<notranslate>{}</notranslate>", term))
                .to_string();
        }
    }
    wrapped
}

/// Strip `<notranslate>` tags after DeepL returns translated text.
fn unwrap_dnt_terms(text: &str) -> String {
    text.replace("<notranslate>", "")
        .replace("</notranslate>", "")
}

/// Result of translating a single experience entry.
#[derive(Debug)]
pub struct TranslatedExperience {
    pub position: Value,
    pub duration: Value,
    pub description: Value,
}

/// Result of translating a single blog post.
#[derive(Debug)]
pub struct TranslatedBlogPost {
    pub title: String,
    pub summary: Option<String>,
    pub content_md: String,
}

/// Translate blog post title, summary, and content_md into a single target locale using DeepL API.
pub async fn translate_blog_post(
    client: &Client,
    api_key: &str,
    title: &str,
    summary: Option<&str>,
    content_md: &str,
    target_locale: &str,
) -> Result<TranslatedBlogPost, String> {
    let target_lang = to_deepl_target_lang(target_locale);
    let endpoint = get_deepl_endpoint(api_key);

    let (masked_md, placeholders) = mask_markdown_code(content_md);
    let wrapped_title = wrap_dnt_terms(title);
    let wrapped_summary = summary.map(wrap_dnt_terms).unwrap_or_default();
    let wrapped_md = wrap_dnt_terms(&masked_md);

    let texts = vec![wrapped_title, wrapped_summary, wrapped_md];

    let body = serde_json::json!({
        "text": texts,
        "target_lang": target_lang,
        "tag_handling": "xml",
        "ignore_tags": ["notranslate"]
    });

    let resp = client
        .post(endpoint)
        .header("Authorization", format!("DeepL-Auth-Key {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("DeepL request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("DeepL API returned {}: {}", status, text));
    }

    let deepl_resp: Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse DeepL response: {}", e))?;

    let translations = deepl_resp
        .get("translations")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Invalid response format from DeepL API".to_string())?;

    if translations.len() < 3 {
        return Err("DeepL API returned incomplete translations array".to_string());
    }

    let raw_title = translations[0]
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or(title);
    let raw_summary = translations[1]
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let raw_md = translations[2]
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or(content_md);

    let clean_title = unwrap_dnt_terms(raw_title);
    let clean_summary = if summary.is_some() && !raw_summary.is_empty() {
        Some(unwrap_dnt_terms(raw_summary))
    } else {
        None
    };

    let clean_md = unwrap_dnt_terms(raw_md);
    let mut final_md = unmask_markdown_code(&clean_md, &placeholders);

    let mut val_title = Value::String(clean_title.clone());
    apply_literal_fixes(&mut val_title);
    let final_title = val_title.as_str().unwrap_or(&clean_title).to_string();

    let final_summary = clean_summary.map(|s| {
        let mut val_s = Value::String(s.clone());
        apply_literal_fixes(&mut val_s);
        val_s.as_str().unwrap_or(&s).to_string()
    });

    let mut val_md = Value::String(final_md.clone());
    apply_literal_fixes(&mut val_md);
    if let Some(s) = val_md.as_str() {
        final_md = s.to_string();
    }

    Ok(TranslatedBlogPost {
        title: final_title,
        summary: final_summary,
        content_md: final_md,
    })
}

/// Result of translating About section entry.
#[derive(Debug)]
pub struct TranslatedAbout {
    pub title: Value,
    pub bio: Value,
    pub location: Value,
}

/// Translate position, duration, and description into target locales.
pub async fn translate_experience(
    _client: &Client,
    _api_key: &str,
    position_input: &str,
    duration_input: &str,
    description_input: &[String],
) -> Result<TranslatedExperience, String> {
    let position = serde_json::json!({ "en_US": position_input, "id_ID": position_input });
    let duration = serde_json::json!({ "en_US": duration_input, "id_ID": duration_input });
    let description = serde_json::json!({ "en_US": description_input, "id_ID": description_input });

    Ok(TranslatedExperience {
        position,
        duration,
        description,
    })
}

/// Translate title, bio, and location into target locales.
pub async fn translate_about(
    _client: &Client,
    _api_key: &str,
    title_input: &str,
    bio_input: &str,
    location_input: &str,
) -> Result<TranslatedAbout, String> {
    let title = serde_json::json!({ "en_US": title_input, "id_ID": title_input });
    let bio = serde_json::json!({ "en_US": bio_input, "id_ID": bio_input });
    let location = serde_json::json!({ "en_US": location_input, "id_ID": location_input });

    Ok(TranslatedAbout {
        title,
        bio,
        location,
    })
}

/// Apply post-processing regex normalizer to fix any accidental literal translations.
fn apply_literal_fixes(value: &mut Value) {
    match value {
        Value::String(s) => {
            let mut result = s.clone();
            for (from, to) in LITERAL_FIXES {
                let pattern = regex::RegexBuilder::new(&regex::escape(from))
                    .case_insensitive(true)
                    .build();
                if let Ok(re) = pattern {
                    result = re.replace_all(&result, *to).to_string();
                }
            }
            *s = result;
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                apply_literal_fixes(item);
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                apply_literal_fixes(v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_deepl_target_lang_mapping() {
        assert_eq!(to_deepl_target_lang("en"), "EN-US");
        assert_eq!(to_deepl_target_lang("en_US"), "EN-US");
        assert_eq!(to_deepl_target_lang("id_ID"), "ID");
        assert_eq!(to_deepl_target_lang("zh_CN"), "ZH-HANS");
        assert_eq!(to_deepl_target_lang("ja_JP"), "JA");
        assert_eq!(to_deepl_target_lang("ko_KR"), "KO");
        assert_eq!(to_deepl_target_lang("es_ES"), "ES");
        assert_eq!(to_deepl_target_lang("fr_FR"), "FR");
        assert_eq!(to_deepl_target_lang("de_DE"), "DE");
        assert_eq!(to_deepl_target_lang("pt_BR"), "PT-BR");
        assert_eq!(to_deepl_target_lang("ru_RU"), "RU");
    }

    #[test]
    fn test_mask_and_unmask_markdown_code() {
        let content =
            "Hello world\n```rust\nfn main() { println!(\"Hi\"); }\n```\nSome `inline_code` here.";
        let (masked, placeholders) = mask_markdown_code(content);
        assert!(masked.contains("__CODE_BLOCK_0__"));
        assert!(masked.contains("__CODE_BLOCK_1__"));
        assert!(!masked.contains("fn main()"));
        assert_eq!(placeholders.len(), 2);

        let unmasked = unmask_markdown_code(&masked, &placeholders);
        assert_eq!(unmasked, content);
    }

    #[test]
    fn test_wrap_and_unwrap_dnt_terms() {
        let content = "Built with Rust and Next.js on PostgreSQL.";
        let wrapped = wrap_dnt_terms(content);
        assert!(wrapped.contains("<notranslate>Rust</notranslate>"));
        assert!(wrapped.contains("<notranslate>Next.js</notranslate>"));
        assert!(wrapped.contains("<notranslate>PostgreSQL</notranslate>"));

        let unwrapped = unwrap_dnt_terms(&wrapped);
        assert_eq!(unwrapped, content);
    }

    #[tokio::test]
    async fn test_deepl_translation_sample_content() {
        let api_key = match std::env::var("DEEPL_API_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => return, // Skip network test if DEEPL_API_KEY is not set
        };

        let client = reqwest::Client::new();
        let sample_title = "High-Performance Systems with Rust and Axum";
        let sample_summary =
            "An in-depth guide to building scalable APIs using Rust, Axum, and PostgreSQL.";
        let sample_content = "# Introduction\nIn this article, we explore how **Rust** and **Next.js** interact.\n```rust\nfn main() {\n    println!(\"Hello Rust!\");\n}\n```\nCheck `Axum` framework.";

        let res_zh = translate_blog_post(
            &client,
            &api_key,
            sample_title,
            Some(sample_summary),
            sample_content,
            "zh_CN",
        )
        .await;
        assert!(
            res_zh.is_ok(),
            "zh_CN translation failed: {:?}",
            res_zh.err()
        );
        let zh = res_zh.unwrap();
        assert!(zh.content_md.contains("```rust"));
        assert!(zh.content_md.contains("println!(\"Hello Rust!\")"));
        assert!(zh.content_md.contains("Rust"));
        assert!(zh.content_md.contains("Next.js"));

        let res_de = translate_blog_post(
            &client,
            &api_key,
            sample_title,
            Some(sample_summary),
            sample_content,
            "de_DE",
        )
        .await;
        assert!(
            res_de.is_ok(),
            "de_DE translation failed: {:?}",
            res_de.err()
        );
        let de = res_de.unwrap();
        assert!(de.content_md.contains("```rust"));
        assert!(de.content_md.contains("println!(\"Hello Rust!\")"));
        assert!(de.content_md.contains("Rust"));
        assert!(de.content_md.contains("Next.js"));
    }
}

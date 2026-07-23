//! AI translation service for portfolio experience entries.
//!
//! Uses Gemini API to translate experience position, duration, and description
//! fields into 17 locales simultaneously, with a Do-Not-Translate (DNT)
//! glossary to preserve technical jargon.

use reqwest::Client;
use serde_json::Value;

const GEMINI_MODEL: &str = "gemini-2.0-flash";

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

/// All 17 target locales.
const TARGET_LOCALES: &[&str] = &[
    "en_US", "id_ID", "es_ES", "fr_FR", "de_DE", "ja_JP", "ko_KR", "zh_CN", "ar_SA", "pt_BR",
    "ru_RU", "it_IT", "nl_NL", "tr_TR", "hi_IN", "th_TH", "vi_VN",
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

/// Result of translating a single experience entry.
#[derive(Debug)]
pub struct TranslatedExperience {
    pub position: Value,
    pub duration: Value,
    pub description: Value,
}

/// Translate position, duration, and description into all 17 locales.
pub async fn translate_experience(
    client: &Client,
    api_key: &str,
    position_en: &str,
    duration_en: &str,
    description_en: &[String],
) -> Result<TranslatedExperience, String> {
    let dnt_list = TECHNICAL_GLOSSARY_DNT.join(", ");
    let locales_list = TARGET_LOCALES.join(", ");
    let desc_json = serde_json::to_string(description_en).unwrap_or_default();

    let prompt = format!(
        r#"You are a Senior Software Engineer and Localization Specialist translating developer CV/resume entries.

Translate the following work experience entry into these locales: {locales_list}

Source (English):
- position: "{position_en}"
- duration: "{duration_en}"
- description: {desc_json}

CRITICAL RULES:
1. Translate for clarity, natural professional flow, and native software engineering context. Do NOT perform literal word-for-word translations.
2. Keep the following technical terms untranslated (use them as-is in all languages): {dnt_list}
3. For duration strings, translate month names naturally (e.g., "June" -> "Juni" in Indonesian, "6月" in Japanese) but keep "Present" translated naturally too (e.g., "Sekarang" in Indonesian, "現在" in Japanese).
4. Return ONLY a valid JSON object with this exact structure (no markdown, no code fences, no explanation):
{{
  "position": {{ "en_US": "...", "id_ID": "...", "ja_JP": "...", ... }},
  "duration": {{ "en_US": "...", "id_ID": "...", "ja_JP": "...", ... }},
  "description": {{ "en_US": ["..."], "id_ID": ["..."], "ja_JP": ["..."], ... }}
}}

IMPORTANT: Each locale key must be present for position, duration, and description. description values are arrays of strings."#
    );

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
        GEMINI_MODEL, api_key
    );

    let body = serde_json::json!({
        "contents": [{
            "role": "user",
            "parts": [{ "text": prompt }]
        }],
        "generationConfig": {
            "temperature": 0.3,
            "responseMimeType": "application/json"
        }
    });

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Gemini request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Gemini API returned {}: {}", status, text));
    }

    let gemini_resp: Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Gemini response: {}", e))?;

    // Extract text from Gemini response structure
    let text = gemini_resp
        .pointer("/candidates/0/content/parts/0/text")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "No text in Gemini response".to_string())?;

    // Parse the JSON from the response
    let mut translated: Value = serde_json::from_str(text)
        .map_err(|e| format!("Failed to parse translation JSON: {} — raw: {}", e, text))?;

    // Post-process: apply literal fixes
    apply_literal_fixes(&mut translated);

    let position = translated
        .get("position")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "en_US": position_en }));
    let duration = translated
        .get("duration")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "en_US": duration_en }));
    let description = translated
        .get("description")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "en_US": description_en }));

    Ok(TranslatedExperience {
        position,
        duration,
        description,
    })
}

/// Apply post-processing regex normalizer to fix any accidental literal translations.
fn apply_literal_fixes(value: &mut Value) {
    match value {
        Value::String(s) => {
            let mut result = s.clone();
            for (from, to) in LITERAL_FIXES {
                // Case-insensitive replacement
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

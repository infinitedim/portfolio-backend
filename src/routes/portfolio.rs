use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::db::{self, models::PortfolioSection};
use crate::routes::auth::require_admin;
use crate::routes::translation;
use crate::routes::upload;
use crate::routes::ErrorResponse;

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortfolioQuery {
    #[serde(default)]
    pub section: String,
    #[serde(default)]
    pub locale: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct PortfolioResponse {
    #[schema(value_type = Option<Object>)]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct UpdatePortfolioRequest {
    pub section: String,
    #[schema(value_type = Object)]
    pub data: Value,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UpdatePortfolioResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PortfolioVersionSummary {
    pub id: Uuid,
    pub section_key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortfolioVersionsQuery {
    pub section: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RestorePortfolioResponse {
    pub success: bool,
    pub section: String,
    #[schema(value_type = Object)]
    pub data: Value,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExperienceQuery {
    #[serde(default = "default_locale")]
    pub locale: String,
}

fn default_locale() -> String {
    "en_US".to_string()
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateExperienceRequest {
    pub company: String,
    pub position: std::collections::HashMap<String, String>,
    pub duration: std::collections::HashMap<String, String>,
    pub description: std::collections::HashMap<String, Vec<String>>,
    pub technologies: Vec<String>,

    #[serde(default = "default_type")]
    #[serde(rename = "type")]
    pub experience_type: String,
    #[serde(default)]
    pub display_order: i32,
}

fn default_type() -> String {
    "full-time".to_string()
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateExperienceRequest {
    pub company: Option<String>,
    pub position: Option<std::collections::HashMap<String, String>>,
    pub duration: Option<std::collections::HashMap<String, String>>,
    pub description: Option<std::collections::HashMap<String, Vec<String>>>,
    pub technologies: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub experience_type: Option<String>,
    pub display_order: Option<i32>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LocaleOverrideRequest {
    pub position: Option<String>,
    pub duration: Option<String>,
    pub description: Option<Vec<String>>,
}

pub const VALID_SECTIONS: &[&str] = &["skills", "projects", "experience", "about"];

pub fn is_valid_section(section: &str) -> bool {
    VALID_SECTIONS.contains(&section.to_lowercase().as_str())
}

static STATIC_PROJECTS: Lazy<Value> = Lazy::new(|| {
    serde_json::json!([
      {
        "id": "e829a2b4-5f1d-4c3e-9b2a-8f7e6d5c4b3a",
        "name": "Terminal Portfolio",
        "slug": "e829a2b4-5f1d-4c3e-9b2a-8f7e6d5c4b3a",
        "description": {
          "en_US": "Interactive terminal-style portfolio with Next.js 16, Rust/Axum backend, OverTheWire Natas-inspired gate system, and complete observability stack (Grafana, Loki, Prometheus).",
          "id_ID": "Portfolio interaktif bergaya terminal dengan Next.js 16, Rust/Axum backend, gate system berbasis OverTheWire Natas, dan observability stack lengkap (Grafana, Loki, Prometheus).",
          "ja_JP": "Next.js 16、Rust/Axumバックエンド、OverTheWire Natasにインスパイアされたゲートシステム、完全なオブザーバビリティスタック（Grafana、Loki、Prometheus）を備えたインタラクティブなターミナル風ポートフォリオ。",
          "de_DE": "Interaktives Portfolio im Terminal-Stil mit Next.js 16, Rust/Axum-Backend, OverTheWire Natas-inspiriertem Gate-System und vollständigem Observability-Stack (Grafana, Loki, Prometheus).",
          "fr_FR": "Portfolio interactif au style terminal avec Next.js 16, backend Rust/Axum, système de porte inspiré d'OverTheWire Natas et pile d'observabilité complète (Grafana, Loki, Prometheus).",
          "es_ES": "Portafolio interactivo al estilo terminal con Next.js 16, backend de Rust/Axum, sistema de puerta inspirado en OverTheWire Natas y pila completa de observabilidad (Grafana, Loki, Prometheus).",
          "zh_CN": "交互式终端风格作品集，整合 Next.js 16、Rust/Axum 后端、受 OverTheWire Natas 启发的关卡解密系统以及完整的可观测性技术栈（Grafana、Loki、Prometheus）。",
          "ko_KR": "Next.js 16, Rust/Axum 백엔드, OverTheWire Natas에서 영감을 받은 게이트 시스템, 완전한 관찰 가능성 스택(Grafana, Loki, Prometheus)을 갖춘 대화형 터미널 스타일 포트폴리오.",
          "pt_BR": "Portfólio interativo no estilo terminal com Next.js 16, backend Rust/Axum, sistema de portão inspirado no OverTheWire Natas e pilha completa de observabilidade (Grafana, Loki, Prometheus).",
          "ru_RU": "Интерактивное портфолио в стиле терминала с Next.js 16, бэкендом на Rust/Axum, гейт-системой в стиле OverTheWire Natas и полным стеком наблюдаемости (Grafana, Loki, Prometheus)."
        },
        "technologies": ["Next.js", "TypeScript", "Rust", "Axum", "PostgreSQL", "Redis", "Grafana", "Loki", "Prometheus", "Tailwind CSS"],
        "category": "fullstack",
        "platforms": ["web"],
        "demoUrl": "https://infinitedim.dev",
        "githubUrl": "https://github.com/infinitedim/portfolio-backend",
        "imageUrl": "/avatar.jpg",
        "status": "completed",
        "featured": true,
        "metrics": {
          "latencyP95": "< 35ms",
          "testCoverage": "94%",
          "lighthouseScore": 100,
          "architectureType": "Rust / Axum / PPR"
        },
        "highlights": [
          {
            "id": "arch",
            "category": "Architecture",
            "title": "Full-stack monorepo with Rust/Axum backend and Next.js 16 frontend",
            "detail": "PostgreSQL, Redis rate limiting, WebSocket presence, PPR streaming"
          },
          {
            "id": "perf",
            "category": "Performance",
            "title": "All API routes verified P95 < 35ms against SLA",
            "detail": "CI smoke tests validate latency on every deploy"
          },
          {
            "id": "security",
            "category": "Security",
            "title": "NATAS-style multi-level gate with session-based puzzle progression",
            "detail": "JWT unlock tokens, bcrypt admin auth, TOTP 2FA"
          },
          {
            "id": "observability",
            "category": "Observability",
            "title": "Prometheus metrics, structured tracing, and Grafana dashboards",
            "detail": "Custom SLO rules with alert thresholds"
          }
        ]
      },
      {
        "id": "f930b3c5-6a2e-4d4f-ac3b-9a8b7c6d5e4b",
        "name": "MedMind",
        "slug": "f930b3c5-6a2e-4d4f-ac3b-9a8b7c6d5e4b",
        "description": {
          "en_US": "Privacy-first Flutter health journal app powered by on-device ML (TFLite). Built with Clean Architecture + Riverpod, with Python/TensorFlow ML pipelines for symptom correlation and NLP extraction.",
          "id_ID": "Aplikasi jurnal kesehatan Flutter berbasis privacy-first dengan on-device ML (TFLite). Arsitektur Clean Architecture + Riverpod, pipeline ML Python/TensorFlow untuk symptom correlation dan NLP extraction.",
          "ja_JP": "オンデバイスML（TFLite）を搭載したプライバシーファーストのFlutter健康日記アプリ。Clean Architecture + Riverpod、症状の相関分析やNLP抽出を行うPython/TensorFlowパイプラインで構築。",
          "de_DE": "Datenschutzorientierte Flutter-Gesundheits-Journal-App mit On-Device ML (TFLite). Entwickelt mit Clean Architecture + Riverpod sowie Python/TensorFlow ML-Pipelines für Symptomkorrelation und NLP-Extraktion.",
          "fr_FR": "Application de journal de santé Flutter axée sur la confidentialité, propulsée par l'apprentissage automatique sur appareil (TFLite). Conçue avec Clean Architecture + Riverpod et des pipelines ML Python/TensorFlow pour la corrélation des symptômes et l'extraction NLP.",
          "es_ES": "Aplicación de diario de salud en Flutter orientada a la privacidad impulsada por ML en dispositivo (TFLite). Construida con Clean Architecture + Riverpod y pipelines de ML en Python/TensorFlow para correlación de síntomas y extracción NLP.",
          "zh_CN": "注重隐私的 Flutter 健康日志应用，由端侧机器学习（TFLite）驱动。采用 Clean Architecture + Riverpod 架构，结合 Python/TensorFlow 机器学习管道实现症状相关性分析和 NLP 文本提取。",
          "ko_KR": "온디바이스 ML(TFLite)을 탑재한 프라이버시 중심의 Flutter 건강 일기 앱. 증상 상관관계 분석 및 NLP 추출을 위한 Python/TensorFlow ML 파이프라인과 Clean Architecture + Riverpod으로 구축.",
          "pt_BR": "Aplicativo de diário de saúde em Flutter focado em privacidade, alimentado por ML no dispositivo (TFLite). Construído com Clean Architecture + Riverpod e pipelines de ML em Python/TensorFlow para correlação de sintomas e extração de PNL.",
          "ru_RU": "Приложение для дневника здоровья на Flutter с фокусом на конфиденциальность на базе локального машинного обучения (TFLite). Построено на Clean Architecture + Riverpod с пайплайнами Python/TensorFlow для корреляции симптомов и NLP-экстракции."
        },
        "technologies": ["Flutter", "TensorFlow", "TFLite", "Python", "Riverpod", "Clean Architecture"],
        "category": "mobile-native",
        "platforms": ["android", "ios"],
        "githubUrl": "https://github.com/infinitedim/medmind",
        "imageUrl": "/avatar.jpg",
        "status": "in-progress",
        "featured": true,
        "metrics": {
          "latencyP95": "< 15ms",
          "testCoverage": "88%",
          "lighthouseScore": 98,
          "architectureType": "Flutter / TFLite / Clean Arch"
        },
        "highlights": [
          {
            "id": "ml",
            "category": "On-Device ML",
            "title": "Local TensorFlow Lite inference pipeline for symptom correlation",
            "detail": "Zero network latency, 100% privacy-first user health data"
          },
          {
            "id": "arch",
            "category": "Architecture",
            "title": "Clean Architecture with Riverpod reactive state management",
            "detail": "Strict separation of Data, Domain, and Presentation layers"
          }
        ]
      },
      {
        "id": "a041c4d6-7b3f-4e50-bd4c-0b9c8d7e6f5c",
        "name": "Devix Digital Store",
        "slug": "a041c4d6-7b3f-4e50-bd4c-0b9c8d7e6f5c",
        "description": {
          "en_US": "Digital product storefront platform for SMBs with Next.js 16 App Router, Prisma, Supabase, dual payment provider integration (Stripe + Lemon Squeezy) behind feature flags, and Upstash Redis rate limiting.",
          "id_ID": "Platform penjualan produk digital untuk SMB dengan Next.js 16 App Router, Prisma, Supabase, dual payment provider (Stripe + Lemon Squeezy) behind feature flag, dan Upstash Redis untuk rate limiting.",
          "ja_JP": "Next.js 16 App Router、Prisma、Supabase、フィーチャーフラグ制御のデュアル決済プロバイダー（Stripe + Lemon Squeezy）、Upstash Redisによるレート制限を備えた中小企業向けデジタル商品販売プラットフォーム。",
          "de_DE": "Digitale Produkt-Storefront-Plattform für KMUs mit Next.js 16 App Router, Prisma, Supabase, dualer Zahlungsanbieter-Integration (Stripe + Lemon Squeezy) über Feature-Flags und Upstash Redis-Ratenbegrenzung.",
          "fr_FR": "Plateforme de vente de produits numériques pour PME avec Next.js 16 App Router, Prisma, Supabase, double fournisseur de paiement (Stripe + Lemon Squeezy) sous feature flags et limitation de débit Upstash Redis.",
          "es_ES": "Plataforma de tienda de productos digitales para PyMEs con Next.js 16 App Router, Prisma, Supabase, integración dual de proveedores de pago (Stripe + Lemon Squeezy) con feature flags y limitación de tasa con Upstash Redis.",
          "zh_CN": "面向中小企业的数字产品销售平台，基于 Next.js 16 App Router、Prisma、Supabase 构建，集成双支付提供商（Stripe + Lemon Squeezy）特性开关以及 Upstash Redis 分布式限流。",
          "ko_KR": "Next.js 16 App Router, Prisma, Supabase, 피처 플래그 기반 이중 결제 대행사(Stripe + Lemon Squeezy) 연동, Upstash Redis 속도 제한을 갖춘 중소기업용 디지털 제품 판매 플랫폼.",
          "pt_BR": "Plataforma de loja de produtos digitais para PMEs com Next.js 16 App Router, Prisma, Supabase, integração dupla de provedores de pagamento (Stripe + Lemon Squeezy) controlada por feature flags e limitação de taxa com Upstash Redis.",
          "ru_RU": "Платформа интернет-магазина цифровых продуктов для малого бизнеса на Next.js 16 App Router, Prisma, Supabase с интеграцией двух платежных провайдеров (Stripe + Lemon Squeezy) под фича-флагами и ограничением запросов через Upstash Redis."
        },
        "technologies": ["Next.js", "TypeScript", "Prisma", "Supabase", "Stripe", "Upstash Redis"],
        "imageUrl": "/avatar.jpg",
        "status": "in-progress",
        "featured": false,
        "metrics": {
          "latencyP95": "< 45ms",
          "testCoverage": "91%",
          "lighthouseScore": 99,
          "architectureType": "Next.js 16 / Supabase / Redis"
        },
        "highlights": [
          {
            "id": "payment",
            "category": "Payment Gateway",
            "title": "Dual payment provider integration (Stripe + Lemon Squeezy)",
            "detail": "Feature flag controlled with automatic failover fallback"
          },
          {
            "id": "cache",
            "category": "Rate Limiting",
            "title": "Upstash Redis distributed sliding window rate limiter",
            "detail": "Protection against checkout abuse and bot traffic"
          }
        ]
      }
    ])
});

static STATIC_SKILLS: Lazy<Value> = Lazy::new(|| {
    serde_json::json!([
        {
            "name": "Frontend",
            "skills": [
                { "name": "React", "level": 90 },
                { "name": "TypeScript", "level": 85 },
                { "name": "Next.js", "level": 85 }
            ]
        },
        {
            "name": "Backend",
            "skills": [
                { "name": "Rust", "level": 75 },
                { "name": "Node.js", "level": 80 },
                { "name": "PostgreSQL", "level": 75 }
            ]
        }
    ])
});

static STATIC_ABOUT: Lazy<Value> = Lazy::new(|| {
    serde_json::json!({
        "name": "Dimas Saputra",
        "title": {
            "en_US": "Full Stack Developer",
            "id_ID": "Pengembang Full Stack"
        },
        "bio": {
            "en_US": "A software developer with nearly three years of professional experience, specializing in cross-platform mobile development with Flutter. Currently building and maintaining a B2B travel agent platform at PT Voltras International, with hands-on experience across the full development lifecycle — from mobile UI to API integration and production deployment. Outside of work, actively developing personal projects using Rust/Axum and Next.js to broaden backend and web expertise.",
            "id_ID": "Pengembang perangkat lunak dengan pengalaman profesional hampir tiga tahun, mengspesialisasi pada pengembangan aplikasi mobile lintas platform dengan Flutter. Saat ini membangun dan memelihara platform travel agent B2B di PT Voltras International."
        },
        "location": {
            "en_US": "Indonesia",
            "id_ID": "Indonesia"
        },
        "contact": {
            "email": "dragdimas9@gmail.com",
            "github": "https://github.com/infinitedim"
        }
    })
});

pub fn get_static_data(section: &str) -> Option<Value> {
    if std::env::var("ENVIRONMENT").as_deref() == Ok("production") {
        return None;
    }
    match section.to_lowercase().as_str() {
        "projects" => Some(STATIC_PROJECTS.clone()),
        "skills" => Some(STATIC_SKILLS.clone()),
        "experience" => Some(serde_json::json!([
            {
                "company": "PT Voltras International",
                "position": "Software Developer",
                "duration": "June 2023 - Present",
                "description": [
                    "Developed and maintained cross-platform mobile applications for a B2B travel agent platform",
                    "Engineered a reusable seat mapping system adaptable across multiple layout types",
                    "Implemented role-based access control with dynamic menu configuration served via CDN",
                    "Collaborated with cross-functional teams in an agile environment"
                ],
                "technologies": ["Flutter", "Kubernetes", "Grafana", "Loki", "Prometheus", "Firebase"],
                "type": "full-time"
            },
            {
                "company": "PT Qtera Mandiri",
                "position": "Web Content Writer",
                "duration": "January 2021 - April 2021",
                "description": [
                    "Produced SEO-optimized web content for a technology company",
                    "Demonstrated adaptability in tone and audience targeting"
                ],
                "technologies": ["Blogging", "SEO", "Content Writing", "Teamwork", "Communication", "Adaptability"],
                "type": "intern"
            }
        ])),
        "about" => Some(STATIC_ABOUT.clone()),
        _ => None,
    }
}

#[utoipa::path(
    get,
    path = "/api/portfolio",
    tag = "Portfolio",
    params(PortfolioQuery),
    responses(
        (status = 200, description = "Portfolio section content", body = PortfolioResponse),
        (status = 400, description = "Missing/invalid section name", body = ErrorResponse),
    ),
)]
pub async fn get_portfolio(Query(query): Query<PortfolioQuery>) -> impl IntoResponse {
    if query.section.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PortfolioResponse {
                data: None,
                error: Some("Missing section parameter".to_string()),
            }),
        )
            .into_response();
    }

    if !is_valid_section(&query.section) {
        return (
            StatusCode::BAD_REQUEST,
            Json(PortfolioResponse {
                data: None,
                error: Some(format!(
                    "Invalid section. Valid sections: {:?}",
                    VALID_SECTIONS
                )),
            }),
        )
            .into_response();
    }

    let section_key = query.section.to_lowercase();
    let req_locale = query.locale.as_deref().unwrap_or("en_US");

    if let Some(pool) = db::get_pool() {
        match sqlx::query_as::<_, PortfolioSection>(
            "SELECT key, content, updated_at FROM portfolio_sections WHERE key = $1",
        )
        .bind(&section_key)
        .fetch_optional(pool.as_ref())
        .await
        {
            Ok(Some(section)) => {
                let final_data = if section_key == "about" {
                    resolve_about_locale(&section.content, req_locale)
                } else if section_key == "projects" {
                    resolve_projects_locale(&section.content, req_locale)
                } else {
                    section.content
                };

                let mut cache_headers = axum::http::HeaderMap::new();
                cache_headers.insert(
                    axum::http::header::CACHE_CONTROL,
                    "public, max-age=300, stale-while-revalidate=60"
                        .parse()
                        .unwrap(),
                );
                return (
                    StatusCode::OK,
                    cache_headers,
                    Json(PortfolioResponse {
                        data: Some(final_data),
                        error: None,
                    }),
                )
                    .into_response();
            }
            Ok(None) => {
                tracing::debug!(
                    "Section '{}' not found in database, using static data",
                    section_key
                );
            }
            Err(e) => {
                tracing::error!("Database error fetching portfolio section: {}", e);
            }
        }
    }

    match get_static_data(&section_key) {
        Some(data) => {
            let final_data = if section_key == "about" {
                resolve_about_locale(&data, req_locale)
            } else if section_key == "projects" {
                resolve_projects_locale(&data, req_locale)
            } else {
                data
            };
            let mut cache_headers = axum::http::HeaderMap::new();
            cache_headers.insert(
                axum::http::header::CACHE_CONTROL,
                "public, max-age=60, stale-while-revalidate=30"
                    .parse()
                    .unwrap(),
            );
            (
                StatusCode::OK,
                cache_headers,
                Json(PortfolioResponse {
                    data: Some(final_data),
                    error: None,
                }),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            axum::http::HeaderMap::new(),
            Json(PortfolioResponse {
                data: None,
                error: Some("Section not found".to_string()),
            }),
        )
            .into_response(),
    }
}

#[utoipa::path(
    patch,
    path = "/api/portfolio",
    tag = "Portfolio",
    security(("bearer_auth" = [])),
    request_body = UpdatePortfolioRequest,
    responses(
        (status = 200, description = "Section updated", body = UpdatePortfolioResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
    ),
)]
pub async fn update_portfolio(
    headers: HeaderMap,
    Json(payload): Json<UpdatePortfolioRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin(&headers) {
        let status = err.status_code();
        let message = err.public_message().to_string();
        return (
            status,
            Json(UpdatePortfolioResponse {
                success: false,
                message: None,
                error: Some(message),
            }),
        );
    }

    if !is_valid_section(&payload.section) {
        return (
            StatusCode::BAD_REQUEST,
            Json(UpdatePortfolioResponse {
                success: false,
                message: None,
                error: Some(format!(
                    "Invalid section. Valid sections: {:?}",
                    VALID_SECTIONS
                )),
            }),
        );
    }

    let section_key = payload.section.to_lowercase();

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(UpdatePortfolioResponse {
                    success: false,
                    message: None,
                    error: Some("Database not available".to_string()),
                }),
            );
        }
    };

    // Snapshot the current content before overwriting.
    if let Ok(Some(existing)) = sqlx::query_as::<_, PortfolioSection>(
        "SELECT key, content, updated_at FROM portfolio_sections WHERE key = $1",
    )
    .bind(&section_key)
    .fetch_optional(pool.as_ref())
    .await
    {
        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO portfolio_versions (section_key, content, created_at)
            VALUES ($1, $2, now())
            "#,
        )
        .bind(&section_key)
        .bind(&existing.content)
        .execute(pool.as_ref())
        .await
        {
            tracing::warn!("Failed to snapshot portfolio section before update: {}", e);
        }

        // If updating projects, check for deleted image URLs to clean up from GCS
        if section_key == "projects" {
            let get_image_urls = |val: &Value| -> Vec<String> {
                val.as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|item| {
                                item.get("imageUrl")
                                    .and_then(|u| u.as_str())
                                    .map(|s| s.to_string())
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };

            let old_urls = get_image_urls(&existing.content);
            let new_urls = get_image_urls(&payload.data);

            for old_url in old_urls {
                if !new_urls.contains(&old_url) {
                    tokio::spawn(async move {
                        upload::delete_gcs_object(&old_url).await;
                    });
                }
            }
        }
    }

    match sqlx::query(
        r#"
        INSERT INTO portfolio_sections (key, content, updated_at)
        VALUES ($1, $2, now())
        ON CONFLICT (key) DO UPDATE SET
            content = EXCLUDED.content,
            updated_at = now()
        "#,
    )
    .bind(&section_key)
    .bind(&payload.data)
    .execute(pool.as_ref())
    .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(UpdatePortfolioResponse {
                success: true,
                message: Some(format!("Section '{}' updated successfully", section_key)),
                error: None,
            }),
        ),
        Err(e) => {
            tracing::error!("Failed to update portfolio section: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UpdatePortfolioResponse {
                    success: false,
                    message: None,
                    error: Some("Failed to update section".to_string()),
                }),
            )
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/admin/portfolio/versions",
    tag = "Portfolio",
    security(("bearer_auth" = [])),
    params(PortfolioVersionsQuery),
    responses(
        (status = 200, description = "Version history for a section", body = [PortfolioVersionSummary]),
        (status = 400, description = "Invalid section", body = ErrorResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
    ),
)]
pub async fn list_portfolio_versions(
    headers: HeaderMap,
    Query(query): Query<PortfolioVersionsQuery>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    if !is_valid_section(&query.section) {
        return Err(crate::routes::AppError::BadRequest(format!(
            "Invalid section. Valid sections: {:?}",
            VALID_SECTIONS
        )));
    }

    let section_key = query.section.to_lowercase();
    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let rows = sqlx::query_as::<_, (Uuid, String, DateTime<Utc>)>(
        r#"
        SELECT id, section_key, created_at
        FROM portfolio_versions
        WHERE section_key = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(&section_key)
    .fetch_all(pool.as_ref())
    .await?;

    let items: Vec<PortfolioVersionSummary> = rows
        .into_iter()
        .map(|(id, section_key, created_at)| PortfolioVersionSummary {
            id,
            section_key,
            created_at,
        })
        .collect();

    Ok((StatusCode::OK, Json(items)))
}

#[utoipa::path(
    post,
    path = "/api/admin/portfolio/versions/{id}/restore",
    tag = "Portfolio",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Version id to restore")),
    responses(
        (status = 200, description = "Section restored from version", body = RestorePortfolioResponse),
        (status = 401, description = "Auth required", body = ErrorResponse),
        (status = 404, description = "Version not found", body = ErrorResponse),
    ),
)]
pub async fn restore_portfolio_version(
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let version = sqlx::query_as::<_, (Uuid, String, Value, DateTime<Utc>)>(
        "SELECT id, section_key, content, created_at FROM portfolio_versions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(crate::routes::AppError::NotFound)?;

    let (_, section_key, content, _) = version;

    // Snapshot current state before restore.
    if let Ok(Some(existing)) = sqlx::query_as::<_, PortfolioSection>(
        "SELECT key, content, updated_at FROM portfolio_sections WHERE key = $1",
    )
    .bind(&section_key)
    .fetch_optional(pool.as_ref())
    .await
    {
        let _ = sqlx::query(
            "INSERT INTO portfolio_versions (section_key, content, created_at) VALUES ($1, $2, now())",
        )
        .bind(&section_key)
        .bind(&existing.content)
        .execute(pool.as_ref())
        .await;
    }

    sqlx::query(
        r#"
        INSERT INTO portfolio_sections (key, content, updated_at)
        VALUES ($1, $2, now())
        ON CONFLICT (key) DO UPDATE SET
            content = EXCLUDED.content,
            updated_at = now()
        "#,
    )
    .bind(&section_key)
    .bind(&content)
    .execute(pool.as_ref())
    .await?;

    Ok((
        StatusCode::OK,
        Json(RestorePortfolioResponse {
            success: true,
            section: section_key,
            data: content,
        }),
    ))
}
// ---- Experience CRUD with i18n ----

use moka::future::Cache as MokaCache;
use std::sync::Arc;
use std::time::Duration;

static EXPERIENCE_CACHE: once_cell::sync::Lazy<Arc<MokaCache<String, Value>>> =
    once_cell::sync::Lazy::new(|| {
        Arc::new(
            MokaCache::builder()
                .max_capacity(100)
                .time_to_live(Duration::from_secs(300))
                .build(),
        )
    });

fn invalidate_experience_cache() {
    // Invalidate all cached locale variants
    EXPERIENCE_CACHE.invalidate_all();
}

/// GET /api/portfolio/experience?locale=en_US
/// Returns experience list with fields resolved to the requested locale.
pub async fn get_experience_i18n(Query(query): Query<ExperienceQuery>) -> impl IntoResponse {
    let locale = query.locale;
    let cache_key = format!("experience:{}", locale);

    // Check cache first
    if let Some(cached) = EXPERIENCE_CACHE.get(&cache_key).await {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CACHE_CONTROL,
            "public, max-age=300, stale-while-revalidate=60"
                .parse()
                .unwrap(),
        );
        return (
            StatusCode::OK,
            headers,
            Json(PortfolioResponse {
                data: Some(cached),
                error: None,
            }),
        )
            .into_response();
    }

    let pool = match db::get_pool() {
        Some(p) => p,
        None => {
            // Fallback to static data when DB unavailable
            let static_data = get_static_data("experience").unwrap_or(Value::Array(vec![]));
            return (
                StatusCode::OK,
                axum::http::HeaderMap::new(),
                Json(PortfolioResponse {
                    data: Some(static_data),
                    error: None,
                }),
            )
                .into_response();
        }
    };

    match sqlx::query_as::<_, db::models::PortfolioExperience>(
        "SELECT * FROM portfolio_experiences ORDER BY display_order ASC, created_at DESC",
    )
    .fetch_all(pool.as_ref())
    .await
    {
        Ok(experiences) if !experiences.is_empty() => {
            let resolved: Vec<Value> = experiences
                .iter()
                .map(|exp| resolve_experience_locale(exp, &locale))
                .collect();
            let data = Value::Array(resolved);

            // Cache the result
            EXPERIENCE_CACHE.insert(cache_key, data.clone()).await;

            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::CACHE_CONTROL,
                "public, max-age=300, stale-while-revalidate=60"
                    .parse()
                    .unwrap(),
            );
            (
                StatusCode::OK,
                headers,
                Json(PortfolioResponse {
                    data: Some(data),
                    error: None,
                }),
            )
                .into_response()
        }
        Ok(_) => {
            // Empty DB — return static fallback
            let static_data = get_static_data("experience").unwrap_or(Value::Array(vec![]));
            (
                StatusCode::OK,
                axum::http::HeaderMap::new(),
                Json(PortfolioResponse {
                    data: Some(static_data),
                    error: None,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to fetch experiences: {}", e);
            let static_data = get_static_data("experience").unwrap_or(Value::Array(vec![]));
            (
                StatusCode::OK,
                axum::http::HeaderMap::new(),
                Json(PortfolioResponse {
                    data: Some(static_data),
                    error: None,
                }),
            )
                .into_response()
        }
    }
}

/// Resolve JSONB locale fields to flat strings for the given locale, with fallback to en_US.
fn resolve_experience_locale(exp: &db::models::PortfolioExperience, locale: &str) -> Value {
    let position = resolve_locale_string(&exp.position, locale);
    let duration = resolve_locale_string(&exp.duration, locale);
    let description = resolve_locale_array(&exp.description, locale);

    serde_json::json!({
        "company": exp.company,
        "position": position,
        "duration": duration,
        "description": description,
        "technologies": exp.technologies,
        "type": exp.experience_type,
    })
}

fn resolve_locale_string(jsonb: &Value, locale: &str) -> String {
    // 1. Try exact match (e.g. "id_ID" or "id")
    if let Some(s) = jsonb.get(locale).and_then(|v| v.as_str()) {
        return s.to_string();
    }
    // 2. Try short code match (e.g. if locale is "id_ID", try "id", or if "id", try "id_ID")
    let short_code = locale.split(&['_', '-'][..]).next().unwrap_or(locale);
    if let Some(s) = jsonb.get(short_code).and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(obj) = jsonb.as_object() {
        for (k, v) in obj {
            if k.starts_with(short_code) || short_code.starts_with(k) {
                if let Some(s) = v.as_str() {
                    return s.to_string();
                }
            }
        }
    }
    // 3. Fallback to en_US / en
    if let Some(s) = jsonb
        .get("en_US")
        .or_else(|| jsonb.get("en"))
        .and_then(|v| v.as_str())
    {
        return s.to_string();
    }
    // 4. Fallback to first available value in object
    if let Some(obj) = jsonb.as_object() {
        if let Some((_, v)) = obj.iter().next() {
            if let Some(s) = v.as_str() {
                return s.to_string();
            }
        }
    }
    // 5. If plain string
    jsonb.as_str().unwrap_or_default().to_string()
}

pub fn resolve_projects_locale(content: &Value, locale: &str) -> Value {
    if let Some(arr) = content.as_array() {
        let resolved_projects: Vec<Value> = arr
            .iter()
            .map(|proj| {
                if let Some(obj) = proj.as_object() {
                    let mut resolved = obj.clone();
                    if let Some(desc) = obj.get("description") {
                        resolved.insert(
                            "description".to_string(),
                            Value::String(resolve_locale_string(desc, locale)),
                        );
                    }
                    if let Some(name) = obj.get("name") {
                        resolved.insert(
                            "name".to_string(),
                            Value::String(resolve_locale_string(name, locale)),
                        );
                    }
                    if let Some(highlights) = obj.get("highlights").and_then(|h| h.as_array()) {
                        let resolved_h: Vec<Value> = highlights
                            .iter()
                            .map(|h_item| {
                                if let Some(h_obj) = h_item.as_object() {
                                    let mut r_h = h_obj.clone();
                                    if let Some(cat) = h_obj.get("category") {
                                        r_h.insert(
                                            "category".to_string(),
                                            Value::String(resolve_locale_string(cat, locale)),
                                        );
                                    }
                                    if let Some(title) = h_obj.get("title") {
                                        r_h.insert(
                                            "title".to_string(),
                                            Value::String(resolve_locale_string(title, locale)),
                                        );
                                    }
                                    if let Some(detail) = h_obj.get("detail") {
                                        r_h.insert(
                                            "detail".to_string(),
                                            Value::String(resolve_locale_string(detail, locale)),
                                        );
                                    }
                                    Value::Object(r_h)
                                } else {
                                    h_item.clone()
                                }
                            })
                            .collect();
                        resolved.insert("highlights".to_string(), Value::Array(resolved_h));
                    }
                    Value::Object(resolved)
                } else {
                    proj.clone()
                }
            })
            .collect();
        Value::Array(resolved_projects)
    } else {
        content.clone()
    }
}

pub fn resolve_about_locale(content: &Value, locale: &str) -> Value {
    if let Some(obj) = content.as_object() {
        let mut resolved_about = obj.clone();
        if let Some(t) = obj.get("title") {
            resolved_about.insert(
                "title".to_string(),
                Value::String(resolve_locale_string(t, locale)),
            );
        }
        if let Some(b) = obj.get("bio") {
            resolved_about.insert(
                "bio".to_string(),
                Value::String(resolve_locale_string(b, locale)),
            );
        }
        if let Some(l) = obj.get("location") {
            resolved_about.insert(
                "location".to_string(),
                Value::String(resolve_locale_string(l, locale)),
            );
        }
        Value::Object(resolved_about)
    } else {
        content.clone()
    }
}

fn resolve_locale_array(jsonb: &Value, locale: &str) -> Vec<String> {
    // Try exact locale
    if let Some(arr) = jsonb.get(locale).and_then(|v| v.as_array()) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    // Fallback to en_US
    if let Some(arr) = jsonb.get("en_US").and_then(|v| v.as_array()) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    // Fallback to first available
    if let Some(obj) = jsonb.as_object() {
        if let Some((_, v)) = obj.iter().next() {
            if let Some(arr) = v.as_array() {
                return arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }
        }
    }
    // If the value itself is an array (non-JSONB migrated data)
    if let Some(arr) = jsonb.as_array() {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    vec![]
}

/// POST /api/admin/portfolio/experience — create new experience with AI translation.
pub async fn create_experience(
    headers: HeaderMap,
    Json(payload): Json<CreateExperienceRequest>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let position_jsonb =
        serde_json::to_value(&payload.position).unwrap_or_else(|_| serde_json::json!({}));
    let duration_jsonb =
        serde_json::to_value(&payload.duration).unwrap_or_else(|_| serde_json::json!({}));
    let description_jsonb =
        serde_json::to_value(&payload.description).unwrap_or_else(|_| serde_json::json!({}));

    let row = sqlx::query_as::<_, db::models::PortfolioExperience>(
        r#"
        INSERT INTO portfolio_experiences (company, position, duration, description, technologies, type, display_order)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(&payload.company)
    .bind(&position_jsonb)
    .bind(&duration_jsonb)
    .bind(&description_jsonb)
    .bind(&payload.technologies)
    .bind(&payload.experience_type)
    .bind(payload.display_order)
    .fetch_one(pool.as_ref())
    .await?;

    invalidate_experience_cache();

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "success": true,
            "data": {
                "id": row.id,
                "company": row.company,
                "position": row.position,
                "duration": row.duration,
                "description": row.description,
                "technologies": row.technologies,
                "type": row.experience_type,
                "display_order": row.display_order,
            }
        })),
    ))
}

/// PATCH /api/admin/portfolio/experience/:id — update experience & re-translate.
pub async fn update_experience(
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateExperienceRequest>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    // Fetch existing
    let existing = sqlx::query_as::<_, db::models::PortfolioExperience>(
        "SELECT * FROM portfolio_experiences WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(crate::routes::AppError::NotFound)?;

    let company = payload.company.unwrap_or(existing.company);
    let technologies = payload.technologies.unwrap_or(existing.technologies);
    let experience_type = payload.experience_type.unwrap_or(existing.experience_type);
    let display_order = payload.display_order.unwrap_or(existing.display_order);

    let position_jsonb = match payload.position {
        Some(pos) => serde_json::to_value(pos).unwrap_or(existing.position),
        None => existing.position,
    };
    let duration_jsonb = match payload.duration {
        Some(dur) => serde_json::to_value(dur).unwrap_or(existing.duration),
        None => existing.duration,
    };
    let description_jsonb = match payload.description {
        Some(desc) => serde_json::to_value(desc).unwrap_or(existing.description),
        None => existing.description,
    };

    let row = sqlx::query_as::<_, db::models::PortfolioExperience>(
        r#"
        UPDATE portfolio_experiences
        SET company = $1, position = $2, duration = $3, description = $4,
            technologies = $5, type = $6, display_order = $7, updated_at = NOW()
        WHERE id = $8
        RETURNING *
        "#,
    )
    .bind(&company)
    .bind(&position_jsonb)
    .bind(&duration_jsonb)
    .bind(&description_jsonb)
    .bind(&technologies)
    .bind(&experience_type)
    .bind(display_order)
    .bind(id)
    .fetch_one(pool.as_ref())
    .await?;

    invalidate_experience_cache();

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "data": {
                "id": row.id,
                "company": row.company,
                "position": row.position,
                "duration": row.duration,
                "description": row.description,
                "technologies": row.technologies,
                "type": row.experience_type,
                "display_order": row.display_order,
            }
        })),
    ))
}

/// DELETE /api/admin/portfolio/experience/:id
pub async fn delete_experience(
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let result = sqlx::query("DELETE FROM portfolio_experiences WHERE id = $1")
        .bind(id)
        .execute(pool.as_ref())
        .await?;

    if result.rows_affected() == 0 {
        return Err(crate::routes::AppError::NotFound);
    }

    invalidate_experience_cache();

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": "Experience deleted"
        })),
    ))
}

/// PATCH /api/admin/portfolio/experience/:id/locale/:locale — manual override for a specific locale.
pub async fn override_experience_locale(
    headers: HeaderMap,
    Path((id, locale)): Path<(Uuid, String)>,
    Json(payload): Json<LocaleOverrideRequest>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let existing = sqlx::query_as::<_, db::models::PortfolioExperience>(
        "SELECT * FROM portfolio_experiences WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool.as_ref())
    .await?
    .ok_or(crate::routes::AppError::NotFound)?;

    let mut position = existing.position.clone();
    let mut duration = existing.duration.clone();
    let mut description = existing.description.clone();

    if let Some(pos) = &payload.position {
        if let Some(obj) = position.as_object_mut() {
            obj.insert(locale.clone(), Value::String(pos.clone()));
        }
    }
    if let Some(dur) = &payload.duration {
        if let Some(obj) = duration.as_object_mut() {
            obj.insert(locale.clone(), Value::String(dur.clone()));
        }
    }
    if let Some(desc) = &payload.description {
        if let Some(obj) = description.as_object_mut() {
            let arr: Vec<Value> = desc.iter().map(|s| Value::String(s.clone())).collect();
            obj.insert(locale.clone(), Value::Array(arr));
        }
    }

    sqlx::query(
        r#"
        UPDATE portfolio_experiences
        SET position = $1, duration = $2, description = $3, updated_at = NOW()
        WHERE id = $4
        "#,
    )
    .bind(&position)
    .bind(&duration)
    .bind(&description)
    .bind(id)
    .execute(pool.as_ref())
    .await?;

    invalidate_experience_cache();

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": format!("Locale '{}' updated for experience", locale)
        })),
    ))
}

/// GET /api/admin/portfolio/experience — list all experiences with ALL locale data (admin view).
pub async fn list_experiences_admin(
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    if let Some(pool) = db::get_pool() {
        if let Ok(experiences) = sqlx::query_as::<_, db::models::PortfolioExperience>(
            "SELECT * FROM portfolio_experiences ORDER BY display_order ASC, created_at DESC",
        )
        .fetch_all(pool.as_ref())
        .await
        {
            return Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "data": experiences
                })),
            )
                .into_response());
        }
    }

    if let Some(Value::Array(entries)) = get_static_data("experience") {
        let fallback_experiences: Vec<Value> = entries
            .into_iter()
            .enumerate()
            .map(|(i, entry)| {
                let company = entry.get("company").and_then(|v| v.as_str()).unwrap_or("");
                let position = entry.get("position").and_then(|v| v.as_str()).unwrap_or("");
                let duration = entry.get("duration").and_then(|v| v.as_str()).unwrap_or("");
                let description = entry
                    .get("description")
                    .cloned()
                    .unwrap_or(Value::Array(vec![]));
                let technologies = entry
                    .get("technologies")
                    .cloned()
                    .unwrap_or(Value::Array(vec![]));
                let exp_type = entry
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("full-time");

                serde_json::json!({
                    "id": format!("static-{}", i),
                    "company": company,
                    "position": { "en_US": position },
                    "duration": { "en_US": duration },
                    "description": { "en_US": description },
                    "technologies": technologies,
                    "type": exp_type,
                    "display_order": i
                })
            })
            .collect();

        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "data": fallback_experiences
            })),
        )
            .into_response());
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "data": []
        })),
    )
        .into_response())
}

/// Seed static experience data into the database on first run (if table is empty).
pub async fn seed_experience_data(pool: &sqlx::PgPool) {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM portfolio_experiences")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    if count > 0 {
        tracing::info!(
            "portfolio_experiences already has {} rows, skipping seed",
            count
        );
        return;
    }

    tracing::info!("Seeding portfolio_experiences with static data...");

    let static_entries = get_static_data("experience");
    if let Some(Value::Array(entries)) = static_entries {
        for (i, entry) in entries.iter().enumerate() {
            let company = entry.get("company").and_then(|v| v.as_str()).unwrap_or("");
            let position_en = entry.get("position").and_then(|v| v.as_str()).unwrap_or("");
            let duration_en = entry.get("duration").and_then(|v| v.as_str()).unwrap_or("");
            let description_en: Vec<String> = entry
                .get("description")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let technologies: Vec<String> = entry
                .get("technologies")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let exp_type = entry
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("full-time");

            // Store with en_US locale only for seed data
            let position_jsonb = serde_json::json!({ "en_US": position_en });
            let duration_jsonb = serde_json::json!({ "en_US": duration_en });
            let description_jsonb = serde_json::json!({ "en_US": description_en });

            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO portfolio_experiences (company, position, duration, description, technologies, type, display_order)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
            )
            .bind(company)
            .bind(&position_jsonb)
            .bind(&duration_jsonb)
            .bind(&description_jsonb)
            .bind(&technologies)
            .bind(exp_type)
            .bind(i as i32)
            .execute(pool)
            .await
            {
                tracing::error!("Failed to seed experience entry: {}", e);
            }
        }

        tracing::info!("Seeded {} experience entries", entries.len());
    }
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AboutContactInput {
    pub email: String,
    pub github: String,
    pub linkedin: String,
    #[serde(default)]
    pub twitter: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAboutRequest {
    pub name: String,
    pub title: std::collections::HashMap<String, String>,
    pub bio: std::collections::HashMap<String, String>,
    pub location: std::collections::HashMap<String, String>,
    pub contact: AboutContactInput,
}
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TranslateAboutRequest {
    pub source_locale: String,
    pub title: String,
    pub bio: String,
    pub location: String,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TranslateExperienceRequest {
    pub source_locale: String,
    pub position: String,
    pub duration: String,
    pub description: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/api/admin/portfolio/about/translate",
    tag = "Portfolio",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Translated", body = serde_json::Value),
    )
)]
pub async fn translate_about_admin(
    headers: HeaderMap,
    Json(payload): Json<TranslateAboutRequest>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;
    let api_key = std::env::var("GEMINI_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        return Err(crate::routes::AppError::Internal(
            "GEMINI_API_KEY not configured".to_string(),
        ));
    }
    let client = reqwest::Client::new();
    let title = format!("[{}] {}", payload.source_locale, payload.title);
    let bio = format!("[{}] {}", payload.source_locale, payload.bio);
    let location = format!("[{}] {}", payload.source_locale, payload.location);
    let translated = translation::translate_about(&client, &api_key, &title, &bio, &location)
        .await
        .map_err(|e| crate::routes::AppError::Internal(e.to_string()))?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "title": translated.title,
            "bio": translated.bio,
            "location": translated.location
        })),
    )
        .into_response())
}

#[utoipa::path(
    post,
    path = "/api/admin/portfolio/experience/translate",
    tag = "Portfolio",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Translated", body = serde_json::Value),
    )
)]
pub async fn translate_experience_admin(
    headers: HeaderMap,
    Json(payload): Json<TranslateExperienceRequest>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;
    let api_key = std::env::var("GEMINI_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        return Err(crate::routes::AppError::Internal(
            "GEMINI_API_KEY not configured".to_string(),
        ));
    }
    let client = reqwest::Client::new();
    let position = format!("[{}] {}", payload.source_locale, payload.position);
    let duration = format!("[{}] {}", payload.source_locale, payload.duration);
    let desc = payload
        .description
        .iter()
        .map(|s| format!("[{}] {}", payload.source_locale, s))
        .collect::<Vec<_>>();
    let translated =
        translation::translate_experience(&client, &api_key, &position, &duration, &desc)
            .await
            .map_err(|e| crate::routes::AppError::Internal(e.to_string()))?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "position": translated.position,
            "duration": translated.duration,
            "description": translated.description
        })),
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/api/admin/portfolio/about",
    tag = "Portfolio",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "About section content", body = PortfolioResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "About section not found", body = ErrorResponse),
    )
)]
pub async fn get_about_admin(
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    if let Some(pool) = db::get_pool() {
        if let Ok(Some(section)) = sqlx::query_as::<_, PortfolioSection>(
            "SELECT key, content, updated_at FROM portfolio_sections WHERE key = 'about'",
        )
        .fetch_optional(pool.as_ref())
        .await
        {
            return Ok((
                StatusCode::OK,
                Json(PortfolioResponse {
                    data: Some(section.content),
                    error: None,
                }),
            )
                .into_response());
        }
    }

    if let Some(static_data) = get_static_data("about") {
        return Ok((
            StatusCode::OK,
            Json(PortfolioResponse {
                data: Some(static_data),
                error: None,
            }),
        )
            .into_response());
    }

    Ok((
        StatusCode::NOT_FOUND,
        Json(PortfolioResponse {
            data: None,
            error: Some("About section data not found".to_string()),
        }),
    )
        .into_response())
}

#[utoipa::path(
    post,
    path = "/api/admin/portfolio/about",
    tag = "Portfolio",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "About section updated", body = PortfolioResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    )
)]
pub async fn update_about_admin(
    headers: HeaderMap,
    Json(payload): Json<UpdateAboutRequest>,
) -> Result<impl IntoResponse, crate::routes::AppError> {
    require_admin(&headers)?;

    let pool = db::get_pool().ok_or(crate::routes::AppError::DbUnavailable)?;

    let title_jsonb =
        serde_json::to_value(&payload.title).unwrap_or_else(|_| serde_json::json!({}));
    let bio_jsonb = serde_json::to_value(&payload.bio).unwrap_or_else(|_| serde_json::json!({}));
    let location_jsonb =
        serde_json::to_value(&payload.location).unwrap_or_else(|_| serde_json::json!({}));

    let content = serde_json::json!({
        "name": payload.name,
        "title": title_jsonb,
        "bio": bio_jsonb,
        "location": location_jsonb,
        "contact": {
            "email": payload.contact.email,
            "github": payload.contact.github,
            "linkedin": payload.contact.linkedin,
            "twitter": payload.contact.twitter.unwrap_or_default(),
        }
    });

    // Snapshot current content before updating
    if let Ok(Some(existing)) = sqlx::query_as::<_, PortfolioSection>(
        "SELECT key, content, updated_at FROM portfolio_sections WHERE key = 'about'",
    )
    .fetch_optional(pool.as_ref())
    .await
    {
        let _ = sqlx::query(
            "INSERT INTO portfolio_versions (section_key, content, created_at) VALUES ('about', $1, now())",
        )
        .bind(&existing.content)
        .execute(pool.as_ref())
        .await;
    }

    sqlx::query(
        r#"
        INSERT INTO portfolio_sections (key, content, updated_at)
        VALUES ('about', $1, now())
        ON CONFLICT (key) DO UPDATE SET
            content = EXCLUDED.content,
            updated_at = now()
        "#,
    )
    .bind(&content)
    .execute(pool.as_ref())
    .await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": "About section updated and translated successfully",
            "data": content
        })),
    ))
}

pub async fn seed_about_data(pool: &sqlx::PgPool) {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM portfolio_sections WHERE key = 'about'")
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    if count > 0 {
        return;
    }

    tracing::info!("Seeding portfolio_sections key 'about' with initial data...");

    let initial_about = serde_json::json!({
        "name": "Dimas Saputra",
        "title": { "en_US": "Full Stack Developer", "id_ID": "Pengembang Full Stack" },
        "bio": {
            "en_US": "A software developer with nearly three years of professional experience, specializing in cross-platform mobile development with Flutter. Currently building and maintaining a B2B travel agent platform at PT Voltras International.",
            "id_ID": "Pengembang perangkat lunak dengan pengalaman profesional hampir tiga tahun, mengespesialisasi pada pengembangan aplikasi mobile lintas platform dengan Flutter."
        },
        "location": { "en_US": "Indonesia", "id_ID": "Indonesia" },
        "contact": {
            "email": "dragdimas9@gmail.com",
            "github": "https://github.com/infinitedim",
            "linkedin": "https://linkedin.com/in/infinitedim",
            "twitter": ""
        }
    });

    let _ = sqlx::query(
        "INSERT INTO portfolio_sections (key, content, updated_at) VALUES ('about', $1, now()) ON CONFLICT DO NOTHING",
    )
    .bind(&initial_about)
    .execute(pool)
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    #[allow(unused_imports)]
    use axum::routing::{get, patch, post};
    use axum::Router;
    use tower::ServiceExt;

    fn portfolio_router() -> Router {
        Router::new()
            .route("/api/portfolio", get(get_portfolio).patch(update_portfolio))
            .route("/api/portfolio/experience", get(get_experience_i18n))
            .route(
                "/api/admin/portfolio/about",
                get(get_about_admin).post(update_about_admin),
            )
            .route(
                "/api/admin/portfolio/versions",
                get(list_portfolio_versions),
            )
            .route(
                "/api/admin/portfolio/versions/{id}/restore",
                post(restore_portfolio_version),
            )
            .route(
                "/api/admin/portfolio/experience",
                get(list_experiences_admin).post(create_experience),
            )
            .route(
                "/api/admin/portfolio/experience/{id}",
                patch(update_experience).delete(delete_experience),
            )
            .route(
                "/api/admin/portfolio/experience/{id}/locale/{locale}",
                patch(override_experience_locale),
            )
            .layer(crate::test_support::mock_connect_info())
    }

    #[tokio::test]
    async fn get_about_admin_requires_auth() {
        let req = Request::get("/api/admin/portfolio/about")
            .body(Body::empty())
            .unwrap();
        let res = portfolio_router().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    async fn get_json<T: serde::de::DeserializeOwned>(app: Router, uri: &str) -> (StatusCode, T) {
        let req = Request::get(uri).body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: T = serde_json::from_slice(&bytes).unwrap();
        (status, value)
    }

    async fn patch_json(app: Router, uri: &str, json: &impl serde::Serialize) -> StatusCode {
        let body = Body::from(serde_json::to_vec(json).unwrap());
        let req = Request::patch(uri)
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        res.status()
    }

    #[test]
    fn test_is_valid_section() {
        assert!(is_valid_section("skills"));
        assert!(is_valid_section("Skills"));
        assert!(is_valid_section("projects"));
        assert!(is_valid_section("experience"));
        assert!(is_valid_section("about"));
        assert!(!is_valid_section("invalid"));
        assert!(!is_valid_section(""));
    }

    #[test]
    fn test_get_static_data() {
        std::env::remove_var("ENVIRONMENT");
        assert!(get_static_data("skills").is_some());
        assert!(get_static_data("projects").is_some());
        assert!(get_static_data("experience").is_some());
        assert!(get_static_data("about").is_some());
        assert!(get_static_data("invalid").is_none());

        std::env::set_var("ENVIRONMENT", "production");
        assert!(get_static_data("projects").is_none());
        assert!(get_static_data("skills").is_none());
        std::env::remove_var("ENVIRONMENT");
    }

    #[tokio::test]
    async fn test_get_portfolio_missing_section_returns_bad_request() {
        let (status, _) = get_json::<PortfolioResponse>(portfolio_router(), "/api/portfolio").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_portfolio_invalid_section_returns_bad_request() {
        let (status, _) =
            get_json::<PortfolioResponse>(portfolio_router(), "/api/portfolio?section=invalid")
                .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_portfolio_skills_returns_ok_with_data() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let (status, body) =
            get_json::<PortfolioResponse>(portfolio_router(), "/api/portfolio?section=skills")
                .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.data.is_some());
        assert!(body.error.is_none());
    }

    #[tokio::test]
    async fn test_update_portfolio_no_auth_returns_unauthorized() {
        let status = patch_json(
            portfolio_router(),
            "/api/portfolio",
            &UpdatePortfolioRequest {
                section: "skills".to_string(),
                data: serde_json::json!({"test": true}),
            },
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn db_portfolio_update_creates_version_and_restore() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = portfolio_router();
        let bearer = crate::test_support::admin_bearer();
        let v1 = serde_json::json!([{"name": "Rust", "level": 80}]);
        let v2 = serde_json::json!([{"name": "Rust", "level": 90}]);

        let patch_body = |data: serde_json::Value| {
            Body::from(
                serde_json::to_vec(&UpdatePortfolioRequest {
                    section: "skills".to_string(),
                    data,
                })
                .unwrap(),
            )
        };

        let req = Request::patch("/api/portfolio")
            .header("content-type", "application/json")
            .header(axum::http::header::AUTHORIZATION, bearer.clone())
            .body(patch_body(v1.clone()))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let req = Request::patch("/api/portfolio")
            .header("content-type", "application/json")
            .header(axum::http::header::AUTHORIZATION, bearer.clone())
            .body(patch_body(v2.clone()))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let req = Request::get("/api/admin/portfolio/versions?section=skills")
            .header(axum::http::header::AUTHORIZATION, bearer.clone())
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let versions: Vec<PortfolioVersionSummary> = serde_json::from_slice(&bytes).unwrap();
        assert!(!versions.is_empty());

        let version_id = versions[0].id;
        let req = Request::post(format!(
            "/api/admin/portfolio/versions/{version_id}/restore"
        ))
        .header(axum::http::header::AUTHORIZATION, bearer)
        .body(Body::empty())
        .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let (_, body) = get_json::<PortfolioResponse>(app, "/api/portfolio?section=skills").await;
        assert_eq!(body.data, Some(v1));
    }

    #[test]
    fn test_resolve_projects_locale() {
        std::env::remove_var("ENVIRONMENT");
        let projects_data = get_static_data("projects").unwrap();

        let id_res = resolve_projects_locale(&projects_data, "id_ID");
        let id_desc = id_res[0]["description"].as_str().unwrap();
        assert!(id_desc.contains("Portfolio interaktif bergaya terminal"));

        let ja_res = resolve_projects_locale(&projects_data, "ja_JP");
        let ja_desc = ja_res[0]["description"].as_str().unwrap();
        assert!(ja_desc.contains("ターミナル風ポートフォリオ"));

        let de_res = resolve_projects_locale(&projects_data, "de_DE");
        let de_desc = de_res[0]["description"].as_str().unwrap();
        assert!(de_desc.contains("Interaktives Portfolio im Terminal-Stil"));

        let fallback_res = resolve_projects_locale(&projects_data, "unknown_LOCALE");
        let fallback_desc = fallback_res[0]["description"].as_str().unwrap();
        assert!(fallback_desc.contains("Interactive terminal-style portfolio"));
    }

    #[tokio::test]
    async fn db_portfolio_experience_and_about_crud() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        seed_experience_data(db.pool.as_ref()).await;
        seed_about_data(db.pool.as_ref()).await;

        let bearer = crate::test_support::admin_bearer();
        let app = Router::new()
            .route(
                "/api/portfolio/experience",
                axum::routing::get(get_experience_i18n),
            )
            .route(
                "/api/admin/portfolio/experience",
                axum::routing::get(list_experiences_admin).post(create_experience),
            )
            .route(
                "/api/admin/portfolio/experience/{id}",
                axum::routing::patch(update_experience).delete(delete_experience),
            )
            .route(
                "/api/admin/portfolio/experience/{id}/locale/{locale}",
                axum::routing::patch(override_experience_locale),
            )
            .route(
                "/api/admin/portfolio/about",
                axum::routing::get(get_about_admin).patch(update_about_admin),
            )
            .layer(crate::test_support::mock_connect_info());

        // 1. Get Experience i18n
        let req_exp = Request::get("/api/portfolio/experience?locale=en_US")
            .body(Body::empty())
            .unwrap();
        let res_exp = app.clone().oneshot(req_exp).await.unwrap();
        assert_eq!(res_exp.status(), StatusCode::OK);

        // 2. Get Admin Experiences List
        let req_admin_exp = Request::get("/api/admin/portfolio/experience")
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        let res_admin_exp = app.clone().oneshot(req_admin_exp).await.unwrap();
        assert_eq!(res_admin_exp.status(), StatusCode::OK);

        // 3. Create Experience
        let mut pos_map = std::collections::HashMap::new();
        pos_map.insert("en_US".to_string(), "Backend Engineer".to_string());
        let mut dur_map = std::collections::HashMap::new();
        dur_map.insert("en_US".to_string(), "2024 - Present".to_string());
        let mut desc_map = std::collections::HashMap::new();
        desc_map.insert("en_US".to_string(), vec!["Built Rust services".to_string()]);

        let create_req = CreateExperienceRequest {
            company: "Acme Corp".to_string(),
            position: pos_map,
            duration: dur_map,
            description: desc_map,
            technologies: vec!["Rust".to_string(), "Axum".to_string()],
            experience_type: "full-time".to_string(),
            display_order: 1,
        };

        let req_create = Request::post("/api/admin/portfolio/experience")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
            .unwrap();
        let res_create = app.clone().oneshot(req_create).await.unwrap();
        assert_eq!(res_create.status(), StatusCode::CREATED);
        let created_body: Value = serde_json::from_slice(
            &axum::body::to_bytes(res_create.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let created_id = created_body["data"]["id"].as_str().unwrap();

        // 4. Override Experience Locale
        let req_override = Request::patch(format!(
            "/api/admin/portfolio/experience/{created_id}/locale/id_ID"
        ))
        .header("authorization", &bearer)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "position": "Insinyur Backend",
                "duration": "2024 - Sekarang",
                "description": ["Membangun layanan Rust"]
            })
            .to_string(),
        ))
        .unwrap();
        let res_override = app.clone().oneshot(req_override).await.unwrap();
        assert_eq!(res_override.status(), StatusCode::OK);

        // 5. Update Experience
        let req_update = Request::patch(format!("/api/admin/portfolio/experience/{created_id}"))
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "company": "Acme Corp Inc"
                })
                .to_string(),
            ))
            .unwrap();
        let res_update = app.clone().oneshot(req_update).await.unwrap();
        assert_eq!(res_update.status(), StatusCode::OK);

        // 6. Delete Experience
        let req_delete = Request::delete(format!("/api/admin/portfolio/experience/{created_id}"))
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        let res_delete = app.clone().oneshot(req_delete).await.unwrap();
        assert_eq!(res_delete.status(), StatusCode::OK);

        // 7. About Admin GET & PATCH
        let req_about_get = Request::get("/api/admin/portfolio/about")
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        let res_about_get = app.clone().oneshot(req_about_get).await.unwrap();
        assert_eq!(res_about_get.status(), StatusCode::OK);

        let req_about_patch = Request::patch("/api/admin/portfolio/about")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "name": "Dimas Saputra",
                    "title": { "en_US": "Senior Backend Architect" },
                    "bio": { "en_US": "Passionate developer" },
                    "location": { "en_US": "Jakarta" },
                    "contact": {
                        "email": "test@example.com",
                        "github": "https://github.com/infinitedim",
                        "linkedin": "https://linkedin.com/in/infinitedim"
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let res_about_patch = app.clone().oneshot(req_about_patch).await.unwrap();
        assert_eq!(res_about_patch.status(), StatusCode::OK);
    }

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_default_locale_and_type_helpers() {
        assert_eq!(default_locale(), "en_US");
        assert_eq!(default_type(), "full-time");
    }

    #[test]
    fn test_resolve_locale_string_edge_cases() {
        let json_obj = serde_json::json!({ "id_ID": "Halo", "en_US": "Hello" });
        assert_eq!(resolve_locale_string(&json_obj, "id_ID"), "Halo");
        assert_eq!(resolve_locale_string(&json_obj, "id"), "Halo");

        let json_fallback = serde_json::json!({ "fr_FR": "Bonjour" });
        assert_eq!(resolve_locale_string(&json_fallback, "ja_JP"), "Bonjour");

        let json_str = serde_json::json!("Plain Value");
        assert_eq!(resolve_locale_string(&json_str, "any"), "Plain Value");
    }

    #[test]
    fn test_resolve_locale_array_edge_cases() {
        let json_arr = serde_json::json!(["Item 1", "Item 2"]);
        assert_eq!(
            resolve_locale_array(&json_arr, "any"),
            vec!["Item 1", "Item 2"]
        );

        let json_obj_arr = serde_json::json!({ "de_DE": ["Eins", "Zwei"] });
        assert_eq!(
            resolve_locale_array(&json_obj_arr, "fr_FR"),
            vec!["Eins", "Zwei"]
        );

        let json_invalid = serde_json::json!(12345);
        assert!(resolve_locale_array(&json_invalid, "any").is_empty());
    }

    #[test]
    fn test_resolve_projects_and_about_non_conforming_json() {
        let non_array_projects = serde_json::json!({ "projects": "not-an-array" });
        let res = resolve_projects_locale(&non_array_projects, "en_US");
        assert_eq!(res, non_array_projects);

        let non_object_about = serde_json::json!("just-a-string");
        let res_about = resolve_about_locale(&non_object_about, "en_US");
        assert_eq!(res_about, non_object_about);
    }

    #[tokio::test]
    async fn test_get_portfolio_static_about_and_projects_endpoints() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let app = Router::new().route("/api/portfolio", get(get_portfolio));

        let req_about = Request::get("/api/portfolio?section=about&locale=id_ID")
            .body(Body::empty())
            .unwrap();
        let res_about = app.clone().oneshot(req_about).await.unwrap();
        assert_eq!(res_about.status(), StatusCode::OK);

        let req_projects = Request::get("/api/portfolio?section=projects&locale=id_ID")
            .body(Body::empty())
            .unwrap();
        let res_projects = app.clone().oneshot(req_projects).await.unwrap();
        assert_eq!(res_projects.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_update_portfolio_invalid_section() {
        let app = Router::new().route("/api/portfolio", patch(update_portfolio));
        let bearer = crate::test_support::admin_bearer();

        let req = Request::patch("/api/portfolio")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "section": "invalid_sec", "data": {} }).to_string(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_portfolio_no_db_returns_service_unavailable() {
        let app = Router::new().route("/api/portfolio", patch(update_portfolio));
        let bearer = crate::test_support::admin_bearer();

        let req = Request::patch("/api/portfolio")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "section": "skills", "data": {} }).to_string(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_admin_portfolio_endpoints_require_auth() {
        let app = Router::new()
            .route(
                "/api/admin/portfolio/versions",
                get(list_portfolio_versions),
            )
            .route(
                "/api/admin/portfolio/versions/{id}/restore",
                post(restore_portfolio_version),
            )
            .route(
                "/api/admin/portfolio/experience",
                get(list_experiences_admin).post(create_experience),
            )
            .route(
                "/api/admin/portfolio/experience/{id}",
                patch(update_experience).delete(delete_experience),
            )
            .route(
                "/api/admin/portfolio/experience/{id}/locale/{loc}",
                patch(override_experience_locale),
            )
            .route("/api/admin/portfolio/about", post(update_about_admin))
            .route(
                "/api/admin/portfolio/about/translate",
                post(translate_about_admin),
            )
            .route(
                "/api/admin/portfolio/experience/translate",
                post(translate_experience_admin),
            );

        let valid_create_exp = serde_json::json!({
            "company": "Test",
            "position": { "en_US": "Dev" },
            "duration": { "en_US": "2024" },
            "description": { "en_US": ["desc"] },
            "technologies": ["Rust"]
        })
        .to_string();

        let valid_override_exp = serde_json::json!({
            "position": "Dev",
            "duration": "2024",
            "description": ["desc"]
        })
        .to_string();

        let valid_about = serde_json::json!({
            "name": "Dev",
            "title": { "en_US": "Title" },
            "bio": { "en_US": "Bio" },
            "location": { "en_US": "Loc" },
            "contact": { "email": "a@b.com", "github": "gh", "linkedin": "li" }
        })
        .to_string();

        let valid_about_trans = serde_json::json!({
            "sourceLocale": "en",
            "title": "Title",
            "bio": "Bio",
            "location": "Loc"
        })
        .to_string();

        let valid_exp_trans = serde_json::json!({
            "sourceLocale": "en",
            "position": "Pos",
            "duration": "Dur",
            "description": ["Desc"]
        })
        .to_string();

        let reqs = vec![
            Request::get("/api/admin/portfolio/versions?section=skills")
                .body(Body::empty())
                .unwrap(),
            Request::post(format!(
                "/api/admin/portfolio/versions/{}/restore",
                Uuid::new_v4()
            ))
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap(),
            Request::get("/api/admin/portfolio/experience")
                .body(Body::empty())
                .unwrap(),
            Request::post("/api/admin/portfolio/experience")
                .header("content-type", "application/json")
                .body(Body::from(valid_create_exp))
                .unwrap(),
            Request::patch(format!(
                "/api/admin/portfolio/experience/{}",
                Uuid::new_v4()
            ))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({"company": "X"}).to_string()))
            .unwrap(),
            Request::delete(format!(
                "/api/admin/portfolio/experience/{}",
                Uuid::new_v4()
            ))
            .body(Body::empty())
            .unwrap(),
            Request::patch(format!(
                "/api/admin/portfolio/experience/{}/locale/fr_FR",
                Uuid::new_v4()
            ))
            .header("content-type", "application/json")
            .body(Body::from(valid_override_exp))
            .unwrap(),
            Request::post("/api/admin/portfolio/about")
                .header("content-type", "application/json")
                .body(Body::from(valid_about))
                .unwrap(),
            Request::post("/api/admin/portfolio/about/translate")
                .header("content-type", "application/json")
                .body(Body::from(valid_about_trans))
                .unwrap(),
            Request::post("/api/admin/portfolio/experience/translate")
                .header("content-type", "application/json")
                .body(Body::from(valid_exp_trans))
                .unwrap(),
        ];

        for req in reqs {
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_list_portfolio_versions_invalid_section() {
        let app = Router::new().route(
            "/api/admin/portfolio/versions",
            get(list_portfolio_versions),
        );
        let bearer = crate::test_support::admin_bearer();

        let req = Request::get("/api/admin/portfolio/versions?section=invalid_sec")
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_translate_about_and_experience_missing_api_key() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let orig_key = std::env::var("GEMINI_API_KEY").ok();
        std::env::remove_var("GEMINI_API_KEY");

        let app = Router::new()
            .route(
                "/api/admin/portfolio/about/translate",
                post(translate_about_admin),
            )
            .route(
                "/api/admin/portfolio/experience/translate",
                post(translate_experience_admin),
            );
        let bearer = crate::test_support::admin_bearer();

        let valid_about_trans = serde_json::json!({
            "sourceLocale": "en",
            "title": "Title",
            "bio": "Bio",
            "location": "Loc"
        })
        .to_string();

        let valid_exp_trans = serde_json::json!({
            "sourceLocale": "en",
            "position": "Pos",
            "duration": "Dur",
            "description": ["Desc"]
        })
        .to_string();

        let req1 = Request::post("/api/admin/portfolio/about/translate")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(valid_about_trans))
            .unwrap();
        let res1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(res1.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let req2 = Request::post("/api/admin/portfolio/experience/translate")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(valid_exp_trans))
            .unwrap();
        let res2 = app.oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::INTERNAL_SERVER_ERROR);

        if let Some(key) = orig_key {
            std::env::set_var("GEMINI_API_KEY", key);
        }
    }

    #[tokio::test]
    async fn test_list_experiences_admin_db_unavailable_fallback() {
        let app = Router::new().route(
            "/api/admin/portfolio/experience",
            get(list_experiences_admin),
        );
        let bearer = crate::test_support::admin_bearer();

        let req = Request::get("/api/admin/portfolio/experience")
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_about_admin_db_unavailable_fallback() {
        let app = Router::new().route("/api/admin/portfolio/about", get(get_about_admin));
        let bearer = crate::test_support::admin_bearer();

        let req = Request::get("/api/admin/portfolio/about")
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn db_portfolio_non_existent_uuid_404s() {
        let _guard = crate::test_support::acquire_test_pool().await;
        let app = portfolio_router();
        let bearer = crate::test_support::admin_bearer();
        let random_id = Uuid::new_v4();

        // 1. Restore version 404
        let req_restore =
            Request::post(format!("/api/admin/portfolio/versions/{random_id}/restore"))
                .header("authorization", &bearer)
                .body(Body::empty())
                .unwrap();
        assert_eq!(
            app.clone().oneshot(req_restore).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );

        // 2. Update experience 404
        let req_update = Request::patch(format!("/api/admin/portfolio/experience/{random_id}"))
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({"company": "X"}).to_string()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req_update).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );

        // 3. Delete experience 404
        let req_delete = Request::delete(format!("/api/admin/portfolio/experience/{random_id}"))
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req_delete).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );

        // 4. Override locale 404
        let req_override = Request::patch(format!(
            "/api/admin/portfolio/experience/{random_id}/locale/fr_FR"
        ))
        .header("authorization", &bearer)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"position": "X"}).to_string()))
        .unwrap();
        assert_eq!(
            app.oneshot(req_override).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn db_get_portfolio_about_and_projects_locale_resolution() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };

        // Insert multi-locale section in DB
        let about_content = serde_json::json!({
            "bio": {
                "en": "English Bio",
                "id": "Bio Indonesia"
            }
        });
        sqlx::query(
            "INSERT INTO portfolio_sections (key, content, updated_at) VALUES ('about', $1, NOW()) ON CONFLICT (key) DO UPDATE SET content = $1",
        )
        .bind(about_content)
        .execute(db.pool.as_ref())
        .await
        .unwrap();

        let app = portfolio_router();
        let req = Request::get("/api/portfolio?section=about&locale=id_ID")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_list_portfolio_versions_and_restore_no_db_returns_503() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let bearer = crate::test_support::admin_bearer();
        let app = portfolio_router();

        let req_list = Request::get("/api/admin/portfolio/versions?section=skills")
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req_list).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let req_restore = Request::post(format!(
            "/api/admin/portfolio/versions/{}/restore",
            Uuid::new_v4()
        ))
        .header("authorization", &bearer)
        .body(Body::empty())
        .unwrap();
        assert_eq!(
            app.oneshot(req_restore).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn test_get_experience_i18n_moka_cache_hit_and_db_unavailable() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        EXPERIENCE_CACHE
            .insert("experience:en_US".to_string(), serde_json::json!([]))
            .await;

        let app = portfolio_router();
        let req = Request::get("/api/portfolio/experience?locale=en_US")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("public"));
    }

    #[tokio::test]
    async fn db_get_experience_i18n_empty_table_returns_static() {
        let Some(db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        sqlx::query("TRUNCATE portfolio_experiences")
            .execute(db.pool.as_ref())
            .await
            .unwrap();

        let app = portfolio_router();
        let req = Request::get("/api/portfolio/experience?locale=id_ID")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[test]
    fn test_resolve_locale_string_all_fallback_branches() {
        // 1. Short code key "id"
        let json1 = serde_json::json!({ "id": "Singkat" });
        assert_eq!(resolve_locale_string(&json1, "id_ID"), "Singkat");

        // 2. Prefix match "en_GB" for "en"
        let json2 = serde_json::json!({ "en_GB": "Colour" });
        assert_eq!(resolve_locale_string(&json2, "en"), "Colour");

        // 3. "en" fallback key for ja_JP
        let json3 = serde_json::json!({ "en": "English Fallback" });
        assert_eq!(resolve_locale_string(&json3, "ja_JP"), "English Fallback");

        // 4. Non-string step 4 skip
        let json4 = serde_json::json!({ "de": 12345, "en": "Valid String" });
        assert_eq!(resolve_locale_string(&json4, "de"), "Valid String");
    }

    #[test]
    fn test_resolve_projects_locale_primitive_elements() {
        let primitives = serde_json::json!([
            123,
            "plain string",
            true,
            { "title": { "en": "Obj Title" } }
        ]);
        let resolved = resolve_projects_locale(&primitives, "en_US");
        assert_eq!(resolved.as_array().unwrap().len(), 4);
    }

    #[test]
    fn test_resolve_locale_array_en_us_fallback_and_type_filtering() {
        let json = serde_json::json!({
            "en_US": ["bullet 1", 42, true]
        });
        let result = resolve_locale_array(&json, "ja_JP");
        assert_eq!(result, vec!["bullet 1"]);
    }

    #[tokio::test]
    async fn test_admin_experience_endpoints_db_unavailable_returns_503() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let bearer = crate::test_support::admin_bearer();
        let app = portfolio_router();
        let id = Uuid::new_v4();

        let valid_payload = serde_json::json!({
            "company": "C",
            "position": { "en_US": "P" },
            "duration": { "en_US": "D" },
            "description": { "en_US": ["Desc"] },
            "technologies": ["Rust"]
        });

        // 1. Create
        let req1 = Request::post("/api/admin/portfolio/experience")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(valid_payload.to_string()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req1).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        // 2. Update
        let req2 = Request::patch(format!("/api/admin/portfolio/experience/{id}"))
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({"company": "U"}).to_string()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req2).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        // 3. Delete
        let req3 = Request::delete(format!("/api/admin/portfolio/experience/{id}"))
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req3).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        // 4. Override locale
        let req4 = Request::patch(format!("/api/admin/portfolio/experience/{id}/locale/id_ID"))
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({"position": "P"}).to_string()))
            .unwrap();
        assert_eq!(
            app.oneshot(req4).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn db_update_experience_all_fields_some() {
        let Some(_db) = crate::test_support::acquire_test_pool().await else {
            return;
        };
        let app = portfolio_router();
        let bearer = crate::test_support::admin_bearer();

        let create_payload = serde_json::json!({
            "company": "Initial Corp",
            "position": { "en_US": "Dev" },
            "duration": { "en_US": "2024" },
            "description": { "en_US": ["Initial desc"] },
            "technologies": ["Rust"]
        });

        // 1. Create initial experience
        let req_create = Request::post("/api/admin/portfolio/experience")
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(create_payload.to_string()))
            .unwrap();
        let res_create = app.clone().oneshot(req_create).await.unwrap();
        assert_eq!(res_create.status(), StatusCode::CREATED);
        let body_bytes = axum::body::to_bytes(res_create.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let exp_id = created["data"]["id"].as_str().unwrap();

        // 2. Patch all fields with Some(...)
        let req_patch = Request::patch(format!("/api/admin/portfolio/experience/{exp_id}"))
            .header("authorization", &bearer)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "company": "Acme Corp Inc",
                    "position": { "en_US": "Senior Dev" },
                    "duration": { "en_US": "2024-Present" },
                    "description": { "en_US": ["Updated desc"] },
                    "technologies": ["Rust", "Axum"],
                    "type": "full-time",
                    "displayOrder": 5
                })
                .to_string(),
            ))
            .unwrap();
        let res_patch = app.clone().oneshot(req_patch).await.unwrap();
        assert_eq!(res_patch.status(), StatusCode::OK);

        // 3. Override experience locale
        let req_override = Request::patch(format!(
            "/api/admin/portfolio/experience/{exp_id}/locale/id_ID"
        ))
        .header("authorization", &bearer)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "position": "Pengembang Senior",
                "duration": "2024-Sekarang",
                "description": ["Deskripsi diperbarui"]
            })
            .to_string(),
        ))
        .unwrap();
        let res_override = app.clone().oneshot(req_override).await.unwrap();
        assert_eq!(res_override.status(), StatusCode::OK);

        // 4. GET experience with locale=id_ID to hit cache & verify locale resolution
        let req_get = Request::get("/api/portfolio/experience?locale=id_ID")
            .body(Body::empty())
            .unwrap();
        let res_get1 = app.clone().oneshot(req_get).await.unwrap();
        assert_eq!(res_get1.status(), StatusCode::OK);

        // Second GET hits cache
        let req_get2 = Request::get("/api/portfolio/experience?locale=id_ID")
            .body(Body::empty())
            .unwrap();
        let res_get2 = app.clone().oneshot(req_get2).await.unwrap();
        assert_eq!(res_get2.status(), StatusCode::OK);

        // 5. Delete experience
        let req_del = Request::delete(format!("/api/admin/portfolio/experience/{exp_id}"))
            .header("authorization", &bearer)
            .body(Body::empty())
            .unwrap();
        let res_del = app.oneshot(req_del).await.unwrap();
        assert_eq!(res_del.status(), StatusCode::OK);
    }
}

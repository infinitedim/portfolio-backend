//! OpenAPI / Swagger UI definitions for the portfolio API.
//!
//! The actual handler-level documentation lives next to each handler via
//! `#[utoipa::path(...)]` attributes — this module is just the entry point
//! that aggregates them into a single `OpenApi` derive and wires up the
//! `bearer_auth` security scheme used by admin endpoints.
//!
//! Mounted at `/api/docs/{*tail}` (Swagger UI) and `/api/docs/openapi.json`
//! (raw spec). Production deployments can disable both with the
//! `ENABLE_SWAGGER_UI=false` environment variable — see `lib.rs`.

use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};

use crate::routes;

/// Adds the JWT bearer security scheme to the generated spec so the
/// "Authorize" button in Swagger UI accepts an access token.
pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .as_mut()
            .expect("OpenApi components should be initialized");
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some(
                        "Access token obtained from `/api/auth/login` (or `/api/auth/2fa/login` \
                         when 2FA is enabled). Pass it as `Authorization: Bearer <token>`.",
                    ))
                    .build(),
            ),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Portfolio API",
        version = "1.0.0",
        description = "REST API powering the personal portfolio. Built with Rust + Axum.\n\n\
                       Most read endpoints are public; admin endpoints require a JWT bearer \
                       token issued by `/api/auth/login`.",
        contact(
            name = "Dimas Saputra",
            url = "https://infinitedim.dev"
        ),
        license(name = "MIT")
    ),
    servers(
        (url = "http://localhost:8080", description = "Local development"),
        (url = "https://api.infinitedim.dev", description = "Production")
    ),
    tags(
        (name = "Authentication", description = "Admin login, registration, and token lifecycle"),
        (name = "Two-Factor Auth", description = "TOTP enrollment + 2FA login challenge"),
        (name = "Blog", description = "Blog posts CRUD + tag listing"),
        (name = "Blog Series", description = "Blog series / collections"),
        (name = "Portfolio", description = "Portfolio sections (skills, projects, about, experience)"),
        (name = "Contact", description = "Public contact-form submission and admin inbox"),
        (name = "Health", description = "Liveness / readiness probes"),
        (name = "RSS", description = "RSS feed for blog posts"),
        (name = "Gate", description = "Terminal gate puzzle verification"),
        (name = "Upload", description = "Blog image upload (admin)"),
        (name = "Logs", description = "Client log ingestion"),
        (name = "Roadmap", description = "Roadmap.sh proxy"),
        (name = "Analytics", description = "Lightweight page view beacons"),
        (name = "GitHub", description = "GitHub API proxy"),
        (name = "Metrics", description = "Prometheus scrape endpoint"),
    ),
    modifiers(&SecurityAddon),
    paths(
        // Auth
        routes::auth::register,
        routes::auth::login,
        routes::auth::verify_token,
        routes::auth::refresh,
        routes::auth::logout,
        // 2FA
        routes::twofa::status,
        routes::twofa::setup,
        routes::twofa::verify_setup,
        routes::twofa::disable,
        routes::twofa::login_challenge,
        // Blog
        routes::blog::list_posts,
        routes::blog::get_post,
        routes::blog::create_post,
        routes::blog::update_post,
        routes::blog::delete_post,
        routes::blog::list_tags,
        routes::blog::link_translations,
        routes::blog::get_translation_group,
        // Blog series
        routes::series::list_series_public,
        routes::series::get_series_public,
        routes::series::list_series_admin,
        routes::series::create_series,
        routes::series::get_series_admin,
        routes::series::update_series,
        routes::series::delete_series,
        // Portfolio
        routes::portfolio::get_portfolio,
        routes::portfolio::update_portfolio,
        routes::portfolio::list_portfolio_versions,
        routes::portfolio::restore_portfolio_version,
        // Contact
        routes::contact::submit_contact_message,
        routes::contact::list_messages,
        routes::contact::get_message,
        routes::contact::update_message,
        routes::contact::delete_message,
        routes::contact::bulk_mark_messages_read,
        routes::contact::bulk_delete_messages,
        // Upload
        routes::upload::upload_image,
        routes::upload::delete_image,
        routes::upload::list_images,
        // Health
        routes::health::health_ping,
        routes::health::health_detailed,
        routes::health::health_database,
        routes::health::health_redis,
        routes::health::health_ready,
        // RSS
        routes::rss::rss_feed,
        // Gate
        routes::gate::status,
        routes::gate::login,
        routes::gate::complete_level_3,
        routes::gate::unlock,
        routes::gate::challenge_2_users_txt,
        // Logs
        routes::logs::receive_client_logs,
        // Roadmap
        routes::roadmap::get_streak,
        routes::roadmap::get_dashboard,
        routes::roadmap::get_teams,
        routes::roadmap::get_favourites,
        routes::roadmap::get_resource_progress,
        routes::roadmap::get_roadmap_detail,
        // Analytics
        crate::metrics::record_pageview,
        // GitHub
        routes::github::get_user,
        routes::github::get_stats,
    ),
    components(schemas(
        crate::metrics::PageviewRequest,
        crate::metrics::PageviewResponse,
        routes::github::GitHubUserResponse,
        routes::github::GitHubStatsResponse,
        routes::github::GitHubRepoSummary,
        routes::github::GitHubProfileStats,
        routes::upload::UploadResponse,
        routes::upload::ImageInfo,
        routes::upload::ImageListResponse,
        routes::contact::BulkMessageIdsRequest,
        routes::contact::BulkMessageActionResponse,
        routes::gate::LoginRequest,
        routes::gate::LoginResponse,
        routes::gate::CompleteLevel3Response,
        routes::gate::GateStatusResponse,
        crate::logging::config::ClientLogBatch,
        crate::logging::config::LogResponse,
    ))
)]
pub struct ApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::OpenApi;

    #[test]
    fn generated_spec_contains_expected_metadata() {
        let spec = ApiDoc::openapi();
        let info = &spec.info;
        assert_eq!(info.title, "Portfolio API");
        assert_eq!(info.version, "1.0.0");
        assert!(info
            .description
            .as_deref()
            .unwrap_or_default()
            .contains("Rust"));
    }

    #[test]
    fn generated_spec_includes_bearer_auth_security_scheme() {
        let spec = ApiDoc::openapi();
        let security = spec
            .components
            .as_ref()
            .and_then(|c| c.security_schemes.get("bearer_auth"));
        assert!(security.is_some(), "bearer_auth should be present");
    }

    #[test]
    fn generated_spec_includes_critical_paths() {
        let spec = ApiDoc::openapi();
        assert!(spec.paths.paths.contains_key("/api/auth/login"));
        assert!(spec.paths.paths.contains_key("/api/blog"));
        assert!(spec.paths.paths.contains_key("/api/contact"));
        assert!(spec.paths.paths.contains_key("/health/ready"));
        assert!(spec.paths.paths.contains_key("/api/analytics/pageview"));
        assert!(spec.paths.paths.contains_key("/api/github/user/{username}"));
        assert!(spec.paths.paths.contains_key("/api/blog/series"));
        assert!(spec
            .paths
            .paths
            .contains_key("/api/admin/portfolio/versions"));
    }
}

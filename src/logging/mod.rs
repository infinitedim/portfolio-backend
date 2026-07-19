pub mod config;
pub mod middleware;

use std::io;
use std::path::{Path, PathBuf};

use tracing_appender::non_blocking;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Resolve the directory used for rotating log files, if any.
///
/// File-based logging is opt-in via the `LOG_DIR` environment variable.
///
///   * `LOG_DIR=/var/log/app` — write rotating files to that path.
///   * `LOG_DIR=` (empty)     — explicitly disable file logging.
///   * `LOG_DIR` unset:
///       - In `ENVIRONMENT=production` we default to **stdout-only** (the
///         expected 12-factor configuration for ephemeral container
///         platforms like Fly.io, ECS, Kubernetes — they all
///         aggregate logs from stdout/stderr; writing to disk on a
///         distroless / read-only / ephemeral filesystem just panics
///         the process at startup).
///       - In any other environment we default to `./logs` to preserve
///         the local-dev experience.
fn log_dir_from_env(is_production: bool) -> Option<PathBuf> {
    match std::env::var("LOG_DIR") {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        }
        Err(_) => {
            if is_production {
                None
            } else {
                Some(PathBuf::from("logs"))
            }
        }
    }
}

/// Returns `Some(dir)` if the directory exists (or was created) and is
/// writable. Returns `None` after emitting a warning to stderr otherwise —
/// callers should fall back to stdout-only logging.
fn prepare_log_dir(dir: &Path) -> Option<PathBuf> {
    if let Err(err) = std::fs::create_dir_all(dir) {
        eprintln!(
            "[logging] LOG_DIR={} is not usable ({}); falling back to stdout-only logging.",
            dir.display(),
            err
        );
        return None;
    }

    // `create_dir_all` succeeds on read-only mounts when the directory
    // already exists, so probe writeability with a touch file. This catches
    // the case where the deploy target has the directory but no write
    // permission for the runtime user (e.g. distroless/container image as
    // UID 1001 on a read-only filesystem).
    let probe = dir.join(".portfolio-backend-write-probe");
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Some(dir.to_path_buf())
        }
        Err(err) => {
            eprintln!(
                "[logging] LOG_DIR={} is not writable ({}); falling back to stdout-only logging.",
                dir.display(),
                err
            );
            None
        }
    }
}

fn build_rolling_appender(dir: &Path, prefix: &str) -> Option<RollingFileAppender> {
    match RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(prefix)
        .build(dir)
    {
        Ok(appender) => Some(appender),
        Err(err) => {
            eprintln!(
                "[logging] failed to initialise rolling appender for {}/{}: {}; \
                 falling back to stdout-only logging.",
                dir.display(),
                prefix,
                err
            );
            None
        }
    }
}

pub fn init() -> Vec<WorkerGuard> {
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    let is_production = environment == "production";

    let log_dir = log_dir_from_env(is_production).and_then(|d| prepare_log_dir(&d));

    let mut guards: Vec<WorkerGuard> = Vec::with_capacity(3);

    let (file_writer, error_writer) = match log_dir.as_deref() {
        Some(dir) => {
            let app = build_rolling_appender(dir, "app.log");
            let err = build_rolling_appender(dir, "error.log");
            match (app, err) {
                (Some(app), Some(err)) => {
                    let (fw, fg) = non_blocking(app);
                    let (ew, eg) = non_blocking(err);
                    guards.push(fg);
                    guards.push(eg);
                    (Some(fw), Some(ew))
                }
                _ => (None, None),
            }
        }
        None => (None, None),
    };

    let (console_writer, console_guard) = non_blocking(io::stdout());
    guards.push(console_guard);

    let log_level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| {
        if is_production {
            "info".to_string()
        } else {
            "debug".to_string()
        }
    });

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "portfolio_backend={},tower_http=debug,axum=debug",
            log_level
        ))
    });

    let (loki_layer, loki_task) = if let Ok(loki_url_str) = std::env::var("LOKI_URL") {
        let trimmed = loki_url_str.trim();
        if trimmed.is_empty() {
            (None, None)
        } else if let Ok(url) = url::Url::parse(trimmed) {
            match tracing_loki::builder()
                .label("application", "portfolio-backend")
                .and_then(|b| b.label("environment", environment.as_str()))
                .and_then(|b| b.build_url(url))
            {
                Ok((layer, task)) => (Some(layer), Some(task)),
                Err(e) => {
                    eprintln!("[logging] failed to initialize Loki layer: {}", e);
                    (None, None)
                }
            }
        } else {
            eprintln!("[logging] invalid LOKI_URL format: {}", trimmed);
            (None, None)
        }
    } else {
        (None, None)
    };

    if let Some(task) = loki_task {
        tokio::spawn(task);
    }

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(loki_layer);

    if is_production {
        let file_layer = file_writer.map(|w| {
            fmt::layer()
                .json()
                .with_writer(w)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true)
        });

        let error_layer = error_writer.map(|w| {
            fmt::layer()
                .json()
                .with_writer(w)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true)
                .with_filter(tracing_subscriber::filter::LevelFilter::ERROR)
        });

        let console_layer = fmt::layer()
            .json()
            .with_writer(console_writer)
            .with_target(false);

        subscriber
            .with(file_layer)
            .with(error_layer)
            .with(console_layer)
            .init();
    } else {
        let file_layer = file_writer.map(|w| {
            fmt::layer()
                .with_writer(w)
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(true)
                .with_line_number(true)
                .with_ansi(false)
        });

        let console_layer = fmt::layer()
            .with_writer(console_writer)
            .with_target(true)
            .pretty()
            .with_thread_ids(false)
            .with_thread_names(false);

        subscriber.with(file_layer).with(console_layer).init();
    }

    match log_dir {
        Some(dir) => tracing::info!(
            "Logging initialised for {} environment with daily file rotation in {}",
            environment,
            dir.display()
        ),
        None => tracing::info!(
            "Logging initialised for {} environment (stdout-only)",
            environment
        ),
    }

    guards
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialise tests that mutate the `LOG_DIR` env var so they don't race
    /// each other on `cargo test` (which runs tests in parallel by default).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_log_dir<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = std::env::var("LOG_DIR").ok();
        match value {
            Some(v) => std::env::set_var("LOG_DIR", v),
            None => std::env::remove_var("LOG_DIR"),
        }
        let result = f();
        match original {
            Some(v) => std::env::set_var("LOG_DIR", v),
            None => std::env::remove_var("LOG_DIR"),
        }
        result
    }

    #[test]
    fn log_dir_env_explicit_path_used_in_any_environment() {
        with_log_dir(Some("/tmp/portfolio-test-logs"), || {
            assert_eq!(
                log_dir_from_env(true),
                Some(PathBuf::from("/tmp/portfolio-test-logs"))
            );
            assert_eq!(
                log_dir_from_env(false),
                Some(PathBuf::from("/tmp/portfolio-test-logs"))
            );
        });
    }

    #[test]
    fn log_dir_env_empty_disables_file_logging() {
        with_log_dir(Some(""), || {
            assert_eq!(log_dir_from_env(true), None);
            assert_eq!(log_dir_from_env(false), None);
        });
    }

    #[test]
    fn log_dir_env_whitespace_treated_as_empty() {
        with_log_dir(Some("   "), || {
            assert_eq!(log_dir_from_env(true), None);
            assert_eq!(log_dir_from_env(false), None);
        });
    }

    #[test]
    fn log_dir_unset_in_production_disables_file_logging() {
        with_log_dir(None, || {
            assert_eq!(log_dir_from_env(true), None);
        });
    }

    #[test]
    fn log_dir_unset_in_development_defaults_to_logs_dir() {
        with_log_dir(None, || {
            assert_eq!(log_dir_from_env(false), Some(PathBuf::from("logs")));
        });
    }

    #[test]
    fn prepare_log_dir_creates_missing_directory_and_returns_path() {
        let tmp = std::env::temp_dir().join(format!(
            "portfolio-backend-prepare-{}",
            uuid::Uuid::new_v4()
        ));
        assert!(!tmp.exists());

        let prepared = prepare_log_dir(&tmp).expect("prepare_log_dir should succeed");
        assert_eq!(prepared, tmp);
        assert!(tmp.is_dir());
        // Probe file should be cleaned up afterwards.
        assert!(!tmp.join(".portfolio-backend-write-probe").exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn prepare_log_dir_returns_none_for_read_only_directory() {
        // Skip on platforms / CI environments where we can't toggle perms.
        let parent = std::env::temp_dir().join(format!(
            "portfolio-backend-readonly-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&parent).expect("create parent dir");

        // Try to make it read-only. If we can't (e.g. running as root), skip.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555))
                .expect("set read-only perms");

            // If we're root, perms are bypassed — skip.
            let probe = parent.join(".bypass-check");
            if std::fs::File::create(&probe).is_ok() {
                let _ = std::fs::remove_file(&probe);
                std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).ok();
                let _ = std::fs::remove_dir_all(&parent);
                return;
            }

            let result = prepare_log_dir(&parent);
            assert!(
                result.is_none(),
                "prepare_log_dir should return None for read-only dir"
            );

            // Restore perms so we can clean up.
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).ok();
        }

        let _guard_clear = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn test_build_rolling_appender() {
        let tmp = std::env::temp_dir().join(format!(
            "portfolio-backend-appender-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let appender = build_rolling_appender(&tmp, "test-app.log");
        assert!(appender.is_some());

        let invalid_path = tmp.join("some-file");
        std::fs::write(&invalid_path, b"hello").unwrap();
        let appender_err = build_rolling_appender(&invalid_path, "test-err.log");
        assert!(appender_err.is_none());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

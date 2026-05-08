use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

/// Client log entry received from frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientLogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Batch of client logs
#[derive(Debug, Deserialize)]
pub struct ClientLogBatch {
    pub logs: Vec<ClientLogEntry>,
}

/// Log response
#[derive(Debug, Serialize)]
pub struct LogResponse {
    pub success: bool,
    pub received: usize,
    pub processed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_display_is_lowercase() {
        assert_eq!(LogLevel::Trace.to_string(), "trace");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Error.to_string(), "error");
    }

    #[test]
    fn client_log_entry_skips_optional_fields_when_empty() {
        let entry = ClientLogEntry {
            timestamp: "2026-05-08T00:00:00Z".to_string(),
            level: "info".to_string(),
            message: "hello".to_string(),
            context: None,
            metadata: None,
        };

        let value = serde_json::to_value(entry).expect("serialize client log");
        assert!(value.get("context").is_none());
        assert!(value.get("metadata").is_none());
    }

    #[test]
    fn log_response_skips_error_when_none() {
        let response = LogResponse {
            success: true,
            received: 2,
            processed: 2,
            error: None,
        };

        let value = serde_json::to_value(response).expect("serialize response");
        assert!(value.get("error").is_none());
    }
}

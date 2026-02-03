/**
 * Logging Configuration
 * Configuration types and utilities for logging
 */
use serde::{Deserialize, Serialize};

/// Log level enumeration
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    #[serde(alias = "fatal")]
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
    pub level: LogLevel,
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
    fn test_log_level_display() {
        assert_eq!(LogLevel::Trace.to_string(), "trace");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Error.to_string(), "error");
    }

    #[test]
    fn test_client_log_entry_serialize_deserialize() {
        let entry = ClientLogEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            level: LogLevel::Info,
            message: "test".to_string(),
            context: Some(serde_json::json!({"key": "value"})),
            metadata: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("info"));
    }

    #[test]
    fn test_client_log_batch_deserialize() {
        let json = r#"{"logs":[{"timestamp":"2024-01-01T00:00:00Z","level":"info","message":"hello"}]}"#;
        let batch: ClientLogBatch = serde_json::from_str(json).unwrap();
        assert_eq!(batch.logs.len(), 1);
        assert_eq!(batch.logs[0].message, "hello");
    }

    #[test]
    fn test_log_response_serialize() {
        let resp = LogResponse {
            success: true,
            received: 5,
            processed: 5,
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("true"));
        assert!(json.contains("5"));
    }
}

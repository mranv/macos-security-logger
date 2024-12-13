use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoggerError {
    #[error("Failed to execute log command: {0}")]
    CommandError(#[from] std::io::Error),

    #[error("Failed to parse log output: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("Failed to access log file: {0}")]
    FileAccessError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Invalid log format: {0}")]
    InvalidFormat(String),
}
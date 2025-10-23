//! Error types for veraaudit application
use crate::credentials::CredentialError;

/// Custom error type for veraaudit operations
#[derive(thiserror::Error, Debug)]
pub enum AuditError {
    /// Veracode API error
    #[error("Veracode API error: {0}")]
    VeracodeApi(#[from] veracode_platform::VeracodeError),

    /// Veracode reporting error
    #[error("Veracode reporting error: {0}")]
    Reporting(#[from] veracode_platform::ReportingError),

    /// Credential error
    #[error("Credential error: {0}")]
    Credential(#[from] CredentialError),

    /// File I/O error
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid datetime format
    #[error("Invalid datetime format: {0}")]
    InvalidDateTimeFormat(String),

    /// Invalid date range
    #[error("Invalid date range: {0}")]
    DateRangeInvalid(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Service mode error
    #[error("Service mode error: {0}")]
    ServiceMode(String),

    /// File cleanup error
    #[error("File cleanup error: {0}")]
    Cleanup(String),
}

/// Result type alias for veraaudit operations
pub type Result<T> = std::result::Result<T, AuditError>;

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

/// Check if an error is an authentication/authorization error (401/403)
/// This indicates that credentials may have expired or are invalid
#[must_use]
pub fn is_auth_error(error: &AuditError) -> bool {
    match error {
        // Check for VeracodeApi errors - Authentication variant
        AuditError::VeracodeApi(veracode_platform::VeracodeError::Authentication(_)) => true,
        // Check for VeracodeApi errors - HttpStatus with 401/403
        AuditError::VeracodeApi(veracode_platform::VeracodeError::HttpStatus {
            status_code, ..
        }) => matches!(status_code, 401 | 403),
        // Check for Reporting errors that wrap VeracodeApi Authentication errors
        AuditError::Reporting(veracode_platform::ReportingError::VeracodeApi(
            veracode_platform::VeracodeError::Authentication(_),
        )) => true,
        // Check for Reporting errors that wrap VeracodeApi HttpStatus with 401/403
        AuditError::Reporting(veracode_platform::ReportingError::VeracodeApi(
            veracode_platform::VeracodeError::HttpStatus { status_code, .. },
        )) => matches!(status_code, 401 | 403),
        // All other VeracodeApi error types are not auth errors
        AuditError::VeracodeApi(
            veracode_platform::VeracodeError::Http(_)
            | veracode_platform::VeracodeError::Serialization(_)
            | veracode_platform::VeracodeError::InvalidResponse(_)
            | veracode_platform::VeracodeError::InvalidConfig(_)
            | veracode_platform::VeracodeError::NotFound(_)
            | veracode_platform::VeracodeError::RetryExhausted(_)
            | veracode_platform::VeracodeError::RateLimited { .. }
            | veracode_platform::VeracodeError::Validation(_),
        ) => false,
        // All other Reporting error types (that don't wrap VeracodeApi)
        AuditError::Reporting(
            veracode_platform::ReportingError::InvalidDate(_)
            | veracode_platform::ReportingError::DateRangeExceeded(_),
        ) => false,
        // All other Reporting errors that wrap non-auth VeracodeApi errors
        AuditError::Reporting(veracode_platform::ReportingError::VeracodeApi(
            veracode_platform::VeracodeError::Http(_)
            | veracode_platform::VeracodeError::Serialization(_)
            | veracode_platform::VeracodeError::InvalidResponse(_)
            | veracode_platform::VeracodeError::InvalidConfig(_)
            | veracode_platform::VeracodeError::NotFound(_)
            | veracode_platform::VeracodeError::RetryExhausted(_)
            | veracode_platform::VeracodeError::RateLimited { .. }
            | veracode_platform::VeracodeError::Validation(_),
        )) => false,
        // All other AuditError types
        AuditError::Credential(_)
        | AuditError::Io(_)
        | AuditError::Json(_)
        | AuditError::InvalidDateTimeFormat(_)
        | AuditError::DateRangeInvalid(_)
        | AuditError::InvalidConfig(_)
        | AuditError::ServiceMode(_)
        | AuditError::Cleanup(_) => false,
    }
}

use crate::cli::Args;
use log::{debug, error, info};
use secrecy::SecretString;
use std::sync::Arc;
use veracode_platform::{VeracodeConfig, VeracodeCredentials, VeracodeRegion};

/// Source of credentials for debugging and logging purposes
#[derive(Debug, Clone)]
pub enum CredentialSource {
    Environment,
    Vault { addr: String, secret_path: String },
}

/// Vault configuration for credential retrieval
#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub addr: String,
    pub jwt: String,
    pub role: String,
    pub secret_path: String,
    pub namespace: Option<String>,
}

/// Custom error types for credential operations
#[derive(thiserror::Error, Debug)]
pub enum CredentialError {
    #[error("Environment variable validation failed: {field}: {message}")]
    ValidationError { field: String, message: String },

    #[error("Vault authentication failed: {context}")]
    VaultAuthError { context: String },

    #[error("Vault secret retrieval failed: {path}: {context}")]
    VaultSecretError { path: String, context: String },

    #[error("Missing required credentials: {missing}")]
    MissingCredentials { missing: String },

    #[error("Vault configuration error: {message}")]
    VaultConfigError { message: String },
}

/// Secure wrapper for API credentials using the new ARC-based system
/// Integrates with veracode-platform's VeracodeCredentials for consistency
#[derive(Clone)]
pub struct SecureApiCredentials {
    /// ARC-based credentials from veracode-platform
    pub credentials: Option<VeracodeCredentials>,
    pub source: CredentialSource,
}

impl std::fmt::Debug for SecureApiCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureApiCredentials")
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "[REDACTED]"),
            )
            .field("source", &self.source)
            .finish()
    }
}

impl SecureApiCredentials {
    #[must_use]
    pub fn new(api_id: Option<String>, api_key: Option<String>) -> Self {
        let credentials = match (api_id, api_key) {
            (Some(id), Some(key)) => Some(VeracodeCredentials::new(id, key)),
            _ => None,
        };

        Self {
            credentials,
            source: CredentialSource::Environment,
        }
    }

    #[must_use]
    pub fn new_with_source(
        api_id: Option<String>,
        api_key: Option<String>,
        source: CredentialSource,
    ) -> Self {
        let credentials = match (api_id, api_key) {
            (Some(id), Some(key)) => Some(VeracodeCredentials::new(id, key)),
            _ => None,
        };

        Self {
            credentials,
            source,
        }
    }

    /// Create from existing VeracodeCredentials
    #[must_use]
    pub fn from_veracode_credentials(
        credentials: VeracodeCredentials,
        source: CredentialSource,
    ) -> Self {
        Self {
            credentials: Some(credentials),
            source,
        }
    }

    /// Extract credentials as owned strings (for API client construction)
    pub fn extract_credentials(&self) -> Result<(String, String), Box<dyn std::error::Error>> {
        match &self.credentials {
            Some(creds) => Ok((
                creds.expose_api_id().to_string(),
                creds.expose_api_key().to_string(),
            )),
            None => {
                error!("❌ Pipeline scan requires Veracode API credentials");
                error!("💡 Set VERACODE_API_ID and VERACODE_API_KEY environment variables");
                error!("💡 API credentials must contain only alphanumeric characters");
                Err("Missing API credentials".into())
            }
        }
    }

    /// Extract credentials as string references (for validation/comparison)
    pub fn extract_credentials_ref(&self) -> Result<(&str, &str), Box<dyn std::error::Error>> {
        if let Some(creds) = &self.credentials {
            Ok((creds.expose_api_id(), creds.expose_api_key()))
        } else {
            error!("❌ Pipeline scan requires Veracode API credentials");
            error!("💡 Set VERACODE_API_ID and VERACODE_API_KEY environment variables");
            error!("💡 API credentials must contain only alphanumeric characters");
            Err("Missing API credentials".into())
        }
    }

    /// Get ARC pointer to API ID for sharing across threads
    pub fn api_id_arc(&self) -> Option<Arc<SecretString>> {
        self.credentials
            .as_ref()
            .map(VeracodeCredentials::api_id_ptr)
    }

    /// Get ARC pointer to API key for sharing across threads
    pub fn api_key_arc(&self) -> Option<Arc<SecretString>> {
        self.credentials
            .as_ref()
            .map(VeracodeCredentials::api_key_ptr)
    }

    /// Get the underlying VeracodeCredentials for direct use with veracode-platform
    #[must_use]
    pub fn get_veracode_credentials(&self) -> Option<&VeracodeCredentials> {
        self.credentials.as_ref()
    }
}

/// Validate API credential with optimized character checking
pub fn validate_api_credential(value: &str, field_name: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field_name} cannot be empty"));
    }

    // Use bytes() for ASCII-only credentials - more efficient than chars() for alphanumeric check
    if !value.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(format!(
            "{field_name} must contain only alphanumeric characters"
        ));
    }

    Ok(())
}

/// Fast validation for credentials that are known to be ASCII
#[inline]
pub fn validate_api_credential_ascii(value: &str, field_name: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field_name} cannot be empty"));
    }

    // Direct byte check for ASCII alphanumeric - fastest path
    for &byte in value.as_bytes() {
        if !byte.is_ascii_alphanumeric() {
            return Err(format!(
                "{field_name} must contain only alphanumeric characters"
            ));
        }
    }

    Ok(())
}

pub fn load_api_credentials(args: &mut Args) -> Result<(), i32> {
    args.api_id = match std::env::var("VERACODE_API_ID") {
        Ok(id) => {
            if let Err(e) = validate_api_credential(&id, "VERACODE_API_ID") {
                error!("❌ Invalid VERACODE_API_ID: {e}");
                return Err(1);
            }
            Some(id)
        }
        Err(_) => None,
    };

    args.api_key = match std::env::var("VERACODE_API_KEY") {
        Ok(key) => {
            if let Err(e) = validate_api_credential(&key, "VERACODE_API_KEY") {
                error!("❌ Invalid VERACODE_API_KEY: {e}");
                return Err(1);
            }
            Some(key)
        }
        Err(_) => None,
    };

    Ok(())
}

/// Load API credentials directly into VeracodeCredentials from Args
pub fn load_veracode_credentials_from_args(
    args: &crate::cli::Args,
) -> Result<VeracodeCredentials, i32> {
    match (&args.api_id, &args.api_key) {
        (Some(id), Some(key)) => {
            // Load directly into VeracodeCredentials - no intermediate copying!
            Ok(VeracodeCredentials::new(id.clone(), key.clone()))
        }
        _ => {
            error!("❌ Missing Veracode API credentials");
            error!("💡 Set VERACODE_API_ID and VERACODE_API_KEY environment variables");
            error!("💡 API credentials must contain only alphanumeric characters");
            Err(1)
        }
    }
}

/// Extract credentials from Args (for owned strings - API client construction)
pub fn check_pipeline_credentials(
    args: &Args,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    match (&args.api_id, &args.api_key) {
        (Some(id), Some(key)) => Ok((id.clone(), key.clone())), // Clone needed for owned return
        _ => {
            error!("❌ Pipeline scan requires Veracode API credentials");
            error!("💡 Set VERACODE_API_ID and VERACODE_API_KEY environment variables");
            error!("💡 API credentials must contain only alphanumeric characters");
            Err("Missing API credentials".into())
        }
    }
}

/// Load credentials directly into VeracodeCredentials from environment variables
pub fn load_veracode_credentials_from_env() -> Result<VeracodeCredentials, CredentialError> {
    debug!("Loading credentials directly into VeracodeCredentials from environment variables");

    let api_id =
        std::env::var("VERACODE_API_ID").map_err(|_| CredentialError::MissingCredentials {
            missing: "VERACODE_API_ID environment variable".to_string(),
        })?;

    let api_key =
        std::env::var("VERACODE_API_KEY").map_err(|_| CredentialError::MissingCredentials {
            missing: "VERACODE_API_KEY environment variable".to_string(),
        })?;

    // Validate credentials before loading into secrecy objects
    validate_api_credential(&api_id, "VERACODE_API_ID").map_err(|msg| {
        CredentialError::ValidationError {
            field: "VERACODE_API_ID".to_string(),
            message: msg,
        }
    })?;

    validate_api_credential(&api_key, "VERACODE_API_KEY").map_err(|msg| {
        CredentialError::ValidationError {
            field: "VERACODE_API_KEY".to_string(),
            message: msg,
        }
    })?;

    // Load directly into VeracodeCredentials - no intermediate copying!
    info!("Successfully loaded credentials directly into VeracodeCredentials");
    Ok(VeracodeCredentials::new(api_id, api_key))
}

/// Create VeracodeConfig directly from VeracodeCredentials
///
/// This function creates a VeracodeConfig using ARC-based credentials for optimal memory sharing.
pub fn create_veracode_config_from_credentials(
    credentials: VeracodeCredentials,
    region_str: &str,
) -> Result<VeracodeConfig, i32> {
    let region = parse_region_from_str(region_str)?;

    // Use ARC-based credentials for optimal memory sharing
    debug!("🔗 Creating VeracodeConfig with ARC-based credentials");
    let base_config =
        VeracodeConfig::from_arc_credentials(credentials.api_id_ptr(), credentials.api_key_ptr())
            .with_region(region);

    // Apply environment variable configuration (reuse existing function from scan.rs)
    Ok(crate::scan::configure_veracode_with_env_vars(base_config))
}

/// Centralized function to create a configured VeracodeConfig from Args
///
/// This function loads credentials directly into VeracodeCredentials and creates
/// a VeracodeConfig using ARC-based credentials for optimal memory sharing.
pub fn create_veracode_config_from_args(args: &Args) -> Result<VeracodeConfig, i32> {
    // Load credentials directly into VeracodeCredentials - no intermediate copying!
    let credentials = load_veracode_credentials_from_args(args)?;
    create_veracode_config_from_credentials(credentials, &args.region)
}

/// Parse region string to VeracodeRegion enum
fn parse_region_from_str(region_str: &str) -> Result<VeracodeRegion, i32> {
    let region = match region_str {
        s if s.eq_ignore_ascii_case("commercial") => VeracodeRegion::Commercial,
        s if s.eq_ignore_ascii_case("european") => VeracodeRegion::European,
        s if s.eq_ignore_ascii_case("federal") => VeracodeRegion::Federal,
        _ => VeracodeRegion::Commercial, // Default to commercial
    };
    Ok(region)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_veracode_credentials_integration() {
        let creds = SecureApiCredentials::new(
            Some("test_api_id_123".to_string()),
            Some("test_api_key_456".to_string()),
        );

        // Test that we can get VeracodeCredentials
        assert!(creds.get_veracode_credentials().is_some());

        // Test ARC pointer access
        assert!(creds.api_id_arc().is_some());
        assert!(creds.api_key_arc().is_some());
    }

    #[test]
    fn test_secure_api_credentials_debug_redaction() {
        let creds = SecureApiCredentials::new(
            Some("test_api_id_123".to_string()),
            Some("test_api_key_456".to_string()),
        );
        let debug_output = format!("{creds:?}");

        // Should show structure but redact actual values
        assert!(debug_output.contains("SecureApiCredentials"));
        assert!(debug_output.contains("credentials"));
        assert!(debug_output.contains("source"));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(debug_output.contains("Environment"));

        // Should not contain actual credential values
        assert!(!debug_output.contains("test_api_id_123"));
        assert!(!debug_output.contains("test_api_key_456"));
    }

    #[test]
    fn test_arc_credential_sharing() {
        let creds = SecureApiCredentials::new(
            Some("test_api_id_123".to_string()),
            Some("test_api_key_456".to_string()),
        );

        // Test ARC pointer sharing
        let api_id_arc = creds.api_id_arc().unwrap();
        let api_key_arc = creds.api_key_arc().unwrap();

        // Should be able to access through ARC
        assert_eq!(api_id_arc.expose_secret(), "test_api_id_123");
        assert_eq!(api_key_arc.expose_secret(), "test_api_key_456");
    }

    #[test]
    fn test_secure_api_credentials_extract_success() {
        let creds = SecureApiCredentials::new(
            Some("test_api_id_123".to_string()),
            Some("test_api_key_456".to_string()),
        );

        let result = creds.extract_credentials();
        assert!(result.is_ok());

        let (id, key) = result.unwrap();
        assert_eq!(id, "test_api_id_123");
        assert_eq!(key, "test_api_key_456");
    }

    #[test]
    fn test_secure_api_credentials_extract_missing_id() {
        let creds = SecureApiCredentials::new(None, Some("test_api_key_456".to_string()));

        let result = creds.extract_credentials();
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_api_credentials_extract_missing_key() {
        let creds = SecureApiCredentials::new(Some("test_api_id_123".to_string()), None);

        let result = creds.extract_credentials();
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_api_credentials_extract_missing_both() {
        let creds = SecureApiCredentials::new(None, None);

        let result = creds.extract_credentials();
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_api_credentials_clone() {
        let creds = SecureApiCredentials::new(
            Some("test_api_id_123".to_string()),
            Some("test_api_key_456".to_string()),
        );

        let cloned_creds = creds.clone();

        // Both should extract the same credentials
        let original_result = creds.extract_credentials().unwrap();
        let cloned_result = cloned_creds.extract_credentials().unwrap();

        assert_eq!(original_result, cloned_result);
    }
}

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
    pub auth_path: String,
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
/// Integrates with veracode-platform's `VeracodeCredentials` for consistency
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

    /// Create from existing `VeracodeCredentials`
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
    ///
    /// # Errors
    /// Returns an error if credentials are not present or cannot be extracted
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
    ///
    /// # Errors
    /// Returns an error if credentials are not present or cannot be extracted
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

    /// Get the underlying `VeracodeCredentials` for direct use with veracode-platform
    #[must_use]
    pub fn get_veracode_credentials(&self) -> Option<&VeracodeCredentials> {
        self.credentials.as_ref()
    }
}

/// Validate API credential with optimized character checking
///
/// # Errors
/// Returns an error if the credential is empty or contains non-alphanumeric characters
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
///
/// # Errors
/// Returns an error if the credential is empty or contains non-alphanumeric characters
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

/// Load API credentials from environment variables into Args
///
/// # Errors
/// Returns an error code if credentials are invalid or validation fails
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

/// Load API credentials directly into `VeracodeCredentials` from Args
///
/// # Errors
/// Returns an error code if API credentials are missing from Args
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
///
/// # Errors
/// Returns an error if API credentials are missing from Args
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

/// Load credentials directly into `VeracodeCredentials` from environment variables
///
/// # Errors
/// Returns an error if required environment variables are missing or credentials are invalid
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

/// Create `VeracodeConfig` directly from `VeracodeCredentials`
///
/// This function creates a `VeracodeConfig` using ARC-based credentials for optimal memory sharing.
///
/// # Errors
/// Returns an error code if region parsing fails
pub fn create_veracode_config_from_credentials(
    credentials: VeracodeCredentials,
    region_str: &str,
) -> Result<VeracodeConfig, i32> {
    let region = parse_region_from_str(region_str)?;

    // Use ARC-based credentials for optimal memory sharing
    debug!("🔗 Creating VeracodeConfig with credentials");
    let base_config =
        VeracodeConfig::from_arc_credentials(credentials.api_id_ptr(), credentials.api_key_ptr())
            .with_region(region);

    // Apply environment variable configuration (reuse existing function from scan.rs)
    Ok(crate::scan::configure_veracode_with_env_vars(base_config))
}

/// Create `VeracodeConfig` with Vault proxy credentials
///
/// This function creates a `VeracodeConfig` and applies optional proxy credentials from Vault.
/// Vault proxy configuration takes precedence over environment variables.
///
/// # Errors
/// Returns an error code if region parsing fails
pub fn create_veracode_config_with_proxy(
    credentials: VeracodeCredentials,
    region_str: &str,
    proxy_url: Option<String>,
    proxy_username: Option<String>,
    proxy_password: Option<String>,
) -> Result<VeracodeConfig, i32> {
    let region = parse_region_from_str(region_str)?;

    // Use ARC-based credentials for optimal memory sharing
    debug!("🔗 Creating VeracodeConfig with credentials and proxy configuration");
    let mut base_config =
        VeracodeConfig::from_arc_credentials(credentials.api_id_ptr(), credentials.api_key_ptr())
            .with_region(region);

    // Apply proxy configuration from Vault if provided (takes priority)
    let has_vault_proxy = proxy_url.is_some();
    if let Some(url) = proxy_url {
        debug!("🔒 Applying proxy configuration from Vault: {}", url);
        base_config = base_config.with_proxy(&url);

        if let (Some(u), Some(p)) = (proxy_username, proxy_password) {
            debug!("🔐 Applying proxy authentication from Vault");
            base_config = base_config.with_proxy_auth(&u, &p);
        }
    }

    // Apply environment variable configuration
    // If Vault proxy config exists, skip env var proxy config
    Ok(crate::scan::configure_veracode_with_env_vars_conditional(
        base_config,
        !has_vault_proxy,
    ))
}

/// Centralized function to create a configured `VeracodeConfig` from Args
///
/// This function loads credentials directly into `VeracodeCredentials` and creates
/// a `VeracodeConfig` using ARC-based credentials for optimal memory sharing.
///
/// # Errors
/// Returns an error code if credential loading or config creation fails
pub fn create_veracode_config_from_args(args: &Args) -> Result<VeracodeConfig, i32> {
    // Load credentials directly into VeracodeCredentials - no intermediate copying!
    let credentials = load_veracode_credentials_from_args(args)?;
    create_veracode_config_from_credentials(credentials, &args.region)
}

/// Parse region string to `VeracodeRegion` enum
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        let api_id_arc = creds.api_id_arc().expect("Expected API ID");
        let api_key_arc = creds.api_key_arc().expect("Expected API key");

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

        let (id, key) = result.expect("Expected valid credentials");
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
        let original_result = creds
            .extract_credentials()
            .expect("Expected valid credentials");
        let cloned_result = cloned_creds
            .extract_credentials()
            .expect("Expected valid credentials");

        assert_eq!(original_result, cloned_result);
    }

    #[test]
    fn test_create_veracode_config_with_proxy_full() {
        let credentials = VeracodeCredentials::new(
            "test_api_id_123".to_string(),
            "test_api_key_456".to_string(),
        );

        let result = create_veracode_config_with_proxy(
            credentials,
            "commercial",
            Some("http://proxy.example.com:8080".to_string()),
            Some("proxy_user".to_string()),
            Some("proxy_pass".to_string()),
        );

        assert!(result.is_ok());
        let config = result.expect("Expected valid config");

        // Verify region is set
        assert_eq!(config.region, VeracodeRegion::Commercial);

        // Verify proxy URL is set
        assert!(config.proxy_url.is_some());
        assert_eq!(
            config.proxy_url.as_ref().expect("Expected proxy URL"),
            "http://proxy.example.com:8080"
        );

        // Proxy auth should be set (verified through config structure)
        assert!(config.proxy_username.is_some());
        assert!(config.proxy_password.is_some());
    }

    #[test]
    fn test_create_veracode_config_with_proxy_no_auth() {
        let credentials = VeracodeCredentials::new(
            "test_api_id_123".to_string(),
            "test_api_key_456".to_string(),
        );

        let result = create_veracode_config_with_proxy(
            credentials,
            "european",
            Some("http://proxy.example.com:8080".to_string()),
            None,
            None,
        );

        assert!(result.is_ok());
        let config = result.expect("Expected valid config");

        // Verify region is set
        assert_eq!(config.region, VeracodeRegion::European);

        // Verify proxy URL is set
        assert!(config.proxy_url.is_some());
        assert_eq!(
            config.proxy_url.as_ref().expect("Expected proxy URL"),
            "http://proxy.example.com:8080"
        );

        // Proxy auth should not be set
        assert!(config.proxy_username.is_none());
        assert!(config.proxy_password.is_none());
    }

    #[test]
    fn test_create_veracode_config_with_no_proxy() {
        let credentials = VeracodeCredentials::new(
            "test_api_id_123".to_string(),
            "test_api_key_456".to_string(),
        );

        let result = create_veracode_config_with_proxy(credentials, "federal", None, None, None);

        assert!(result.is_ok());
        let config = result.expect("Expected valid config");

        // Verify region is set
        assert_eq!(config.region, VeracodeRegion::Federal);

        // Verify no proxy is set
        assert!(config.proxy_url.is_none());
        assert!(config.proxy_username.is_none());
        assert!(config.proxy_password.is_none());
    }

    #[test]
    fn test_create_veracode_config_from_credentials_no_proxy() {
        let credentials = VeracodeCredentials::new(
            "test_api_id_123".to_string(),
            "test_api_key_456".to_string(),
        );

        let result = create_veracode_config_from_credentials(credentials, "commercial");

        assert!(result.is_ok());
        let config = result.expect("Expected valid config");

        // Verify region is set
        assert_eq!(config.region, VeracodeRegion::Commercial);

        // Verify credentials are set (ARC pointers exist)
        // api_id_arc() and api_key_arc() return Arc directly, not Option
        assert!(!config.api_id_arc().expose_secret().is_empty());
        assert!(!config.api_key_arc().expose_secret().is_empty());
    }

    #[test]
    fn test_parse_region_from_str() {
        let commercial = parse_region_from_str("commercial").expect("Expected valid region");
        assert_eq!(commercial, VeracodeRegion::Commercial);

        let commercial_upper = parse_region_from_str("COMMERCIAL").expect("Expected valid region");
        assert_eq!(commercial_upper, VeracodeRegion::Commercial);

        let european = parse_region_from_str("european").expect("Expected valid region");
        assert_eq!(european, VeracodeRegion::European);

        let federal = parse_region_from_str("federal").expect("Expected valid region");
        assert_eq!(federal, VeracodeRegion::Federal);

        // Invalid region defaults to commercial
        let invalid = parse_region_from_str("invalid").expect("Expected valid region");
        assert_eq!(invalid, VeracodeRegion::Commercial);
    }

    // Security tests for API credential validators
    // These tests ensure fuzz-discovered edge cases are handled correctly

    #[test]
    fn test_validate_api_credential_valid() {
        // Valid alphanumeric only
        assert!(validate_api_credential("abc123", "api_id").is_ok());
        assert!(validate_api_credential("ABC123XYZ", "api_key").is_ok());
        assert!(validate_api_credential("1234567890", "api_id").is_ok());
    }

    #[test]
    fn test_validate_api_credential_rejects_empty() {
        let result = validate_api_credential("", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .contains("cannot be empty")
        );
    }

    #[test]
    fn test_validate_api_credential_rejects_special_chars() {
        // Reject dash
        let result = validate_api_credential("abc-123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for dash")
                .contains("alphanumeric")
        );

        // Reject underscore
        let result = validate_api_credential("abc_123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for underscore")
                .contains("alphanumeric")
        );

        // Reject dot
        let result = validate_api_credential("abc.123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for dot")
                .contains("alphanumeric")
        );

        // Reject space
        let result = validate_api_credential("abc 123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for space")
                .contains("alphanumeric")
        );
    }

    #[test]
    fn test_validate_api_credential_rejects_unicode() {
        // Reject unicode non-breaking space (U+00A0)
        let result = validate_api_credential("abc\u{00A0}123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for non-breaking space")
                .contains("alphanumeric")
        );

        // Reject unicode zero-width space (U+200B)
        let result = validate_api_credential("abc\u{200B}123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for zero-width space")
                .contains("alphanumeric")
        );

        // Reject unicode ideographic space (U+3000)
        let result = validate_api_credential("abc\u{3000}123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for ideographic space")
                .contains("alphanumeric")
        );
    }

    #[test]
    fn test_validate_api_credential_rejects_control_chars() {
        // Reject newline
        let result = validate_api_credential("abc\n123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for newline")
                .contains("alphanumeric")
        );

        // Reject carriage return
        let result = validate_api_credential("abc\r123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for carriage return")
                .contains("alphanumeric")
        );

        // Reject null byte
        let result = validate_api_credential("abc\x00123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for null byte")
                .contains("alphanumeric")
        );

        // Reject tab
        let result = validate_api_credential("abc\t123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for tab")
                .contains("alphanumeric")
        );
    }

    #[test]
    fn test_validate_api_credential_ascii_valid() {
        // Valid alphanumeric only
        assert!(validate_api_credential_ascii("abc123", "api_id").is_ok());
        assert!(validate_api_credential_ascii("ABC123XYZ", "api_key").is_ok());
        assert!(validate_api_credential_ascii("1234567890", "api_id").is_ok());
    }

    #[test]
    fn test_validate_api_credential_ascii_rejects_empty() {
        let result = validate_api_credential_ascii("", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .contains("cannot be empty")
        );
    }

    #[test]
    fn test_validate_api_credential_ascii_rejects_special_chars() {
        // Reject dash
        let result = validate_api_credential_ascii("abc-123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for dash")
                .contains("alphanumeric")
        );

        // Reject underscore
        let result = validate_api_credential_ascii("abc_123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for underscore")
                .contains("alphanumeric")
        );
    }

    #[test]
    fn test_validate_api_credential_ascii_rejects_control_chars() {
        // Reject newline
        let result = validate_api_credential_ascii("abc\n123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for newline")
                .contains("alphanumeric")
        );

        // Reject null byte
        let result = validate_api_credential_ascii("abc\x00123", "api_id");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error for null byte")
                .contains("alphanumeric")
        );
    }

    // Property-based security tests using proptest
    // These tests use constrained input spaces for optimal performance
    #[cfg(test)]
    mod proptest_security_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 10 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Security Property 1: Validator never panics on any input
            /// Tests with constrained ASCII strings (0-256 chars) that match real credential patterns
            #[test]
            fn validate_never_panics_on_any_input(s in "[\\x00-\\x7F]{0,256}") {
                // Should always return Ok or Err, never panic
                let _ = validate_api_credential(&s, "test");
            }

            /// Security Property 2: Pure alphanumeric strings always pass validation
            /// Real Veracode credentials are typically 20-128 alphanumeric characters
            #[test]
            fn alphanumeric_strings_always_valid(s in "[a-zA-Z0-9]{1,128}") {
                let result = validate_api_credential(&s, "test");
                prop_assert!(
                    result.is_ok(),
                    "Alphanumeric string should be valid: {:?}",
                    s
                );
            }

            /// Security Property 3: Strings containing non-alphanumeric always fail
            /// This prevents injection attacks, control character exploits, etc.
            #[test]
            fn non_alphanumeric_always_fails(
                prefix in "[a-zA-Z0-9]{0,32}",
                bad_char in "[^a-zA-Z0-9\\x00]",  // Exclude null to avoid string termination issues
                suffix in "[a-zA-Z0-9]{0,32}"
            ) {
                let s = format!("{prefix}{bad_char}{suffix}");
                let result = validate_api_credential(&s, "test");
                prop_assert!(
                    result.is_err(),
                    "String with non-alphanumeric char should be invalid: {:?}",
                    s
                );
            }

            /// Security Property 4: Both validators agree on ASCII inputs
            /// Ensures validate_api_credential and validate_api_credential_ascii have identical behavior
            #[test]
            fn validators_agree_on_ascii_inputs(s in "[\\x00-\\x7F]{0,128}") {
                let result1 = validate_api_credential(&s, "test");
                let result2 = validate_api_credential_ascii(&s, "test");
                prop_assert_eq!(
                    result1.is_ok(),
                    result2.is_ok(),
                    "Both validators must agree on ASCII input: {:?}",
                    s
                );
            }

            /// Security Property 5: Empty strings always rejected
            /// Verifies that validator correctly handles the empty string edge case
            #[test]
            fn empty_string_always_rejected(field_name in ".*") {
                let result = validate_api_credential("", &field_name);
                prop_assert!(
                    result.is_err(),
                    "Empty string should always be rejected"
                );
                prop_assert!(
                    result.unwrap_err().contains("cannot be empty"),
                    "Error message should mention 'cannot be empty'"
                );
            }
        }
    }
}

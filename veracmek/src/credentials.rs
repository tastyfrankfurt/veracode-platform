use log::{debug, info, warn};
use veracode_platform::{VeracodeConfig, VeracodeCredentials, VeracodeRegion};

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
    debug!("🔗 Creating VeracodeConfig with credentials");
    let mut base_config =
        VeracodeConfig::from_arc_credentials(credentials.api_id_ptr(), credentials.api_key_ptr())
            .with_region(region);

    // Apply environment variable configuration
    base_config = configure_veracode_with_env_vars(base_config);

    Ok(base_config)
}

/// Create VeracodeConfig with Vault proxy credentials
///
/// This function creates a VeracodeConfig and applies optional proxy credentials from Vault.
/// Vault proxy configuration takes priority over environment variables.
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
    base_config = configure_veracode_with_env_vars_conditional(base_config, !has_vault_proxy);

    Ok(base_config)
}

/// Configure VeracodeConfig with environment variables
///
/// This function applies various environment variable settings to the VeracodeConfig.
fn configure_veracode_with_env_vars(config: VeracodeConfig) -> VeracodeConfig {
    configure_veracode_with_env_vars_conditional(config, true)
}

/// Configure VeracodeConfig with environment variables (with conditional proxy loading)
///
/// This function applies various environment variable settings to the VeracodeConfig.
/// If `include_proxy` is false, proxy configuration from env vars is skipped.
fn configure_veracode_with_env_vars_conditional(
    mut config: VeracodeConfig,
    include_proxy: bool,
) -> VeracodeConfig {
    use std::env;

    // Certificate validation
    if env::var("VERACMEK_DISABLE_CERT_VALIDATION").is_ok() {
        config = config.with_certificate_validation_disabled();
        warn!(
            "⚠️  WARNING: Certificate validation disabled for Veracode API via VERACMEK_DISABLE_CERT_VALIDATION"
        );
        warn!("   This should only be used in development environments!");
    }

    // Proxy configuration from environment variables (if enabled)
    if include_proxy {
        let proxy_url = env::var("HTTPS_PROXY")
            .or_else(|_| env::var("https_proxy"))
            .or_else(|_| env::var("HTTP_PROXY"))
            .or_else(|_| env::var("http_proxy"))
            .ok();

        if let Some(url) = proxy_url {
            debug!("🔒 Proxy configuration detected from environment: {}", url);
            config = config.with_proxy(&url);

            // Try to load proxy authentication credentials
            let username = env::var("PROXY_USERNAME")
                .or_else(|_| env::var("proxy_username"))
                .ok();

            let password = env::var("PROXY_PASSWORD")
                .or_else(|_| env::var("proxy_password"))
                .ok();

            if let (Some(u), Some(p)) = (username, password) {
                debug!("🔐 Proxy authentication credentials found in environment");
                config = config.with_proxy_auth(&u, &p);
            }
        }
    }

    config
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

    #[test]
    fn test_validate_api_credential_valid() {
        assert!(validate_api_credential("test123", "TEST_FIELD").is_ok());
        assert!(validate_api_credential("ABC123xyz", "TEST_FIELD").is_ok());
    }

    #[test]
    fn test_validate_api_credential_invalid() {
        assert!(validate_api_credential("", "TEST_FIELD").is_err());
        assert!(validate_api_credential("test-123", "TEST_FIELD").is_err());
        assert!(validate_api_credential("test@123", "TEST_FIELD").is_err());
    }

    #[test]
    fn test_parse_region_from_str() {
        assert!(matches!(
            parse_region_from_str("commercial"),
            Ok(VeracodeRegion::Commercial)
        ));
        assert!(matches!(
            parse_region_from_str("Commercial"),
            Ok(VeracodeRegion::Commercial)
        ));
        assert!(matches!(
            parse_region_from_str("COMMERCIAL"),
            Ok(VeracodeRegion::Commercial)
        ));
        assert!(matches!(
            parse_region_from_str("european"),
            Ok(VeracodeRegion::European)
        ));
        assert!(matches!(
            parse_region_from_str("federal"),
            Ok(VeracodeRegion::Federal)
        ));
        assert!(matches!(
            parse_region_from_str("invalid"),
            Ok(VeracodeRegion::Commercial)
        ));
    }
}

use crate::credentials::{
    CredentialError, CredentialSource, SecureApiCredentials, VaultConfig, validate_api_credential,
};
use backoff::{ExponentialBackoff, backoff::Backoff};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::time::Duration;
use vaultrs::{auth::oidc, client::VaultClient, client::VaultClientSettingsBuilder, kv2};

/// Vault client for secure credential management
pub struct VaultCredentialClient {
    client: VaultClient,
}

impl VaultCredentialClient {
    /// Create a new vault client from configuration
    pub async fn new(config: &VaultConfig) -> Result<Self, CredentialError> {
        let client = create_vault_client(config).await?;
        authenticate_vault(&client, config).await?;

        Ok(Self { client })
    }

    /// Retrieve credentials from vault
    pub async fn get_credentials(
        &self,
        secret_path: &str,
    ) -> Result<SecureApiCredentials, CredentialError> {
        let secret_data = retrieve_vault_secret(&self.client, secret_path).await?;

        // Extract API credentials from vault secret
        let api_id = secret_data.get("VERACODE_API_ID").map(|s| s.to_string());
        let api_key = secret_data.get("VERACODE_API_KEY").map(|s| s.to_string());

        // Validate extracted credentials
        if let Some(ref id) = api_id {
            validate_api_credential(id, "VERACODE_API_ID from vault").map_err(|msg| {
                CredentialError::ValidationError {
                    field: "VERACODE_API_ID".to_string(),
                    message: msg,
                }
            })?;
        }

        if let Some(ref key) = api_key {
            validate_api_credential(key, "VERACODE_API_KEY from vault").map_err(|msg| {
                CredentialError::ValidationError {
                    field: "VERACODE_API_KEY".to_string(),
                    message: msg,
                }
            })?;
        }

        let source = CredentialSource::Vault {
            addr: "vault".to_string(), // We don't store the full address for security
            secret_path: secret_path.to_string(),
        };

        info!("Successfully loaded and validated credentials from vault");

        Ok(SecureApiCredentials::new_with_source(
            api_id, api_key, source,
        ))
    }
}

/// Load vault configuration from environment variables
pub fn load_vault_config_from_env() -> Result<VaultConfig, CredentialError> {
    debug!("Attempting to load vault configuration from environment");

    let addr = std::env::var("VAULT_CLI_ADDR").map_err(|_| CredentialError::VaultConfigError {
        message: "VAULT_CLI_ADDR not found".to_string(),
    })?;

    let jwt = std::env::var("VAULT_CLI_JWT").map_err(|_| CredentialError::VaultConfigError {
        message: "VAULT_CLI_JWT not found".to_string(),
    })?;

    let role = std::env::var("VAULT_CLI_ROLE").map_err(|_| CredentialError::VaultConfigError {
        message: "VAULT_CLI_ROLE not found".to_string(),
    })?;

    let secret_path =
        std::env::var("VAULT_CLI_SECRET_PATH").map_err(|_| CredentialError::VaultConfigError {
            message: "VAULT_CLI_SECRET_PATH not found".to_string(),
        })?;

    let namespace = std::env::var("VAULT_CLI_NAMESPACE").ok();

    // Validate vault configuration
    validate_vault_config(&addr, &jwt, &role, &secret_path)?;

    info!("Vault configuration loaded successfully from environment");

    Ok(VaultConfig {
        addr,
        jwt,
        role,
        secret_path,
        namespace,
    })
}

/// Load credentials from vault with full error handling
pub async fn load_credentials_from_vault(
    config: VaultConfig,
) -> Result<SecureApiCredentials, CredentialError> {
    info!("Loading credentials from vault at: {}", config.addr);

    let vault_client = VaultCredentialClient::new(&config).await?;
    vault_client.get_credentials(&config.secret_path).await
}

/// Enhanced secure credential loading with vault support and fallback
pub async fn load_secure_api_credentials_with_vault()
-> Result<SecureApiCredentials, CredentialError> {
    debug!("Starting enhanced credential loading with vault support");

    // Priority 1: Try vault configuration
    match load_vault_config_from_env() {
        Ok(vault_config) => {
            info!("Vault configuration found, attempting vault credential retrieval");
            match load_credentials_from_vault(vault_config).await {
                Ok(credentials) => {
                    info!("Successfully loaded credentials from vault");
                    return Ok(credentials);
                }
                Err(e) => {
                    warn!("Vault credential loading failed: {e}");
                    info!("Falling back to environment variables");
                }
            }
        }
        Err(e) => {
            debug!("Vault configuration not available: {e}");
            debug!("Using environment variable fallback");
        }
    }

    // Priority 2: Fallback to environment variables
    crate::credentials::load_secure_api_credentials_from_env()
}

/// Validate vault configuration with input sanitization
fn validate_vault_config(
    addr: &str,
    jwt: &str,
    role: &str,
    secret_path: &str,
) -> Result<(), CredentialError> {
    // Validate vault address (must be HTTPS and reasonable length)
    if !addr.starts_with("https://") {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_ADDR".to_string(),
            message: "Vault address must use HTTPS".to_string(),
        });
    }

    if addr.len() > 150 {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_ADDR".to_string(),
            message: "Vault address too long (max 150 chars)".to_string(),
        });
    }

    // Validate JWT format and length
    if jwt.len() > 50
        || !jwt
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_JWT".to_string(),
            message: "JWT must be alphanumeric with -_. only (max 50 chars)".to_string(),
        });
    }

    // Validate role name
    if role.len() > 50 || role.is_empty() {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_ROLE".to_string(),
            message: "Role name must be 1-50 characters".to_string(),
        });
    }

    // Validate secret path
    if secret_path.len() > 200 || secret_path.is_empty() {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_SECRET_PATH".to_string(),
            message: "Secret path must be 1-200 characters".to_string(),
        });
    }

    debug!("Vault configuration validation passed");
    Ok(())
}

/// Create vault client with retry logic
async fn create_vault_client(config: &VaultConfig) -> Result<VaultClient, CredentialError> {
    debug!("Creating vault client for addr: {}", config.addr);

    // Check for cert validation override (reuse existing verascan pattern)
    let verify_certs = std::env::var("VERASCAN_DISABLE_CERT_VALIDATION")
        .map(|v| v != "true")
        .unwrap_or(true);

    let mut settings_builder = VaultClientSettingsBuilder::default();
    settings_builder.address(&config.addr).verify(verify_certs);

    if let Some(ref namespace) = config.namespace {
        settings_builder.namespace(Some(namespace.clone()));
    }

    let settings = settings_builder
        .build()
        .map_err(|e| CredentialError::VaultConfigError {
            message: format!("Failed to build vault client settings: {e}"),
        })?;

    let client = VaultClient::new(settings).map_err(|e| CredentialError::VaultAuthError {
        context: format!("Failed to create vault client: {e}"),
    })?;

    debug!("Vault client created successfully");
    Ok(client)
}

/// Authenticate with vault using exponential backoff
async fn authenticate_vault(
    client: &VaultClient,
    config: &VaultConfig,
) -> Result<(), CredentialError> {
    info!("Authenticating with vault using OIDC");

    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_millis(500),
        max_interval: Duration::from_secs(8),
        max_elapsed_time: Some(Duration::from_secs(60)),
        multiplier: 2.0,
        ..Default::default()
    };

    let mut backoff = backoff;

    loop {
        match oidc::login(client, &config.role, &config.jwt, config.namespace.clone()).await {
            Ok(_) => {
                info!("Vault authentication successful");
                return Ok(());
            }
            Err(e) => {
                let error_msg = format!("Vault authentication failed: {e}");

                if let Some(delay) = backoff.next_backoff() {
                    warn!("Vault auth failed, retrying in {delay:?}: {error_msg}");
                    tokio::time::sleep(delay).await;
                } else {
                    error!("Vault authentication exhausted all retries");
                    return Err(CredentialError::VaultAuthError { context: error_msg });
                }
            }
        }
    }
}

/// Retrieve credentials from vault with retry logic
async fn retrieve_vault_secret(
    client: &VaultClient,
    secret_path: &str,
) -> Result<HashMap<String, String>, CredentialError> {
    debug!("Retrieving secret from vault path: {secret_path}");

    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_millis(500),
        max_interval: Duration::from_secs(10),
        max_elapsed_time: Some(Duration::from_secs(45)),
        multiplier: 2.0,
        ..Default::default()
    };

    let mut backoff = backoff;

    loop {
        match kv2::read(client, "secret", secret_path).await {
            Ok(secret) => {
                info!("Successfully retrieved secret from vault");
                return Ok(secret);
            }
            Err(e) => {
                let error_msg = format!("Failed to retrieve secret: {e}");

                if let Some(delay) = backoff.next_backoff() {
                    warn!("Secret retrieval failed, retrying in {delay:?}: {error_msg}");
                    tokio::time::sleep(delay).await;
                } else {
                    error!("Secret retrieval exhausted all retries");
                    return Err(CredentialError::VaultSecretError {
                        path: secret_path.to_string(),
                        context: error_msg,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_config_validation_success() {
        let result = validate_vault_config(
            "https://vault.example.com",
            "valid-jwt-123",
            "test-role",
            "secret/path",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_vault_config_validation_non_https() {
        let result = validate_vault_config(
            "http://vault.example.com",
            "valid-jwt-123",
            "test-role",
            "secret/path",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn test_vault_config_validation_long_addr() {
        let long_addr = format!("https://{}.com", "a".repeat(200));
        let result = validate_vault_config(&long_addr, "valid-jwt-123", "test-role", "secret/path");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_vault_config_validation_invalid_jwt() {
        let result = validate_vault_config(
            "https://vault.example.com",
            "invalid@jwt#123",
            "test-role",
            "secret/path",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("JWT"));
    }
}

use crate::credentials::{CredentialError, VaultConfig, validate_api_credential};
use backoff::{ExponentialBackoff, future::retry};
use log::{debug, error, info, warn};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use url::Url;
use vaultrs::{
    auth::oidc,
    client::{Client, VaultClient, VaultClientSettingsBuilder},
    error::ClientError,
    kv2, token,
};

// Character sets for validation
const SPECIAL_CHARS: &[char] = &[
    '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '}', '|', '~',
    '.',
];
const JWT_CHARS: &[char] = &['-', '_', '.'];

// Secret data validation limits
const MAX_SECRET_SIZE_BYTES: usize = 1024 * 1024; // 1MB limit
const MAX_SECRET_KEYS: usize = 100; // Maximum number of keys in secret
const MAX_KEY_LENGTH: usize = 256; // Maximum length for secret key names
const MAX_VALUE_LENGTH: usize = 64 * 1024; // 64KB per secret value

/// Secure HashMap that deserializes string values directly into SecretString
/// This avoids creating intermediate plain text strings during deserialization
#[derive(Debug)]
pub struct SecureSecretMap(HashMap<String, SecretString>);

impl SecureSecretMap {
    /// Get a secret by key
    pub fn get(&self, key: &str) -> Option<&SecretString> {
        self.0.get(key)
    }

    /// Get the number of secrets
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over key-value pairs
    pub fn iter(&self) -> impl Iterator<Item = (&String, &SecretString)> {
        self.0.iter()
    }
}

impl<'de> Deserialize<'de> for SecureSecretMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize as HashMap<String, String> first (unavoidable with serde)
        let plain_map: HashMap<String, String> = HashMap::deserialize(deserializer)?;

        // Immediately convert to SecretString and let the original strings drop
        let secure_map: HashMap<String, SecretString> = plain_map
            .into_iter()
            .map(|(k, v)| (k, SecretString::new(v.into())))
            .collect();

        Ok(SecureSecretMap(secure_map))
    }
}

/// Vault client for secure credential management
pub struct VaultCredentialClient {
    client: VaultClient,
}

impl VaultCredentialClient {
    /// Create a new vault client from configuration
    pub async fn new(config: &VaultConfig) -> Result<Self, CredentialError> {
        let mut client = create_vault_client(config)?;
        authenticate_vault(&mut client, config).await?;

        Ok(Self { client })
    }

    /// Retrieve credentials from vault directly into VeracodeCredentials
    pub async fn get_veracode_credentials(
        &self,
        secret_path: &str,
    ) -> Result<veracode_platform::VeracodeCredentials, CredentialError> {
        let (parsed_secret_path, secret_engine) = parse_secret_path(secret_path);
        let secret_data =
            retrieve_vault_secret(&self.client, &parsed_secret_path, &secret_engine).await?;

        // Validate the secret data before processing
        validate_secret_data(&secret_data)?;

        // Extract API credentials from vault secret
        let api_id_secret = secret_data
            .get("api_id")
            .ok_or_else(|| CredentialError::MissingCredentials {
                missing: "api_id not found in vault secret".to_string(),
            })?
            .clone();

        let api_key_secret = secret_data
            .get("api_secret")
            .ok_or_else(|| CredentialError::MissingCredentials {
                missing: "api_secret not found in vault secret".to_string(),
            })?
            .clone();

        // Validate extracted credentials (temporarily expose for validation only)
        validate_api_credential(api_id_secret.expose_secret(), "api_id from vault").map_err(
            |msg| CredentialError::ValidationError {
                field: "api_id".to_string(),
                message: msg,
            },
        )?;

        validate_api_credential(api_key_secret.expose_secret(), "api_secret from vault").map_err(
            |msg| CredentialError::ValidationError {
                field: "api_secret".to_string(),
                message: msg,
            },
        )?;

        info!("Successfully loaded and validated credentials from vault");

        // Create VeracodeCredentials using the public constructor
        // Note: This momentarily exposes secrets but VeracodeCredentials::new() immediately
        // wraps them in Arc<SecretString> for secure storage
        Ok(veracode_platform::VeracodeCredentials::new(
            api_id_secret.expose_secret().to_string(),
            api_key_secret.expose_secret().to_string(),
        ))
    }

    /// Revoke the vault token after use
    pub async fn revoke_token(&self) -> Result<(), CredentialError> {
        revoke_vault_token(&self.client).await
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

    let auth_path = std::env::var("VAULT_CLI_AUTH_PATH").unwrap_or_else(|_| "auth/jwt".to_string()); // Default to "auth/jwt" if not specified

    // Validate vault configuration
    validate_vault_config(&addr, &jwt, &role, &secret_path, &auth_path)?;

    info!("Vault configuration loaded successfully from environment");

    Ok(VaultConfig {
        addr,
        jwt,
        role,
        secret_path,
        namespace,
        auth_path,
    })
}

/// Load credentials from vault directly into VeracodeCredentials
pub async fn load_veracode_credentials_from_vault(
    config: VaultConfig,
) -> Result<veracode_platform::VeracodeCredentials, CredentialError> {
    info!("Loading credentials from vault at: {}", config.addr);

    let vault_client = VaultCredentialClient::new(&config).await?;
    let credentials = vault_client
        .get_veracode_credentials(&config.secret_path)
        .await?;

    // Revoke the token after successful credential retrieval for security
    if let Err(e) = vault_client.revoke_token().await {
        warn!("Token revocation failed, but credential retrieval was successful: {e}");
        // Continue - token revocation failure shouldn't prevent successful completion
    } else {
        debug!("Vault token revoked successfully after credential retrieval");
    }

    Ok(credentials)
}

/// Load VeracodeCredentials with vault support and environment fallback
pub async fn load_veracode_credentials_with_vault()
-> Result<veracode_platform::VeracodeCredentials, CredentialError> {
    // Priority 1: Try vault configuration
    match load_vault_config_from_env() {
        Ok(vault_config) => {
            info!("Vault configuration found, attempting vault credential retrieval");
            match load_veracode_credentials_from_vault(vault_config).await {
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
            info!("Vault configuration not available: {e}");
            debug!("Using environment variable fallback");
        }
    }

    // Priority 2: Fallback to environment variables
    crate::credentials::load_veracode_credentials_from_env()
}

/// Validate vault configuration with comprehensive input sanitization
fn validate_vault_config(
    addr: &str,
    jwt: &str,
    role: &str,
    secret_path: &str,
    auth_path: &str,
) -> Result<(), CredentialError> {
    // Validate vault address with URL parsing
    validate_vault_addr(addr)?;
    validate_jwt_token(jwt)?;
    validate_role(role)?;
    validate_secret_path(secret_path)?;
    validate_auth_path(auth_path)?;

    debug!("Vault configuration validation passed");
    Ok(())
}

fn validate_vault_addr(addr: &str) -> Result<(), CredentialError> {
    if addr.len() > 150 {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_ADDR".to_string(),
            message: "VAULT_CLI_ADDR must not exceed 150 characters.".to_string(),
        });
    }
    match Url::parse(addr) {
        Ok(url) => {
            if url.scheme() != "https" {
                return Err(CredentialError::ValidationError {
                    field: "VAULT_CLI_ADDR".to_string(),
                    message: "VAULT_CLI_ADDR must use HTTPS protocol".to_string(),
                });
            }
        }
        Err(_) => {
            return Err(CredentialError::ValidationError {
                field: "VAULT_CLI_ADDR".to_string(),
                message: "VAULT_CLI_ADDR must be a valid URL".to_string(),
            });
        }
    }
    Ok(())
}

fn validate_jwt_token(token: &str) -> Result<(), CredentialError> {
    if token.len() > 20000 {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_JWT".to_string(),
            message: "VAULT_CLI_JWT must not exceed 20000 characters.".to_string(),
        });
    }
    let allowed_jwt = |c: char| c.is_ascii_alphanumeric() || JWT_CHARS.contains(&c);
    if !token.chars().all(allowed_jwt) {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_JWT".to_string(),
            message: "VAULT_CLI_JWT contains invalid characters. Allowed: a-z, A-Z, 0-9, '-', '_', '.' (dot as separator)".to_string(),
        });
    }
    Ok(())
}

fn validate_role(role: &str) -> Result<(), CredentialError> {
    if role.len() > 100 {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_ROLE".to_string(),
            message: "VAULT_CLI_ROLE must not exceed 100 characters.".to_string(),
        });
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || SPECIAL_CHARS.contains(&c);
    if !role.chars().all(allowed) {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_ROLE".to_string(),
            message: "VAULT_CLI_ROLE contains invalid characters. Allowed: alphanumeric and ! # $ % & ' * + - / = ? ^ _ ` { } | ~ .".to_string(),
        });
    }
    Ok(())
}

fn validate_secret_path(path: &str) -> Result<(), CredentialError> {
    if path.len() > 200 {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_SECRET_PATH".to_string(),
            message: "VAULT_CLI_SECRET_PATH must not exceed 200 characters.".to_string(),
        });
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || SPECIAL_CHARS.contains(&c) || c == '@';
    if !path.chars().all(allowed) {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_SECRET_PATH".to_string(),
            message: "VAULT_CLI_SECRET_PATH contains invalid characters. Allowed: alphanumeric and ! # $ % & ' * + - / = ? ^ _ ` { } | ~ . @".to_string(),
        });
    }
    Ok(())
}

fn validate_auth_path(auth_path: &str) -> Result<(), CredentialError> {
    if auth_path.len() > 100 {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_AUTH_PATH".to_string(),
            message: "VAULT_CLI_AUTH_PATH must not exceed 100 characters.".to_string(),
        });
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '/' || c == '-' || c == '_';
    if !auth_path.chars().all(allowed) {
        return Err(CredentialError::ValidationError {
            field: "VAULT_CLI_AUTH_PATH".to_string(),
            message:
                "VAULT_CLI_AUTH_PATH contains invalid characters. Allowed: alphanumeric and / - _"
                    .to_string(),
        });
    }
    Ok(())
}

/// Create vault client with retry logic
fn create_vault_client(config: &VaultConfig) -> Result<VaultClient, CredentialError> {
    debug!("Creating vault client for addr: {}", config.addr);

    // Check for cert validation override (reuse existing veracmek pattern)
    let verify_certs = std::env::var("VERACMEK_DISABLE_CERT_VALIDATION")
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

/// Authenticate with vault using exponential backoff and proper token management
async fn authenticate_vault(
    client: &mut VaultClient,
    config: &VaultConfig,
) -> Result<(), CredentialError> {
    info!("Authenticating with vault using OIDC");

    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_millis(500),
        max_interval: Duration::from_secs(10),
        max_elapsed_time: Some(Duration::from_secs(60)),
        multiplier: 2.0,
        ..Default::default()
    };

    // Extract mount point from configurable auth path
    let auth_path = &config.auth_path;
    let mount_point = if let Some(stripped) = auth_path.strip_prefix("auth/") {
        stripped // Remove "auth/" prefix
    } else {
        auth_path // Use as-is if it doesn't start with "auth/"
    };
    debug!(
        "Using auth_path='{auth_path}', mount_point='{mount_point}', role='{}'",
        config.role
    );

    let operation = || async {
        debug!("Attempting JWT login...");
        match oidc::login(client, mount_point, &config.jwt, Some(config.role.clone())).await {
            Ok(auth_info) => {
                info!("JWT authentication successful");
                Ok(auth_info)
            }
            Err(e) => {
                warn!("JWT authentication failed: {e}");

                // Pattern match on specific error types for better error handling
                match &e {
                    // Certificate/TLS errors should not be retried
                    ClientError::RestClientBuildError { source } => {
                        error!(
                            "REST client build error (likely TLS/certificate issue) - not retrying: {source}"
                        );
                        Err(backoff::Error::permanent(CredentialError::VaultAuthError {
                            context: format!("TLS/certificate error: {source}"),
                        }))
                    }
                    // API errors (like 401 Unauthorized) should not be retried
                    ClientError::APIError { code, errors: _ } if *code == 401 || *code == 403 => {
                        error!("Authentication failed with HTTP {code} - not retrying");
                        Err(backoff::Error::permanent(CredentialError::VaultAuthError {
                            context: format!("Authentication failed with HTTP {code}"),
                        }))
                    }
                    // Other API errors might be retryable (5xx server errors)
                    ClientError::APIError { code, errors: _ } if *code >= 500 => {
                        debug!("Server error HTTP {code} - retrying");
                        Err(backoff::Error::transient(CredentialError::VaultAuthError {
                            context: format!("Server error HTTP {code}"),
                        }))
                    }
                    // Handle RestClientError with detailed TLS/certificate detection
                    ClientError::RestClientError { source } => {
                        // Log the full error chain for debugging
                        error!("REST client error details: {source}");
                        let mut error_source = source.source();
                        let mut level = 1;
                        while let Some(err) = error_source {
                            error!("Error source level {level}: {err}");
                            error_source = err.source();
                            level += 1;
                        }

                        // Check the underlying error message for TLS/certificate issues
                        let error_msg = format!("{source}");
                        if error_msg.contains("certificate")
                            || error_msg.contains("tls")
                            || error_msg.contains("ssl")
                            || error_msg.contains("Certificate")
                            || error_msg.contains("TLS")
                            || error_msg.contains("SSL")
                        {
                            error!("Certificate/TLS error in request - not retrying: {source}");
                            Err(backoff::Error::permanent(CredentialError::VaultAuthError {
                                context: format!("TLS/certificate error: {source}"),
                            }))
                        } else if error_msg.contains("connection")
                            || error_msg.contains("timeout")
                            || error_msg.contains("rate limit")
                            || error_msg.contains("server error")
                        {
                            debug!("Retryable request error - retrying: {source}");
                            Err(backoff::Error::transient(CredentialError::VaultAuthError {
                                context: format!("Network error: {source}"),
                            }))
                        } else {
                            debug!("Unknown request error - retrying: {source}");
                            Err(backoff::Error::transient(CredentialError::VaultAuthError {
                                context: format!("Request error: {source}"),
                            }))
                        }
                    }
                    // Parse certificate errors should not be retried
                    ClientError::ParseCertificateError { source, path } => {
                        error!("Certificate parsing error at {path} - not retrying: {source}");
                        Err(backoff::Error::permanent(CredentialError::VaultAuthError {
                            context: format!("Certificate parsing error at {path}: {source}"),
                        }))
                    }
                    // All other errors - default to retrying
                    _ => {
                        debug!("Other error during authentication - retrying: {e}");
                        Err(backoff::Error::transient(CredentialError::VaultAuthError {
                            context: format!("Authentication error: {e}"),
                        }))
                    }
                }
            }
        }
    };

    let auth_info =
        retry(backoff, operation)
            .await
            .map_err(|_| CredentialError::VaultAuthError {
                context: "Authentication failed after all retry attempts".to_string(),
            })?;

    // CRITICAL FIX: Set the token on the client for subsequent requests
    client.set_token(&auth_info.client_token);
    debug!("Token set on client for future requests");

    Ok(())
}

/// Retrieve credentials from vault with comprehensive error handling and retry logic
/// Uses secure deserialization to minimize plain text exposure in memory
async fn retrieve_vault_secret(
    client: &VaultClient,
    secret_path: &str,
    secret_engine: &str,
) -> Result<SecureSecretMap, CredentialError> {
    debug!("Retrieving secret from vault path: {secret_path} using engine: {secret_engine}");

    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_millis(500),
        max_interval: Duration::from_secs(8),
        max_elapsed_time: Some(Duration::from_secs(45)),
        multiplier: 2.0,
        ..Default::default()
    };

    let operation = || async {
        debug!("Attempting secret retrieval...");
        match kv2::read::<SecureSecretMap>(client, secret_engine, secret_path).await {
            Ok(secure_secret) => {
                info!("Successfully retrieved secret from path: {secret_path}");
                Ok(secure_secret)
            }
            Err(e) => {
                warn!("Secret retrieval failed: {e}");

                // Pattern match on specific error types for better error handling
                match &e {
                    // API errors (like 401 Unauthorized, 403 Forbidden) should not be retried
                    ClientError::APIError { code, errors: _ } if *code == 401 || *code == 403 => {
                        error!("Access denied with HTTP {code} - not retrying");
                        Err(backoff::Error::permanent(
                            CredentialError::VaultSecretError {
                                path: secret_path.to_string(),
                                context: format!("Access denied with HTTP {code}"),
                            },
                        ))
                    }
                    // 404 Not Found should not be retried
                    ClientError::APIError { code, errors: _ } if *code == 404 => {
                        error!("Secret not found with HTTP {code} - not retrying");
                        Err(backoff::Error::permanent(
                            CredentialError::VaultSecretError {
                                path: secret_path.to_string(),
                                context: format!("Secret not found with HTTP {code}"),
                            },
                        ))
                    }
                    // Other 4xx client errors should not be retried
                    ClientError::APIError { code, errors: _ } if *code >= 400 && *code < 500 => {
                        error!("Client error HTTP {code} - not retrying");
                        Err(backoff::Error::permanent(
                            CredentialError::VaultSecretError {
                                path: secret_path.to_string(),
                                context: format!("Client error HTTP {code}"),
                            },
                        ))
                    }
                    // 5xx server errors might be retryable
                    ClientError::APIError { code, errors: _ } if *code >= 500 => {
                        debug!("Server error HTTP {code} - retrying");
                        Err(backoff::Error::transient(
                            CredentialError::VaultSecretError {
                                path: secret_path.to_string(),
                                context: format!("Server error HTTP {code}"),
                            },
                        ))
                    }
                    // For non-API errors, check error message content
                    _ => {
                        let error_msg = format!("{e}");
                        if error_msg.contains("connection")
                            || error_msg.contains("timeout")
                            || error_msg.contains("rate limit")
                            || error_msg.contains("server error")
                        {
                            debug!("Retryable error during secret retrieval - retrying...");
                            Err(backoff::Error::transient(
                                CredentialError::VaultSecretError {
                                    path: secret_path.to_string(),
                                    context: error_msg,
                                },
                            ))
                        } else if error_msg.contains("not found")
                            || error_msg.contains("forbidden")
                            || error_msg.contains("unauthorized")
                        {
                            debug!("Permanent error during secret retrieval - not retrying");
                            Err(backoff::Error::permanent(
                                CredentialError::VaultSecretError {
                                    path: secret_path.to_string(),
                                    context: error_msg,
                                },
                            ))
                        } else {
                            debug!("Unknown error during secret retrieval - retrying...");
                            Err(backoff::Error::transient(
                                CredentialError::VaultSecretError {
                                    path: secret_path.to_string(),
                                    context: error_msg,
                                },
                            ))
                        }
                    }
                }
            }
        }
    };

    retry(backoff, operation)
        .await
        .map_err(|_| CredentialError::VaultSecretError {
            path: secret_path.to_string(),
            context: "Secret retrieval failed after all retry attempts".to_string(),
        })
}

/// Parse secret path to extract engine name and path
fn parse_secret_path(full_path: &str) -> (String, String) {
    if let Some(at_pos) = full_path.rfind('@') {
        let secret_path = full_path[..at_pos].to_string();
        let secret_engine = full_path[at_pos + 1..].to_string();
        if secret_engine.is_empty() {
            // If @ is present but engine is empty, default to kvv2
            (secret_path, "kvv2".to_string())
        } else {
            (secret_path, secret_engine)
        }
    } else {
        // No @ symbol found, default to kvv2
        (full_path.to_string(), "kvv2".to_string())
    }
}

/// Validate secret data retrieved from vault
fn validate_secret_data(secret: &SecureSecretMap) -> Result<(), CredentialError> {
    // Check total number of keys
    if secret.len() > MAX_SECRET_KEYS {
        return Err(CredentialError::ValidationError {
            field: "secret_data".to_string(),
            message: format!(
                "Secret contains too many keys: {} (max: {})",
                secret.len(),
                MAX_SECRET_KEYS
            ),
        });
    }

    if secret.is_empty() {
        return Err(CredentialError::ValidationError {
            field: "secret_data".to_string(),
            message: "Secret data is empty".to_string(),
        });
    }

    let mut total_size = 0;

    for (key, value) in secret.iter() {
        // Validate key length
        if key.len() > MAX_KEY_LENGTH {
            return Err(CredentialError::ValidationError {
                field: "secret_key".to_string(),
                message: format!(
                    "Secret key '{}' exceeds maximum length: {} (max: {})",
                    key,
                    key.len(),
                    MAX_KEY_LENGTH
                ),
            });
        }

        // Validate value length (need to expose secret temporarily for validation)
        let value_len = value.expose_secret().len();
        if value_len > MAX_VALUE_LENGTH {
            return Err(CredentialError::ValidationError {
                field: "secret_value".to_string(),
                message: format!(
                    "Secret value for key '{}' exceeds maximum length: {} (max: {})",
                    key, value_len, MAX_VALUE_LENGTH
                ),
            });
        }

        // Check for suspicious key names
        if key.trim().is_empty() {
            return Err(CredentialError::ValidationError {
                field: "secret_key".to_string(),
                message: "Secret key cannot be empty or whitespace only".to_string(),
            });
        }

        // Validate key contains only safe characters
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-/.".contains(c))
        {
            return Err(CredentialError::ValidationError {
                field: "secret_key".to_string(),
                message: format!(
                    "Secret key '{key}' contains invalid characters. Allowed: alphanumeric, _, -, /, ."
                ),
            });
        }

        // Check for null bytes or other dangerous content
        let value_str = value.expose_secret();
        if key.contains('\0') || value_str.contains('\0') {
            return Err(CredentialError::ValidationError {
                field: "secret_data".to_string(),
                message: "Secret data contains null bytes".to_string(),
            });
        }

        // Accumulate total size
        total_size += key.len() + value_len;
    }

    // Check total size limit
    if total_size > MAX_SECRET_SIZE_BYTES {
        return Err(CredentialError::ValidationError {
            field: "secret_data".to_string(),
            message: format!(
                "Total secret size exceeds limit: {total_size} bytes (max: {MAX_SECRET_SIZE_BYTES})"
            ),
        });
    }

    Ok(())
}

/// Revoke vault token with retry logic
async fn revoke_vault_token(client: &VaultClient) -> Result<(), CredentialError> {
    debug!("Attempting to revoke Vault token with retry logic...");

    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_millis(250),
        max_interval: Duration::from_secs(5),
        max_elapsed_time: Some(Duration::from_secs(30)),
        multiplier: 2.0,
        ..Default::default()
    };

    let operation = || async {
        debug!("Attempting token revocation...");
        match token::revoke_self(client).await {
            Ok(_) => {
                info!("Successfully revoked Vault token");
                Ok(())
            }
            Err(e) => {
                warn!("Token revocation failed: {e}");

                // Pattern match on specific error types for better error handling
                match &e {
                    // API errors (like 401 Unauthorized, 403 Forbidden) should not be retried
                    ClientError::APIError { code, errors: _ } if *code == 401 || *code == 403 => {
                        error!("Token revocation access denied with HTTP {code} - not retrying");
                        Err(backoff::Error::permanent(CredentialError::VaultAuthError {
                            context: format!("Token revocation access denied with HTTP {code}"),
                        }))
                    }
                    // Other 4xx client errors should not be retried
                    ClientError::APIError { code, errors: _ } if *code >= 400 && *code < 500 => {
                        error!("Token revocation client error HTTP {code} - not retrying");
                        Err(backoff::Error::permanent(CredentialError::VaultAuthError {
                            context: format!("Token revocation client error with HTTP {code}"),
                        }))
                    }
                    // 5xx server errors might be retryable
                    ClientError::APIError { code, errors: _ } if *code >= 500 => {
                        debug!("Token revocation server error HTTP {code} - retrying");
                        Err(backoff::Error::transient(CredentialError::VaultAuthError {
                            context: format!("Token revocation server error with HTTP {code}"),
                        }))
                    }
                    // For non-API errors, check error message content
                    _ => {
                        let error_msg = format!("{e}");
                        if error_msg.contains("connection")
                            || error_msg.contains("timeout")
                            || error_msg.contains("rate limit")
                            || error_msg.contains("server error")
                        {
                            debug!("Retryable error during token revocation - retrying...");
                            Err(backoff::Error::transient(CredentialError::VaultAuthError {
                                context: format!("Network error during revocation: {error_msg}"),
                            }))
                        } else {
                            debug!("Non-retryable revocation error - failing permanently");
                            Err(backoff::Error::permanent(CredentialError::VaultAuthError {
                                context: format!("Token revocation error: {error_msg}"),
                            }))
                        }
                    }
                }
            }
        }
    };

    retry(backoff, operation)
        .await
        .map_err(|_| CredentialError::VaultAuthError {
            context: "Token revocation failed after all retry attempts".to_string(),
        })
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
            "auth/jwt",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_vault_config_validation_with_engine() {
        let result = validate_vault_config(
            "https://vault.example.com",
            "valid-jwt-123",
            "test-role",
            "secret/path@kvv2",
            "auth/jwt",
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
            "auth/jwt",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn test_parse_secret_path() {
        // Test with engine specified
        let (path, engine) = parse_secret_path("my/test/path@kvv2");
        assert_eq!(path, "my/test/path");
        assert_eq!(engine, "kvv2");

        // Test with different engine
        let (path, engine) = parse_secret_path("my/other/test@secret");
        assert_eq!(path, "my/other/test");
        assert_eq!(engine, "secret");

        // Test without engine (should default to kvv2)
        let (path, engine) = parse_secret_path("my/test/path");
        assert_eq!(path, "my/test/path");
        assert_eq!(engine, "kvv2");

        // Test with @ but empty engine (should default to kvv2)
        let (path, engine) = parse_secret_path("my/test/path@");
        assert_eq!(path, "my/test/path");
        assert_eq!(engine, "kvv2");
    }

    #[test]
    fn test_validate_secret_data_valid() {
        let mut map = HashMap::new();
        map.insert("api_id".to_string(), SecretString::new("user123".into()));
        map.insert(
            "api_secret".to_string(),
            SecretString::new("secret_key".into()),
        );
        let secret = SecureSecretMap(map);

        assert!(validate_secret_data(&secret).is_ok());
    }

    #[test]
    fn test_validate_secret_data_empty() {
        let map: HashMap<String, SecretString> = HashMap::new();
        let secret = SecureSecretMap(map);
        assert!(validate_secret_data(&secret).is_err());
    }

    #[test]
    fn test_validate_secret_data_too_many_keys() {
        let mut map = HashMap::new();
        for i in 0..101 {
            // Exceeds MAX_SECRET_KEYS (100)
            map.insert(format!("key{i}"), SecretString::new("value".into()));
        }
        let secret = SecureSecretMap(map);
        assert!(validate_secret_data(&secret).is_err());
    }

    #[test]
    fn test_auth_path_validation_success() {
        let result = validate_auth_path("auth/jwt");
        assert!(result.is_ok());

        let result = validate_auth_path("auth/custom");
        assert!(result.is_ok());

        let result = validate_auth_path("auth/my-auth");
        assert!(result.is_ok());

        let result = validate_auth_path("jwt");
        assert!(result.is_ok());
    }

    #[test]
    fn test_auth_path_validation_invalid_chars() {
        let result = validate_auth_path("auth/jwt@invalid");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid characters")
        );
    }

    #[test]
    fn test_auth_path_validation_too_long() {
        let long_path = format!("auth/{}", "a".repeat(100));
        let result = validate_auth_path(&long_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceed"));
    }
}

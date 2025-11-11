use crate::credentials::{CredentialError, VaultConfig, validate_api_credential};
use backon::{ExponentialBuilder, Retryable};
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

/// Secure `HashMap` that deserializes string values directly into `SecretString`
/// This avoids creating intermediate plain text strings during deserialization
#[derive(Debug)]
pub struct SecureSecretMap(HashMap<String, SecretString>);

impl SecureSecretMap {
    /// Get a secret by key
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&SecretString> {
        self.0.get(key)
    }

    /// Get the number of secrets
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    #[must_use]
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
    ///
    /// # Errors
    ///
    /// Returns error if vault client creation or authentication fails
    pub async fn new(config: &VaultConfig) -> Result<Self, CredentialError> {
        let mut client = create_vault_client(config)?;
        authenticate_vault(&mut client, config).await?;

        Ok(Self { client })
    }

    /// Retrieve credentials from vault directly into `VeracodeCredentials`
    ///
    /// # Errors
    ///
    /// Returns error if vault secret retrieval or validation fails
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

    /// Retrieve optional proxy credentials from vault
    /// Returns (`proxy_url`, `proxy_username`, `proxy_password`) as optional values
    ///
    /// # Errors
    ///
    /// Returns error if vault secret retrieval or validation fails
    pub async fn get_proxy_credentials(
        &self,
        secret_path: &str,
    ) -> Result<(Option<String>, Option<String>, Option<String>), CredentialError> {
        let (parsed_secret_path, secret_engine) = parse_secret_path(secret_path);
        let secret_data =
            retrieve_vault_secret(&self.client, &parsed_secret_path, &secret_engine).await?;

        // Validate the secret data before processing
        validate_secret_data(&secret_data)?;

        // Extract optional proxy credentials from vault secret
        let proxy_url = secret_data
            .get("proxy_url")
            .map(|s| s.expose_secret().to_string());

        let proxy_username = secret_data
            .get("proxy_username")
            .map(|s| s.expose_secret().to_string());

        let proxy_password = secret_data
            .get("proxy_password")
            .map(|s| s.expose_secret().to_string());

        if proxy_url.is_some() {
            info!("Proxy configuration found in vault secret");
        }

        Ok((proxy_url, proxy_username, proxy_password))
    }

    /// Revoke the vault token after use
    ///
    /// # Errors
    ///
    /// Returns error if vault token revocation fails
    pub async fn revoke_token(&self) -> Result<(), CredentialError> {
        revoke_vault_token(&self.client).await
    }
}

/// Load vault configuration from environment variables
///
/// # Errors
///
/// Returns error if required environment variables are missing or validation fails
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

/// Load `VeracodeCredentials` and proxy configuration from Vault with environment fallback
/// Returns (credentials, `proxy_url`, `proxy_username`, `proxy_password`)
///
/// # Errors
///
/// Returns error if vault configuration loading, authentication, or credential retrieval fails
pub async fn load_credentials_and_proxy_from_vault() -> Result<
    (
        veracode_platform::VeracodeCredentials,
        Option<String>,
        Option<String>,
        Option<String>,
    ),
    CredentialError,
> {
    // Priority 1: Try vault configuration
    match load_vault_config_from_env() {
        Ok(vault_config) => {
            info!("Vault configuration found, attempting vault credential and proxy retrieval");

            let vault_client = VaultCredentialClient::new(&vault_config).await?;

            // Load credentials
            let credentials = vault_client
                .get_veracode_credentials(&vault_config.secret_path)
                .await?;

            // Load optional proxy credentials
            let (proxy_url, proxy_username, proxy_password) = vault_client
                .get_proxy_credentials(&vault_config.secret_path)
                .await?;

            // Revoke the token after successful credential retrieval for security
            if let Err(e) = vault_client.revoke_token().await {
                warn!("Token revocation failed, but credential retrieval was successful: {e}");
            } else {
                debug!("Vault token revoked successfully after credential retrieval");
            }

            info!("Successfully loaded credentials and proxy configuration from vault");
            return Ok((credentials, proxy_url, proxy_username, proxy_password));
        }
        Err(e) => {
            info!("Vault configuration not available: {e}");
            debug!("Using environment variable fallback");
        }
    }

    // Priority 2: Fallback to environment variables
    let credentials = crate::credentials::load_veracode_credentials_from_env()?;
    Ok((credentials, None, None, None))
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

    let auth_info = (|| async {
        debug!("Attempting JWT login...");
        oidc::login(client, mount_point, &config.jwt, Some(config.role.clone())).await
    })
    .retry(
        ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(500))
            .with_max_delay(Duration::from_secs(10))
            .with_max_times(10) // Approximately 60 seconds with exponential backoff
            .with_factor(2.0),
    )
    .when(|e: &ClientError| is_retryable_vault_error(e))
    .await
    .map_err(|e| {
        warn!("JWT authentication failed: {e}");
        classify_vault_error(&e, "Authentication", |context| {
            CredentialError::VaultAuthError { context }
        })
    })?;

    info!("JWT authentication successful");

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

    (|| async {
        debug!("Attempting secret retrieval...");
        kv2::read::<SecureSecretMap>(client, secret_engine, secret_path).await
    })
    .retry(
        ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(500))
            .with_max_delay(Duration::from_secs(8))
            .with_max_times(8) // Approximately 45 seconds with exponential backoff
            .with_factor(2.0),
    )
    .when(|e: &ClientError| is_retryable_vault_error(e))
    .await
    .map_err(|e| {
        warn!("Secret retrieval failed: {e}");
        classify_vault_error(&e, "Secret retrieval", |context| {
            CredentialError::VaultSecretError {
                path: secret_path.to_string(),
                context,
            }
        })
    })
    .inspect(|_| {
        info!("Successfully retrieved secret from path: {secret_path}");
    })
}

/// Parse secret path to extract engine name and path
fn parse_secret_path(full_path: &str) -> (String, String) {
    if let Some(at_pos) = full_path.rfind('@') {
        let secret_path = full_path.get(..at_pos).unwrap_or(full_path).to_string();
        let secret_engine = full_path
            .get(at_pos.saturating_add(1)..)
            .unwrap_or("")
            .to_string();
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

    let mut total_size: usize = 0;

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
        total_size = total_size
            .saturating_add(key.len())
            .saturating_add(value_len);
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

    (|| async {
        debug!("Attempting token revocation...");
        token::revoke_self(client).await
    })
    .retry(
        ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(250))
            .with_max_delay(Duration::from_secs(5))
            .with_max_times(7) // Approximately 30 seconds with exponential backoff
            .with_factor(2.0),
    )
    .when(|e: &ClientError| is_retryable_vault_error(e))
    .await
    .map_err(|e| {
        warn!("Token revocation failed: {e}");
        classify_vault_error(&e, "Token revocation", |context| {
            CredentialError::VaultAuthError { context }
        })
    })
    .map(|_| {
        info!("Successfully revoked Vault token");
    })
}

/// Checks if an error chain contains a certificate/TLS error by traversing
/// the error source chain and checking for specific rustls error types.
///
/// This uses proper type-based error detection instead of fragile string matching.
fn is_certificate_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&dyn std::error::Error> = Some(error);

    while let Some(err) = current {
        // Check for rustls::Error - requires rustls to be in scope
        // We check the error type name as a fallback since rustls is a transitive dependency
        let error_type = format!("{:?}", err);

        // Check for io::Error with InvalidData kind (often wraps rustls errors)
        if let Some(io_err) = err.downcast_ref::<std::io::Error>()
            && io_err.kind() == std::io::ErrorKind::InvalidData
        {
            // Check the inner error recursively
            if let Some(inner) = io_err.get_ref()
                && is_certificate_error(inner)
            {
                return true;
            }
            // Also check if this InvalidData error mentions certificate issues
            let io_msg = format!("{}", io_err).to_lowercase();
            if io_msg.contains("certificate") || io_msg.contains("invalidcertificate") {
                return true;
            }
        }

        // Check error debug representation for rustls certificate errors
        // This catches rustls::Error::InvalidCertificate and related variants
        if error_type.contains("InvalidCertificate")
            || error_type.contains("NoCertificatesPresented")
            || error_type.contains("UnsupportedNameType")
        {
            return true;
        }

        // Move to next error in chain
        current = err.source();
    }

    false
}

/// Checks if an error chain contains a retryable network error
/// by traversing the error source chain and checking for specific error types.
fn is_network_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&dyn std::error::Error> = Some(error);

    while let Some(err) = current {
        // Check for io::Error with retryable kinds
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            #[allow(clippy::wildcard_enum_match_arm)]
            match io_err.kind() {
                std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::WouldBlock => return true,
                _ => {}
            }
        }

        // Check error debug representation for network-related errors
        let error_type = format!("{:?}", err);
        if error_type.contains("Timeout") || error_type.contains("TimedOut") {
            return true;
        }

        // Move to next error in chain
        current = err.source();
    }

    false
}

/// Determine if a `ClientError` should be retried based on error type
///
/// Returns true for transient/retryable errors, false for permanent errors
fn is_retryable_vault_error(error: &ClientError) -> bool {
    match error {
        // Certificate/TLS Errors - NEVER retry
        ClientError::RestClientBuildError { .. } |
        ClientError::ParseCertificateError { .. } |
        // File Errors - NEVER retry
        ClientError::FileNotFoundError { .. } |
        ClientError::FileReadError { .. } |
        ClientError::FileWriteError { .. } |
        // Configuration/Validation Errors - NEVER retry
        ClientError::InvalidLoginMethodError |
        ClientError::InvalidUpdateParameter |
        ClientError::WrapInvalidError |
        // Data Parsing/Response Errors - NEVER retry
        ClientError::JsonParseError { .. } |
        ClientError::ResponseEmptyError |
        ClientError::ResponseDataEmptyError |
        ClientError::ResponseWrapError => false,

        // HTTP API Errors - Classify by status code
        ClientError::APIError { code, .. } => {
            match *code {
                // Transient Errors (Retryable)
                412 | 429 | 472 | 473 | 500 | 502 | 503 => true,
                // HTTP 501 is permanent (Vault not initialized)
                501 => false,
                // 4xx errors are permanent (client errors)
                400..=499 => false,
                // Other 5xx errors are transient (server errors)
                500..=599 => true,
                // Unexpected status codes - default to permanent (safe default)
                _ => false,
            }
        }

        // RestClientError - Type-based error detection
        ClientError::RestClientError { source } => {
            // Certificate/TLS errors are not retryable
            if is_certificate_error(source) {
                false
            }
            // Network errors are retryable
            else if is_network_error(source) {
                true
            }
            // Unknown REST client errors - default to permanent (safe default)
            else {
                false
            }
        }
    }
}

/// Classify a `ClientError` and create a `CredentialError` with proper context
///
/// This function implements proper error handling based on:
/// - Vault API documentation for HTTP status codes
/// - vaultrs `ClientError` variants
/// - Provides detailed error messages for debugging
fn classify_vault_error<E>(
    error: &ClientError,
    operation_context: &str,
    error_constructor: impl Fn(String) -> E,
) -> E {
    match error {
        // Certificate/TLS Errors
        ClientError::RestClientBuildError { source } => {
            error!(
                "{operation_context}: REST client build error (likely TLS/certificate) - not retrying: {source}"
            );
            error_constructor(format!("REST client build error: {source}"))
        }

        ClientError::ParseCertificateError { source, path } => {
            error!(
                "{operation_context}: Certificate parsing error at {path} - not retrying: {source}"
            );
            error_constructor(format!("Certificate parsing error at {path}: {source}"))
        }

        // File Errors
        ClientError::FileNotFoundError { path } => {
            error!("{operation_context}: File not found: {path} - not retrying");
            error_constructor(format!("File not found: {path}"))
        }

        ClientError::FileReadError { source, path } => {
            error!("{operation_context}: File read error at {path} - not retrying: {source}");
            error_constructor(format!("File read error at {path}: {source}"))
        }

        ClientError::FileWriteError { source, path } => {
            error!("{operation_context}: File write error at {path} - not retrying: {source}");
            error_constructor(format!("File write error at {path}: {source}"))
        }

        // Configuration/Validation Errors
        ClientError::InvalidLoginMethodError => {
            error!("{operation_context}: Invalid login method - not retrying");
            error_constructor("Invalid login method".to_string())
        }

        ClientError::InvalidUpdateParameter => {
            error!("{operation_context}: Invalid update parameter - not retrying");
            error_constructor("Invalid update parameter".to_string())
        }

        ClientError::WrapInvalidError => {
            error!("{operation_context}: Invalid wrap operation - not retrying");
            error_constructor("Invalid wrap operation".to_string())
        }

        // Data Parsing/Response Errors
        ClientError::JsonParseError { source } => {
            error!("{operation_context}: JSON parsing error - not retrying: {source}");
            error_constructor(format!("JSON parsing error: {source}"))
        }

        ClientError::ResponseEmptyError => {
            error!("{operation_context}: Response empty - not retrying");
            error_constructor("Empty response when data expected".to_string())
        }

        ClientError::ResponseDataEmptyError => {
            error!("{operation_context}: Response data empty - not retrying");
            error_constructor("Empty response data".to_string())
        }

        ClientError::ResponseWrapError => {
            error!("{operation_context}: Response wrap error - not retrying");
            error_constructor("Response wrap error".to_string())
        }

        // HTTP API Errors
        ClientError::APIError { code, errors } => {
            let error_details = if !errors.is_empty() {
                format!(": {}", errors.join(", "))
            } else {
                String::new()
            };

            match *code {
                // Transient Errors (Retryable)
                412 => {
                    debug!(
                        "{operation_context}: Precondition failed (HTTP 412){error_details} - retrying"
                    );
                    error_constructor(format!(
                        "Precondition failed - eventually consistent data missing (HTTP 412){error_details}"
                    ))
                }
                429 => {
                    debug!(
                        "{operation_context}: Standby node (HTTP 429){error_details} - retrying"
                    );
                    error_constructor(format!("Standby node status (HTTP 429){error_details}"))
                }
                472 => {
                    debug!(
                        "{operation_context}: DR replication secondary (HTTP 472){error_details} - retrying"
                    );
                    error_constructor(format!(
                        "DR replication secondary (HTTP 472){error_details}"
                    ))
                }
                473 => {
                    debug!(
                        "{operation_context}: Performance standby (HTTP 473){error_details} - retrying"
                    );
                    error_constructor(format!("Performance standby (HTTP 473){error_details}"))
                }
                500 => {
                    debug!(
                        "{operation_context}: Internal server error (HTTP 500){error_details} - retrying"
                    );
                    error_constructor(format!("Internal server error (HTTP 500){error_details}"))
                }
                502 => {
                    debug!("{operation_context}: Bad gateway (HTTP 502){error_details} - retrying");
                    error_constructor(format!(
                        "Third-party service error (HTTP 502){error_details}"
                    ))
                }
                503 => {
                    debug!(
                        "{operation_context}: Service unavailable (HTTP 503){error_details} - retrying"
                    );
                    error_constructor(format!(
                        "Vault sealed or maintenance (HTTP 503){error_details}"
                    ))
                }

                // Permanent Errors (Client Errors)
                400 => {
                    error!(
                        "{operation_context}: Bad request (HTTP 400){error_details} - not retrying"
                    );
                    error_constructor(format!("Bad request (HTTP 400){error_details}"))
                }
                401 => {
                    error!(
                        "{operation_context}: Unauthorized (HTTP 401){error_details} - not retrying"
                    );
                    error_constructor(format!("Unauthorized (HTTP 401){error_details}"))
                }
                403 => {
                    error!(
                        "{operation_context}: Forbidden (HTTP 403){error_details} - not retrying"
                    );
                    error_constructor(format!("Forbidden/Access denied (HTTP 403){error_details}"))
                }
                404 => {
                    error!(
                        "{operation_context}: Not found (HTTP 404){error_details} - not retrying"
                    );
                    error_constructor(format!("Not found (HTTP 404){error_details}"))
                }
                405 => {
                    error!(
                        "{operation_context}: Method not allowed (HTTP 405){error_details} - not retrying"
                    );
                    error_constructor(format!("Method not allowed (HTTP 405){error_details}"))
                }
                501 => {
                    error!(
                        "{operation_context}: Vault not initialized (HTTP 501){error_details} - not retrying"
                    );
                    error_constructor(format!("Vault not initialized (HTTP 501){error_details}"))
                }

                // Catch-all Patterns
                code if (400..500).contains(&code) => {
                    error!(
                        "{operation_context}: Client error (HTTP {code}){error_details} - not retrying"
                    );
                    error_constructor(format!("Client error (HTTP {code}){error_details}"))
                }
                code if (500..600).contains(&code) => {
                    debug!(
                        "{operation_context}: Server error (HTTP {code}){error_details} - retrying"
                    );
                    error_constructor(format!("Server error (HTTP {code}){error_details}"))
                }
                code => {
                    error!(
                        "{operation_context}: Unexpected HTTP {code}{error_details} - not retrying"
                    );
                    error_constructor(format!("Unexpected HTTP status {code}{error_details}"))
                }
            }
        }

        // RestClientError - Type-based error detection
        ClientError::RestClientError { source } => {
            // Log the full error chain for debugging
            error!("{operation_context}: REST client error: {source}");
            let mut error_source = source.source();
            let mut level: usize = 1;
            while let Some(err) = error_source {
                error!("Error source level {level}: {err}");
                error_source = err.source();
                level = level.saturating_add(1);
            }

            if is_certificate_error(source) {
                error!(
                    "{operation_context}: Certificate/TLS error detected - not retrying: {source}"
                );
                error_constructor(format!("TLS/certificate error: {source}"))
            } else if is_network_error(source) {
                debug!("{operation_context}: Network error - retrying: {source}");
                error_constructor(format!("Network error: {source}"))
            } else {
                error!("{operation_context}: Unknown REST client error - not retrying: {source}");
                error_constructor(format!("REST client error: {source}"))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

    // Tests for is_retryable_vault_error function

    #[test]
    fn test_is_retryable_http_403_forbidden() {
        let error = ClientError::APIError {
            code: 403,
            errors: vec!["access denied".to_string()],
        };
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_http_401_unauthorized() {
        let error = ClientError::APIError {
            code: 401,
            errors: vec![],
        };
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_http_404_not_found() {
        let error = ClientError::APIError {
            code: 404,
            errors: vec![],
        };
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_http_400_bad_request() {
        let error = ClientError::APIError {
            code: 400,
            errors: vec!["invalid request".to_string()],
        };
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_http_405_method_not_allowed() {
        let error = ClientError::APIError {
            code: 405,
            errors: vec![],
        };
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_http_501_vault_not_initialized() {
        let error = ClientError::APIError {
            code: 501,
            errors: vec![],
        };
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_http_412_precondition_failed() {
        let error = ClientError::APIError {
            code: 412,
            errors: vec![],
        };
        assert!(is_retryable_vault_error(&error)); // Retryable (transient)
    }

    #[test]
    fn test_is_retryable_http_429_standby_node() {
        let error = ClientError::APIError {
            code: 429,
            errors: vec![],
        };
        assert!(is_retryable_vault_error(&error)); // Retryable (transient)
    }

    #[test]
    fn test_is_retryable_http_472_dr_replication() {
        let error = ClientError::APIError {
            code: 472,
            errors: vec![],
        };
        assert!(is_retryable_vault_error(&error)); // Retryable (transient)
    }

    #[test]
    fn test_is_retryable_http_473_performance_standby() {
        let error = ClientError::APIError {
            code: 473,
            errors: vec![],
        };
        assert!(is_retryable_vault_error(&error)); // Retryable (transient)
    }

    #[test]
    fn test_is_retryable_http_500_internal_server_error() {
        let error = ClientError::APIError {
            code: 500,
            errors: vec!["internal error".to_string()],
        };
        assert!(is_retryable_vault_error(&error)); // Retryable (transient)
    }

    #[test]
    fn test_is_retryable_http_502_bad_gateway() {
        let error = ClientError::APIError {
            code: 502,
            errors: vec![],
        };
        assert!(is_retryable_vault_error(&error)); // Retryable (transient)
    }

    #[test]
    fn test_is_retryable_http_503_service_unavailable() {
        let error = ClientError::APIError {
            code: 503,
            errors: vec![],
        };
        assert!(is_retryable_vault_error(&error)); // Retryable (transient)
    }

    #[test]
    fn test_is_retryable_file_not_found() {
        let error = ClientError::FileNotFoundError {
            path: "/path/to/file".to_string(),
        };
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_invalid_login_method() {
        let error = ClientError::InvalidLoginMethodError;
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_response_empty() {
        let error = ClientError::ResponseEmptyError;
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_response_data_empty() {
        let error = ClientError::ResponseDataEmptyError;
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_invalid_update_parameter() {
        let error = ClientError::InvalidUpdateParameter;
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_wrap_invalid() {
        let error = ClientError::WrapInvalidError;
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_generic_4xx_is_permanent() {
        // Test that other 4xx errors (not explicitly handled) are permanent
        let error = ClientError::APIError {
            code: 409, // Conflict
            errors: vec![],
        };
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }

    #[test]
    fn test_is_retryable_generic_5xx_is_transient() {
        // Test that other 5xx errors (not explicitly handled) are transient
        let error = ClientError::APIError {
            code: 504, // Gateway Timeout
            errors: vec![],
        };
        assert!(is_retryable_vault_error(&error)); // Retryable (transient)
    }

    #[test]
    fn test_is_retryable_unexpected_status_is_permanent() {
        // Test that unexpected status codes default to permanent (safe default)
        let error = ClientError::APIError {
            code: 999,
            errors: vec![],
        };
        assert!(!is_retryable_vault_error(&error)); // Not retryable (permanent)
    }
}

//! Centralized HTTP client with robust networking capabilities
//!
//! This module provides a centralized HTTP client with built-in retry logic,
//! configurable timeouts, exponential backoff, and authentication strategies
//! for reliable API integrations across GraphQL, REST, and other protocols.

use reqwest::{
    Client,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

use log::{debug, info};

/// Authentication strategy for API clients
#[derive(Debug, Clone)]
pub enum AuthStrategy {
    /// Bearer token in Authorization header
    Bearer(String),
    /// Custom header with token
    CustomHeader { name: String, value: String },
    /// No authentication
    None,
}

impl AuthStrategy {
    /// Apply authentication to headers
    pub fn apply_to_headers(&self, headers: &mut HeaderMap) -> Result<(), HttpClientError> {
        match self {
            AuthStrategy::Bearer(token) => {
                let auth_value =
                    HeaderValue::from_str(&format!("Bearer {token}")).map_err(|e| {
                        HttpClientError::AuthenticationError(format!("Invalid bearer token: {e}"))
                    })?;
                headers.insert(AUTHORIZATION, auth_value);
            }
            AuthStrategy::CustomHeader { name, value } => {
                let header_name: HeaderName = name.parse().map_err(|e| {
                    HttpClientError::ConfigurationError(format!(
                        "Invalid header name '{name}': {e}"
                    ))
                })?;
                let header_value = HeaderValue::from_str(value).map_err(|e| {
                    HttpClientError::ConfigurationError(format!(
                        "Invalid header value for '{name}': {e}"
                    ))
                })?;
                headers.insert(header_name, header_value);
            }
            AuthStrategy::None => {
                // No authentication to apply
            }
        }
        Ok(())
    }
}

/// HTTP timeout configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpTimeouts {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub validation_timeout: Duration,
}

impl Default for HttpTimeouts {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            validation_timeout: Duration::from_secs(10),
        }
    }
}

/// Retry configuration for network requests
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

/// HTTP client configuration
#[derive(Clone, Debug)]
pub struct HttpClientConfig {
    pub base_url: String,
    pub default_headers: HeaderMap,
    pub timeouts: HttpTimeouts,
    pub retry_config: RetryConfig,
    pub disable_cert_validation: bool,
    /// HTTP/HTTPS proxy URL (optional)
    pub proxy_url: Option<String>,
    /// Proxy authentication username (optional)
    pub proxy_username: Option<String>,
    /// Proxy authentication password (optional)
    pub proxy_password: Option<String>,
}

impl HttpClientConfig {
    #[must_use]
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            default_headers: HeaderMap::new(),
            timeouts: HttpTimeouts::default(),
            retry_config: RetryConfig::default(),
            disable_cert_validation: false,
            proxy_url: None,
            proxy_username: None,
            proxy_password: None,
        }
    }

    #[must_use]
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = headers;
        self
    }

    #[must_use]
    pub fn with_timeouts(mut self, timeouts: HttpTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    #[must_use]
    pub fn with_retry_config(mut self, retry_config: RetryConfig) -> Self {
        self.retry_config = retry_config;
        self
    }

    #[must_use]
    pub fn with_cert_validation(mut self, validate: bool) -> Self {
        self.disable_cert_validation = !validate;
        self
    }

    /// Set HTTP/HTTPS proxy URL
    #[must_use]
    pub fn with_proxy(mut self, proxy_url: impl Into<String>) -> Self {
        self.proxy_url = Some(proxy_url.into());
        self
    }

    /// Set proxy authentication credentials
    #[must_use]
    pub fn with_proxy_auth(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.proxy_username = Some(username.into());
        self.proxy_password = Some(password.into());
        self
    }
}

/// Error types for HTTP client operations
#[derive(Debug, thiserror::Error)]
pub enum HttpClientError {
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("API error: {status} - {message}")]
    ApiError { status: u16, message: String },
    #[error("Request failed after {attempts} retry attempts: {last_error}")]
    RetryExhausted { attempts: u32, last_error: String },
    #[error("Request timeout after {duration:?}")]
    Timeout { duration: Duration },
    #[error("Client configuration error: {0}")]
    ConfigurationError(String),
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    #[error("GraphQL error: {0}")]
    GraphQLError(String),
    #[error("GitLab specific error: {0}")]
    GitLabError(String),
}

// Type aliases for backward compatibility and clarity
pub type ApiClientError = HttpClientError;
pub type GraphQLClientError = HttpClientError;
pub type GitLabClientError = HttpClientError;

/// Debug output utilities for API clients
impl HttpClientError {
    /// Print connectivity test message
    pub fn print_connectivity_test(api_name: &str) {
        info!("🔍 Testing {api_name} connectivity...");
    }

    /// Print successful connectivity message
    pub fn print_connectivity_success(api_name: &str) {
        info!("✅ {api_name} connectivity test successful");
    }

    /// Print validation message
    pub fn print_validation(api_name: &str) {
        info!("🔍 Validating {api_name} integration requirements...");
    }

    /// Print validation success
    pub fn print_validation_success(api_name: &str) {
        info!("✅ {api_name} connectivity validated successfully!");
    }

    /// Print API access confirmation
    pub fn print_api_access() {
        info!("   API access: ✅ Authenticated");
    }

    /// Print permission check result
    pub fn print_permission_result(operation: &str, allowed: bool) {
        if allowed {
            info!("   {operation}: ✅ Permitted");
        } else {
            info!("   {operation}: ⚠️  May be restricted");
        }
    }

    /// Print permission error
    pub fn print_permission_error(operation: &str, error: &str) {
        info!("   {operation}: ⚠️  Error checking permissions: {error}");
    }
}

/// Centralized HTTP client with robust networking
pub struct RobustHttpClient {
    client: Client,
    config: HttpClientConfig,
}

impl RobustHttpClient {
    /// Create a new robust HTTP client
    pub fn new(config: HttpClientConfig) -> Result<Self, HttpClientError> {
        let mut client_builder = Client::builder()
            .default_headers(config.default_headers.clone())
            .connect_timeout(config.timeouts.connect_timeout)
            .timeout(config.timeouts.request_timeout);

        if config.disable_cert_validation {
            debug!("⚠️  WARNING: Certificate validation disabled");
            debug!("   This should only be used in development environments!");
            client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        // Configure proxy if specified
        if let Some(proxy_url) = &config.proxy_url {
            let mut proxy = reqwest::Proxy::all(proxy_url).map_err(|e| {
                HttpClientError::ConfigurationError(format!("Invalid proxy URL: {e}"))
            })?;

            // Add basic authentication if credentials are provided
            if let (Some(username), Some(password)) =
                (&config.proxy_username, &config.proxy_password)
            {
                proxy = proxy.basic_auth(username, password);
            }

            client_builder = client_builder.proxy(proxy);
            debug!("🔒 HTTP proxy configured: {}", proxy_url);
        }

        let client = client_builder
            .build()
            .map_err(HttpClientError::RequestError)?;

        debug!("🔧 HTTP Client initialized");
        debug!("   Base URL: {}", config.base_url);
        debug!("   Connect timeout: {:?}", config.timeouts.connect_timeout);
        debug!("   Request timeout: {:?}", config.timeouts.request_timeout);
        debug!("   Max retries: {}", config.retry_config.max_retries);
        debug!(
            "   Initial retry delay: {:?}",
            config.retry_config.initial_delay
        );

        Ok(Self { client, config })
    }

    /// Execute a GET request with retry logic
    pub async fn get<T>(&self, endpoint: &str) -> Result<T, HttpClientError>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.config.base_url, endpoint);

        debug!("🌐 GET {url} (with retry logic)");

        let response = self
            .execute_with_retry(|| self.client.get(&url).send())
            .await?;

        self.handle_response(response).await
    }

    /// Execute a POST request with retry logic
    pub async fn post<T, R>(&self, endpoint: &str, payload: &T) -> Result<R, HttpClientError>
    where
        T: Serialize,
        R: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.config.base_url, endpoint);
        let payload_json = serde_json::to_value(payload)?;

        debug!("🌐 POST {url} (with retry logic)");
        if let Ok(json) = serde_json::to_string_pretty(&payload_json) {
            debug!("📤 Request payload:\n{json}");
        }

        let response = self
            .execute_with_retry(|| self.client.post(&url).json(&payload_json).send())
            .await?;

        self.handle_response(response).await
    }

    /// Execute a PUT request with retry logic
    pub async fn put<T, R>(&self, endpoint: &str, payload: &T) -> Result<R, HttpClientError>
    where
        T: Serialize,
        R: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.config.base_url, endpoint);
        let payload_json = serde_json::to_value(payload)?;

        debug!("🌐 PUT {url} (with retry logic)");

        let response = self
            .execute_with_retry(|| self.client.put(&url).json(&payload_json).send())
            .await?;

        self.handle_response(response).await
    }

    /// Execute a DELETE request with retry logic
    pub async fn delete<T>(&self, endpoint: &str) -> Result<T, HttpClientError>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.config.base_url, endpoint);

        debug!("🌐 DELETE {url} (with retry logic)");

        let response = self
            .execute_with_retry(|| self.client.delete(&url).send())
            .await?;

        self.handle_response(response).await
    }

    /// Upload a file with retry logic - critical for large files
    pub async fn upload_file<T>(
        &self,
        endpoint: &str,
        file_data: Vec<u8>,
        file_name: &str,
        additional_fields: Option<T>,
    ) -> Result<serde_json::Value, HttpClientError>
    where
        T: Serialize + Clone,
    {
        let url = format!("{}{}", self.config.base_url, endpoint);

        debug!("🌐 UPLOAD {url} (with retry logic)");
        debug!("📤 File: {file_name} ({} bytes)", file_data.len());

        // Serialize additional fields once
        let additional_fields_json = if let Some(ref fields) = additional_fields {
            serde_json::to_value(fields).ok()
        } else {
            None
        };

        // Note: reqwest::multipart::Form doesn't implement Clone, so we need to rebuild it for retries
        let response = self
            .execute_with_retry(|| {
                let mut retry_form = reqwest::multipart::Form::new().part(
                    "file",
                    reqwest::multipart::Part::bytes(file_data.clone())
                        .file_name(file_name.to_string()),
                );

                if let Some(ref json) = additional_fields_json
                    && let Some(obj) = json.as_object()
                {
                    for (key, value) in obj {
                        if let Some(text) = value.as_str() {
                            retry_form = retry_form.text(key.clone(), text.to_string());
                        }
                    }
                }

                self.client.post(&url).multipart(retry_form).send()
            })
            .await?;

        self.handle_response(response).await
    }

    /// Execute a request with retry logic and exponential backoff
    async fn execute_with_retry<F, Fut>(
        &self,
        operation: F,
    ) -> Result<reqwest::Response, HttpClientError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
    {
        let mut last_error = None;
        let mut current_delay = self.config.retry_config.initial_delay;

        for attempt in 0..=self.config.retry_config.max_retries {
            if attempt > 0 {
                debug!(
                    "🔄 Retry attempt {}/{} after {}ms delay",
                    attempt,
                    self.config.retry_config.max_retries,
                    current_delay.as_millis()
                );
            }

            match operation().await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    last_error = Some(error.to_string());

                    // Check if error is retryable
                    if !self.is_retryable_error(&error) {
                        debug!("❌ Non-retryable error encountered: {error}");
                        return Err(HttpClientError::RequestError(error));
                    }

                    // Don't sleep after the last attempt
                    if attempt < self.config.retry_config.max_retries {
                        // Add jitter if enabled
                        let delay = if self.config.retry_config.jitter {
                            self.add_jitter(current_delay)
                        } else {
                            current_delay
                        };

                        debug!("⏳ Waiting {}ms before retry...", delay.as_millis());

                        sleep(delay).await;

                        // Calculate next delay with exponential backoff
                        current_delay = std::cmp::min(
                            Duration::from_millis(
                                (current_delay.as_millis() as f64
                                    * self.config.retry_config.backoff_multiplier)
                                    as u64,
                            ),
                            self.config.retry_config.max_delay,
                        );
                    }
                }
            }
        }

        Err(HttpClientError::RetryExhausted {
            attempts: self.config.retry_config.max_retries + 1,
            last_error: last_error.unwrap_or_else(|| "Unknown error".to_string()),
        })
    }

    /// Check if an error should trigger a retry
    fn is_retryable_error(&self, error: &reqwest::Error) -> bool {
        // Retry on network/connection errors
        if error.is_connect() || error.is_timeout() || error.is_request() {
            return true;
        }

        // Retry on specific HTTP status codes
        if let Some(status) = error.status() {
            match status.as_u16() {
                // Server errors (5xx) - usually temporary
                500..=599 => true,
                // Rate limiting
                429 => true,
                // Client errors (4xx) - usually permanent, don't retry
                400..=499 => false,
                _ => false,
            }
        } else {
            // If no status code, likely a network error, retry
            true
        }
    }

    /// Add random jitter to delay to avoid thundering herd
    fn add_jitter(&self, delay: Duration) -> Duration {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Simple deterministic "random" based on current time
        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .hash(&mut hasher);

        let jitter_factor = (hasher.finish() % 50) as f64 / 100.0; // 0-50% jitter
        let jitter_multiplier = 1.0 + jitter_factor;

        Duration::from_millis((delay.as_millis() as f64 * jitter_multiplier) as u64)
    }

    /// Handle HTTP response and convert to typed result
    async fn handle_response<T>(&self, response: reqwest::Response) -> Result<T, HttpClientError>
    where
        T: serde::de::DeserializeOwned,
    {
        let status = response.status();

        if status.is_success() {
            let result: T = response.json().await?;

            debug!("📥 API Response: {status}");

            Ok(result)
        } else {
            let status_code = status.as_u16();
            let error_text = response.text().await.unwrap_or("Unknown error".to_string());

            debug!("❌ API Error: {status_code} - {error_text}");

            Err(HttpClientError::ApiError {
                status: status_code,
                message: error_text,
            })
        }
    }

    /// Test connectivity to the configured endpoint
    pub async fn test_connectivity(&self, endpoint: &str) -> Result<(), HttpClientError> {
        let url = format!("{}{}", self.config.base_url, endpoint);

        debug!("🔍 Testing connectivity to {url}");

        let response = self
            .execute_with_retry(|| self.client.get(&url).send())
            .await?;

        let status = response.status();
        if status.is_success() {
            debug!("✅ Connectivity test successful");
            Ok(())
        } else {
            let status_code = status.as_u16();
            let error_text = response.text().await.unwrap_or("Unknown error".to_string());
            Err(HttpClientError::ApiError {
                status: status_code,
                message: format!("Connectivity test failed: {error_text}"),
            })
        }
    }

    /// Get the base URL for this client
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }
}

/// Builder for creating HTTP client configurations from environment variables
pub struct HttpClientConfigBuilder {
    config: HttpClientConfig,
}

impl HttpClientConfigBuilder {
    #[must_use]
    pub fn new(base_url: String) -> Self {
        Self {
            config: HttpClientConfig::new(base_url),
        }
    }

    /// Load timeout configuration from environment variables with prefix
    pub fn with_env_timeouts(mut self, prefix: &str) -> Self {
        use std::env;

        let connect_timeout = env::var(format!("{prefix}_CONNECT_TIMEOUT"))
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(10));

        let request_timeout = env::var(format!("{prefix}_REQUEST_TIMEOUT"))
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));

        let validation_timeout = env::var(format!("{prefix}_VALIDATION_TIMEOUT"))
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(10));

        self.config.timeouts = HttpTimeouts {
            connect_timeout,
            request_timeout,
            validation_timeout,
        };

        self
    }

    /// Load retry configuration from environment variables with prefix
    pub fn with_env_retry_config(mut self, prefix: &str) -> Self {
        use std::env;

        let max_retries = env::var(format!("{prefix}_MAX_RETRIES"))
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(3);

        let initial_delay = env::var(format!("{prefix}_INITIAL_RETRY_DELAY_MS"))
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_millis(500));

        let max_delay = env::var(format!("{prefix}_MAX_RETRY_DELAY_MS"))
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_secs(10));

        let backoff_multiplier = env::var(format!("{prefix}_BACKOFF_MULTIPLIER"))
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(2.0);

        let jitter = env::var(format!("{prefix}_DISABLE_JITTER"))
            .map(|s| s.to_lowercase() != "true")
            .unwrap_or(true);

        self.config.retry_config = RetryConfig {
            max_retries,
            initial_delay,
            max_delay,
            backoff_multiplier,
            jitter,
        };

        self
    }

    /// Load certificate validation setting from environment variables with prefix
    #[must_use]
    pub fn with_env_cert_validation(mut self, prefix: &str) -> Self {
        use std::env;

        self.config.disable_cert_validation =
            env::var(format!("{prefix}_DISABLE_CERT_VALIDATION")).is_ok();
        self
    }

    /// Load proxy configuration from environment variables
    ///
    /// Checks for standard HTTP_PROXY/HTTPS_PROXY variables first,
    /// then falls back to prefixed variables if provided.
    /// Also loads proxy authentication credentials if available.
    #[must_use]
    pub fn with_env_proxy(mut self, prefix: Option<&str>) -> Self {
        use std::env;

        // Try standard environment variables first
        let proxy_url = env::var("HTTPS_PROXY")
            .or_else(|_| env::var("https_proxy"))
            .or_else(|_| env::var("HTTP_PROXY"))
            .or_else(|_| env::var("http_proxy"))
            .or_else(|_| {
                // Try prefixed variables if prefix is provided
                if let Some(prefix) = prefix {
                    env::var(format!("{prefix}_PROXY_URL"))
                } else {
                    Err(env::VarError::NotPresent)
                }
            })
            .ok();

        if let Some(url) = proxy_url {
            self.config.proxy_url = Some(url);

            // Try to load proxy authentication credentials
            let username = env::var("PROXY_USERNAME")
                .or_else(|_| env::var("proxy_username"))
                .or_else(|_| {
                    if let Some(prefix) = prefix {
                        env::var(format!("{prefix}_PROXY_USERNAME"))
                    } else {
                        Err(env::VarError::NotPresent)
                    }
                })
                .ok();

            let password = env::var("PROXY_PASSWORD")
                .or_else(|_| env::var("proxy_password"))
                .or_else(|_| {
                    if let Some(prefix) = prefix {
                        env::var(format!("{prefix}_PROXY_PASSWORD"))
                    } else {
                        Err(env::VarError::NotPresent)
                    }
                })
                .ok();

            if let (Some(u), Some(p)) = (username, password) {
                self.config.proxy_username = Some(u);
                self.config.proxy_password = Some(p);
            }
        }

        self
    }

    #[must_use]
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.config.default_headers = headers;
        self
    }

    /// Apply authentication strategy to the configuration
    pub fn with_auth_strategy(mut self, auth: AuthStrategy) -> Result<Self, HttpClientError> {
        auth.apply_to_headers(&mut self.config.default_headers)?;
        Ok(self)
    }

    /// Convenience method for API clients with common patterns
    pub fn for_api_client(base_url: String, env_prefix: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        Self::new(base_url)
            .with_headers(headers)
            .with_env_timeouts(env_prefix)
            .with_env_retry_config(env_prefix)
            .with_env_cert_validation(env_prefix)
    }

    /// Enable debug mode for API clients
    #[must_use]
    pub fn with_api(self, api_name: &str) -> Self {
        debug!("🔍 Initializing {api_name} client with debug mode enabled");
        self
    }

    #[must_use]
    pub fn build(self) -> HttpClientConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};

    #[test]
    fn test_http_timeouts_default() {
        let timeouts = HttpTimeouts::default();
        assert_eq!(timeouts.connect_timeout, Duration::from_secs(10));
        assert_eq!(timeouts.request_timeout, Duration::from_secs(30));
        assert_eq!(timeouts.validation_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_retry_config_default() {
        let retry_config = RetryConfig::default();
        assert_eq!(retry_config.max_retries, 3);
        assert_eq!(retry_config.initial_delay, Duration::from_millis(500));
        assert_eq!(retry_config.max_delay, Duration::from_secs(10));
        assert_eq!(retry_config.backoff_multiplier, 2.0);
        assert!(retry_config.jitter);
    }

    #[test]
    fn test_http_client_config_builder() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer test-token"));

        let config = HttpClientConfig::new("https://api.example.com".to_string())
            .with_headers(headers)
            .with_cert_validation(false);

        assert_eq!(config.base_url, "https://api.example.com");
        // Debug functionality removed from config
        assert!(config.disable_cert_validation);
        assert_eq!(config.default_headers.len(), 2);
    }

    #[test]
    fn test_http_client_config_builder_env_vars() {
        use std::env;

        // Set test environment variables
        unsafe {
            env::set_var("TEST_CONNECT_TIMEOUT", "15");
            env::set_var("TEST_REQUEST_TIMEOUT", "45");
            env::set_var("TEST_MAX_RETRIES", "5");
            env::set_var("TEST_INITIAL_RETRY_DELAY_MS", "1000");
            env::set_var("TEST_BACKOFF_MULTIPLIER", "1.5");
            env::set_var("TEST_DISABLE_CERT_VALIDATION", "true");
        }

        let config = HttpClientConfigBuilder::new("https://api.example.com".to_string())
            .with_env_timeouts("TEST")
            .with_env_retry_config("TEST")
            .with_env_cert_validation("TEST")
            .build();

        assert_eq!(config.timeouts.connect_timeout, Duration::from_secs(15));
        assert_eq!(config.timeouts.request_timeout, Duration::from_secs(45));
        assert_eq!(config.retry_config.max_retries, 5);
        assert_eq!(
            config.retry_config.initial_delay,
            Duration::from_millis(1000)
        );
        assert_eq!(config.retry_config.backoff_multiplier, 1.5);
        assert!(config.disable_cert_validation);

        // Clean up
        unsafe {
            env::remove_var("TEST_CONNECT_TIMEOUT");
            env::remove_var("TEST_REQUEST_TIMEOUT");
            env::remove_var("TEST_MAX_RETRIES");
            env::remove_var("TEST_INITIAL_RETRY_DELAY_MS");
            env::remove_var("TEST_BACKOFF_MULTIPLIER");
            env::remove_var("TEST_DISABLE_CERT_VALIDATION");
        }
    }

    #[tokio::test]
    async fn test_http_client_creation() {
        let config = HttpClientConfig::new("https://api.example.com".to_string());

        let client = RobustHttpClient::new(config);
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.base_url(), "https://api.example.com");
    }

    #[test]
    fn test_jitter_calculation() {
        let config = HttpClientConfig::new("https://api.example.com".to_string());
        let client = RobustHttpClient::new(config).unwrap();

        let original_delay = Duration::from_millis(1000);
        let jittered_delay = client.add_jitter(original_delay);

        // Jittered delay should be between 100% and 150% of original
        assert!(jittered_delay >= original_delay);
        assert!(jittered_delay <= Duration::from_millis(1500));
    }
}

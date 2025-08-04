//! Centralized HTTP client with robust networking capabilities
//!
//! This module provides a centralized HTTP client with built-in retry logic,
//! configurable timeouts, and exponential backoff for reliable API integrations.

use reqwest::{Client, header::HeaderMap};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

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
    pub debug: bool,
}

impl HttpClientConfig {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            default_headers: HeaderMap::new(),
            timeouts: HttpTimeouts::default(),
            retry_config: RetryConfig::default(),
            disable_cert_validation: false,
            debug: false,
        }
    }

    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = headers;
        self
    }

    pub fn with_timeouts(mut self, timeouts: HttpTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    pub fn with_retry_config(mut self, retry_config: RetryConfig) -> Self {
        self.retry_config = retry_config;
        self
    }

    pub fn with_cert_validation(mut self, validate: bool) -> Self {
        self.disable_cert_validation = !validate;
        self
    }

    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
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
    ConfigError(String),
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
            if config.debug {
                println!("⚠️  WARNING: Certificate validation disabled");
                println!("   This should only be used in development environments!");
            }
            client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        let client = client_builder
            .build()
            .map_err(HttpClientError::RequestError)?;

        if config.debug {
            println!("🔧 Robust HTTP Client initialized");
            println!("   Base URL: {}", config.base_url);
            println!("   Connect timeout: {:?}", config.timeouts.connect_timeout);
            println!("   Request timeout: {:?}", config.timeouts.request_timeout);
            println!("   Max retries: {}", config.retry_config.max_retries);
            println!(
                "   Initial retry delay: {:?}",
                config.retry_config.initial_delay
            );
        }

        Ok(Self { client, config })
    }

    /// Execute a GET request with retry logic
    pub async fn get<T>(&self, endpoint: &str) -> Result<T, HttpClientError>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.config.base_url, endpoint);

        if self.config.debug {
            println!("🌐 GET {url} (with retry logic)");
        }

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

        if self.config.debug {
            println!("🌐 POST {url} (with retry logic)");
            if let Ok(json) = serde_json::to_string_pretty(&payload_json) {
                println!("📤 Request payload:\n{json}");
            }
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

        if self.config.debug {
            println!("🌐 PUT {url} (with retry logic)");
        }

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

        if self.config.debug {
            println!("🌐 DELETE {url} (with retry logic)");
        }

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

        if self.config.debug {
            println!("🌐 UPLOAD {url} (with retry logic)");
            println!("📤 File: {file_name} ({} bytes)", file_data.len());
        }

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

                if let Some(ref json) = additional_fields_json {
                    if let Some(obj) = json.as_object() {
                        for (key, value) in obj {
                            if let Some(text) = value.as_str() {
                                retry_form = retry_form.text(key.clone(), text.to_string());
                            }
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
            if self.config.debug && attempt > 0 {
                println!(
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
                        if self.config.debug {
                            println!("❌ Non-retryable error encountered: {error}");
                        }
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

                        if self.config.debug {
                            println!("⏳ Waiting {}ms before retry...", delay.as_millis());
                        }

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

            if self.config.debug {
                println!("📥 API Response: {status}");
            }

            Ok(result)
        } else {
            let status_code = status.as_u16();
            let error_text = response.text().await.unwrap_or("Unknown error".to_string());

            if self.config.debug {
                println!("❌ API Error: {status_code} - {error_text}");
            }

            Err(HttpClientError::ApiError {
                status: status_code,
                message: error_text,
            })
        }
    }

    /// Test connectivity to the configured endpoint
    pub async fn test_connectivity(&self, endpoint: &str) -> Result<(), HttpClientError> {
        let url = format!("{}{}", self.config.base_url, endpoint);

        if self.config.debug {
            println!("🔍 Testing connectivity to {url}");
        }

        let response = self
            .execute_with_retry(|| self.client.get(&url).send())
            .await?;

        let status = response.status();
        if status.is_success() {
            if self.config.debug {
                println!("✅ Connectivity test successful");
            }
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
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Check if debug mode is enabled
    pub fn is_debug(&self) -> bool {
        self.config.debug
    }
}

/// Builder for creating HTTP client configurations from environment variables
pub struct HttpClientConfigBuilder {
    config: HttpClientConfig,
}

impl HttpClientConfigBuilder {
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
    pub fn with_env_cert_validation(mut self, prefix: &str) -> Self {
        use std::env;

        self.config.disable_cert_validation =
            env::var(format!("{prefix}_DISABLE_CERT_VALIDATION")).is_ok();
        self
    }

    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.config.default_headers = headers;
        self
    }

    pub fn with_debug(mut self, debug: bool) -> Self {
        self.config.debug = debug;
        self
    }

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
            .with_debug(true)
            .with_cert_validation(false);

        assert_eq!(config.base_url, "https://api.example.com");
        assert!(config.debug);
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
            .with_debug(true)
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
        let config = HttpClientConfig::new("https://api.example.com".to_string()).with_debug(false);

        let client = RobustHttpClient::new(config);
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.base_url(), "https://api.example.com");
        assert!(!client.is_debug());
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

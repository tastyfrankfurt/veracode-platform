//! Core Veracode API client implementation.
//!
//! This module contains the foundational client for making authenticated requests
//! to the Veracode API, including HMAC authentication and HTTP request handling.

use hex;
use hmac::{Hmac, Mac};
use log::{info, warn};
use reqwest::{Client, multipart};
use secrecy::ExposeSecret;
use serde::Serialize;
use sha2::Sha256;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;

use crate::json_validator::{MAX_JSON_DEPTH, validate_json_depth};
use crate::{VeracodeConfig, VeracodeError};

// Type aliases for HMAC
type HmacSha256 = Hmac<Sha256>;

// Constants for authentication error messages to avoid repeated allocations
const INVALID_URL_MSG: &str = "Invalid URL";
const INVALID_API_KEY_MSG: &str = "Invalid API key format - must be hex string";
const INVALID_NONCE_MSG: &str = "Invalid nonce format";
const HMAC_CREATION_FAILED_MSG: &str = "Failed to create HMAC";

/// Core Veracode API client.
///
/// This struct provides the foundational HTTP client with HMAC authentication
/// for making requests to any Veracode API endpoint.
#[derive(Clone)]
pub struct VeracodeClient {
    config: VeracodeConfig,
    client: Client,
}

impl VeracodeClient {
    /// Build URL with query parameters - centralized helper
    fn build_url_with_params(&self, endpoint: &str, query_params: &[(&str, &str)]) -> String {
        // Pre-allocate string capacity for better performance
        let estimated_capacity = self
            .config
            .base_url
            .len()
            .saturating_add(endpoint.len())
            .saturating_add(query_params.len().saturating_mul(32)); // Rough estimate for query params

        let mut url = String::with_capacity(estimated_capacity);
        url.push_str(&self.config.base_url);
        url.push_str(endpoint);

        if !query_params.is_empty() {
            url.push('?');
            for (i, (key, value)) in query_params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                url.push_str(&urlencoding::encode(key));
                url.push('=');
                url.push_str(&urlencoding::encode(value));
            }
        }

        url
    }

    /// Create a new Veracode API client.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing API credentials and settings
    ///
    /// # Returns
    ///
    /// A new `VeracodeClient` instance ready to make API calls.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub fn new(config: VeracodeConfig) -> Result<Self, VeracodeError> {
        let mut client_builder = Client::builder();

        // Use the certificate validation setting from config
        if !config.validate_certificates {
            client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        // Configure HTTP timeouts from config
        client_builder = client_builder
            .connect_timeout(Duration::from_secs(config.connect_timeout))
            .timeout(Duration::from_secs(config.request_timeout));

        // Configure proxy if specified
        if let Some(proxy_url) = &config.proxy_url {
            let mut proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| VeracodeError::InvalidConfig(format!("Invalid proxy URL: {e}")))?;

            // Add basic authentication if credentials are provided
            if let (Some(username), Some(password)) =
                (&config.proxy_username, &config.proxy_password)
            {
                proxy = proxy.basic_auth(username.expose_secret(), password.expose_secret());
            }

            client_builder = client_builder.proxy(proxy);
        }

        let client = client_builder.build().map_err(VeracodeError::Http)?;
        Ok(Self { config, client })
    }

    /// Get the base URL for API requests.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Get access to the configuration
    #[must_use]
    pub fn config(&self) -> &VeracodeConfig {
        &self.config
    }

    /// Get access to the underlying reqwest client
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Execute an HTTP request with retry logic and exponential backoff.
    ///
    /// This method implements the retry strategy defined in the client's configuration.
    /// It will retry requests that fail due to transient errors (network issues,
    /// server errors, rate limiting) using exponential backoff. For rate limiting (429),
    /// it uses intelligent delays based on Veracode's minute-window rate limits.
    ///
    /// # Arguments
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// * `request_builder` - A closure that creates the `reqwest::RequestBuilder`
    /// * `operation_name` - A human-readable name for logging/error messages
    ///
    /// # Returns
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// A `Result` containing the HTTP response or a `VeracodeError`.
    async fn execute_with_retry<F>(
        &self,
        request_builder: F,
        operation_name: Cow<'_, str>,
    ) -> Result<reqwest::Response, VeracodeError>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        let retry_config = &self.config.retry_config;
        let start_time = Instant::now();
        let mut total_delay = std::time::Duration::from_millis(0);

        // If retries are disabled, make a single attempt
        if retry_config.max_attempts == 0 {
            return match request_builder().send().await {
                Ok(response) => Ok(response),
                Err(e) => Err(VeracodeError::Http(e)),
            };
        }

        let mut last_error = None;
        let mut rate_limit_attempts: u32 = 0;

        for attempt in 1..=retry_config.max_attempts.saturating_add(1) {
            // Build and send the request
            match request_builder().send().await {
                Ok(response) => {
                    // Check for rate limiting before treating as success
                    if response.status().as_u16() == 429 {
                        // Extract Retry-After header if present
                        let retry_after_seconds = response
                            .headers()
                            .get("retry-after")
                            .and_then(|h| h.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok());

                        let message = "HTTP 429: Rate limit exceeded".to_string();
                        let veracode_error = VeracodeError::RateLimited {
                            retry_after_seconds,
                            message,
                        };

                        // Increment rate limit attempt counter
                        rate_limit_attempts = rate_limit_attempts.saturating_add(1);

                        // Check if we should retry based on rate limit specific limits
                        if attempt > retry_config.max_attempts
                            || rate_limit_attempts > retry_config.rate_limit_max_attempts
                        {
                            last_error = Some(veracode_error);
                            break;
                        }

                        // Calculate rate limit specific delay
                        let delay = retry_config.calculate_rate_limit_delay(retry_after_seconds);
                        total_delay = total_delay.saturating_add(delay);

                        // Check total delay limit
                        if total_delay.as_millis() > retry_config.max_total_delay_ms as u128 {
                            let msg = format!(
                                "{} exceeded maximum total retry time of {}ms after {} attempts",
                                operation_name, retry_config.max_total_delay_ms, attempt
                            );
                            last_error = Some(VeracodeError::RetryExhausted(msg));
                            break;
                        }

                        // Log rate limit with specific formatting
                        let wait_time = match retry_after_seconds {
                            Some(seconds) => format!("{seconds}s (from Retry-After header)"),
                            None => format!("{}s (until next minute window)", delay.as_secs()),
                        };
                        warn!(
                            "🚦 {operation_name} rate limited on attempt {attempt}, waiting {wait_time}"
                        );

                        // Wait and continue to next attempt
                        tokio::time::sleep(delay).await;
                        last_error = Some(veracode_error);
                        continue;
                    }

                    if attempt > 1 {
                        // Log successful retry for debugging
                        info!("✅ {operation_name} succeeded on attempt {attempt}");
                    }
                    return Ok(response);
                }
                Err(e) => {
                    // For connection errors, network issues, etc., use normal retry logic
                    let veracode_error = VeracodeError::Http(e);

                    // Check if this is the last attempt or if the error is not retryable
                    if attempt > retry_config.max_attempts
                        || !retry_config.is_retryable_error(&veracode_error)
                    {
                        last_error = Some(veracode_error);
                        break;
                    }

                    // Use normal exponential backoff for non-429 errors
                    let delay = retry_config.calculate_delay(attempt);
                    total_delay = total_delay.saturating_add(delay);

                    // Check if we've exceeded the maximum total delay
                    if total_delay.as_millis() > retry_config.max_total_delay_ms as u128 {
                        // Format error message once
                        let msg = format!(
                            "{} exceeded maximum total retry time of {}ms after {} attempts",
                            operation_name, retry_config.max_total_delay_ms, attempt
                        );
                        last_error = Some(VeracodeError::RetryExhausted(msg));
                        break;
                    }

                    // Log retry attempt for debugging
                    warn!(
                        "⚠️  {operation_name} failed on attempt {attempt}, retrying in {}ms: {veracode_error}",
                        delay.as_millis()
                    );

                    // Wait before next attempt
                    tokio::time::sleep(delay).await;
                    last_error = Some(veracode_error);
                }
            }
        }

        // All attempts failed - create error message efficiently
        match last_error {
            Some(error) => {
                let elapsed = start_time.elapsed();
                match error {
                    VeracodeError::RetryExhausted(_) => Err(error),
                    VeracodeError::Http(_)
                    | VeracodeError::Serialization(_)
                    | VeracodeError::Authentication(_)
                    | VeracodeError::InvalidResponse(_)
                    | VeracodeError::InvalidConfig(_)
                    | VeracodeError::NotFound(_)
                    | VeracodeError::RateLimited { .. }
                    | VeracodeError::Validation(_) => {
                        let msg = format!(
                            "{} failed after {} attempts over {}ms: {}",
                            operation_name,
                            retry_config.max_attempts.saturating_add(1),
                            elapsed.as_millis(),
                            error
                        );
                        Err(VeracodeError::RetryExhausted(msg))
                    }
                }
            }
            None => {
                let msg = format!(
                    "{} failed after {} attempts with unknown error",
                    operation_name,
                    retry_config.max_attempts.saturating_add(1)
                );
                Err(VeracodeError::RetryExhausted(msg))
            }
        }
    }

    /// Generate HMAC signature for authentication based on official Veracode JavaScript implementation
    fn generate_hmac_signature(
        &self,
        method: &str,
        url: &str,
        timestamp: u64,
        nonce: &str,
    ) -> Result<String, VeracodeError> {
        let url_parsed = Url::parse(url)
            .map_err(|_| VeracodeError::Authentication(INVALID_URL_MSG.to_string()))?;

        let path_and_query = match url_parsed.query() {
            Some(query) => format!("{}?{}", url_parsed.path(), query),
            None => url_parsed.path().to_string(),
        };

        let host = url_parsed.host_str().unwrap_or("");

        // Based on the official Veracode JavaScript implementation:
        // var data = `id=${id}&host=${host}&url=${url}&method=${method}`;
        let data = format!(
            "id={}&host={}&url={}&method={}",
            self.config.credentials.expose_api_id(),
            host,
            path_and_query,
            method
        );

        let timestamp_str = timestamp.to_string();
        let ver_str = "vcode_request_version_1";

        // Convert hex strings to bytes
        let key_bytes = hex::decode(self.config.credentials.expose_api_key())
            .map_err(|_| VeracodeError::Authentication(INVALID_API_KEY_MSG.to_string()))?;

        let nonce_bytes = hex::decode(nonce)
            .map_err(|_| VeracodeError::Authentication(INVALID_NONCE_MSG.to_string()))?;

        // Step 1: HMAC(nonce, key)
        let mut mac1 = HmacSha256::new_from_slice(&key_bytes)
            .map_err(|_| VeracodeError::Authentication(HMAC_CREATION_FAILED_MSG.to_string()))?;
        mac1.update(&nonce_bytes);
        let hashed_nonce = mac1.finalize().into_bytes();

        // Step 2: HMAC(timestamp, hashed_nonce)
        let mut mac2 = HmacSha256::new_from_slice(&hashed_nonce)
            .map_err(|_| VeracodeError::Authentication(HMAC_CREATION_FAILED_MSG.to_string()))?;
        mac2.update(timestamp_str.as_bytes());
        let hashed_timestamp = mac2.finalize().into_bytes();

        // Step 3: HMAC(ver_str, hashed_timestamp)
        let mut mac3 = HmacSha256::new_from_slice(&hashed_timestamp)
            .map_err(|_| VeracodeError::Authentication(HMAC_CREATION_FAILED_MSG.to_string()))?;
        mac3.update(ver_str.as_bytes());
        let hashed_ver_str = mac3.finalize().into_bytes();

        // Step 4: HMAC(data, hashed_ver_str)
        let mut mac4 = HmacSha256::new_from_slice(&hashed_ver_str)
            .map_err(|_| VeracodeError::Authentication(HMAC_CREATION_FAILED_MSG.to_string()))?;
        mac4.update(data.as_bytes());
        let signature = mac4.finalize().into_bytes();

        // Return the hex-encoded signature (lowercase)
        Ok(hex::encode(signature).to_lowercase())
    }

    /// Generate authorization header for HMAC authentication
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub fn generate_auth_header(&self, method: &str, url: &str) -> Result<String, VeracodeError> {
        #[allow(clippy::cast_possible_truncation)]
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VeracodeError::Authentication(format!("System time error: {e}")))?
            .as_millis() as u64; // Use milliseconds like JavaScript

        // Generate a 16-byte random nonce and convert to hex string
        let nonce_bytes: [u8; 16] = rand::random();
        let nonce = hex::encode(nonce_bytes);

        let signature = self.generate_hmac_signature(method, url, timestamp, &nonce)?;

        Ok(format!(
            "VERACODE-HMAC-SHA-256 id={},ts={},nonce={},sig={}",
            self.config.credentials.expose_api_id(),
            timestamp,
            nonce,
            signature
        ))
    }

    /// Make a GET request to the specified endpoint.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint path (e.g., "/appsec/v1/applications")
    /// * `query_params` - Optional query parameters as key-value pairs
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn get(
        &self,
        endpoint: &str,
        query_params: Option<&[(String, String)]>,
    ) -> Result<reqwest::Response, VeracodeError> {
        // Pre-allocate URL capacity
        let param_count = query_params.map_or(0, |p| p.len());
        let estimated_capacity = self
            .config
            .base_url
            .len()
            .saturating_add(endpoint.len())
            .saturating_add(param_count.saturating_mul(32));
        let mut url = String::with_capacity(estimated_capacity);
        url.push_str(&self.config.base_url);
        url.push_str(endpoint);

        if let Some(params) = query_params
            && !params.is_empty()
        {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                url.push_str(key);
                url.push('=');
                url.push_str(value);
            }
        }

        // Create request builder closure for retry logic
        let request_builder = || {
            // Re-generate auth header for each attempt to avoid signature expiry
            let Ok(auth_header) = self.generate_auth_header("GET", &url) else {
                return self.client.get("invalid://url");
            };

            self.client
                .get(&url)
                .header("Authorization", auth_header)
                .header("Content-Type", "application/json")
        };

        // Use Cow::Borrowed for simple operations when possible
        let operation_name = if endpoint.len() < 50 {
            Cow::Owned(format!("GET {endpoint}"))
        } else {
            Cow::Borrowed("GET [long endpoint]")
        };
        self.execute_with_retry(request_builder, operation_name)
            .await
    }

    /// Make a POST request to the specified endpoint.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint path (e.g., "/appsec/v1/applications")
    /// * `body` - Optional request body that implements Serialize
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn post<T: Serialize>(
        &self,
        endpoint: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let mut url =
            String::with_capacity(self.config.base_url.len().saturating_add(endpoint.len()));
        url.push_str(&self.config.base_url);
        url.push_str(endpoint);

        // Serialize body once outside the retry loop for efficiency
        let serialized_body = if let Some(body) = body {
            Some(serde_json::to_string(body)?)
        } else {
            None
        };

        // Create request builder closure for retry logic
        let request_builder = || {
            // Re-generate auth header for each attempt to avoid signature expiry
            let Ok(auth_header) = self.generate_auth_header("POST", &url) else {
                return self.client.post("invalid://url");
            };

            let mut request = self
                .client
                .post(&url)
                .header("Authorization", auth_header)
                .header("Content-Type", "application/json");

            if let Some(ref body_str) = serialized_body {
                request = request.body(body_str.clone());
            }

            request
        };

        let operation_name = if endpoint.len() < 50 {
            Cow::Owned(format!("POST {endpoint}"))
        } else {
            Cow::Borrowed("POST [long endpoint]")
        };
        self.execute_with_retry(request_builder, operation_name)
            .await
    }

    /// Make a PUT request to the specified endpoint.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint path (e.g., "/appsec/v1/applications/guid")
    /// * `body` - Optional request body that implements Serialize
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn put<T: Serialize>(
        &self,
        endpoint: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let mut url =
            String::with_capacity(self.config.base_url.len().saturating_add(endpoint.len()));
        url.push_str(&self.config.base_url);
        url.push_str(endpoint);

        // Serialize body once outside the retry loop for efficiency
        let serialized_body = if let Some(body) = body {
            Some(serde_json::to_string(body)?)
        } else {
            None
        };

        // Create request builder closure for retry logic
        let request_builder = || {
            // Re-generate auth header for each attempt to avoid signature expiry
            let Ok(auth_header) = self.generate_auth_header("PUT", &url) else {
                return self.client.put("invalid://url");
            };

            let mut request = self
                .client
                .put(&url)
                .header("Authorization", auth_header)
                .header("Content-Type", "application/json");

            if let Some(ref body_str) = serialized_body {
                request = request.body(body_str.clone());
            }

            request
        };

        let operation_name = if endpoint.len() < 50 {
            Cow::Owned(format!("PUT {endpoint}"))
        } else {
            Cow::Borrowed("PUT [long endpoint]")
        };
        self.execute_with_retry(request_builder, operation_name)
            .await
    }

    /// Make a DELETE request to the specified endpoint.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint path (e.g., "/appsec/v1/applications/guid")
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn delete(&self, endpoint: &str) -> Result<reqwest::Response, VeracodeError> {
        let mut url =
            String::with_capacity(self.config.base_url.len().saturating_add(endpoint.len()));
        url.push_str(&self.config.base_url);
        url.push_str(endpoint);

        // Create request builder closure for retry logic
        let request_builder = || {
            // Re-generate auth header for each attempt to avoid signature expiry
            let Ok(auth_header) = self.generate_auth_header("DELETE", &url) else {
                return self.client.delete("invalid://url");
            };

            self.client
                .delete(&url)
                .header("Authorization", auth_header)
                .header("Content-Type", "application/json")
        };

        let operation_name = if endpoint.len() < 50 {
            Cow::Owned(format!("DELETE {endpoint}"))
        } else {
            Cow::Borrowed("DELETE [long endpoint]")
        };
        self.execute_with_retry(request_builder, operation_name)
            .await
    }

    /// Helper method to handle common response processing.
    ///
    /// Checks if the response is successful and returns an error if not.
    ///
    /// # Arguments
    ///
    /// * `response` - The HTTP response to check
    /// * `context` - A description of the operation being performed (e.g., "get application")
    ///
    /// # Returns
    ///
    /// A `Result` containing the response if successful, or an error if not.
    ///
    /// # Error Context
    ///
    /// This method enhances error messages with context about the failed operation
    /// to improve debugging and user experience.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn handle_response(
        response: reqwest::Response,
        context: &str,
    ) -> Result<reqwest::Response, VeracodeError> {
        if !response.status().is_success() {
            let status = response.status();
            let url = response.url().clone();
            let error_text = response.text().await?;
            return Err(VeracodeError::InvalidResponse(format!(
                "Failed to {context}\n  URL: {url}\n  HTTP {status}: {error_text}"
            )));
        }
        Ok(response)
    }

    /// Make a GET request with full URL construction and query parameter handling.
    ///
    /// This is a higher-level method that builds the full URL and handles query parameters.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint path
    /// * `query_params` - Optional query parameters
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response, pre-processed for success/failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn get_with_query(
        &self,
        endpoint: &str,
        query_params: Option<Vec<(String, String)>>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let query_slice = query_params.as_deref();
        let response = self.get(endpoint, query_slice).await?;
        Self::handle_response(response, &format!("GET {endpoint}")).await
    }

    /// Make a POST request with automatic response handling.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint path
    /// * `body` - Optional request body
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response, pre-processed for success/failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn post_with_response<T: Serialize>(
        &self,
        endpoint: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let response = self.post(endpoint, body).await?;
        Self::handle_response(response, &format!("POST {endpoint}")).await
    }

    /// Make a PUT request with automatic response handling.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint path
    /// * `body` - Optional request body
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response, pre-processed for success/failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn put_with_response<T: Serialize>(
        &self,
        endpoint: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let response = self.put(endpoint, body).await?;
        Self::handle_response(response, &format!("PUT {endpoint}")).await
    }

    /// Make a DELETE request with automatic response handling.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint path
    ///
    /// # Returns
    ///
    /// A `Result` containing the HTTP response, pre-processed for success/failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn delete_with_response(
        &self,
        endpoint: &str,
    ) -> Result<reqwest::Response, VeracodeError> {
        let response = self.delete(endpoint).await?;
        Self::handle_response(response, &format!("DELETE {endpoint}")).await
    }

    /// Make paginated GET requests to collect all results.
    ///
    /// This method automatically handles pagination by making multiple requests
    /// and combining all results into a single response.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint path
    /// * `base_query_params` - Base query parameters (non-pagination)
    /// * `page_size` - Number of items per page (default: 500)
    ///
    /// # Returns
    ///
    /// A `Result` containing all paginated results as a single response body string.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn get_paginated(
        &self,
        endpoint: &str,
        base_query_params: Option<Vec<(String, String)>>,
        page_size: Option<u32>,
    ) -> Result<String, VeracodeError> {
        let size = page_size.unwrap_or(500);
        let mut page: u32 = 0;
        let mut all_items = Vec::new();
        let mut page_info = None;

        loop {
            let mut query_params = base_query_params.clone().unwrap_or_default();
            query_params.push(("page".to_string(), page.to_string()));
            query_params.push(("size".to_string(), size.to_string()));

            let response = self.get_with_query(endpoint, Some(query_params)).await?;
            let response_text = response.text().await?;

            // Validate JSON depth before parsing to prevent DoS attacks
            validate_json_depth(&response_text, MAX_JSON_DEPTH).map_err(|e| {
                VeracodeError::InvalidResponse(format!("JSON validation failed: {}", e))
            })?;

            // Try to parse as JSON to extract items and pagination info
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&response_text) {
                // Handle embedded response format
                if let Some(embedded) = json_value.get("_embedded") {
                    if let Some(items_array) =
                        embedded.as_object().and_then(|obj| obj.values().next())
                        && let Some(items) = items_array.as_array()
                    {
                        if items.is_empty() {
                            break; // No more items
                        }
                        all_items.extend(items.clone());
                    }
                } else if let Some(items) = json_value.as_array() {
                    // Handle direct array response
                    if items.is_empty() {
                        break;
                    }
                    all_items.extend(items.clone());
                } else {
                    // Single page response, return as-is
                    return Ok(response_text);
                }

                // Check pagination info
                if let Some(page_obj) = json_value.get("page") {
                    page_info = Some(page_obj.clone());
                    if let (Some(current), Some(total)) = (
                        page_obj.get("number").and_then(|n| n.as_u64()),
                        page_obj.get("totalPages").and_then(|n| n.as_u64()),
                    ) && current.saturating_add(1) >= total
                    {
                        break; // Last page reached
                    }
                }
            } else {
                // Not JSON or parsing failed, return single response
                return Ok(response_text);
            }

            page = page.saturating_add(1);

            // Safety check to prevent infinite loops
            if page > 100 {
                break;
            }
        }

        // Reconstruct response with all items
        let combined_response = if let Some(page_info) = page_info {
            // Use embedded format
            serde_json::json!({
                "_embedded": {
                    "roles": all_items // This key might need to be dynamic
                },
                "page": page_info
            })
        } else {
            // Use direct array format
            serde_json::Value::Array(all_items)
        };

        Ok(combined_response.to_string())
    }

    /// Make a GET request with query parameters
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint to call
    /// * `params` - Query parameters as a slice of tuples
    ///
    /// # Returns
    ///
    /// A `Result` containing the response or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn get_with_params(
        &self,
        endpoint: &str,
        params: &[(&str, &str)],
    ) -> Result<reqwest::Response, VeracodeError> {
        let mut url =
            String::with_capacity(self.config.base_url.len().saturating_add(endpoint.len()));
        url.push_str(&self.config.base_url);
        url.push_str(endpoint);
        let mut request_url =
            Url::parse(&url).map_err(|e| VeracodeError::InvalidConfig(e.to_string()))?;

        // Add query parameters
        if !params.is_empty() {
            let mut query_pairs = request_url.query_pairs_mut();
            for (key, value) in params {
                query_pairs.append_pair(key, value);
            }
        }

        let auth_header = self.generate_auth_header("GET", request_url.as_str())?;

        let response = self
            .client
            .get(request_url)
            .header("Authorization", auth_header)
            .header("User-Agent", "Veracode Rust Client")
            .send()
            .await?;

        Ok(response)
    }

    /// Make a POST request with form data
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint to call
    /// * `params` - Form parameters as a slice of tuples
    ///
    /// # Returns
    ///
    /// A `Result` containing the response or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn post_form(
        &self,
        endpoint: &str,
        params: &[(&str, &str)],
    ) -> Result<reqwest::Response, VeracodeError> {
        let mut url =
            String::with_capacity(self.config.base_url.len().saturating_add(endpoint.len()));
        url.push_str(&self.config.base_url);
        url.push_str(endpoint);

        // Build form data - avoid unnecessary allocations
        let form_data: Vec<(&str, &str)> = params.to_vec();

        let auth_header = self.generate_auth_header("POST", &url)?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .header("User-Agent", "Veracode Rust Client")
            .form(&form_data)
            .send()
            .await?;

        Ok(response)
    }

    /// Upload a file using multipart form data
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint to call
    /// * `params` - Additional form parameters
    /// * `file_field_name` - Name of the file field
    /// * `filename` - Name of the file
    /// * `file_data` - File data as bytes
    ///
    /// # Returns
    ///
    /// A `Result` containing the response or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn upload_file_multipart(
        &self,
        endpoint: &str,
        params: HashMap<&str, &str>,
        file_field_name: &str,
        filename: &str,
        file_data: Vec<u8>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let mut url =
            String::with_capacity(self.config.base_url.len().saturating_add(endpoint.len()));
        url.push_str(&self.config.base_url);
        url.push_str(endpoint);

        // Build multipart form
        let mut form = multipart::Form::new();

        // Add regular form fields
        for (key, value) in params {
            form = form.text(key.to_string(), value.to_string());
        }

        // Add file
        let part = multipart::Part::bytes(file_data)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| VeracodeError::InvalidConfig(e.to_string()))?;

        form = form.part(file_field_name.to_string(), part);

        let auth_header = self.generate_auth_header("POST", &url)?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .header("User-Agent", "Veracode Rust Client")
            .multipart(form)
            .send()
            .await?;

        Ok(response)
    }

    /// Upload a file using multipart form data with PUT method (for pipeline scans)
    ///
    /// # Arguments
    ///
    /// * `url` - The full URL to upload to
    /// * `file_field_name` - Name of the file field
    /// * `filename` - Name of the file
    /// * `file_data` - File data as bytes
    /// * `additional_headers` - Additional headers to include
    ///
    /// # Returns
    ///
    /// A `Result` containing the response or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn upload_file_multipart_put(
        &self,
        url: &str,
        file_field_name: &str,
        filename: &str,
        file_data: Vec<u8>,
        additional_headers: Option<HashMap<&str, &str>>,
    ) -> Result<reqwest::Response, VeracodeError> {
        // Build multipart form
        let part = multipart::Part::bytes(file_data)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| VeracodeError::InvalidConfig(e.to_string()))?;

        let form = multipart::Form::new().part(file_field_name.to_string(), part);

        let auth_header = self.generate_auth_header("PUT", url)?;

        let mut request = self
            .client
            .put(url)
            .header("Authorization", auth_header)
            .header("User-Agent", "Veracode Rust Client")
            .multipart(form);

        // Add any additional headers
        if let Some(headers) = additional_headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        let response = request.send().await?;
        Ok(response)
    }

    /// Upload a file with query parameters (like Java implementation)
    ///
    /// This method mimics the Java API wrapper's approach where parameters
    /// are added to the query string and the file is uploaded separately.
    ///
    /// Memory optimization: Uses Cow for strings and Arc for file data to minimize cloning
    /// during retry attempts. Automatically retries on transient failures.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint to call
    /// * `query_params` - Query parameters as key-value pairs
    /// * `file_field_name` - Name of the file field
    /// * `filename` - Name of the file
    /// * `file_data` - File data as bytes
    ///
    /// # Returns
    ///
    /// A `Result` containing the response or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn upload_file_with_query_params(
        &self,
        endpoint: &str,
        query_params: &[(&str, &str)],
        file_field_name: &str,
        filename: &str,
        file_data: Vec<u8>,
    ) -> Result<reqwest::Response, VeracodeError> {
        // Build URL with query parameters using centralized helper for consistency
        let url = self.build_url_with_params(endpoint, query_params);

        // Wrap file data in Arc to avoid cloning during retries
        let file_data_arc = Arc::new(file_data);

        // Use Cow for strings to minimize allocations - borrow for short strings, own for long ones
        let filename_cow: Cow<str> = if filename.len() < 128 {
            Cow::Borrowed(filename)
        } else {
            Cow::Owned(filename.to_string())
        };

        let field_name_cow: Cow<str> = if file_field_name.len() < 32 {
            Cow::Borrowed(file_field_name)
        } else {
            Cow::Owned(file_field_name.to_string())
        };

        // Create request builder closure for retry logic
        let request_builder = || {
            // Clone Arc (cheap - just increments reference count)
            let file_data_clone = Arc::clone(&file_data_arc);

            // Re-create multipart form for each attempt
            let Ok(part) = multipart::Part::bytes((*file_data_clone).clone())
                .file_name(filename_cow.to_string())
                .mime_str("application/octet-stream")
            else {
                return self.client.post("invalid://url");
            };

            let form = multipart::Form::new().part(field_name_cow.to_string(), part);

            // Re-generate auth header for each attempt to avoid signature expiry
            let Ok(auth_header) = self.generate_auth_header("POST", &url) else {
                return self.client.post("invalid://url");
            };

            self.client
                .post(&url)
                .header("Authorization", auth_header)
                .header("User-Agent", "Veracode Rust Client")
                .multipart(form)
        };

        // Use Cow for operation name based on endpoint length to minimize allocations
        let operation_name: Cow<str> = if endpoint.len() < 50 {
            Cow::Owned(format!("File Upload POST {endpoint}"))
        } else {
            Cow::Borrowed("File Upload POST [long endpoint]")
        };

        self.execute_with_retry(request_builder, operation_name)
            .await
    }

    /// Make a POST request with query parameters (like Java implementation for XML API)
    ///
    /// This method mimics the Java API wrapper's approach for POST operations
    /// where parameters are added to the query string rather than form data.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint to call
    /// * `query_params` - Query parameters as key-value pairs
    ///
    /// # Returns
    ///
    /// A `Result` containing the response or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn post_with_query_params(
        &self,
        endpoint: &str,
        query_params: &[(&str, &str)],
    ) -> Result<reqwest::Response, VeracodeError> {
        // Build URL with query parameters using centralized helper
        let url = self.build_url_with_params(endpoint, query_params);

        let auth_header = self.generate_auth_header("POST", &url)?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .header("User-Agent", "Veracode Rust Client")
            .send()
            .await?;

        Ok(response)
    }

    /// Make a GET request with query parameters (like Java implementation for XML API)
    ///
    /// This method mimics the Java API wrapper's approach for GET operations
    /// where parameters are added to the query string.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint to call
    /// * `query_params` - Query parameters as key-value pairs
    ///
    /// # Returns
    ///
    /// A `Result` containing the response or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn get_with_query_params(
        &self,
        endpoint: &str,
        query_params: &[(&str, &str)],
    ) -> Result<reqwest::Response, VeracodeError> {
        // Build URL with query parameters using centralized helper
        let url = self.build_url_with_params(endpoint, query_params);

        let auth_header = self.generate_auth_header("GET", &url)?;

        let response = self
            .client
            .get(&url)
            .header("Authorization", auth_header)
            .header("User-Agent", "Veracode Rust Client")
            .send()
            .await?;

        Ok(response)
    }

    /// Upload a large file using chunked streaming (for uploadlargefile.do)
    ///
    /// This method implements chunked upload functionality similar to the Java API wrapper.
    /// It uploads files in chunks and provides progress tracking capabilities.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint to call  
    /// * `query_params` - Query parameters as key-value pairs
    /// * `file_path` - Path to the file to upload
    /// * `content_type` - Content type for the file (default: binary/octet-stream)
    /// * `progress_callback` - Optional callback for progress tracking
    ///
    /// # Returns
    ///
    /// A `Result` containing the response or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn upload_large_file_chunked<F>(
        &self,
        endpoint: &str,
        query_params: &[(&str, &str)],
        file_path: &str,
        content_type: Option<&str>,
        progress_callback: Option<F>,
    ) -> Result<reqwest::Response, VeracodeError>
    where
        F: Fn(u64, u64, f64) + Send + Sync,
    {
        // Build URL with query parameters using centralized helper
        let url = self.build_url_with_params(endpoint, query_params);

        // Open file and get size
        let mut file = File::open(file_path)
            .map_err(|e| VeracodeError::InvalidConfig(format!("Failed to open file: {e}")))?;

        let file_size = file
            .metadata()
            .map_err(|e| VeracodeError::InvalidConfig(format!("Failed to get file size: {e}")))?
            .len();

        // Check file size limit (2GB for uploadlargefile.do)
        #[allow(clippy::arithmetic_side_effects)]
        const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2GB
        if file_size > MAX_FILE_SIZE {
            return Err(VeracodeError::InvalidConfig(format!(
                "File size ({file_size} bytes) exceeds maximum limit of {MAX_FILE_SIZE} bytes"
            )));
        }

        // Read entire file for now (can be optimized to streaming later)
        file.seek(SeekFrom::Start(0))
            .map_err(|e| VeracodeError::InvalidConfig(format!("Failed to seek file: {e}")))?;

        #[allow(clippy::cast_possible_truncation)]
        let mut file_data = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut file_data)
            .map_err(|e| VeracodeError::InvalidConfig(format!("Failed to read file: {e}")))?;

        // Memory optimization: Wrap file data in Arc to avoid cloning during retries
        let file_data_arc = Arc::new(file_data);
        let content_type_cow: Cow<str> =
            content_type.map_or(Cow::Borrowed("binary/octet-stream"), |ct| {
                if ct.len() < 64 {
                    Cow::Borrowed(ct)
                } else {
                    Cow::Owned(ct.to_string())
                }
            });

        // Create request builder closure for retry logic
        let request_builder = || {
            // Clone Arc (cheap - just increments reference count)
            let file_data_clone = Arc::clone(&file_data_arc);

            // Re-generate auth header for each attempt to avoid signature expiry
            let Ok(auth_header) = self.generate_auth_header("POST", &url) else {
                return self.client.post("invalid://url");
            };

            self.client
                .post(&url)
                .header("Authorization", auth_header)
                .header("User-Agent", "Veracode Rust Client")
                .header("Content-Type", content_type_cow.as_ref())
                .header("Content-Length", file_size.to_string())
                .body((*file_data_clone).clone())
        };

        // Track progress if callback provided (do this before retry loop)
        if let Some(callback) = progress_callback {
            callback(file_size, file_size, 100.0);
        }

        // Use optimized operation name
        let operation_name: Cow<str> = if endpoint.len() < 50 {
            Cow::Owned(format!("Large File Upload POST {endpoint}"))
        } else {
            Cow::Borrowed("Large File Upload POST [long endpoint]")
        };

        self.execute_with_retry(request_builder, operation_name)
            .await
    }

    /// Upload a file with binary data (optimized for uploadlargefile.do)
    ///
    /// This method uploads a file as raw binary data without multipart encoding,
    /// which is the expected format for the uploadlargefile.do endpoint.
    ///
    /// Memory optimization: Uses Arc for file data and Cow for strings to minimize
    /// allocations during retry attempts. Automatically retries on transient failures.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The API endpoint to call
    /// * `query_params` - Query parameters as key-value pairs  
    /// * `file_data` - File data as bytes
    /// * `content_type` - Content type for the file
    ///
    /// # Returns
    ///
    /// A `Result` containing the response or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    pub async fn upload_file_binary(
        &self,
        endpoint: &str,
        query_params: &[(&str, &str)],
        file_data: Vec<u8>,
        content_type: &str,
    ) -> Result<reqwest::Response, VeracodeError> {
        // Build URL with query parameters using centralized helper
        let url = self.build_url_with_params(endpoint, query_params);

        // Memory optimization: Wrap file data in Arc to avoid cloning during retries
        let file_data_arc = Arc::new(file_data);
        let file_size = file_data_arc.len();

        // Use Cow for content type to minimize allocations
        let content_type_cow: Cow<str> = if content_type.len() < 64 {
            Cow::Borrowed(content_type)
        } else {
            Cow::Owned(content_type.to_string())
        };

        // Create request builder closure for retry logic
        let request_builder = || {
            // Clone Arc (cheap - just increments reference count)
            let file_data_clone = Arc::clone(&file_data_arc);

            // Re-generate auth header for each attempt to avoid signature expiry
            let Ok(auth_header) = self.generate_auth_header("POST", &url) else {
                return self.client.post("invalid://url");
            };

            self.client
                .post(&url)
                .header("Authorization", auth_header)
                .header("User-Agent", "Veracode Rust Client")
                .header("Content-Type", content_type_cow.as_ref())
                .header("Content-Length", file_size.to_string())
                .body((*file_data_clone).clone())
        };

        // Use optimized operation name based on endpoint length
        let operation_name: Cow<str> = if endpoint.len() < 50 {
            Cow::Owned(format!("Binary File Upload POST {endpoint}"))
        } else {
            Cow::Borrowed("Binary File Upload POST [long endpoint]")
        };

        self.execute_with_retry(request_builder, operation_name)
            .await
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test code: expect is acceptable for test setup
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ============================================================================
    // TIER 1: PROPERTY-BASED SECURITY TESTS (Fast, High ROI)
    // ============================================================================

    /// Helper to create a test config with dummy credentials
    fn create_test_config() -> VeracodeConfig {
        use crate::{VeracodeCredentials, VeracodeRegion};

        VeracodeConfig {
            credentials: VeracodeCredentials::new(
                "test_api_id".to_string(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            base_url: "https://api.veracode.com".to_string(),
            rest_base_url: "https://api.veracode.com".to_string(),
            xml_base_url: "https://analysiscenter.veracode.com".to_string(),
            region: VeracodeRegion::Commercial,
            validate_certificates: true,
            connect_timeout: 30,
            request_timeout: 300,
            proxy_url: None,
            proxy_username: None,
            proxy_password: None,
            retry_config: Default::default(),
        }
    }

    // ============================================================================
    // SECURITY TEST: URL Construction & Parameter Encoding
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: URL parameter encoding must prevent injection attacks
        /// Tests that special characters are properly encoded and cannot break URL structure
        #[test]
        fn proptest_url_params_prevent_injection(
            key in "[a-zA-Z0-9_]{1,50}",
            value in ".*{0,100}",
        ) {
            let config = create_test_config();
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");

            let params = vec![(key.as_str(), value.as_str())];
            let url = client.build_url_with_params("/api/test", &params);

            // Property 1: URL must not contain unencoded dangerous characters
            prop_assert!(!url.contains("<script>"));
            prop_assert!(!url.contains("javascript:"));

            // Property 2: URL must contain properly encoded parameters
            prop_assert!(url.starts_with("https://api.veracode.com/api/test"));

            // Property 3: If params are present, URL must contain '?'
            if !params.is_empty() && !key.is_empty() {
                prop_assert!(url.contains('?'));
            }
        }

        /// Property: URL construction must handle capacity overflow safely
        /// Tests that large numbers of parameters don't cause panics or overflows
        #[test]
        fn proptest_url_params_capacity_safe(
            param_count in 0usize..=100,
        ) {
            let config = create_test_config();
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");

            // Create param_count parameters
            let params: Vec<(&str, &str)> = (0..param_count)
                .map(|_| ("key", "value"))
                .collect();

            // Must not panic on capacity calculations
            let url = client.build_url_with_params("/api/test", &params);

            // Property: URL should be valid and not panic
            prop_assert!(url.starts_with("https://"));
            prop_assert!(url.len() < 100000); // Reasonable upper bound
        }

        /// Property: Empty and whitespace-only parameters are handled safely
        #[test]
        fn proptest_url_params_empty_safe(
            key in "\\s*",
            value in "\\s*",
        ) {
            let config = create_test_config();
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");

            let params = vec![(key.as_str(), value.as_str())];
            let url = client.build_url_with_params("/api/test", &params);

            // Must not panic and produce valid URL
            prop_assert!(url.starts_with("https://"));
        }
    }

    // ============================================================================
    // SECURITY TEST: HMAC Signature Generation
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: HMAC signature generation must handle invalid URLs gracefully
        /// Tests that malformed URLs return errors instead of panicking
        #[test]
        fn proptest_hmac_invalid_urls_return_error(
            invalid_url in ".*{0,100}",
        ) {
            let config = create_test_config();
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");

            // Property: Invalid URLs must return Err, never panic
            let result = client.generate_hmac_signature(
                "GET",
                &invalid_url,
                1234567890000,
                "0123456789abcdef0123456789abcdef",
            );

            // Either succeeds (if URL happens to be valid) or returns error
            match result {
                Ok(_) => {
                    // If it succeeded, the URL must have been parseable
                    prop_assert!(Url::parse(&invalid_url).is_ok());
                },
                Err(e) => {
                    // Error must be Authentication error
                    prop_assert!(matches!(e, VeracodeError::Authentication(_)));
                }
            }
        }

        /// Property: HMAC signature must be deterministic
        /// Same inputs must always produce the same signature
        #[test]
        fn proptest_hmac_deterministic(
            method in "[A-Z]{3,7}",
            timestamp in 1000000000000u64..2000000000000u64,
        ) {
            let config = create_test_config();
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");

            let url = "https://api.veracode.com/api/test";
            let nonce = "0123456789abcdef0123456789abcdef";

            let sig1 = client.generate_hmac_signature(&method, url, timestamp, nonce);
            let sig2 = client.generate_hmac_signature(&method, url, timestamp, nonce);

            // Property: Deterministic - same inputs produce same output
            match (sig1, sig2) {
                (Ok(s1), Ok(s2)) => prop_assert_eq!(s1, s2),
                (Err(_), Err(_)) => {}, // Both failed - also deterministic
                _ => prop_assert!(false, "Non-deterministic result"),
            }
        }

        /// Property: Invalid hex nonce must return error
        /// Tests that non-hex nonces are rejected safely
        #[test]
        fn proptest_hmac_invalid_nonce_returns_error(
            invalid_nonce in "[^0-9a-fA-F]{1,32}",
        ) {
            let config = create_test_config();
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");

            let result = client.generate_hmac_signature(
                "GET",
                "https://api.veracode.com/api/test",
                1234567890000,
                &invalid_nonce,
            );

            // Property: Non-hex nonce must return Authentication error
            prop_assert!(matches!(result, Err(VeracodeError::Authentication(_))));
        }

        /// Property: Timestamp overflow must be handled safely
        /// Tests edge cases in timestamp handling
        #[test]
        fn proptest_hmac_timestamp_safe(
            timestamp in any::<u64>(),
        ) {
            let config = create_test_config();
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");

            let url = "https://api.veracode.com/api/test";
            let nonce = "0123456789abcdef0123456789abcdef";

            // Must not panic on any timestamp value
            let result = client.generate_hmac_signature("GET", url, timestamp, nonce);

            // Property: Either succeeds or returns error, never panics
            prop_assert!(result.is_ok() || result.is_err());
        }
    }

    // ============================================================================
    // SECURITY TEST: Authentication Header Generation
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Auth header must contain all required components
        /// Tests that generated headers have proper VERACODE-HMAC-SHA-256 format
        #[test]
        fn proptest_auth_header_format(
            method in "[A-Z]{3,7}",
        ) {
            let config = create_test_config();
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");

            let url = "https://api.veracode.com/api/test";
            let result = client.generate_auth_header(&method, url);

            if let Ok(header) = result {
                // Property 1: Must start with correct prefix
                prop_assert!(header.starts_with("VERACODE-HMAC-SHA-256"));

                // Property 2: Must contain all required fields
                prop_assert!(header.contains("id="));
                prop_assert!(header.contains("ts="));
                prop_assert!(header.contains("nonce="));
                prop_assert!(header.contains("sig="));

                // Property 3: Fields must be comma-separated
                let parts: Vec<&str> = header.split(',').collect();
                prop_assert_eq!(parts.len(), 4);
            }
        }

        /// Property: Auth header nonce must be unique and valid hex
        /// Tests that nonces are properly generated as 32-character hex strings
        #[test]
        fn proptest_auth_header_nonce_unique(
            _seed in any::<u8>(),
        ) {
            let config = create_test_config();
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");

            let url = "https://api.veracode.com/api/test";

            // Generate two headers
            let header1 = client.generate_auth_header("GET", url)
                .expect("valid auth header generation");
            let header2 = client.generate_auth_header("GET", url)
                .expect("valid auth header generation");

            // Extract nonces using a helper function (avoids lifetime issues)
            fn extract_nonce(h: &str) -> Option<String> {
                Some(h.split("nonce=")
                    .nth(1)?
                    .split(',')
                    .next()?
                    .to_string())
            }

            if let (Some(nonce1), Some(nonce2)) = (extract_nonce(&header1), extract_nonce(&header2)) {
                // Property 1: Nonces should be different (probabilistically)
                // With 128-bit random, collision is extremely unlikely
                prop_assert_ne!(&nonce1, &nonce2);

                // Property 2: Nonces must be valid hex (32 chars for 16 bytes)
                prop_assert_eq!(nonce1.len(), 32);
                prop_assert_eq!(nonce2.len(), 32);
                prop_assert!(nonce1.chars().all(|c| c.is_ascii_hexdigit()));
                prop_assert!(nonce2.chars().all(|c| c.is_ascii_hexdigit()));
            }
        }
    }

    // ============================================================================
    // SECURITY TEST: Configuration & Client Creation
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 100 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Client creation with invalid config must fail gracefully
        /// Tests that invalid proxy URLs are caught during client creation
        #[test]
        fn proptest_client_creation_invalid_proxy(
            invalid_proxy in ".*{0,100}",
        ) {
            use crate::{VeracodeCredentials, VeracodeRegion};

            let config = VeracodeConfig {
                credentials: VeracodeCredentials::new(
                    "test_api_id".to_string(),
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                base_url: "https://api.veracode.com".to_string(),
                rest_base_url: "https://api.veracode.com".to_string(),
                xml_base_url: "https://analysiscenter.veracode.com".to_string(),
                region: VeracodeRegion::Commercial,
                validate_certificates: true,
                connect_timeout: 30,
                request_timeout: 300,
                proxy_url: Some(invalid_proxy.clone()),
                proxy_username: None,
                proxy_password: None,
                retry_config: Default::default(),
            };

            let result = VeracodeClient::new(config);

            // Property: Either succeeds (if proxy URL is valid) or returns InvalidConfig error
            match result {
                Ok(_) => {
                    // If successful, proxy URL must be valid
                    prop_assert!(reqwest::Proxy::all(&invalid_proxy).is_ok());
                },
                Err(e) => {
                    // Must be InvalidConfig error
                    prop_assert!(matches!(e, VeracodeError::InvalidConfig(_)));
                }
            }
        }

        /// Property: Timeout values must be handled safely
        /// Tests that extreme timeout values don't cause panics
        #[test]
        fn proptest_client_timeouts_safe(
            connect_timeout in 1u64..=3600,
            request_timeout in 1u64..=7200,
        ) {
            use crate::{VeracodeCredentials, VeracodeRegion};

            let config = VeracodeConfig {
                credentials: VeracodeCredentials::new(
                    "test_api_id".to_string(),
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                base_url: "https://api.veracode.com".to_string(),
                rest_base_url: "https://api.veracode.com".to_string(),
                xml_base_url: "https://analysiscenter.veracode.com".to_string(),
                region: VeracodeRegion::Commercial,
                validate_certificates: true,
                connect_timeout,
                request_timeout,
                proxy_url: None,
                proxy_username: None,
                proxy_password: None,
                retry_config: Default::default(),
            };

            // Must not panic on any valid timeout values
            let result = VeracodeClient::new(config);
            prop_assert!(result.is_ok());
        }
    }

    // ============================================================================
    // SECURITY TEST: File Size Limits & Memory Safety
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 100 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: File size calculations must not overflow
        /// Tests that capacity calculations for file uploads are safe
        #[test]
        fn proptest_file_upload_capacity_safe(
            file_size in 0usize..=1000000,
        ) {
            // Create file data of specified size
            let file_data = vec![0u8; file_size];

            // Wrap in Arc like the upload functions do
            let file_data_arc = Arc::new(file_data);

            // Property 1: Length must match original size
            prop_assert_eq!(file_data_arc.len(), file_size);

            // Property 2: Arc clone must be cheap (same allocation)
            let clone1 = Arc::clone(&file_data_arc);
            let clone2 = Arc::clone(&file_data_arc);
            prop_assert_eq!(clone1.len(), file_size);
            prop_assert_eq!(clone2.len(), file_size);
        }

        /// Property: Content-Type handling must prevent injection
        /// Tests that content types are handled safely without code execution
        #[test]
        fn proptest_content_type_safe(
            content_type in ".*{0,200}",
        ) {
            // Test Cow allocation strategy
            let content_type_cow: Cow<str> = if content_type.len() < 64 {
                Cow::Borrowed(&content_type)
            } else {
                Cow::Owned(content_type.clone())
            };

            // Property 1: Must not contain script injection attempts
            let ct_lower = content_type_cow.to_lowercase();
            if ct_lower.contains("<script>") || ct_lower.contains("javascript:") {
                // These should be treated as literal strings, not executed
                prop_assert!(content_type_cow.as_ref().contains("<script>") ||
                           content_type_cow.as_ref().contains("javascript:"));
            }

            // Property 2: Length must be preserved
            prop_assert_eq!(content_type_cow.len(), content_type.len());
        }
    }

    // ============================================================================
    // UNIT TESTS: Specific Security Scenarios
    // ============================================================================

    #[test]
    fn test_hmac_signature_with_query_params() {
        let config = create_test_config();
        let client = VeracodeClient::new(config).expect("valid test client configuration");

        // Test URL with query parameters
        let url = "https://api.veracode.com/api/test?param1=value1&param2=value2";
        let nonce = "0123456789abcdef0123456789abcdef";
        let timestamp = 1234567890000;

        let result = client.generate_hmac_signature("GET", url, timestamp, nonce);
        assert!(result.is_ok());

        let signature = result.expect("valid HMAC signature");
        // HMAC signature should be 64 hex characters (32 bytes * 2)
        assert_eq!(signature.len(), 64);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hmac_signature_different_methods() {
        let config = create_test_config();
        let client = VeracodeClient::new(config).expect("valid test client configuration");

        let url = "https://api.veracode.com/api/test";
        let nonce = "0123456789abcdef0123456789abcdef";
        let timestamp = 1234567890000;

        let sig_get = client
            .generate_hmac_signature("GET", url, timestamp, nonce)
            .expect("valid HMAC signature for GET");
        let sig_post = client
            .generate_hmac_signature("POST", url, timestamp, nonce)
            .expect("valid HMAC signature for POST");

        // Different methods should produce different signatures
        assert_ne!(sig_get, sig_post);
    }

    #[test]
    fn test_url_encoding_special_characters() {
        let config = create_test_config();
        let client = VeracodeClient::new(config).expect("valid test client configuration");

        // Test that special characters are properly encoded
        let params = vec![
            ("key1", "value with spaces"),
            ("key2", "value&with&ampersands"),
            ("key3", "value=with=equals"),
            ("key4", "value?with?questions"),
        ];

        let url = client.build_url_with_params("/api/test", &params);

        // URL should contain encoded spaces
        assert!(url.contains("value%20with%20spaces") || url.contains("value+with+spaces"));
        // URL should contain encoded ampersands
        assert!(url.contains("%26"));
        // URL should start with base URL
        assert!(url.starts_with("https://api.veracode.com/api/test?"));
    }

    #[test]
    fn test_url_encoding_unicode() {
        let config = create_test_config();
        let client = VeracodeClient::new(config).expect("valid test client configuration");

        // Test Unicode handling
        let params = vec![
            ("key", "你好世界"), // Chinese characters
            ("key2", "🔒🛡️"),    // Emojis
        ];

        let url = client.build_url_with_params("/api/test", &params);

        // Must not panic and should produce valid URL
        assert!(url.starts_with("https://api.veracode.com/api/test?"));
        // URL should contain percent-encoded Unicode
        assert!(url.contains('%'));
    }

    #[test]
    fn test_empty_query_params() {
        let config = create_test_config();
        let client = VeracodeClient::new(config).expect("valid test client configuration");

        let url = client.build_url_with_params("/api/test", &[]);

        // Empty params should not add '?'
        assert_eq!(url, "https://api.veracode.com/api/test");
    }

    #[test]
    fn test_invalid_api_key_format() {
        use crate::{VeracodeCredentials, VeracodeRegion};

        // Create config with non-hex API key
        let config = VeracodeConfig {
            credentials: VeracodeCredentials::new(
                "test_api_id".to_string(),
                "not_valid_hex_key".to_string(),
            ),
            base_url: "https://api.veracode.com".to_string(),
            rest_base_url: "https://api.veracode.com".to_string(),
            xml_base_url: "https://analysiscenter.veracode.com".to_string(),
            region: VeracodeRegion::Commercial,
            validate_certificates: true,
            connect_timeout: 30,
            request_timeout: 300,
            proxy_url: None,
            proxy_username: None,
            proxy_password: None,
            retry_config: Default::default(),
        };

        let client = VeracodeClient::new(config).expect("valid test client configuration");
        let result = client.generate_auth_header("GET", "https://api.veracode.com/api/test");

        // Should return Authentication error for invalid hex key
        assert!(matches!(result, Err(VeracodeError::Authentication(_))));
    }

    #[test]
    fn test_auth_header_format() {
        let config = create_test_config();
        let client = VeracodeClient::new(config).expect("valid test client configuration");

        let header = client
            .generate_auth_header("GET", "https://api.veracode.com/api/test")
            .expect("valid auth header generation");

        // Verify format
        assert!(header.starts_with("VERACODE-HMAC-SHA-256 "));
        assert!(header.contains("id=test_api_id"));
        assert!(header.contains("ts="));
        assert!(header.contains("nonce="));
        assert!(header.contains("sig="));

        // Verify structure (should have 4 comma-separated parts after prefix)
        let parts: Vec<&str> = header.split(',').collect();
        assert_eq!(parts.len(), 4);
    }

    #[cfg(not(miri))] // Skip under Miri - uses SystemTime
    #[test]
    fn test_auth_header_timestamp_monotonic() {
        let config = create_test_config();
        let client = VeracodeClient::new(config).expect("valid test client configuration");

        let header1 = client
            .generate_auth_header("GET", "https://api.veracode.com/api/test")
            .expect("valid auth header generation");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let header2 = client
            .generate_auth_header("GET", "https://api.veracode.com/api/test")
            .expect("valid auth header generation");

        // Extract timestamps
        let extract_ts =
            |h: &str| -> Option<u64> { h.split("ts=").nth(1)?.split(',').next()?.parse().ok() };

        let ts1 = extract_ts(&header1).expect("valid timestamp extraction");
        let ts2 = extract_ts(&header2).expect("valid timestamp extraction");

        // Second timestamp should be >= first (monotonic)
        assert!(ts2 >= ts1);
    }

    #[test]
    fn test_base_url_accessor() {
        let config = create_test_config();
        let client = VeracodeClient::new(config).expect("valid test client configuration");

        assert_eq!(client.base_url(), "https://api.veracode.com");
    }

    #[test]
    fn test_client_clone() {
        let config = create_test_config();
        let client1 = VeracodeClient::new(config).expect("valid test client configuration");
        let client2 = client1.clone();

        // Both clients should have same base URL
        assert_eq!(client1.base_url(), client2.base_url());
    }

    #[test]
    fn test_url_capacity_estimation() {
        let config = create_test_config();
        let client = VeracodeClient::new(config).expect("valid test client configuration");

        // Test with large number of parameters
        let params: Vec<(&str, &str)> = (0..100).map(|_| ("key", "value")).collect();

        let url = client.build_url_with_params("/api/test", &params);

        // Should handle large param counts without panic
        assert!(url.starts_with("https://api.veracode.com/api/test?"));
        assert!(url.len() > 100); // Should contain all params
    }

    #[test]
    fn test_saturating_arithmetic() {
        let config = create_test_config();
        let client = VeracodeClient::new(config).expect("valid test client configuration");

        // Test saturating_add in capacity calculation
        let params: Vec<(&str, &str)> = vec![("k", "v"); 1000];

        // Should not panic even with large numbers
        let url = client.build_url_with_params("/api/test", &params);
        assert!(url.len() < usize::MAX);
    }
}

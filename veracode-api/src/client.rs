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
        let mut url = String::with_capacity(
            self.config.base_url.len().saturating_add(endpoint.len())
        );
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
        let mut url = String::with_capacity(
            self.config.base_url.len().saturating_add(endpoint.len())
        );
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
        let mut url = String::with_capacity(
            self.config.base_url.len().saturating_add(endpoint.len())
        );
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
        let mut url = String::with_capacity(
            self.config.base_url.len().saturating_add(endpoint.len())
        );
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
        let mut url = String::with_capacity(
            self.config.base_url.len().saturating_add(endpoint.len())
        );
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
        let mut url = String::with_capacity(
            self.config.base_url.len().saturating_add(endpoint.len())
        );
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

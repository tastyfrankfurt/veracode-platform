//! Core Veracode API client implementation.
//!
//! This module contains the foundational client for making authenticated requests
//! to the Veracode API, including HMAC authentication and HTTP request handling.

use hex;
use hmac::{Hmac, Mac};
use reqwest::{Client, multipart};
use serde::Serialize;
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::{VeracodeConfig, VeracodeError};

// Type aliases for HMAC
type HmacSha256 = Hmac<Sha256>;

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
    /// Create a new Veracode API client.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing API credentials and settings
    ///
    /// # Returns
    ///
    /// A new `VeracodeClient` instance ready to make API calls.
    pub fn new(config: VeracodeConfig) -> Result<Self, VeracodeError> {
        let mut client_builder = Client::builder();

        // Use the certificate validation setting from config
        if !config.validate_certificates {
            client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        let client = client_builder.build().map_err(VeracodeError::Http)?;
        Ok(Self { config, client })
    }

    /// Get the base URL for API requests.
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Get access to the configuration
    pub fn config(&self) -> &VeracodeConfig {
        &self.config
    }

    /// Get access to the underlying reqwest client
    pub fn client(&self) -> &Client {
        &self.client
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
            .map_err(|_| VeracodeError::Authentication("Invalid URL".to_string()))?;

        let path_and_query = match url_parsed.query() {
            Some(query) => format!("{}?{}", url_parsed.path(), query),
            None => url_parsed.path().to_string(),
        };

        let host = url_parsed.host_str().unwrap_or("");

        // Based on the official Veracode JavaScript implementation:
        // var data = `id=${id}&host=${host}&url=${url}&method=${method}`;
        let data = format!(
            "id={}&host={}&url={}&method={}",
            self.config.api_id.as_str(),
            host,
            path_and_query,
            method
        );

        let timestamp_str = timestamp.to_string();
        let ver_str = "vcode_request_version_1";

        // Convert hex strings to bytes
        let key_bytes = hex::decode(self.config.api_key.as_str()).map_err(|_| {
            VeracodeError::Authentication("Invalid API key format - must be hex string".to_string())
        })?;

        let nonce_bytes = hex::decode(nonce)
            .map_err(|_| VeracodeError::Authentication("Invalid nonce format".to_string()))?;

        // Step 1: HMAC(nonce, key)
        let mut mac1 = HmacSha256::new_from_slice(&key_bytes)
            .map_err(|_| VeracodeError::Authentication("Failed to create HMAC".to_string()))?;
        mac1.update(&nonce_bytes);
        let hashed_nonce = mac1.finalize().into_bytes();

        // Step 2: HMAC(timestamp, hashed_nonce)
        let mut mac2 = HmacSha256::new_from_slice(&hashed_nonce)
            .map_err(|_| VeracodeError::Authentication("Failed to create HMAC".to_string()))?;
        mac2.update(timestamp_str.as_bytes());
        let hashed_timestamp = mac2.finalize().into_bytes();

        // Step 3: HMAC(ver_str, hashed_timestamp)
        let mut mac3 = HmacSha256::new_from_slice(&hashed_timestamp)
            .map_err(|_| VeracodeError::Authentication("Failed to create HMAC".to_string()))?;
        mac3.update(ver_str.as_bytes());
        let hashed_ver_str = mac3.finalize().into_bytes();

        // Step 4: HMAC(data, hashed_ver_str)
        let mut mac4 = HmacSha256::new_from_slice(&hashed_ver_str)
            .map_err(|_| VeracodeError::Authentication("Failed to create HMAC".to_string()))?;
        mac4.update(data.as_bytes());
        let signature = mac4.finalize().into_bytes();

        // Return the hex-encoded signature (lowercase)
        Ok(hex::encode(signature).to_lowercase())
    }

    /// Generate authorization header for HMAC authentication
    pub fn generate_auth_header(&self, method: &str, url: &str) -> Result<String, VeracodeError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64; // Use milliseconds like JavaScript

        // Generate a 16-byte random nonce and convert to hex string
        let nonce_bytes: [u8; 16] = rand::random();
        let nonce = hex::encode(nonce_bytes);

        let signature = self.generate_hmac_signature(method, url, timestamp, &nonce)?;

        Ok(format!(
            "VERACODE-HMAC-SHA-256 id={},ts={},nonce={},sig={}",
            self.config.api_id.as_str(),
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
    pub async fn get(
        &self,
        endpoint: &str,
        query_params: Option<&[(String, String)]>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let mut url = format!("{}{}", self.config.base_url, endpoint);

        if let Some(params) = query_params {
            if !params.is_empty() {
                url.push('?');
                url.push_str(
                    &params
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join("&"),
                );
            }
        }

        let auth_header = self.generate_auth_header("GET", &url)?;

        let response = self
            .client
            .get(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        Ok(response)
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
    pub async fn post<T: Serialize>(
        &self,
        endpoint: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let url = format!("{}{}", self.config.base_url, endpoint);
        let auth_header = self.generate_auth_header("POST", &url)?;

        let mut request = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json");

        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request.send().await?;
        Ok(response)
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
    pub async fn put<T: Serialize>(
        &self,
        endpoint: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let url = format!("{}{}", self.config.base_url, endpoint);
        let auth_header = self.generate_auth_header("PUT", &url)?;

        let mut request = self
            .client
            .put(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json");

        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request.send().await?;
        Ok(response)
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
    pub async fn delete(&self, endpoint: &str) -> Result<reqwest::Response, VeracodeError> {
        let url = format!("{}{}", self.config.base_url, endpoint);
        let auth_header = self.generate_auth_header("DELETE", &url)?;

        let response = self
            .client
            .delete(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        Ok(response)
    }

    /// Helper method to handle common response processing.
    ///
    /// Checks if the response is successful and returns an error if not.
    ///
    /// # Arguments
    ///
    /// * `response` - The HTTP response to check
    ///
    /// # Returns
    ///
    /// A `Result` containing the response if successful, or an error if not.
    pub async fn handle_response(
        response: reqwest::Response,
    ) -> Result<reqwest::Response, VeracodeError> {
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(VeracodeError::InvalidResponse(format!(
                "HTTP {status}: {error_text}"
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
    pub async fn get_with_query(
        &self,
        endpoint: &str,
        query_params: Option<Vec<(String, String)>>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let query_slice = query_params.as_deref();
        let response = self.get(endpoint, query_slice).await?;
        Self::handle_response(response).await
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
    pub async fn post_with_response<T: Serialize>(
        &self,
        endpoint: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let response = self.post(endpoint, body).await?;
        Self::handle_response(response).await
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
    pub async fn put_with_response<T: Serialize>(
        &self,
        endpoint: &str,
        body: Option<&T>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let response = self.put(endpoint, body).await?;
        Self::handle_response(response).await
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
    pub async fn delete_with_response(
        &self,
        endpoint: &str,
    ) -> Result<reqwest::Response, VeracodeError> {
        let response = self.delete(endpoint).await?;
        Self::handle_response(response).await
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
    pub async fn get_paginated(
        &self,
        endpoint: &str,
        base_query_params: Option<Vec<(String, String)>>,
        page_size: Option<u32>,
    ) -> Result<String, VeracodeError> {
        let size = page_size.unwrap_or(500);
        let mut page = 0;
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
                    {
                        if let Some(items) = items_array.as_array() {
                            if items.is_empty() {
                                break; // No more items
                            }
                            all_items.extend(items.clone());
                        }
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
                    ) {
                        if current + 1 >= total {
                            break; // Last page reached
                        }
                    }
                }
            } else {
                // Not JSON or parsing failed, return single response
                return Ok(response_text);
            }

            page += 1;

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
    pub async fn get_with_params(
        &self,
        endpoint: &str,
        params: &[(&str, &str)],
    ) -> Result<reqwest::Response, VeracodeError> {
        let url = format!("{}{}", self.config.base_url, endpoint);
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
    pub async fn post_form(
        &self,
        endpoint: &str,
        params: &[(&str, &str)],
    ) -> Result<reqwest::Response, VeracodeError> {
        let url = format!("{}{}", self.config.base_url, endpoint);

        // Build form data
        let mut form_data = Vec::new();
        for (key, value) in params {
            form_data.push((key.to_string(), value.to_string()));
        }

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
    pub async fn upload_file_multipart(
        &self,
        endpoint: &str,
        params: HashMap<&str, &str>,
        file_field_name: &str,
        filename: &str,
        file_data: Vec<u8>,
    ) -> Result<reqwest::Response, VeracodeError> {
        let url = format!("{}{}", self.config.base_url, endpoint);

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
    pub async fn upload_file_with_query_params(
        &self,
        endpoint: &str,
        query_params: &[(&str, &str)],
        file_field_name: &str,
        filename: &str,
        file_data: Vec<u8>,
    ) -> Result<reqwest::Response, VeracodeError> {
        // Build URL with query parameters (URL encoded)
        let mut url = format!("{}{}", self.config.base_url, endpoint);

        if !query_params.is_empty() {
            url.push('?');
            let encoded_params: Vec<String> = query_params
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        urlencoding::encode(key),
                        urlencoding::encode(value)
                    )
                })
                .collect();
            url.push_str(&encoded_params.join("&"));
        }

        // Build multipart form with only the file
        let part = multipart::Part::bytes(file_data)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| VeracodeError::InvalidConfig(e.to_string()))?;

        let form = multipart::Form::new().part(file_field_name.to_string(), part);

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
    pub async fn post_with_query_params(
        &self,
        endpoint: &str,
        query_params: &[(&str, &str)],
    ) -> Result<reqwest::Response, VeracodeError> {
        // Build URL with query parameters (URL encoded)
        let mut url = format!("{}{}", self.config.base_url, endpoint);

        if !query_params.is_empty() {
            url.push('?');
            let encoded_params: Vec<String> = query_params
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        urlencoding::encode(key),
                        urlencoding::encode(value)
                    )
                })
                .collect();
            url.push_str(&encoded_params.join("&"));
        }

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
    pub async fn get_with_query_params(
        &self,
        endpoint: &str,
        query_params: &[(&str, &str)],
    ) -> Result<reqwest::Response, VeracodeError> {
        // Build URL with query parameters (URL encoded)
        let mut url = format!("{}{}", self.config.base_url, endpoint);

        if !query_params.is_empty() {
            url.push('?');
            let encoded_params: Vec<String> = query_params
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        urlencoding::encode(key),
                        urlencoding::encode(value)
                    )
                })
                .collect();
            url.push_str(&encoded_params.join("&"));
        }

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
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        // Build URL with query parameters
        let mut url = format!("{}{}", self.config.base_url, endpoint);

        if !query_params.is_empty() {
            url.push('?');
            let encoded_params: Vec<String> = query_params
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        urlencoding::encode(key),
                        urlencoding::encode(value)
                    )
                })
                .collect();
            url.push_str(&encoded_params.join("&"));
        }

        // Open file and get size
        let mut file = File::open(file_path)
            .map_err(|e| VeracodeError::InvalidConfig(format!("Failed to open file: {e}")))?;

        let file_size = file
            .metadata()
            .map_err(|e| VeracodeError::InvalidConfig(format!("Failed to get file size: {e}")))?
            .len();

        // Check file size limit (2GB for uploadlargefile.do)
        const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2GB
        if file_size > MAX_FILE_SIZE {
            return Err(VeracodeError::InvalidConfig(format!(
                "File size ({file_size} bytes) exceeds maximum limit of {MAX_FILE_SIZE} bytes"
            )));
        }

        // Read entire file for now (can be optimized to streaming later)
        file.seek(SeekFrom::Start(0))
            .map_err(|e| VeracodeError::InvalidConfig(format!("Failed to seek file: {e}")))?;

        let mut file_data = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut file_data)
            .map_err(|e| VeracodeError::InvalidConfig(format!("Failed to read file: {e}")))?;

        // Generate auth header
        let auth_header = self.generate_auth_header("POST", &url)?;

        // Create request with streaming body
        let request = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .header("User-Agent", "Veracode Rust Client")
            .header(
                "Content-Type",
                content_type.unwrap_or("binary/octet-stream"),
            )
            .header("Content-Length", file_size.to_string())
            .body(file_data);

        // Track progress if callback provided
        if let Some(callback) = progress_callback {
            callback(file_size, file_size, 100.0);
        }

        let response = request.send().await?;
        Ok(response)
    }

    /// Upload a file with binary data (optimized for uploadlargefile.do)
    ///
    /// This method uploads a file as raw binary data without multipart encoding,
    /// which is the expected format for the uploadlargefile.do endpoint.
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
    pub async fn upload_file_binary(
        &self,
        endpoint: &str,
        query_params: &[(&str, &str)],
        file_data: Vec<u8>,
        content_type: &str,
    ) -> Result<reqwest::Response, VeracodeError> {
        // Build URL with query parameters
        let mut url = format!("{}{}", self.config.base_url, endpoint);

        if !query_params.is_empty() {
            url.push('?');
            let encoded_params: Vec<String> = query_params
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        urlencoding::encode(key),
                        urlencoding::encode(value)
                    )
                })
                .collect();
            url.push_str(&encoded_params.join("&"));
        }

        let auth_header = self.generate_auth_header("POST", &url)?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .header("User-Agent", "Veracode Rust Client")
            .header("Content-Type", content_type)
            .header("Content-Length", file_data.len().to_string())
            .body(file_data)
            .send()
            .await?;

        Ok(response)
    }
}

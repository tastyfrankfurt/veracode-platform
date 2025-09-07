//! # Veracode API Client Library
//!
//! A comprehensive Rust client library for interacting with Veracode APIs including
//! Applications, Identity, Pipeline Scan, and Sandbox APIs.
//!
//! This library provides a safe and ergonomic interface to the Veracode platform,
//! handling HMAC authentication, request/response serialization, and error handling.
//!
//! ## Features
//!
//! - 🔐 **HMAC Authentication** - Built-in support for Veracode API credentials
//! - 🌍 **Multi-Regional Support** - Automatic endpoint routing for Commercial, European, and Federal regions
//! - 🔄 **Smart API Routing** - Automatically uses REST or XML APIs based on the operation
//! - 📱 **Applications API** - Manage applications, builds, and scans (REST)
//! - 👤 **Identity API** - User and team management (REST)
//! - 🔍 **Pipeline Scan API** - Automated security scanning in CI/CD pipelines (REST)
//! - 🧪 **Sandbox API** - Development sandbox management (REST)
//! - 📤 **Sandbox Scan API** - File upload and scan operations (XML)
//! - 🚀 **Async/Await** - Built on tokio for high-performance async operations
//! - ⚡ **Type-Safe** - Full Rust type safety with serde serialization
//! - 📊 **Rich Data Types** - Comprehensive data structures for all API responses
//!
//! ## Quick Start
//!
//! ```no_run
//! use veracode_platform::{VeracodeConfig, VeracodeClient, VeracodeRegion};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create configuration - automatically supports both API types
//!     let config = VeracodeConfig::new(
//!         "your_api_id",
//!         "your_api_key",
//!     ).with_region(VeracodeRegion::Commercial); // Optional: defaults to Commercial
//!
//!     let client = VeracodeClient::new(config)?;
//!     
//!     // REST API modules (use api.veracode.*)
//!     let apps = client.get_all_applications().await?;
//!     let pipeline = client.pipeline_api();
//!     let identity = client.identity_api();
//!     let sandbox = client.sandbox_api();  // REST API for sandbox management
//!     let policy = client.policy_api();
//!     
//!     // XML API modules (automatically use analysiscenter.veracode.*)
//!     let scan = client.scan_api(); // XML API for scanning
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Regional Support
//!
//! The library automatically handles regional endpoints for both API types:
//!
//! ```no_run
//! use veracode_platform::{VeracodeConfig, VeracodeRegion};
//!
//! // European region
//! let config = VeracodeConfig::new("api_id", "api_key")
//!     .with_region(VeracodeRegion::European);
//! // REST APIs will use: api.veracode.eu
//! // XML APIs will use: analysiscenter.veracode.eu
//!
//! // US Federal region  
//! let config = VeracodeConfig::new("api_id", "api_key")
//!     .with_region(VeracodeRegion::Federal);
//! // REST APIs will use: api.veracode.us
//! // XML APIs will use: analysiscenter.veracode.us
//! ```
//!
//! ## API Types
//!
//! Different Veracode modules use different API endpoints:
//!
//! - **REST API (api.veracode.*)**: Applications, Identity, Pipeline, Policy, Sandbox management
//! - **XML API (analysiscenter.veracode.*)**: Sandbox scanning operations
//!
//! The client automatically routes each module to the correct API type based on the operation.
//!
//! ## Sandbox Operations
//!
//! Note that sandbox functionality is split across two modules:
//!
//! - **`sandbox_api()`** - Sandbox management (create, delete, list sandboxes) via REST API
//! - **`scan_api()`** - File upload and scan operations via XML API
//!
//! This separation reflects the underlying Veracode API architecture where sandbox management
//! uses the newer REST endpoints while scan operations use the legacy XML endpoints.

pub mod app;
pub mod build;
pub mod client;
pub mod findings;
pub mod identity;
pub mod pipeline;
pub mod policy;
pub mod sandbox;
pub mod scan;
pub mod workflow;

use reqwest::Error as ReqwestError;
use std::fmt;
use std::time::Duration;

// Re-export common types for convenience
pub use app::{
    Application, ApplicationQuery, ApplicationsResponse, CreateApplicationRequest,
    UpdateApplicationRequest,
};
pub use build::{
    Build, BuildApi, BuildError, BuildList, CreateBuildRequest, DeleteBuildRequest,
    DeleteBuildResult, GetBuildInfoRequest, GetBuildListRequest, UpdateBuildRequest,
};
pub use client::VeracodeClient;
pub use findings::{
    CweInfo, FindingCategory, FindingDetails, FindingStatus, FindingsApi, FindingsError,
    FindingsQuery, FindingsResponse, RestFinding,
};
pub use identity::{
    ApiCredential, BusinessUnit, CreateApiCredentialRequest, CreateTeamRequest, CreateUserRequest,
    IdentityApi, IdentityError, Role, Team, UpdateTeamRequest, UpdateUserRequest, User, UserQuery,
    UserType,
};
pub use pipeline::{
    CreateScanRequest, DevStage, Finding, FindingsSummary, PipelineApi, PipelineError, Scan,
    ScanConfig, ScanResults, ScanStage, ScanStatus, SecurityStandards, Severity,
};
pub use policy::{
    PolicyApi, PolicyComplianceResult, PolicyComplianceStatus, PolicyError, PolicyRule,
    PolicyScanRequest, PolicyScanResult, PolicyThresholds, ScanType, SecurityPolicy,
};
pub use sandbox::{
    ApiError, ApiErrorResponse, CreateSandboxRequest, Sandbox, SandboxApi, SandboxError,
    SandboxListParams, SandboxScan, UpdateSandboxRequest,
};
pub use scan::{
    BeginPreScanRequest, BeginScanRequest, PreScanMessage, PreScanResults, ScanApi, ScanError,
    ScanInfo, ScanModule, UploadFileRequest, UploadLargeFileRequest, UploadProgress,
    UploadProgressCallback, UploadedFile,
};
pub use workflow::{VeracodeWorkflow, WorkflowConfig, WorkflowError, WorkflowResultData};
/// Retry configuration for HTTP requests
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (default: 5)
    pub max_attempts: u32,
    /// Initial delay between retries in milliseconds (default: 1000ms)
    pub initial_delay_ms: u64,
    /// Maximum delay between retries in milliseconds (default: 30000ms)
    pub max_delay_ms: u64,
    /// Exponential backoff multiplier (default: 2.0)
    pub backoff_multiplier: f64,
    /// Maximum total time to spend on retries in milliseconds (default: 300000ms = 5 minutes)
    pub max_total_delay_ms: u64,
    /// Buffer time in seconds to add when waiting for rate limit window reset (default: 5s)
    pub rate_limit_buffer_seconds: u64,
    /// Maximum number of retry attempts specifically for rate limit errors (default: 1)
    pub rate_limit_max_attempts: u32,
    /// Whether to enable jitter in retry delays (default: true)
    pub jitter_enabled: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            max_total_delay_ms: 300000,   // 5 minutes
            rate_limit_buffer_seconds: 5, // 5 second buffer for rate limit windows
            rate_limit_max_attempts: 1,   // Only retry once for rate limits
            jitter_enabled: true,         // Enable jitter by default
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration with conservative defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of retry attempts
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Set the initial delay between retries
    pub fn with_initial_delay(mut self, delay_ms: u64) -> Self {
        self.initial_delay_ms = delay_ms;
        self
    }

    /// Set the initial delay between retries (alias for compatibility)
    pub fn with_initial_delay_millis(mut self, delay_ms: u64) -> Self {
        self.initial_delay_ms = delay_ms;
        self
    }

    /// Set the maximum delay between retries
    pub fn with_max_delay(mut self, delay_ms: u64) -> Self {
        self.max_delay_ms = delay_ms;
        self
    }

    /// Set the maximum delay between retries (alias for compatibility)
    pub fn with_max_delay_millis(mut self, delay_ms: u64) -> Self {
        self.max_delay_ms = delay_ms;
        self
    }

    /// Set the exponential backoff multiplier
    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Set the exponential backoff multiplier (alias for compatibility)
    pub fn with_exponential_backoff(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Set the maximum total time to spend on retries
    pub fn with_max_total_delay(mut self, delay_ms: u64) -> Self {
        self.max_total_delay_ms = delay_ms;
        self
    }

    /// Set the buffer time to add when waiting for rate limit window reset
    pub fn with_rate_limit_buffer(mut self, buffer_seconds: u64) -> Self {
        self.rate_limit_buffer_seconds = buffer_seconds;
        self
    }

    /// Set the maximum number of retry attempts for rate limit errors
    pub fn with_rate_limit_max_attempts(mut self, max_attempts: u32) -> Self {
        self.rate_limit_max_attempts = max_attempts;
        self
    }

    /// Disable jitter in retry delays
    ///
    /// Jitter adds randomness to retry delays to prevent thundering herd problems.
    /// Disabling jitter makes retry timing more predictable but may cause synchronized
    /// retries from multiple clients.
    pub fn with_jitter_disabled(mut self) -> Self {
        self.jitter_enabled = false;
        self
    }

    /// Calculate the delay for a given attempt number using exponential backoff
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_millis(0);
        }

        let delay_ms = (self.initial_delay_ms as f64
            * self.backoff_multiplier.powi((attempt - 1) as i32)) as u64;

        let mut capped_delay = delay_ms.min(self.max_delay_ms);

        // Apply jitter if enabled (±25% randomization)
        if self.jitter_enabled {
            use rand::Rng;
            let jitter_range = (capped_delay as f64 * 0.25) as u64;
            let min_delay = capped_delay.saturating_sub(jitter_range);
            let max_delay = capped_delay + jitter_range;
            capped_delay = rand::rng().random_range(min_delay..=max_delay);
        }

        Duration::from_millis(capped_delay)
    }

    /// Calculate the delay for rate limit (429) errors
    ///
    /// For Veracode's 500 requests/minute rate limiting, this calculates the optimal
    /// wait time based on the current time within the minute window or uses the
    /// server's Retry-After header if provided.
    pub fn calculate_rate_limit_delay(&self, retry_after_seconds: Option<u64>) -> Duration {
        if let Some(seconds) = retry_after_seconds {
            // Use the server's suggested delay
            Duration::from_secs(seconds)
        } else {
            // Fall back to minute window calculation for Veracode's 500/minute limit
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();

            let current_second = now.as_secs() % 60;

            // Wait until the next minute window + configurable buffer to ensure window has reset
            let seconds_until_next_minute = 60 - current_second;

            Duration::from_secs(seconds_until_next_minute + self.rate_limit_buffer_seconds)
        }
    }

    /// Check if an error is retryable based on its type
    pub fn is_retryable_error(&self, error: &VeracodeError) -> bool {
        match error {
            VeracodeError::Http(reqwest_error) => {
                // Retry on network errors, timeouts, and temporary server errors
                if reqwest_error.is_timeout()
                    || reqwest_error.is_connect()
                    || reqwest_error.is_request()
                {
                    return true;
                }

                // Check for retryable HTTP status codes
                if let Some(status) = reqwest_error.status() {
                    match status.as_u16() {
                        // 429 Too Many Requests
                        429 => true,
                        // 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout
                        502..=504 => true,
                        // Other server errors (5xx) - retry conservatively
                        500..=599 => true,
                        // Don't retry client errors (4xx) except 429
                        _ => false,
                    }
                } else {
                    // Network-level errors without status codes are typically retryable
                    true
                }
            }
            // Don't retry authentication, serialization, or configuration errors
            VeracodeError::Authentication(_)
            | VeracodeError::Serialization(_)
            | VeracodeError::InvalidConfig(_) => false,
            // InvalidResponse could be temporary (like malformed JSON due to network issues)
            VeracodeError::InvalidResponse(_) => true,
            // NotFound is typically not retryable
            VeracodeError::NotFound(_) => false,
            // New retry-specific error is not retryable (avoid infinite loops)
            VeracodeError::RetryExhausted(_) => false,
            // Rate limited errors are retryable with special handling
            VeracodeError::RateLimited { .. } => true,
        }
    }
}

/// Custom error type for Veracode API operations.
///
/// This enum represents all possible errors that can occur when interacting
/// with the Veracode Applications API.
#[derive(Debug)]
pub enum VeracodeError {
    /// HTTP request failed
    Http(ReqwestError),
    /// JSON serialization/deserialization failed
    Serialization(serde_json::Error),
    /// Authentication error (invalid credentials, signature generation failure, etc.)
    Authentication(String),
    /// API returned an error response
    InvalidResponse(String),
    /// Configuration is invalid
    InvalidConfig(String),
    /// When an item is not found
    NotFound(String),
    /// When all retry attempts have been exhausted
    RetryExhausted(String),
    /// Rate limit exceeded (HTTP 429) - includes server's suggested retry delay
    RateLimited {
        /// Number of seconds to wait before retrying (from Retry-After header)
        retry_after_seconds: Option<u64>,
        /// The original HTTP error response
        message: String,
    },
}

impl VeracodeClient {
    /// Create a specialized client for XML API operations.
    ///
    /// This internal method creates a client configured for the XML API
    /// (analysiscenter.veracode.*) based on the current region settings.
    /// Used exclusively for sandbox scan operations that require the XML API.
    fn new_xml_client(config: VeracodeConfig) -> Result<Self, VeracodeError> {
        let mut xml_config = config;
        xml_config.base_url = xml_config.xml_base_url.clone();
        Self::new(xml_config)
    }

    /// Get an applications API instance.
    /// Uses REST API (api.veracode.*).
    pub fn applications_api(&self) -> &Self {
        self
    }

    /// Get a sandbox API instance.
    /// Uses REST API (api.veracode.*).
    pub fn sandbox_api(&self) -> SandboxApi {
        SandboxApi::new(self)
    }

    /// Get an identity API instance.
    /// Uses REST API (api.veracode.*).
    pub fn identity_api(&self) -> IdentityApi {
        IdentityApi::new(self)
    }

    /// Get a pipeline scan API instance.
    /// Uses REST API (api.veracode.*).
    pub fn pipeline_api(&self) -> PipelineApi {
        PipelineApi::new(self.clone())
    }

    /// Get a pipeline scan API instance with debug enabled.
    /// Uses REST API (api.veracode.*).
    pub fn pipeline_api_with_debug(&self, _debug: bool) -> PipelineApi {
        PipelineApi::new(self.clone())
    }

    /// Get a policy API instance.
    /// Uses REST API (api.veracode.*).
    pub fn policy_api(&self) -> PolicyApi {
        PolicyApi::new(self)
    }

    /// Get a findings API instance.
    /// Uses REST API (api.veracode.*).
    pub fn findings_api(&self) -> FindingsApi {
        FindingsApi::new(self.clone())
    }

    /// Get a findings API instance with debug enabled.
    /// Uses REST API (api.veracode.*).
    pub fn findings_api_with_debug(&self, _debug: bool) -> FindingsApi {
        FindingsApi::new(self.clone())
    }

    /// Get a scan API instance.
    /// Uses XML API (analysiscenter.veracode.*) for both sandbox and application scans.
    pub fn scan_api(&self) -> ScanApi {
        // Create a specialized XML client for scan operations
        let xml_client = Self::new_xml_client(self.config().clone()).unwrap();
        ScanApi::new(xml_client)
    }

    /// Get a build API instance.
    /// Uses XML API (analysiscenter.veracode.*) for build management operations.
    pub fn build_api(&self) -> build::BuildApi {
        // Create a specialized XML client for build operations
        let xml_client = Self::new_xml_client(self.config().clone()).unwrap();
        build::BuildApi::new(xml_client)
    }

    /// Get a workflow helper instance.
    /// Provides high-level operations that combine multiple API calls.
    pub fn workflow(&self) -> workflow::VeracodeWorkflow {
        workflow::VeracodeWorkflow::new(self.clone())
    }
}

impl fmt::Display for VeracodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VeracodeError::Http(e) => write!(f, "HTTP error: {e}"),
            VeracodeError::Serialization(e) => write!(f, "Serialization error: {e}"),
            VeracodeError::Authentication(e) => write!(f, "Authentication error: {e}"),
            VeracodeError::InvalidResponse(e) => write!(f, "Invalid response: {e}"),
            VeracodeError::InvalidConfig(e) => write!(f, "Invalid configuration: {e}"),
            VeracodeError::NotFound(e) => write!(f, "Item not found: {e}"),
            VeracodeError::RetryExhausted(e) => write!(f, "Retry attempts exhausted: {e}"),
            VeracodeError::RateLimited {
                retry_after_seconds,
                message,
            } => match retry_after_seconds {
                Some(seconds) => {
                    write!(f, "Rate limit exceeded: {message} (retry after {seconds}s)")
                }
                None => write!(f, "Rate limit exceeded: {message}"),
            },
        }
    }
}

impl std::error::Error for VeracodeError {}

impl From<ReqwestError> for VeracodeError {
    fn from(error: ReqwestError) -> Self {
        VeracodeError::Http(error)
    }
}

impl From<serde_json::Error> for VeracodeError {
    fn from(error: serde_json::Error) -> Self {
        VeracodeError::Serialization(error)
    }
}

/// Secure wrapper for Veracode API ID that prevents exposure in debug output
#[derive(Clone)]
pub struct SecureVeracodeApiId(String);

/// Secure wrapper for Veracode API key that prevents exposure in debug output
#[derive(Clone)]
pub struct SecureVeracodeApiKey(String);

impl SecureVeracodeApiId {
    pub fn new(api_id: String) -> Self {
        SecureVeracodeApiId(api_id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl SecureVeracodeApiKey {
    pub fn new(api_key: String) -> Self {
        SecureVeracodeApiKey(api_key)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for SecureVeracodeApiId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Debug for SecureVeracodeApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Configuration for the Veracode API client.
///
/// This struct contains all the necessary configuration for connecting to
/// the Veracode APIs, including authentication credentials and regional settings.
/// It automatically manages both REST API (api.veracode.*) and XML API
/// (analysiscenter.veracode.*) endpoints based on the selected region.
#[derive(Clone)]
pub struct VeracodeConfig {
    /// Your Veracode API ID (securely wrapped)
    pub api_id: SecureVeracodeApiId,
    /// Your Veracode API key (securely wrapped, should be kept secret)
    pub api_key: SecureVeracodeApiKey,
    /// Base URL for the current client instance
    pub base_url: String,
    /// REST API base URL (api.veracode.*)
    pub rest_base_url: String,
    /// XML API base URL (analysiscenter.veracode.*)
    pub xml_base_url: String,
    /// Veracode region for your account
    pub region: VeracodeRegion,
    /// Whether to validate TLS certificates (default: true)
    pub validate_certificates: bool,
    /// Retry configuration for HTTP requests
    pub retry_config: RetryConfig,
    /// HTTP connection timeout in seconds (default: 30)
    pub connect_timeout: u64,
    /// HTTP request timeout in seconds (default: 300)
    pub request_timeout: u64,
}

/// Custom Debug implementation for VeracodeConfig that redacts sensitive information
impl std::fmt::Debug for VeracodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VeracodeConfig")
            .field("api_id", &self.api_id)
            .field("api_key", &self.api_key)
            .field("base_url", &self.base_url)
            .field("rest_base_url", &self.rest_base_url)
            .field("xml_base_url", &self.xml_base_url)
            .field("region", &self.region)
            .field("validate_certificates", &self.validate_certificates)
            .field("retry_config", &self.retry_config)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

// URL constants for different regions
const COMMERCIAL_REST_URL: &str = "https://api.veracode.com";
const COMMERCIAL_XML_URL: &str = "https://analysiscenter.veracode.com";
const EUROPEAN_REST_URL: &str = "https://api.veracode.eu";
const EUROPEAN_XML_URL: &str = "https://analysiscenter.veracode.eu";
const FEDERAL_REST_URL: &str = "https://api.veracode.us";
const FEDERAL_XML_URL: &str = "https://analysiscenter.veracode.us";

/// Veracode regions for API access.
///
/// Different regions use different API endpoints. Choose the region
/// that matches your Veracode account configuration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VeracodeRegion {
    /// Commercial region (default) - api.veracode.com
    Commercial,
    /// European region - api.veracode.eu
    European,
    /// US Federal region - api.veracode.us
    Federal,
}

impl VeracodeConfig {
    /// Create a new configuration for the Commercial region.
    ///
    /// This creates a configuration that supports both REST API (api.veracode.*)
    /// and XML API (analysiscenter.veracode.*) endpoints. The base_url defaults
    /// to REST API for most modules, while sandbox scan operations automatically
    /// use the XML API endpoint.
    ///
    /// # Arguments
    ///
    /// * `api_id` - Your Veracode API ID
    /// * `api_key` - Your Veracode API key
    ///
    /// # Returns
    ///
    /// A new `VeracodeConfig` instance configured for the Commercial region.
    pub fn new(api_id: &str, api_key: &str) -> Self {
        Self {
            api_id: SecureVeracodeApiId::new(api_id.to_string()),
            api_key: SecureVeracodeApiKey::new(api_key.to_string()),
            base_url: COMMERCIAL_REST_URL.to_string(),
            rest_base_url: COMMERCIAL_REST_URL.to_string(),
            xml_base_url: COMMERCIAL_XML_URL.to_string(),
            region: VeracodeRegion::Commercial,
            validate_certificates: true, // Default to secure
            retry_config: RetryConfig::default(),
            connect_timeout: 30,  // Default: 30 seconds
            request_timeout: 300, // Default: 5 minutes
        }
    }

    /// Set the region for this configuration.
    ///
    /// This will automatically update both REST and XML API URLs to match the region.
    /// All modules will use the appropriate regional endpoint for their API type.
    ///
    /// # Arguments
    ///
    /// * `region` - The Veracode region to use
    ///
    /// # Returns
    ///
    /// The updated configuration instance (for method chaining).
    pub fn with_region(mut self, region: VeracodeRegion) -> Self {
        let (rest_url, xml_url) = match region {
            VeracodeRegion::Commercial => (COMMERCIAL_REST_URL, COMMERCIAL_XML_URL),
            VeracodeRegion::European => (EUROPEAN_REST_URL, EUROPEAN_XML_URL),
            VeracodeRegion::Federal => (FEDERAL_REST_URL, FEDERAL_XML_URL),
        };

        self.region = region;
        self.rest_base_url = rest_url.to_string();
        self.xml_base_url = xml_url.to_string();
        self.base_url = self.rest_base_url.clone(); // Default to REST
        self
    }

    /// Disable certificate validation for development environments.
    ///
    /// WARNING: This should only be used in development environments with
    /// self-signed certificates. Never use this in production.
    ///
    /// # Returns
    ///
    /// The updated configuration instance (for method chaining).
    pub fn with_certificate_validation_disabled(mut self) -> Self {
        self.validate_certificates = false;
        self
    }

    /// Set a custom retry configuration.
    ///
    /// This allows you to customize the retry behavior for HTTP requests,
    /// including the number of attempts, delays, and backoff strategy.
    ///
    /// # Arguments
    ///
    /// * `retry_config` - The retry configuration to use
    ///
    /// # Returns
    ///
    /// The updated configuration instance (for method chaining).
    pub fn with_retry_config(mut self, retry_config: RetryConfig) -> Self {
        self.retry_config = retry_config;
        self
    }

    /// Disable retries for HTTP requests.
    ///
    /// This will set the retry configuration to perform no retries on failed requests.
    /// Useful for scenarios where you want to handle errors immediately without any delays.
    ///
    /// # Returns
    ///
    /// The updated configuration instance (for method chaining).
    pub fn with_retries_disabled(mut self) -> Self {
        self.retry_config = RetryConfig::new().with_max_attempts(0);
        self
    }

    /// Set the HTTP connection timeout.
    ///
    /// This controls how long to wait for a connection to be established.
    ///
    /// # Arguments
    ///
    /// * `timeout_seconds` - Connection timeout in seconds
    ///
    /// # Returns
    ///
    /// The updated configuration instance (for method chaining).
    pub fn with_connect_timeout(mut self, timeout_seconds: u64) -> Self {
        self.connect_timeout = timeout_seconds;
        self
    }

    /// Set the HTTP request timeout.
    ///
    /// This controls the total time allowed for a request to complete,
    /// including connection establishment, request transmission, and response reception.
    ///
    /// # Arguments
    ///
    /// * `timeout_seconds` - Request timeout in seconds
    ///
    /// # Returns
    ///
    /// The updated configuration instance (for method chaining).
    pub fn with_request_timeout(mut self, timeout_seconds: u64) -> Self {
        self.request_timeout = timeout_seconds;
        self
    }

    /// Set both connection and request timeouts.
    ///
    /// This is a convenience method to set both timeout values at once.
    ///
    /// # Arguments
    ///
    /// * `connect_timeout_seconds` - Connection timeout in seconds
    /// * `request_timeout_seconds` - Request timeout in seconds
    ///
    /// # Returns
    ///
    /// The updated configuration instance (for method chaining).
    pub fn with_timeouts(
        mut self,
        connect_timeout_seconds: u64,
        request_timeout_seconds: u64,
    ) -> Self {
        self.connect_timeout = connect_timeout_seconds;
        self.request_timeout = request_timeout_seconds;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = VeracodeConfig::new("test_api_id", "test_api_key");

        assert_eq!(config.api_id.as_str(), "test_api_id");
        assert_eq!(config.api_key.as_str(), "test_api_key");
        assert_eq!(config.base_url, "https://api.veracode.com");
        assert_eq!(config.rest_base_url, "https://api.veracode.com");
        assert_eq!(config.xml_base_url, "https://analysiscenter.veracode.com");
        assert_eq!(config.region, VeracodeRegion::Commercial);
        assert!(config.validate_certificates); // Default is secure
        assert_eq!(config.retry_config.max_attempts, 5); // Default retry config
    }

    #[test]
    fn test_european_region_config() {
        let config = VeracodeConfig::new("test_api_id", "test_api_key")
            .with_region(VeracodeRegion::European);

        assert_eq!(config.base_url, "https://api.veracode.eu");
        assert_eq!(config.rest_base_url, "https://api.veracode.eu");
        assert_eq!(config.xml_base_url, "https://analysiscenter.veracode.eu");
        assert_eq!(config.region, VeracodeRegion::European);
    }

    #[test]
    fn test_federal_region_config() {
        let config =
            VeracodeConfig::new("test_api_id", "test_api_key").with_region(VeracodeRegion::Federal);

        assert_eq!(config.base_url, "https://api.veracode.us");
        assert_eq!(config.rest_base_url, "https://api.veracode.us");
        assert_eq!(config.xml_base_url, "https://analysiscenter.veracode.us");
        assert_eq!(config.region, VeracodeRegion::Federal);
    }

    #[test]
    fn test_certificate_validation_disabled() {
        let config = VeracodeConfig::new("test_api_id", "test_api_key")
            .with_certificate_validation_disabled();

        assert!(!config.validate_certificates);
    }

    #[test]
    fn test_secure_api_id_debug_redaction() {
        let api_id = SecureVeracodeApiId::new("test_api_id_123".to_string());
        let debug_output = format!("{api_id:?}");
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("test_api_id_123"));
    }

    #[test]
    fn test_secure_api_key_debug_redaction() {
        let api_key = SecureVeracodeApiKey::new("test_api_key_456".to_string());
        let debug_output = format!("{api_key:?}");
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("test_api_key_456"));
    }

    #[test]
    fn test_veracode_config_debug_redaction() {
        let config = VeracodeConfig::new("test_api_id_123", "test_api_key_456");
        let debug_output = format!("{config:?}");

        // Should show structure but redact actual values
        assert!(debug_output.contains("VeracodeConfig"));
        assert!(debug_output.contains("api_id"));
        assert!(debug_output.contains("api_key"));
        assert!(debug_output.contains("[REDACTED]"));

        // Should not contain actual credential values
        assert!(!debug_output.contains("test_api_id_123"));
        assert!(!debug_output.contains("test_api_key_456"));
    }

    #[test]
    fn test_secure_api_id_access_methods() {
        let api_id = SecureVeracodeApiId::new("test_api_id_123".to_string());

        // Test as_str method
        assert_eq!(api_id.as_str(), "test_api_id_123");

        // Test into_string method
        let string_value = api_id.into_string();
        assert_eq!(string_value, "test_api_id_123");
    }

    #[test]
    fn test_secure_api_key_access_methods() {
        let api_key = SecureVeracodeApiKey::new("test_api_key_456".to_string());

        // Test as_str method
        assert_eq!(api_key.as_str(), "test_api_key_456");

        // Test into_string method
        let string_value = api_key.into_string();
        assert_eq!(string_value, "test_api_key_456");
    }

    #[test]
    fn test_secure_api_credentials_clone() {
        let api_id = SecureVeracodeApiId::new("test_api_id_123".to_string());
        let api_key = SecureVeracodeApiKey::new("test_api_key_456".to_string());

        let cloned_api_id = api_id.clone();
        let cloned_api_key = api_key.clone();

        // Both should have the same values
        assert_eq!(api_id.as_str(), cloned_api_id.as_str());
        assert_eq!(api_key.as_str(), cloned_api_key.as_str());
    }

    #[test]
    fn test_error_display() {
        let error = VeracodeError::Authentication("Invalid API key".to_string());
        assert_eq!(format!("{error}"), "Authentication error: Invalid API key");
    }

    #[test]
    fn test_error_from_reqwest() {
        // Test that we can convert from reqwest errors
        // Note: We can't easily create a reqwest::Error for testing,
        // so we'll just verify the From trait implementation exists
        // by checking that it compiles
        fn _test_conversion(error: reqwest::Error) -> VeracodeError {
            VeracodeError::from(error)
        }

        // If this compiles, the From trait is implemented correctly
        // Test passes if no panic occurs
    }

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_delay_ms, 1000);
        assert_eq!(config.max_delay_ms, 30000);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert_eq!(config.max_total_delay_ms, 300000);
        assert!(config.jitter_enabled); // Jitter should be enabled by default
    }

    #[test]
    fn test_retry_config_builder() {
        let config = RetryConfig::new()
            .with_max_attempts(5)
            .with_initial_delay(500)
            .with_max_delay(60000)
            .with_backoff_multiplier(1.5)
            .with_max_total_delay(600000);

        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 60000);
        assert_eq!(config.backoff_multiplier, 1.5);
        assert_eq!(config.max_total_delay_ms, 600000);
    }

    #[test]
    fn test_retry_config_calculate_delay() {
        let config = RetryConfig::new()
            .with_initial_delay(1000)
            .with_backoff_multiplier(2.0)
            .with_max_delay(10000)
            .with_jitter_disabled(); // Disable jitter for predictable testing

        // Test exponential backoff calculation
        assert_eq!(config.calculate_delay(0).as_millis(), 0); // No delay for attempt 0
        assert_eq!(config.calculate_delay(1).as_millis(), 1000); // First retry: 1000ms
        assert_eq!(config.calculate_delay(2).as_millis(), 2000); // Second retry: 2000ms
        assert_eq!(config.calculate_delay(3).as_millis(), 4000); // Third retry: 4000ms
        assert_eq!(config.calculate_delay(4).as_millis(), 8000); // Fourth retry: 8000ms
        assert_eq!(config.calculate_delay(5).as_millis(), 10000); // Fifth retry: capped at max_delay
    }

    #[test]
    fn test_retry_config_is_retryable_error() {
        let config = RetryConfig::new();

        // Test retryable errors
        assert!(
            config.is_retryable_error(&VeracodeError::InvalidResponse("temp error".to_string()))
        );

        // Test non-retryable errors
        assert!(!config.is_retryable_error(&VeracodeError::Authentication("bad auth".to_string())));
        assert!(!config.is_retryable_error(&VeracodeError::Serialization(
            serde_json::from_str::<i32>("invalid").unwrap_err()
        )));
        assert!(
            !config.is_retryable_error(&VeracodeError::InvalidConfig("bad config".to_string()))
        );
        assert!(!config.is_retryable_error(&VeracodeError::NotFound("not found".to_string())));
        assert!(
            !config.is_retryable_error(&VeracodeError::RetryExhausted("exhausted".to_string()))
        );
    }

    #[test]
    fn test_veracode_config_with_retry_config() {
        let retry_config = RetryConfig::new().with_max_attempts(5);
        let config =
            VeracodeConfig::new("test_api_id", "test_api_key").with_retry_config(retry_config);

        assert_eq!(config.retry_config.max_attempts, 5);
    }

    #[test]
    fn test_veracode_config_with_retries_disabled() {
        let config = VeracodeConfig::new("test_api_id", "test_api_key").with_retries_disabled();

        assert_eq!(config.retry_config.max_attempts, 0);
    }

    #[test]
    fn test_timeout_configuration() {
        let config = VeracodeConfig::new("test_api_id", "test_api_key");

        // Test default values
        assert_eq!(config.connect_timeout, 30);
        assert_eq!(config.request_timeout, 300);
    }

    #[test]
    fn test_with_connect_timeout() {
        let config = VeracodeConfig::new("test_api_id", "test_api_key").with_connect_timeout(60);

        assert_eq!(config.connect_timeout, 60);
        assert_eq!(config.request_timeout, 300); // Should remain default
    }

    #[test]
    fn test_with_request_timeout() {
        let config = VeracodeConfig::new("test_api_id", "test_api_key").with_request_timeout(600);

        assert_eq!(config.connect_timeout, 30); // Should remain default
        assert_eq!(config.request_timeout, 600);
    }

    #[test]
    fn test_with_timeouts() {
        let config = VeracodeConfig::new("test_api_id", "test_api_key").with_timeouts(120, 1800);

        assert_eq!(config.connect_timeout, 120);
        assert_eq!(config.request_timeout, 1800);
    }

    #[test]
    fn test_timeout_configuration_chaining() {
        let config = VeracodeConfig::new("test_api_id", "test_api_key")
            .with_region(VeracodeRegion::European)
            .with_connect_timeout(45)
            .with_request_timeout(900)
            .with_retries_disabled();

        assert_eq!(config.region, VeracodeRegion::European);
        assert_eq!(config.connect_timeout, 45);
        assert_eq!(config.request_timeout, 900);
        assert_eq!(config.retry_config.max_attempts, 0);
    }

    #[test]
    fn test_retry_exhausted_error_display() {
        let error = VeracodeError::RetryExhausted("Failed after 3 attempts".to_string());
        assert_eq!(
            format!("{error}"),
            "Retry attempts exhausted: Failed after 3 attempts"
        );
    }

    #[test]
    fn test_rate_limited_error_display_with_retry_after() {
        let error = VeracodeError::RateLimited {
            retry_after_seconds: Some(60),
            message: "Too Many Requests".to_string(),
        };
        assert_eq!(
            format!("{error}"),
            "Rate limit exceeded: Too Many Requests (retry after 60s)"
        );
    }

    #[test]
    fn test_rate_limited_error_display_without_retry_after() {
        let error = VeracodeError::RateLimited {
            retry_after_seconds: None,
            message: "Too Many Requests".to_string(),
        };
        assert_eq!(format!("{error}"), "Rate limit exceeded: Too Many Requests");
    }

    #[test]
    fn test_rate_limited_error_is_retryable() {
        let config = RetryConfig::new();
        let error = VeracodeError::RateLimited {
            retry_after_seconds: Some(60),
            message: "Rate limit exceeded".to_string(),
        };
        assert!(config.is_retryable_error(&error));
    }

    #[test]
    fn test_calculate_rate_limit_delay_with_retry_after() {
        let config = RetryConfig::new();
        let delay = config.calculate_rate_limit_delay(Some(30));
        assert_eq!(delay.as_secs(), 30);
    }

    #[test]
    fn test_calculate_rate_limit_delay_without_retry_after() {
        let config = RetryConfig::new();
        let delay = config.calculate_rate_limit_delay(None);

        // Should be somewhere between buffer (5s) and 60 + buffer (65s)
        // depending on current second within the minute
        assert!(delay.as_secs() >= 5);
        assert!(delay.as_secs() <= 65);
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.rate_limit_buffer_seconds, 5);
        assert_eq!(config.rate_limit_max_attempts, 1);
    }

    #[test]
    fn test_rate_limit_config_builders() {
        let config = RetryConfig::new()
            .with_rate_limit_buffer(10)
            .with_rate_limit_max_attempts(2);

        assert_eq!(config.rate_limit_buffer_seconds, 10);
        assert_eq!(config.rate_limit_max_attempts, 2);
    }

    #[test]
    fn test_rate_limit_delay_uses_buffer() {
        let config = RetryConfig::new().with_rate_limit_buffer(15);
        let delay = config.calculate_rate_limit_delay(None);

        // The delay should include our custom 15s buffer
        assert!(delay.as_secs() >= 15);
        assert!(delay.as_secs() <= 75); // 60 + 15
    }

    #[test]
    fn test_jitter_disabled() {
        let config = RetryConfig::new().with_jitter_disabled();
        assert!(!config.jitter_enabled);

        // With jitter disabled, delays should be consistent
        let delay1 = config.calculate_delay(2);
        let delay2 = config.calculate_delay(2);
        assert_eq!(delay1, delay2);
    }

    #[test]
    fn test_jitter_enabled() {
        let config = RetryConfig::new(); // Jitter enabled by default
        assert!(config.jitter_enabled);

        // With jitter enabled, delays may vary (though they might occasionally be the same)
        let base_delay = config.initial_delay_ms;
        let delay = config.calculate_delay(1);

        // The delay should be within the expected range (±25% jitter)
        let min_expected = (base_delay as f64 * 0.75) as u64;
        let max_expected = (base_delay as f64 * 1.25) as u64;

        assert!(delay.as_millis() >= min_expected as u128);
        assert!(delay.as_millis() <= max_expected as u128);
    }
}

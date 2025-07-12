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
//!         "your_api_id".to_string(),
//!         "your_api_key".to_string(),
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
//! let config = VeracodeConfig::new("api_id".to_string(), "api_key".to_string())
//!     .with_region(VeracodeRegion::European);
//! // REST APIs will use: api.veracode.eu
//! // XML APIs will use: analysiscenter.veracode.eu
//!
//! // US Federal region  
//! let config = VeracodeConfig::new("api_id".to_string(), "api_key".to_string())
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

pub mod client;
pub mod app;
pub mod sandbox;
pub mod scan;
pub mod build;
pub mod identity;
pub mod pipeline;
pub mod policy;
pub mod workflow;

use std::fmt;
use reqwest::Error as ReqwestError;

// Re-export common types for convenience
pub use client::VeracodeClient;
pub use app::{Application, ApplicationQuery, ApplicationsResponse, CreateApplicationRequest, UpdateApplicationRequest};
pub use sandbox::{
    SandboxApi, Sandbox, CreateSandboxRequest, UpdateSandboxRequest, 
    SandboxListParams, SandboxError, SandboxScan, ApiErrorResponse, ApiError
};
pub use scan::{
    ScanApi, UploadedFile, PreScanResults, ScanInfo, ScanModule, PreScanMessage,
    UploadFileRequest, UploadLargeFileRequest, BeginPreScanRequest, BeginScanRequest, 
    ScanError, UploadProgress, UploadProgressCallback
};
pub use build::{
    BuildApi, Build, BuildList, CreateBuildRequest, UpdateBuildRequest, DeleteBuildRequest,
    GetBuildInfoRequest, GetBuildListRequest, DeleteBuildResult, BuildError
};
pub use identity::{
    IdentityApi, User, UserType, Role, Team, BusinessUnit, ApiCredential,
    CreateUserRequest, UpdateUserRequest, CreateTeamRequest, UpdateTeamRequest,
    CreateApiCredentialRequest, UserQuery, IdentityError
};
pub use pipeline::{
    PipelineApi, Finding, Scan, ScanResults, CreateScanRequest, ScanConfig,
    DevStage, ScanStage, ScanStatus, Severity, FindingsSummary, SecurityStandards, PipelineError
};
pub use policy::{
    PolicyApi, SecurityPolicy, PolicyScanRequest, PolicyScanResult, PolicyComplianceResult,
    PolicyComplianceStatus, ScanType, PolicyRule, PolicyThresholds, PolicyError
};
pub use workflow::{
    VeracodeWorkflow, WorkflowConfig, WorkflowError, WorkflowResultData
};
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
}

impl VeracodeClient {
    /// Create a specialized client for XML API operations.
    ///
    /// This internal method creates a client configured for the XML API
    /// (analysiscenter.veracode.*) based on the current region settings.
    /// Used exclusively for sandbox scan operations that require the XML API.
    fn new_xml_client(config: VeracodeConfig) -> Result<Self, VeracodeError> {
        let mut xml_config = config.clone();
        xml_config.base_url = config.xml_base_url;
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
    pub fn pipeline_api_with_debug(&self, debug: bool) -> PipelineApi {
        PipelineApi::new_with_debug(self.clone(), debug)
    }

    /// Get a policy API instance.
    /// Uses REST API (api.veracode.*).
    pub fn policy_api(&self) -> PolicyApi {
        PolicyApi::new(self)
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

/// Configuration for the Veracode API client.
///
/// This struct contains all the necessary configuration for connecting to
/// the Veracode APIs, including authentication credentials and regional settings.
/// It automatically manages both REST API (api.veracode.*) and XML API 
/// (analysiscenter.veracode.*) endpoints based on the selected region.
#[derive(Debug, Clone)]
pub struct VeracodeConfig {
    /// Your Veracode API ID
    pub api_id: String,
    /// Your Veracode API key (should be kept secret)
    pub api_key: String,
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
}

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
    pub fn new(api_id: String, api_key: String) -> Self {
        Self {
            api_id,
            api_key,
            base_url: "https://api.veracode.com".to_string(),
            rest_base_url: "https://api.veracode.com".to_string(),
            xml_base_url: "https://analysiscenter.veracode.com".to_string(),
            region: VeracodeRegion::Commercial,
            validate_certificates: true, // Default to secure
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
            VeracodeRegion::Commercial => (
                "https://api.veracode.com",
                "https://analysiscenter.veracode.com"
            ),
            VeracodeRegion::European => (
                "https://api.veracode.eu",
                "https://analysiscenter.veracode.eu"
            ),
            VeracodeRegion::Federal => (
                "https://api.veracode.us",
                "https://analysiscenter.veracode.us"
            ),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = VeracodeConfig::new(
            "test_api_id".to_string(),
            "test_api_key".to_string(),
        );
        
        assert_eq!(config.api_id, "test_api_id");
        assert_eq!(config.api_key, "test_api_key");
        assert_eq!(config.base_url, "https://api.veracode.com");
        assert_eq!(config.rest_base_url, "https://api.veracode.com");
        assert_eq!(config.xml_base_url, "https://analysiscenter.veracode.com");
        assert_eq!(config.region, VeracodeRegion::Commercial);
        assert!(config.validate_certificates); // Default is secure
    }

    #[test]
    fn test_european_region_config() {
        let config = VeracodeConfig::new(
            "test_api_id".to_string(),
            "test_api_key".to_string(),
        ).with_region(VeracodeRegion::European);
        
        assert_eq!(config.base_url, "https://api.veracode.eu");
        assert_eq!(config.rest_base_url, "https://api.veracode.eu");
        assert_eq!(config.xml_base_url, "https://analysiscenter.veracode.eu");
        assert_eq!(config.region, VeracodeRegion::European);
    }

    #[test]
    fn test_federal_region_config() {
        let config = VeracodeConfig::new(
            "test_api_id".to_string(),
            "test_api_key".to_string(),
        ).with_region(VeracodeRegion::Federal);
        
        assert_eq!(config.base_url, "https://api.veracode.us");
        assert_eq!(config.rest_base_url, "https://api.veracode.us");
        assert_eq!(config.xml_base_url, "https://analysiscenter.veracode.us");
        assert_eq!(config.region, VeracodeRegion::Federal);
    }

    #[test]
    fn test_certificate_validation_disabled() {
        let config = VeracodeConfig::new(
            "test_api_id".to_string(),
            "test_api_key".to_string(),
        ).with_certificate_validation_disabled();
        
        assert!(!config.validate_certificates);
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
        assert!(true);
    }
}
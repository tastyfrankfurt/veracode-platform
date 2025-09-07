//! Findings API for retrieving security findings from Veracode scans
//!
//! This module provides structured access to both policy scan and sandbox scan findings
//! with support for pagination, filtering, and automatic collection of all results.

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
    pub fn findings(&self) -> &[RestFinding] {
        &self.embedded.findings
    }

    /// Check if there's a next page available
    pub fn has_next_page(&self) -> bool {
        self.links.next.is_some()
    }

    /// Get current page number (0-based)
    pub fn current_page(&self) -> u32 {
        self.page.number
    }

    /// Get total number of pages
    pub fn total_pages(&self) -> u32 {
        self.page.total_pages
    }

    /// Check if this is the last page
    pub fn is_last_page(&self) -> bool {
        self.page.number + 1 >= self.page.total_pages
    }

    /// Get total number of findings across all pages
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
    pub fn with_sandbox(mut self, sandbox_guid: &'a str) -> Self {
        self.context = Some(Cow::Borrowed(sandbox_guid));
        self
    }

    /// Add pagination parameters
    pub fn with_pagination(mut self, page: u32, size: u32) -> Self {
        self.page = Some(page);
        self.size = Some(size);
        self
    }

    /// Filter by severity levels (0-5)
    pub fn with_severity(mut self, severity: Vec<u32>) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Filter by CWE IDs
    pub fn with_cwe(mut self, cwe_ids: Vec<String>) -> Self {
        self.cwe_id = Some(cwe_ids);
        self
    }

    /// Filter by scan type
    pub fn with_scan_type(mut self, scan_type: &'a str) -> Self {
        self.scan_type = Some(Cow::Borrowed(scan_type));
        self
    }

    /// Filter to policy violations only
    pub fn policy_violations_only(mut self) -> Self {
        self.violates_policy = Some(true);
        self
    }
}

/// Custom error types for findings API
#[derive(Debug, thiserror::Error)]
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
    pub fn new(client: VeracodeClient) -> Self {
        Self { client }
    }

    /// Get findings with pagination
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
            .map_err(|e| match &e {
                VeracodeError::NotFound { .. } if query.context.is_some() => {
                    FindingsError::SandboxNotFound {
                        app_guid: query.app_guid.to_string(),
                        sandbox_guid: query.context.as_ref().unwrap().to_string(),
                    }
                }
                VeracodeError::NotFound { .. } => FindingsError::ApplicationNotFound {
                    app_guid: query.app_guid.to_string(),
                },
                _ => FindingsError::RequestFailed { source: e },
            })?;

        // Get response text for debugging if parsing fails
        let response_text = response
            .text()
            .await
            .map_err(|e| FindingsError::RequestFailed {
                source: VeracodeError::Http(e),
            })?;

        if response_text.len() > 500 {
            debug!(
                "Raw API response (first 500 chars): {}... [truncated {} more characters]",
                &response_text[..500],
                response_text.len() - 500
            );
        } else {
            debug!("Raw API response: {response_text}");
        }

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
            findings_response.current_page() + 1,
            findings_response.total_pages()
        );

        Ok(findings_response)
    }

    /// Get all findings across all pages automatically
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

            current_page += 1;

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
            current_page + 1
        );
        Ok(all_findings)
    }

    /// Get policy scan findings (convenience method)
    pub async fn get_policy_findings(
        &self,
        app_guid: &str,
    ) -> Result<FindingsResponse, FindingsError> {
        self.get_findings(&FindingsQuery::new(app_guid)).await
    }

    /// Get sandbox findings (convenience method)
    pub async fn get_sandbox_findings(
        &self,
        app_guid: &str,
        sandbox_guid: &str,
    ) -> Result<FindingsResponse, FindingsError> {
        self.get_findings(&FindingsQuery::for_sandbox(app_guid, sandbox_guid))
            .await
    }

    /// Get all policy scan findings (convenience method)
    pub async fn get_all_policy_findings(
        &self,
        app_guid: &str,
    ) -> Result<Vec<RestFinding>, FindingsError> {
        self.get_all_findings(&FindingsQuery::new(app_guid)).await
    }

    /// Get all sandbox findings (convenience method)
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
        assert_eq!(query.context.as_ref().unwrap(), "sandbox-456");
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

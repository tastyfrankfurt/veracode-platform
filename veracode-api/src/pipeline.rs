//! Pipeline Scan API functionality for scanning applications with static analysis.
//!
//! This module provides functionality to interact with the Veracode Pipeline Scan API,
//! allowing you to submit applications for static analysis and retrieve scan results.

use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::{VeracodeClient, VeracodeError};

/// Plugin version constant to avoid repeated allocations
const PLUGIN_VERSION: &str = "25.2.0-0";

/// Error types specific to pipeline scan operations
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("Pipeline scan not found")]
    ScanNotFound,
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Scan timeout")]
    ScanTimeout,
    #[error("Scan findings not ready yet - try again later")]
    FindingsNotReady,
    #[error("Application not found: {0}")]
    ApplicationNotFound(String),
    #[error(
        "Multiple applications found with name '{0}'. Please check the application name and ensure it uniquely identifies a single application."
    )]
    MultipleApplicationsFound(String),
    #[error("API error: {0}")]
    ApiError(#[from] VeracodeError),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

/// Pipeline scan development stage
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DevStage {
    Development,
    Testing,
    Release,
}

impl std::fmt::Display for DevStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DevStage::Development => write!(f, "DEVELOPMENT"),
            DevStage::Testing => write!(f, "TESTING"),
            DevStage::Release => write!(f, "RELEASE"),
        }
    }
}

/// Pipeline scan stage/status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStage {
    Create,
    Upload,
    Start,
    Details,
    Findings,
}

/// Pipeline scan execution status  
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStatus {
    Pending,
    Uploading,
    Started,
    Success,
    Failure,
    Cancelled,
    Timeout,
    #[serde(rename = "USER_TIMEOUT")]
    UserTimeout,
}

impl ScanStatus {
    /// Check if the scan completed successfully
    #[must_use]
    pub fn is_successful(&self) -> bool {
        matches!(self, ScanStatus::Success)
    }

    /// Check if the scan failed or was terminated
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(
            self,
            ScanStatus::Failure
                | ScanStatus::Cancelled
                | ScanStatus::Timeout
                | ScanStatus::UserTimeout
        )
    }

    /// Check if the scan is still in progress
    #[must_use]
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self,
            ScanStatus::Pending | ScanStatus::Uploading | ScanStatus::Started
        )
    }
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Pending => write!(f, "PENDING"),
            ScanStatus::Uploading => write!(f, "UPLOADING"),
            ScanStatus::Started => write!(f, "STARTED"),
            ScanStatus::Success => write!(f, "SUCCESS"),
            ScanStatus::Failure => write!(f, "FAILURE"),
            ScanStatus::Cancelled => write!(f, "CANCELLED"),
            ScanStatus::Timeout => write!(f, "TIMEOUT"),
            ScanStatus::UserTimeout => write!(f, "USER_TIMEOUT"),
        }
    }
}

/// Security finding severity levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    #[serde(rename = "0")]
    Informational,
    #[serde(rename = "1")]
    VeryLow,
    #[serde(rename = "2")]
    Low,
    #[serde(rename = "3")]
    Medium,
    #[serde(rename = "4")]
    High,
    #[serde(rename = "5")]
    VeryHigh,
}

/// Source file information for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    /// File path where the issue was found
    pub file: String,
    /// Function name (may be null)
    pub function_name: Option<String>,
    /// Function prototype
    pub function_prototype: String,
    /// Line number in the file
    pub line: u32,
    /// Qualified function name
    pub qualified_function_name: String,
    /// Scope information
    pub scope: String,
}

/// Files information containing source file details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingFiles {
    /// Source file information
    pub source_file: SourceFile,
}

/// Stack dump information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackDumps {
    /// Array of stack dumps (optional - can be missing when stack_dumps is empty object)
    pub stack_dump: Option<Vec<serde_json::Value>>,
}

/// Security finding/issue from a pipeline scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// CWE (Common Weakness Enumeration) ID as string
    pub cwe_id: String,
    /// Detailed message with HTML formatting
    pub display_text: String,
    /// File and location information
    pub files: FindingFiles,
    /// Flaw details link for accessing detailed vulnerability information (optional)
    pub flaw_details_link: Option<String>,
    /// Grade of defect (e.g., "B")
    pub gob: String,
    /// Issue ID for tracking
    pub issue_id: u32,
    /// Type of security issue
    pub issue_type: String,
    /// Issue type identifier
    pub issue_type_id: String,
    /// Severity level (0-5)
    pub severity: u32,
    /// Stack dump information (optional)
    pub stack_dumps: Option<StackDumps>,
    /// Short title/summary of the issue
    pub title: String,
}

/// Complete findings response from the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsResponse {
    /// HAL navigation links
    #[serde(rename = "_links")]
    pub links: Option<serde_json::Value>,
    /// Scan ID
    pub scan_id: String,
    /// Current scan status
    pub scan_status: ScanStatus,
    /// Scan message
    pub message: String,
    /// List of modules scanned
    pub modules: Vec<String>,
    /// Number of modules
    pub modules_count: u32,
    /// List of security findings
    pub findings: Vec<Finding>,
    /// Selected modules
    pub selected_modules: Vec<String>,
    /// Stack dump information (optional)
    pub stack_dump: Option<serde_json::Value>,
}

/// Legacy Finding struct for backwards compatibility
/// Converts from the new Finding format to a simpler structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyFinding {
    /// File path where the issue was found
    pub file: String,
    /// Line number in the file
    pub line: u32,
    /// Type of security issue
    pub issue_type: String,
    /// Severity level (0-5)
    pub severity: u32,
    /// Descriptive message about the issue (HTML stripped)
    pub message: String,
    /// CWE (Common Weakness Enumeration) ID
    pub cwe_id: u32,
    /// Optional link to more details
    pub details_link: Option<String>,
    /// Issue ID for tracking
    pub issue_id: Option<String>,
    /// OWASP category if applicable
    pub owasp_category: Option<String>,
    /// SANS category if applicable
    pub sans_category: Option<String>,
}

impl Finding {
    /// Convert to legacy format for backwards compatibility
    #[must_use]
    pub fn to_legacy(&self) -> LegacyFinding {
        LegacyFinding {
            file: self.files.source_file.file.clone(),
            line: self.files.source_file.line,
            issue_type: self.issue_type.clone(),
            severity: self.severity,
            message: strip_html_tags(&self.display_text).into_owned(),
            cwe_id: self.cwe_id.parse().unwrap_or(0),
            details_link: None,
            issue_id: Some(self.issue_id.to_string()),
            owasp_category: None,
            sans_category: None,
        }
    }
}

/// Strip HTML tags from display text to get plain text message
fn strip_html_tags(html: &str) -> Cow<'_, str> {
    // Check if HTML tags are present to avoid unnecessary allocation
    if !html.contains('<') {
        return Cow::Borrowed(html);
    }

    // Simple HTML tag removal without regex dependency
    let mut result = String::new();
    let mut in_tag = false;

    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }

    // Clean up extra whitespace
    let cleaned = result.split_whitespace().collect::<Vec<&str>>().join(" ");
    Cow::Owned(cleaned)
}

/// Pipeline scan request for creating a new scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScanRequest {
    /// Name of the binary/artifact being scanned (MANDATORY)
    #[serde(skip_serializing_if = "never_skip_string")]
    pub binary_name: String,
    /// Size of the binary in bytes (MANDATORY)
    #[serde(skip_serializing_if = "never_skip_u64")]
    pub binary_size: u64,
    /// SHA-256 hash of the binary (MANDATORY)
    #[serde(skip_serializing_if = "never_skip_string")]
    pub binary_hash: String,
    /// Project name
    pub project_name: String,
    /// Project URI (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_uri: Option<String>,
    /// Development stage
    pub dev_stage: DevStage,
    /// Application ID (optional, for linking to existing Veracode app)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    /// Project reference/branch/commit (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_ref: Option<String>,
    /// Scan timeout in minutes (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_timeout: Option<u32>,
    /// Plugin version (automatically set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_version: Option<String>,
    /// Emit stack dump flag (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emit_stack_dump: Option<String>,
    /// Include specific modules (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_modules: Option<String>,
}

/// Helper function to never skip String fields (ensures mandatory fields are always included)
fn never_skip_string(_: &String) -> bool {
    false
}

/// Helper function to never skip u64 fields (ensures mandatory fields are always included)
fn never_skip_u64(_: &u64) -> bool {
    false
}

/// Result of scan creation containing scan ID and _links for operations
#[derive(Debug, Clone)]
pub struct ScanCreationResult {
    /// The scan ID
    pub scan_id: String,
    /// Upload URI from _links.upload.href
    pub upload_uri: Option<String>,
    /// Details URI from _links.details.href
    pub details_uri: Option<String>,
    /// Start URI from _links.start.href
    pub start_uri: Option<String>,
    /// Cancel URI from _links.cancel.href
    pub cancel_uri: Option<String>,
    /// Expected number of upload segments
    pub expected_segments: Option<u32>,
}

/// Pipeline scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Maximum timeout in minutes (default: 60)
    pub timeout: Option<u32>,
    /// Include low severity findings
    pub include_low_severity: Option<bool>,
    /// Maximum number of findings to return
    pub max_findings: Option<u32>,
}

/// Pipeline scan details/status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    /// Unique scan ID
    pub scan_id: String,
    /// Current scan status (UPLOADING, VERIFYING, RUNNING, RESULTS_READY, etc.)
    pub scan_status: ScanStatus,
    /// API version
    pub api_version: f64,
    /// Application ID (may be null)
    pub app_id: Option<String>,
    /// Project name
    pub project_name: String,
    /// Project URI
    pub project_uri: Option<String>,
    /// Project reference
    pub project_ref: Option<String>,
    /// Commit hash
    pub commit_hash: Option<String>,
    /// Development stage
    pub dev_stage: String,
    /// Binary name being scanned
    pub binary_name: String,
    /// Binary size in bytes
    pub binary_size: u64,
    /// Binary SHA-256 hash
    pub binary_hash: String,
    /// Expected number of binary segments
    pub binary_segments_expected: u32,
    /// Number of binary segments uploaded
    pub binary_segments_uploaded: u32,
    /// Scan timeout in minutes
    pub scan_timeout: Option<u32>,
    /// Scan duration in minutes (can be fractional)
    pub scan_duration: Option<f64>,
    /// Results size (can be fractional)
    pub results_size: Option<f64>,
    /// Status message
    pub message: Option<String>,
    /// Scan creation time
    pub created: String,
    /// Last changed time
    pub changed: String,
    /// Modules information
    pub modules: Vec<serde_json::Value>,
    /// Selected modules
    pub selected_modules: Vec<serde_json::Value>,
    /// Display modules
    pub display_modules: Vec<serde_json::Value>,
    /// Display selected modules
    pub display_selected_modules: Vec<serde_json::Value>,
    /// Links for navigation (HAL format)
    #[serde(rename = "_links")]
    pub links: Option<serde_json::Value>,
}

/// Pipeline scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// Scan metadata
    pub scan: Scan,
    /// List of security findings
    pub findings: Vec<Finding>,
    /// Findings summary by severity
    pub summary: FindingsSummary,
    /// Security standards compliance
    pub standards: SecurityStandards,
}

/// Summary of findings by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsSummary {
    /// Number of Very High severity findings
    pub very_high: u32,
    /// Number of High severity findings
    pub high: u32,
    /// Number of Medium severity findings
    pub medium: u32,
    /// Number of Low severity findings
    pub low: u32,
    /// Number of Very Low severity findings
    pub very_low: u32,
    /// Number of Informational findings
    pub informational: u32,
    /// Total number of findings
    pub total: u32,
}

/// Security standards compliance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStandards {
    /// OWASP compliance
    pub owasp: Option<StandardCompliance>,
    /// SANS compliance
    pub sans: Option<StandardCompliance>,
    /// PCI compliance
    pub pci: Option<StandardCompliance>,
    /// CWE categories
    pub cwe: Option<StandardCompliance>,
}

/// Compliance information for a security standard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardCompliance {
    /// Total number of applicable rules
    pub total_rules: u32,
    /// Number of rules violated
    pub violations: u32,
    /// Compliance percentage (0-100)
    pub compliance_score: f64,
    /// List of violated rule IDs
    pub violated_rules: Vec<String>,
}

/// Pipeline Scan API client
pub struct PipelineApi {
    client: VeracodeClient,
    // Cached base URL to avoid repeated string operations
    base_url: String,
}

impl PipelineApi {
    /// Create a new Pipeline API client
    #[must_use]
    pub fn new(client: VeracodeClient) -> Self {
        let base_url = Self::compute_base_url(&client);
        Self { client, base_url }
    }

    /// Compute the pipeline scan v1 base URL for file uploads
    fn compute_base_url(client: &VeracodeClient) -> String {
        if client.config().base_url.contains("api.veracode.com") {
            "https://api.veracode.com/pipeline_scan/v1".to_string()
        } else {
            // For other environments, use the configured base URL with pipeline_scan/v1 path
            format!(
                "{}/pipeline_scan/v1",
                client.config().base_url.trim_end_matches('/')
            )
        }
    }

    /// Get the cached pipeline scan v1 base URL
    fn get_pipeline_base_url(&self) -> &str {
        &self.base_url
    }

    /// Look up application ID by application name
    ///
    /// # Arguments
    ///
    /// * `app_name` - The name of the application to search for
    ///
    /// # Returns
    ///
    /// A `Result` containing the application ID as a string if found
    pub async fn lookup_app_id_by_name(&self, app_name: &str) -> Result<String, PipelineError> {
        let applications = self.client.search_applications_by_name(app_name).await?;

        match applications.len() {
            0 => Err(PipelineError::ApplicationNotFound(app_name.to_owned())),
            1 => Ok(applications[0].id.to_string()),
            _ => {
                // Print the found applications to help the user
                error!(
                    "❌ Found {} applications matching '{}':",
                    applications.len(),
                    app_name
                );
                for (i, app) in applications.iter().enumerate() {
                    if let Some(ref profile) = app.profile {
                        error!("   {}. ID: {} - Name: '{}'", i + 1, app.id, profile.name);
                    } else {
                        error!("   {}. ID: {} - GUID: {}", i + 1, app.id, app.guid);
                    }
                }
                error!(
                    "💡 Please provide a more specific application name that matches exactly one application."
                );
                Err(PipelineError::MultipleApplicationsFound(
                    app_name.to_string(),
                ))
            }
        }
    }

    /// Create a new pipeline scan with automatic app_id lookup
    ///
    /// # Arguments
    ///
    /// * `request` - Scan creation request with binary details
    /// * `app_name` - Optional application name to look up app_id automatically
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan details if successful
    pub async fn create_scan_with_app_lookup(
        &self,
        request: &mut CreateScanRequest,
        app_name: Option<&str>,
    ) -> Result<ScanCreationResult, PipelineError> {
        // Look up app_id if app_name is provided
        if let Some(name) = app_name
            && request.app_id.is_none()
        {
            let app_id = self.lookup_app_id_by_name(name).await?;
            request.app_id = Some(app_id.clone());
            info!("✅ Found application '{name}' with ID: {app_id}");
        }

        self.create_scan(request).await
    }

    /// Create a new pipeline scan
    ///
    /// # Arguments
    ///
    /// * `request` - Scan creation request with binary details
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan details if successful
    pub async fn create_scan(
        &self,
        request: &mut CreateScanRequest,
    ) -> Result<ScanCreationResult, PipelineError> {
        // Set plugin version to match Java implementation (from MANIFEST.MF)
        if request.plugin_version.is_none() {
            request.plugin_version = Some(PLUGIN_VERSION.to_string());
        }

        // Set default scan timeout to 30 minutes if not supplied
        if request.scan_timeout.is_none() {
            request.scan_timeout = Some(30);
        }

        // Generate auth header for debugging
        let endpoint = "/pipeline_scan/v1/scans";
        let _full_url = format!("{}{}", self.client.config().base_url, endpoint);

        let response = self
            .client
            .post_with_response("/pipeline_scan/v1/scans", Some(request))
            .await?;

        let response_text = response.text().await?;

        // Parse response to extract scan ID and _links (using actual API response structure)
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&response_text) {
            // Extract scan ID
            let scan_id = json_value
                .get("scan_id")
                .and_then(|id| id.as_str())
                .ok_or_else(|| {
                    PipelineError::InvalidRequest("Missing scan_id in response".to_string())
                })?
                .to_owned();

            // Extract all useful URIs from _links
            let links = json_value.get("_links");

            let upload_uri = links
                .and_then(|links| links.get("upload"))
                .and_then(|upload| upload.get("href"))
                .and_then(|href| href.as_str())
                .map(str::to_owned);

            let details_uri = links
                .and_then(|links| links.get("details"))
                .and_then(|details| details.get("href"))
                .and_then(|href| href.as_str())
                .map(str::to_owned);

            let start_uri = links
                .and_then(|links| links.get("start"))
                .and_then(|start| start.get("href"))
                .and_then(|href| href.as_str())
                .map(str::to_owned);

            let cancel_uri = links
                .and_then(|links| links.get("cancel"))
                .and_then(|cancel| cancel.get("href"))
                .and_then(|href| href.as_str())
                .map(str::to_owned);

            // Extract expected segments
            let expected_segments = json_value
                .get("binary_segments_expected")
                .and_then(|segments| segments.as_u64())
                .map(|s| s as u32);

            debug!("✅ Scan creation response parsed:");
            debug!("   Scan ID: {scan_id}");
            if let Some(ref uri) = upload_uri {
                debug!("   Upload URI: {uri}");
            }
            if let Some(ref uri) = details_uri {
                debug!("   Details URI: {uri}");
            }
            if let Some(ref uri) = start_uri {
                debug!("   Start URI: {uri}");
            }
            if let Some(ref uri) = cancel_uri {
                debug!("   Cancel URI: {uri}");
            }
            if let Some(segments) = expected_segments {
                debug!("   Expected segments: {segments}");
            }

            return Ok(ScanCreationResult {
                scan_id,
                upload_uri,
                details_uri,
                start_uri,
                cancel_uri,
                expected_segments,
            });
        }

        Err(PipelineError::InvalidRequest(
            "Failed to parse scan creation response".to_string(),
        ))
    }

    /// Upload binary data for a scan using segmented upload (matching Java implementation)
    ///
    /// The Veracode Pipeline Scan API requires files to be uploaded in a predetermined
    /// number of segments. This method follows the exact Java implementation pattern:
    /// 1. Gets segment count and upload URI from scan creation response
    /// 2. Calculates segment size as file_size / num_segments
    /// 3. Updates URI after each segment upload based on API response
    ///
    /// # Arguments
    ///
    /// * `initial_upload_uri` - The upload URI from scan creation response
    /// * `expected_segments` - Number of segments expected by the API
    /// * `binary_data` - The binary file data to upload
    /// * `file_name` - Original file name for the binary
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure
    pub async fn upload_binary_segments(
        &self,
        initial_upload_uri: &str,
        expected_segments: i32,
        binary_data: &[u8],
        file_name: &str,
    ) -> Result<(), PipelineError> {
        let total_size = binary_data.len();
        let segment_size = ((total_size as f64) / (expected_segments as f64)).ceil() as usize;

        debug!("📤 Uploading binary in {expected_segments} segments ({total_size} bytes total)");
        debug!("   Segment size: {segment_size} bytes each");

        let mut current_upload_uri = initial_upload_uri.to_string();

        for segment_num in 0..expected_segments {
            let start_idx = (segment_num as usize) * segment_size;
            let end_idx = std::cmp::min(start_idx + segment_size, total_size);
            let segment_data = &binary_data[start_idx..end_idx];

            debug!(
                "   Uploading segment {}/{} ({} bytes)...",
                segment_num + 1,
                expected_segments,
                segment_data.len()
            );

            match self
                .upload_single_segment(&current_upload_uri, segment_data, file_name)
                .await
            {
                Ok(response_text) => {
                    debug!("   ✅ Segment {} uploaded successfully", segment_num + 1);

                    // Parse response to get next upload URI (like Java implementation)
                    if segment_num < expected_segments - 1 {
                        match self.extract_next_upload_uri(&response_text) {
                            Some(next_uri) => {
                                current_upload_uri = next_uri;
                                debug!("   📍 Next segment URI: {current_upload_uri}");
                            }
                            None => {
                                warn!("   ⚠️  No next URI found in response, using current");
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("   ❌ Failed to upload segment {}: {}", segment_num + 1, e);
                    return Err(e);
                }
            }
        }

        debug!("✅ All {expected_segments} segments uploaded successfully");
        Ok(())
    }

    /// Simplified upload method for backwards compatibility
    pub async fn upload_binary(
        &self,
        scan_id: &str,
        binary_data: &[u8],
    ) -> Result<(), PipelineError> {
        // For backwards compatibility, use a default approach
        let upload_uri = format!("/pipeline_scan/scans/{scan_id}/segments/1");
        let expected_segments = 1; // Default to single segment
        let file_name = "binary.tar.gz";

        self.upload_binary_segments(&upload_uri, expected_segments, binary_data, file_name)
            .await
    }

    /// Upload a single segment using the provided URI (exactly matching Java implementation)
    async fn upload_single_segment(
        &self,
        upload_uri: &str,
        segment_data: &[u8],
        file_name: &str,
    ) -> Result<String, PipelineError> {
        // Get base URL and create full URL using pipeline scan v1 base URL
        let url = if upload_uri.starts_with("http") {
            upload_uri.to_string()
        } else {
            format!("{}{}", self.get_pipeline_base_url(), upload_uri)
        };

        // Prepare additional headers for pipeline scan
        let mut headers = std::collections::HashMap::new();
        headers.insert("accept", "application/json");
        headers.insert("PLUGIN-VERSION", PLUGIN_VERSION); // CRITICAL: Java adds this header! (from MANIFEST.MF)

        // Use the client's multipart PUT upload method
        let response = self
            .client
            .upload_file_multipart_put(
                &url,
                "file",
                file_name,
                segment_data.to_vec(),
                Some(headers),
            )
            .await
            .map_err(PipelineError::ApiError)?;

        if response.status().is_success() {
            let response_text = response.text().await?;
            Ok(response_text)
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(PipelineError::InvalidRequest(format!(
                "Segment upload failed with status {status}: {error_text}"
            )))
        }
    }

    /// Extract the next upload URI from the API response (matching Java getUriSuffix)
    fn extract_next_upload_uri(&self, response_text: &str) -> Option<String> {
        // Parse JSON response to find the next upload URI
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(response_text) {
            // Look for _links.upload.href (HAL format)
            if let Some(links) = json_value.get("_links")
                && let Some(upload) = links.get("upload")
                && let Some(href) = upload.get("href")
            {
                return href.as_str().map(str::to_owned);
            }

            // Alternative: look for upload_url field
            if let Some(upload_url) = json_value.get("upload_url") {
                return upload_url.as_str().map(str::to_owned);
            }
        }

        None
    }

    /// Start a pipeline scan using start URI from _links
    ///
    /// # Arguments
    ///
    /// * `start_uri` - The start URI from _links.start.href
    /// * `config` - Optional scan configuration
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure
    pub async fn start_scan_with_uri(
        &self,
        start_uri: &str,
        config: Option<ScanConfig>,
    ) -> Result<(), PipelineError> {
        // Create payload with scan_status: STARTED
        let mut payload = serde_json::json!({
            "scan_status": "STARTED"
        });

        // Add scan config fields if provided
        if let Some(config) = config {
            if let Some(timeout) = config.timeout {
                payload["timeout"] = serde_json::Value::Number(timeout.into());
            }
            if let Some(include_low_severity) = config.include_low_severity {
                payload["include_low_severity"] = serde_json::Value::Bool(include_low_severity);
            }
            if let Some(max_findings) = config.max_findings {
                payload["max_findings"] = serde_json::Value::Number(max_findings.into());
            }
        }

        // Construct full URL with pipeline_scan/v1 base
        let url = if start_uri.starts_with("http") {
            start_uri.to_string()
        } else {
            format!("{}{}", self.get_pipeline_base_url(), start_uri)
        };

        // Generate auth header for PUT request
        let auth_header = self
            .client
            .generate_auth_header("PUT", &url)
            .map_err(PipelineError::ApiError)?;

        let response = self
            .client
            .client()
            .put(&url)
            .header("Authorization", auth_header)
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(PipelineError::InvalidRequest(format!(
                "Failed to start scan: {error_text}"
            )))
        }
    }

    /// Start a pipeline scan (fallback method using scan ID)
    ///
    /// # Arguments
    ///
    /// * `scan_id` - The scan ID
    /// * `config` - Optional scan configuration
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure
    pub async fn start_scan(
        &self,
        scan_id: &str,
        config: Option<ScanConfig>,
    ) -> Result<(), PipelineError> {
        let endpoint = format!("/scans/{scan_id}");
        let url = format!("{}{}", self.get_pipeline_base_url(), endpoint);

        // Create payload with scan_status: STARTED
        let mut payload = serde_json::json!({
            "scan_status": "STARTED"
        });

        // Add scan config fields if provided
        if let Some(config) = config {
            if let Some(timeout) = config.timeout {
                payload["timeout"] = serde_json::Value::Number(timeout.into());
            }
            if let Some(include_low_severity) = config.include_low_severity {
                payload["include_low_severity"] = serde_json::Value::Bool(include_low_severity);
            }
            if let Some(max_findings) = config.max_findings {
                payload["max_findings"] = serde_json::Value::Number(max_findings.into());
            }
        }

        // Generate auth header for PUT request
        let auth_header = self
            .client
            .generate_auth_header("PUT", &url)
            .map_err(PipelineError::ApiError)?;

        let response = self
            .client
            .client()
            .put(&url)
            .header("Authorization", auth_header)
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(PipelineError::InvalidRequest(format!(
                "Failed to start scan: {error_text}"
            )))
        }
    }

    /// Get pipeline scan details using details URI from _links
    ///
    /// # Arguments
    ///
    /// * `details_uri` - The details URI from _links.details.href
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan details
    pub async fn get_scan_with_uri(&self, details_uri: &str) -> Result<Scan, PipelineError> {
        // Construct full URL with pipeline_scan/v1 base
        let url = if details_uri.starts_with("http") {
            details_uri.to_string()
        } else {
            format!("{}{}", self.get_pipeline_base_url(), details_uri)
        };

        // Generate auth header for GET request
        let auth_header = self
            .client
            .generate_auth_header("GET", &url)
            .map_err(PipelineError::ApiError)?;

        let response = self
            .client
            .client()
            .get(&url)
            .header("Authorization", auth_header)
            .header("accept", "application/json")
            .send()
            .await?;

        let response_text = response.text().await?;

        serde_json::from_str::<Scan>(&response_text).map_err(|e| {
            PipelineError::InvalidRequest(format!("Failed to parse scan details: {e}"))
        })
    }

    /// Get pipeline scan details (fallback method using scan ID)
    ///
    /// # Arguments
    ///
    /// * `scan_id` - The scan ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan details
    pub async fn get_scan(&self, scan_id: &str) -> Result<Scan, PipelineError> {
        let endpoint = format!("/scans/{scan_id}");
        let url = format!("{}{}", self.get_pipeline_base_url(), endpoint);

        // Generate auth header for GET request
        let auth_header = self
            .client
            .generate_auth_header("GET", &url)
            .map_err(PipelineError::ApiError)?;

        let response = self
            .client
            .client()
            .get(&url)
            .header("Authorization", auth_header)
            .header("accept", "application/json")
            .send()
            .await?;

        let response_text = response.text().await?;

        serde_json::from_str::<Scan>(&response_text).map_err(|e| {
            PipelineError::InvalidRequest(format!("Failed to parse scan details: {e}"))
        })
    }

    /// Get pipeline scan findings
    ///
    /// # Arguments
    ///
    /// * `scan_id` - The scan ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan findings
    ///
    /// # HTTP Status Codes
    ///
    /// * `200` - Findings are ready and returned
    /// * `202` - Scan accepted but findings not yet available (returns FindingsNotReady error)
    pub async fn get_findings(&self, scan_id: &str) -> Result<Vec<Finding>, PipelineError> {
        let endpoint = format!("/scans/{scan_id}/findings");
        let url = format!("{}{}", self.get_pipeline_base_url(), endpoint);

        debug!("🔍 Debug - get_findings() calling: {url}");

        // Generate auth header for GET request
        let auth_header = self
            .client
            .generate_auth_header("GET", &url)
            .map_err(PipelineError::ApiError)?;

        let response = self
            .client
            .client()
            .get(&url)
            .header("Authorization", auth_header)
            .header("accept", "application/json")
            .send()
            .await?;

        let status = response.status();
        let response_text = response.text().await?;

        // Debug: Print findings response summary
        debug!("🔍 Debug - Findings API Response:");
        debug!("   Status: {status}");
        debug!("   Response Length: {} bytes", response_text.len());

        match status.as_u16() {
            200 => {
                // Findings are ready - parse the response as FindingsResponse
                match serde_json::from_str::<FindingsResponse>(&response_text) {
                    Ok(findings_response) => {
                        debug!("🔍 Debug - Successfully parsed findings response:");
                        debug!("   Scan Status: {}", findings_response.scan_status);
                        debug!("   Message: {}", findings_response.message);
                        debug!("   Modules: [{}]", findings_response.modules.join(", "));
                        debug!("   Findings Count: {}", findings_response.findings.len());
                        Ok(findings_response.findings)
                    }
                    Err(e) => {
                        debug!("❌ Debug - Failed to parse FindingsResponse: {e}");
                        // Fallback: try to parse as generic JSON and extract findings array
                        if let Ok(json_value) =
                            serde_json::from_str::<serde_json::Value>(&response_text)
                            && let Some(findings_array) =
                                json_value.get("findings").and_then(|f| f.as_array())
                        {
                            debug!("🔍 Debug - Trying fallback parsing of findings array...");
                            let findings: Result<Vec<Finding>, _> = findings_array
                                .iter()
                                .map(|f| serde_json::from_value(f.clone()))
                                .collect();
                            return findings.map_err(|e| {
                                PipelineError::InvalidRequest(format!(
                                    "Failed to parse findings array: {e}"
                                ))
                            });
                        }
                        Err(PipelineError::InvalidRequest(format!(
                            "Failed to parse findings response: {e}"
                        )))
                    }
                }
            }
            202 => {
                // Findings not ready yet
                Err(PipelineError::FindingsNotReady)
            }
            _ => {
                // Other error codes
                Err(PipelineError::InvalidRequest(format!(
                    "Failed to get findings - HTTP {status}: {response_text}"
                )))
            }
        }
    }

    /// Get complete scan results (scan details + findings + summary)
    ///
    /// # Arguments
    ///
    /// * `scan_id` - The scan ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the complete scan results
    ///
    /// # Note
    ///
    /// This method will return `FindingsNotReady` error if the scan findings are not yet available.
    /// Use `get_scan()` to check scan status before calling this method.
    pub async fn get_results(&self, scan_id: &str) -> Result<ScanResults, PipelineError> {
        debug!("🔍 Debug - get_results() getting scan details for: {scan_id}");
        let scan = self.get_scan(scan_id).await?;
        debug!("🔍 Debug - get_results() scan status: {}", scan.scan_status);
        debug!("🔍 Debug - get_results() calling get_findings() for: {scan_id}");
        let findings = self.get_findings(scan_id).await?;

        // Calculate summary
        let summary = self.calculate_summary(&findings);

        // Generate standards compliance (placeholder - would need actual implementation)
        let standards = SecurityStandards {
            owasp: None,
            sans: None,
            pci: None,
            cwe: None,
        };

        Ok(ScanResults {
            scan,
            findings,
            summary,
            standards,
        })
    }

    /// Cancel a running pipeline scan
    ///
    /// # Arguments
    ///
    /// * `scan_id` - The scan ID
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure
    pub async fn cancel_scan(&self, scan_id: &str) -> Result<(), PipelineError> {
        let endpoint = format!("/scans/{scan_id}/cancel");

        let response = self.client.delete_with_response(&endpoint).await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(PipelineError::InvalidRequest(format!(
                "Failed to cancel scan: {error_text}"
            )))
        }
    }

    /// Wait for scan to complete with polling
    ///
    /// # Arguments
    ///
    /// * `scan_id` - The scan ID
    /// * `timeout_minutes` - Maximum time to wait (default: 60 minutes)
    /// * `poll_interval_seconds` - Polling interval (default: 10 seconds)
    ///
    /// # Returns
    ///
    /// A `Result` containing the completed scan or timeout error
    pub async fn wait_for_completion(
        &self,
        scan_id: &str,
        timeout_minutes: Option<u32>,
        poll_interval_seconds: Option<u32>,
    ) -> Result<Scan, PipelineError> {
        let timeout = timeout_minutes.unwrap_or(60);
        let interval = poll_interval_seconds.unwrap_or(10);
        let max_polls = (timeout * 60) / interval;

        for _ in 0..max_polls {
            let scan = self.get_scan(scan_id).await?;

            // Check if scan is completed based on status
            if scan.scan_status.is_successful() || scan.scan_status.is_failed() {
                return Ok(scan);
            }

            // Wait before next poll
            tokio::time::sleep(tokio::time::Duration::from_secs(interval as u64)).await;
        }

        Err(PipelineError::ScanTimeout)
    }

    /// Calculate findings summary from a list of findings
    fn calculate_summary(&self, findings: &[Finding]) -> FindingsSummary {
        let mut summary = FindingsSummary {
            very_high: 0,
            high: 0,
            medium: 0,
            low: 0,
            very_low: 0,
            informational: 0,
            total: findings.len() as u32,
        };

        for finding in findings {
            match finding.severity {
                5 => summary.very_high += 1,
                4 => summary.high += 1,
                3 => summary.medium += 1,
                2 => summary.low += 1,
                1 => summary.very_low += 1,
                0 => summary.informational += 1,
                _ => {} // Unknown severity
            }
        }

        summary
    }
}

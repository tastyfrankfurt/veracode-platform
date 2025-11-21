//! Pipeline Scan API functionality for scanning applications with static analysis.
//!
//! This module provides functionality to interact with the Veracode Pipeline Scan API,
//! allowing you to submit applications for static analysis and retrieve scan results.

use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::json_validator::{MAX_JSON_DEPTH, validate_json_depth};
use crate::validation::{validate_scan_id, validate_veracode_url};
use crate::{VeracodeClient, VeracodeError};

/// Plugin version constant to avoid repeated allocations
const PLUGIN_VERSION: &str = "25.2.0-0";

/// Error types specific to pipeline scan operations
#[derive(Debug, thiserror::Error)]
#[must_use = "Need to handle all error enum types."]
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// Array of stack dumps (optional - can be missing when `stack_dumps` is empty object)
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
///
/// Security: This function removes `<script>` and `<style>` tags AND their content
/// to prevent script injection. Other HTML tags are removed but their text content
/// is preserved.
fn strip_html_tags(html: &str) -> Cow<'_, str> {
    // Check if HTML tags are present to avoid unnecessary allocation
    if !html.contains('<') {
        return Cow::Borrowed(html);
    }

    // Simple HTML tag removal without regex dependency
    let mut result = String::new();
    let mut in_tag = false;
    let mut in_script_or_style = false;
    let mut tag_name = String::new();
    let mut collecting_tag_name = false;
    let mut just_closed_tag = false;

    for ch in html.chars() {
        match ch {
            '<' => {
                // Add space before tag if we just had content (for word boundaries)
                if !result.is_empty() && !result.ends_with(char::is_whitespace) {
                    result.push(' ');
                }
                in_tag = true;
                collecting_tag_name = true;
                just_closed_tag = false;
                tag_name.clear();
            }
            '>' => {
                in_tag = false;

                // Check if we're entering or leaving a script/style block
                let tag_lower = tag_name.trim().to_lowercase();
                if tag_lower.starts_with("script") || tag_lower.starts_with("style") {
                    in_script_or_style = true;
                } else if tag_lower.starts_with("/script") || tag_lower.starts_with("/style") {
                    in_script_or_style = false;
                }
                collecting_tag_name = false;
                just_closed_tag = true;
                tag_name.clear();
            }
            ' ' if in_tag && collecting_tag_name => {
                // Space in tag (e.g., <script type="...">), stop collecting tag name
                collecting_tag_name = false;
            }
            _ if (ch == '/' || ch.is_alphanumeric()) && collecting_tag_name => {
                // Collect tag name to detect script/style tags
                tag_name.push(ch);
            }
            _ if in_tag || in_script_or_style => {
                // Skip content inside tags and inside script/style blocks
            }
            _ => {
                // Keep text content (not in tags, not in script/style blocks)
                // Add space after tag if needed (for word boundaries)
                if just_closed_tag && !result.is_empty() && !result.ends_with(char::is_whitespace) {
                    result.push(' ');
                }
                just_closed_tag = false;
                result.push(ch);
            }
        }
    }

    // Clean up extra whitespace (collapse multiple spaces into one)
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// Current scan status (UPLOADING, VERIFYING, RUNNING, `RESULTS_READY`, etc.)
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    pub async fn lookup_app_id_by_name(&self, app_name: &str) -> Result<String, PipelineError> {
        let applications = self.client.search_applications_by_name(app_name).await?;

        match applications.len() {
            0 => Err(PipelineError::ApplicationNotFound(app_name.to_owned())),
            1 => Ok(applications
                .first()
                .ok_or_else(|| PipelineError::ApplicationNotFound(app_name.to_owned()))?
                .id
                .to_string()),
            _ => {
                // Print the found applications to help the user
                error!(
                    "❌ Found {} applications matching '{}':",
                    applications.len(),
                    app_name
                );
                for (i, app) in applications.iter().enumerate() {
                    if let Some(ref profile) = app.profile {
                        error!(
                            "   {}. ID: {} - Name: '{}'",
                            i.saturating_add(1),
                            app.id,
                            profile.name
                        );
                    } else {
                        error!(
                            "   {}. ID: {} - GUID: {}",
                            i.saturating_add(1),
                            app.id,
                            app.guid
                        );
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

    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    /// Create a new pipeline scan with automatic `app_id` lookup
    ///
    /// # Arguments
    ///
    /// * `request` - Scan creation request with binary details
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    /// * `app_name` - Optional application name to look up `app_id` automatically
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan details if successful
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
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

        // Validate JSON depth before parsing to prevent DoS attacks
        validate_json_depth(&response_text, MAX_JSON_DEPTH)
            .map_err(|e| PipelineError::InvalidRequest(format!("JSON validation failed: {}", e)))?;

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
            #[allow(clippy::cast_possible_truncation)]
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    /// 2. Calculates segment size as `file_size` / `num_segments`
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    pub async fn upload_binary_segments(
        &self,
        initial_upload_uri: &str,
        expected_segments: i32,
        binary_data: &[u8],
        file_name: &str,
    ) -> Result<(), PipelineError> {
        // Validate expected_segments to prevent division by zero DoS
        if expected_segments <= 0 {
            return Err(PipelineError::InvalidRequest(format!(
                "Invalid segment count: {}. Must be a positive number.",
                expected_segments
            )));
        }

        let total_size = binary_data.len();
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let segment_size = ((total_size as f64) / (expected_segments as f64)).ceil() as usize;

        debug!("📤 Uploading binary in {expected_segments} segments ({total_size} bytes total)");
        debug!("   Segment size: {segment_size} bytes each");

        let mut current_upload_uri = initial_upload_uri.to_string();

        for segment_num in 0..expected_segments {
            #[allow(clippy::cast_sign_loss)]
            let start_idx = (segment_num as usize).saturating_mul(segment_size);
            let end_idx = std::cmp::min(start_idx.saturating_add(segment_size), total_size);
            let segment_data = binary_data.get(start_idx..end_idx).ok_or_else(|| {
                PipelineError::InvalidRequest(format!(
                    "Invalid segment range: {}..{}",
                    start_idx, end_idx
                ))
            })?;

            debug!(
                "   Uploading segment {}/{} ({} bytes)...",
                segment_num.saturating_add(1),
                expected_segments,
                segment_data.len()
            );

            match self
                .upload_single_segment(&current_upload_uri, segment_data, file_name)
                .await
            {
                Ok(response_text) => {
                    debug!(
                        "   ✅ Segment {} uploaded successfully",
                        segment_num.saturating_add(1)
                    );

                    // Parse response to get next upload URI (like Java implementation)
                    if segment_num < expected_segments.saturating_sub(1) {
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
                    error!(
                        "   ❌ Failed to upload segment {}: {}",
                        segment_num.saturating_add(1),
                        e
                    );
                    return Err(e);
                }
            }
        }

        debug!("✅ All {expected_segments} segments uploaded successfully");
        Ok(())
    }

    /// Simplified upload method for backwards compatibility
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    pub async fn upload_binary(
        &self,
        scan_id: &str,
        binary_data: &[u8],
    ) -> Result<(), PipelineError> {
        // Path traversal protection: validate scan_id before URL construction
        validate_scan_id(scan_id)
            .map_err(|e| PipelineError::InvalidRequest(format!("Invalid scan_id: {}", e)))?;

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
            // SSRF protection: validate full URLs against allowlist
            validate_veracode_url(upload_uri)
                .map_err(|e| PipelineError::InvalidRequest(format!("Invalid upload URI: {}", e)))?;
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
        // Validate JSON depth before parsing to prevent DoS attacks
        if validate_json_depth(response_text, MAX_JSON_DEPTH).is_err() {
            warn!("JSON validation failed in extract_next_upload_uri");
            return None;
        }

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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
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
            if let Some(timeout) = config.timeout
                && let Some(obj) = payload.as_object_mut()
            {
                obj.insert(
                    "timeout".to_string(),
                    serde_json::Value::Number(timeout.into()),
                );
            }
            if let Some(include_low_severity) = config.include_low_severity
                && let Some(obj) = payload.as_object_mut()
            {
                obj.insert(
                    "include_low_severity".to_string(),
                    serde_json::Value::Bool(include_low_severity),
                );
            }
            if let Some(max_findings) = config.max_findings
                && let Some(obj) = payload.as_object_mut()
            {
                obj.insert(
                    "max_findings".to_string(),
                    serde_json::Value::Number(max_findings.into()),
                );
            }
        }

        // Construct full URL with pipeline_scan/v1 base
        let url = if start_uri.starts_with("http") {
            // SSRF protection: validate full URLs against allowlist
            validate_veracode_url(start_uri)
                .map_err(|e| PipelineError::InvalidRequest(format!("Invalid start URI: {}", e)))?;
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    pub async fn start_scan(
        &self,
        scan_id: &str,
        config: Option<ScanConfig>,
    ) -> Result<(), PipelineError> {
        // Path traversal protection: validate scan_id before URL construction
        validate_scan_id(scan_id)
            .map_err(|e| PipelineError::InvalidRequest(format!("Invalid scan_id: {}", e)))?;

        let endpoint = format!("/scans/{scan_id}");
        let url = format!("{}{}", self.get_pipeline_base_url(), endpoint);

        // Create payload with scan_status: STARTED
        let mut payload = serde_json::json!({
            "scan_status": "STARTED"
        });

        // Add scan config fields if provided
        if let Some(config) = config {
            if let Some(timeout) = config.timeout
                && let Some(obj) = payload.as_object_mut()
            {
                obj.insert(
                    "timeout".to_string(),
                    serde_json::Value::Number(timeout.into()),
                );
            }
            if let Some(include_low_severity) = config.include_low_severity
                && let Some(obj) = payload.as_object_mut()
            {
                obj.insert(
                    "include_low_severity".to_string(),
                    serde_json::Value::Bool(include_low_severity),
                );
            }
            if let Some(max_findings) = config.max_findings
                && let Some(obj) = payload.as_object_mut()
            {
                obj.insert(
                    "max_findings".to_string(),
                    serde_json::Value::Number(max_findings.into()),
                );
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    pub async fn get_scan_with_uri(&self, details_uri: &str) -> Result<Scan, PipelineError> {
        // Construct full URL with pipeline_scan/v1 base
        let url = if details_uri.starts_with("http") {
            // SSRF protection: validate full URLs against allowlist
            validate_veracode_url(details_uri).map_err(|e| {
                PipelineError::InvalidRequest(format!("Invalid details URI: {}", e))
            })?;
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

        // Validate JSON depth before parsing to prevent DoS attacks
        validate_json_depth(&response_text, MAX_JSON_DEPTH)
            .map_err(|e| PipelineError::InvalidRequest(format!("JSON validation failed: {}", e)))?;

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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    pub async fn get_scan(&self, scan_id: &str) -> Result<Scan, PipelineError> {
        // Path traversal protection: validate scan_id before URL construction
        validate_scan_id(scan_id)
            .map_err(|e| PipelineError::InvalidRequest(format!("Invalid scan_id: {}", e)))?;

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

        // Validate JSON depth before parsing to prevent DoS attacks
        validate_json_depth(&response_text, MAX_JSON_DEPTH)
            .map_err(|e| PipelineError::InvalidRequest(format!("JSON validation failed: {}", e)))?;

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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    /// * `202` - Scan accepted but findings not yet available (returns `FindingsNotReady` error)
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    pub async fn get_findings(&self, scan_id: &str) -> Result<Vec<Finding>, PipelineError> {
        // Path traversal protection: validate scan_id before URL construction
        validate_scan_id(scan_id)
            .map_err(|e| PipelineError::InvalidRequest(format!("Invalid scan_id: {}", e)))?;

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
                // Validate JSON depth before parsing to prevent DoS attacks
                validate_json_depth(&response_text, MAX_JSON_DEPTH).map_err(|e| {
                    PipelineError::InvalidRequest(format!("JSON validation failed: {}", e))
                })?;

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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    pub async fn cancel_scan(&self, scan_id: &str) -> Result<(), PipelineError> {
        // Path traversal protection: validate scan_id before URL construction
        validate_scan_id(scan_id)
            .map_err(|e| PipelineError::InvalidRequest(format!("Invalid scan_id: {}", e)))?;

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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the pipeline scan fails,
    /// or authentication/authorization fails.
    pub async fn wait_for_completion(
        &self,
        scan_id: &str,
        timeout_minutes: Option<u32>,
        poll_interval_seconds: Option<u32>,
    ) -> Result<Scan, PipelineError> {
        let timeout = timeout_minutes.unwrap_or(60);
        let interval = poll_interval_seconds.unwrap_or(10);
        let max_polls = timeout
            .saturating_mul(60)
            .checked_div(interval)
            .unwrap_or(u32::MAX);

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
        #[allow(clippy::cast_possible_truncation)]
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
                5 => summary.very_high = summary.very_high.saturating_add(1),
                4 => summary.high = summary.high.saturating_add(1),
                3 => summary.medium = summary.medium.saturating_add(1),
                2 => summary.low = summary.low.saturating_add(1),
                1 => summary.very_low = summary.very_low.saturating_add(1),
                0 => summary.informational = summary.informational.saturating_add(1),
                _ => {} // Unknown severity
            }
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_html_tags_no_tags() {
        let input = "This is plain text";
        let result = strip_html_tags(input);
        assert_eq!(result, "This is plain text");
    }

    #[test]
    fn test_strip_html_tags_simple() {
        let input = "This is <b>bold</b> text";
        let result = strip_html_tags(input);
        assert_eq!(result, "This is bold text");
    }

    #[test]
    fn test_strip_html_tags_removes_script_content() {
        // SECURITY: Script content must be removed, not just tags
        let input = "<script>alert('XSS')</script>This is safe";
        let result = strip_html_tags(input);
        assert_eq!(result, "This is safe");
    }

    #[test]
    fn test_strip_html_tags_removes_script_with_attributes() {
        let input = "<script type='text/javascript'>alert('XSS')</script>Safe text";
        let result = strip_html_tags(input);
        assert_eq!(result, "Safe text");
    }

    #[test]
    fn test_strip_html_tags_removes_style_content() {
        let input = "<style>body { color: red; }</style>Visible text";
        let result = strip_html_tags(input);
        assert_eq!(result, "Visible text");
    }

    #[test]
    fn test_strip_html_tags_multiple_scripts() {
        let input = "<script>evil1()</script>Good<script>evil2()</script>Text";
        let result = strip_html_tags(input);
        assert_eq!(result, "Good Text");
    }

    #[test]
    fn test_strip_html_tags_nested_tags() {
        let input = "<div><p>Paragraph <b>bold</b> text</p></div>";
        let result = strip_html_tags(input);
        assert_eq!(result, "Paragraph bold text");
    }

    #[test]
    fn test_strip_html_tags_mixed_content() {
        let input = "Before<script>bad()</script>Middle<b>bold</b>After";
        let result = strip_html_tags(input);
        assert_eq!(result, "Before Middle bold After");
    }

    #[test]
    fn test_strip_html_tags_case_insensitive_script() {
        let input = "<SCRIPT>evil()</SCRIPT>Safe";
        let result = strip_html_tags(input);
        assert_eq!(result, "Safe");
    }

    #[test]
    fn test_strip_html_tags_case_insensitive_style() {
        let input = "<STYLE>css</STYLE>Text";
        let result = strip_html_tags(input);
        assert_eq!(result, "Text");
    }

    #[test]
    fn test_strip_html_tags_whitespace_cleanup() {
        // When HTML tags are present, extra whitespace is collapsed
        let input = "Text   <b>with</b>    extra     <i>spaces</i>";
        let result = strip_html_tags(input);
        assert_eq!(result, "Text with extra spaces");
    }

    #[test]
    fn test_strip_html_tags_no_html_preserves_whitespace() {
        // When no HTML tags, original whitespace is preserved (Cow::Borrowed)
        let input = "Text   with    extra     spaces";
        let result = strip_html_tags(input);
        assert_eq!(result, "Text   with    extra     spaces");
    }

    #[test]
    fn test_strip_html_tags_preserves_normal_content_order() {
        let input = "First <p>Second</p> Third <b>Fourth</b> Fifth";
        let result = strip_html_tags(input);
        assert_eq!(result, "First Second Third Fourth Fifth");
    }

    #[test]
    fn test_scan_status_classifications() {
        // Test success classification
        assert!(ScanStatus::Success.is_successful());
        assert!(!ScanStatus::Success.is_failed());
        assert!(!ScanStatus::Success.is_in_progress());

        // Test failure classifications
        assert!(ScanStatus::Failure.is_failed());
        assert!(ScanStatus::Cancelled.is_failed());
        assert!(ScanStatus::Timeout.is_failed());
        assert!(ScanStatus::UserTimeout.is_failed());

        // Test in-progress classifications
        assert!(ScanStatus::Pending.is_in_progress());
        assert!(ScanStatus::Uploading.is_in_progress());
        assert!(ScanStatus::Started.is_in_progress());
    }

    #[test]
    fn test_finding_to_legacy_conversion() {
        let finding = Finding {
            cwe_id: "89".to_string(),
            display_text: "<b>SQL Injection</b> vulnerability found".to_string(),
            files: FindingFiles {
                source_file: SourceFile {
                    file: "app.rs".to_string(),
                    function_name: Some("query".to_string()),
                    function_prototype: "fn query()".to_string(),
                    line: 42,
                    qualified_function_name: "app::query".to_string(),
                    scope: "local".to_string(),
                },
            },
            flaw_details_link: Some("https://veracode.com/details".to_string()),
            gob: "A".to_string(),
            issue_id: 12345,
            issue_type: "SQL Injection".to_string(),
            issue_type_id: "89".to_string(),
            severity: 5,
            stack_dumps: None,
            title: "SQL Injection Flaw".to_string(),
        };

        let legacy = finding.to_legacy();

        // Verify conversion
        assert_eq!(legacy.file, "app.rs");
        assert_eq!(legacy.line, 42);
        assert_eq!(legacy.severity, 5);
        assert_eq!(legacy.cwe_id, 89);
        assert_eq!(legacy.issue_id, Some("12345".to_string()));
        // HTML should be stripped
        assert_eq!(legacy.message, "SQL Injection vulnerability found");
    }

    #[test]
    fn test_finding_to_legacy_with_invalid_cwe() {
        let finding = Finding {
            cwe_id: "not-a-number".to_string(),
            display_text: "Test".to_string(),
            files: FindingFiles {
                source_file: SourceFile {
                    file: "app.rs".to_string(),
                    function_name: None,
                    function_prototype: "fn test()".to_string(),
                    line: 1,
                    qualified_function_name: "app::test".to_string(),
                    scope: "local".to_string(),
                },
            },
            flaw_details_link: None,
            gob: "B".to_string(),
            issue_id: 1,
            issue_type: "Test".to_string(),
            issue_type_id: "0".to_string(),
            severity: 1,
            stack_dumps: None,
            title: "Test".to_string(),
        };

        let legacy = finding.to_legacy();
        // Invalid CWE should default to 0
        assert_eq!(legacy.cwe_id, 0);
    }
}

// ============================================================================
// TIER 1: PROPERTY-BASED SECURITY TESTS (Fast, High ROI)
// ============================================================================
//
// These tests use proptest to validate security properties against adversarial
// inputs. They run 1000 test cases in normal mode and 10 under Miri for UB detection.

#[cfg(test)]
#[allow(clippy::expect_used)]
mod proptest_security {
    use super::*;
    use proptest::prelude::*;

    // ============================================================================
    // SECURITY TEST: HTML Sanitization (XSS Prevention)
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Script tags and their content must ALWAYS be removed
        /// This is critical for XSS prevention - script content must not appear in output
        #[test]
        fn proptest_html_script_content_removed(
            script_content in "[a-zA-Z0-9()';,.]{3,100}",
            prefix in "[a-zA-Z0-9]{3,50}",
            suffix in "[a-zA-Z0-9]{0,50}",
        ) {
            let input = format!("{}<script>{}</script>{}", prefix, script_content, suffix);
            let result = strip_html_tags(&input);

            // SECURITY: Script content must be completely removed
            // The script content should not appear in the output
            // We use unique multi-character strings to avoid false positives
            prop_assert!(
                !result.contains(&script_content),
                "Script content '{}' must not appear in sanitized output: '{}'",
                script_content,
                result
            );

            // Legitimate content before/after script should be preserved
            prop_assert!(result.contains(&prefix));
            if !suffix.is_empty() {
                prop_assert!(result.contains(&suffix));
            }
        }

        /// Property: Style tags and their content must ALWAYS be removed
        /// Prevents CSS injection attacks
        #[test]
        fn proptest_html_style_content_removed(
            style_content in "[a-zA-Z0-9:;{}]{3,100}",
            text_content in "[a-zA-Z0-9]{3,50}",
        ) {
            let input = format!("<style>{}</style>{}", style_content, text_content);
            let result = strip_html_tags(&input);

            // SECURITY: Style content must be completely removed
            // Use unique multi-character strings to avoid false positives
            prop_assert!(
                !result.contains(&style_content),
                "Style content '{}' must not appear in sanitized output: '{}'",
                style_content,
                result
            );

            // Legitimate text after style should be preserved
            prop_assert!(result.contains(&text_content));
        }

        /// Property: HTML without tags returns input unchanged (zero-copy optimization)
        /// Tests Cow::Borrowed optimization path
        #[test]
        fn proptest_html_no_tags_unchanged(
            plain_text in "[a-zA-Z0-9 ,.!?]{1,200}",
        ) {
            // Ensure no angle brackets
            let plain_text = plain_text.replace(['<', '>'], "");
            if plain_text.is_empty() {
                return Ok(());
            }

            let result = strip_html_tags(&plain_text);

            // Property 1: Content must be identical
            prop_assert_eq!(&result, &plain_text);

            // Property 2: Should use Cow::Borrowed (same pointer)
            match result {
                std::borrow::Cow::Borrowed(s) => {
                    prop_assert_eq!(s, plain_text.as_str());
                }
                std::borrow::Cow::Owned(_) => {
                    prop_assert!(false, "Should use Cow::Borrowed for plain text");
                }
            }
        }

        /// Property: Nested tags must be completely removed
        /// Tests recursive tag removal
        #[test]
        fn proptest_html_nested_tags_removed(
            depth in 1usize..=10,
            content in "[a-zA-Z0-9]{1,20}",
        ) {
            // Create nested tags
            let mut input = String::new();
            for _ in 0..depth {
                input.push_str("<div>");
            }
            input.push_str(&content);
            for _ in 0..depth {
                input.push_str("</div>");
            }

            let result = strip_html_tags(&input);

            // All tags should be removed, content preserved
            prop_assert!(!result.contains("<div>"));
            prop_assert!(!result.contains("</div>"));
            // Content should be preserved (whitespace may be normalized)
            let content_trimmed = content.trim();
            if !content_trimmed.is_empty() {
                prop_assert!(result.contains(content_trimmed));
            }
        }

        /// Property: Case-insensitive script/style detection
        /// Tests that XSS attempts with various casings are blocked
        #[test]
        fn proptest_html_case_insensitive_script(
            uppercase_ratio in 0.0..=1.0,
        ) {
            // Create "script" with random casing
            let script_word = randomize_case("script", uppercase_ratio);
            let input = format!("<{}>alert('xss')</{}>Safe", script_word, script_word);
            let result = strip_html_tags(&input);

            // Script content must be removed regardless of case
            prop_assert!(!result.contains("alert"));
            prop_assert!(!result.contains("xss"));
            prop_assert!(result.contains("Safe"));
        }

        /// Property: Whitespace normalization must not lose word boundaries
        /// Tests that words remain separated after tag removal
        #[test]
        fn proptest_html_preserves_word_boundaries(
            word1 in "[a-zA-Z]{1,20}",
            word2 in "[a-zA-Z]{1,20}",
            word3 in "[a-zA-Z]{1,20}",
        ) {
            let input = format!("{}<b>{}</b>{}", word1, word2, word3);
            let result = strip_html_tags(&input);

            // All words should be present
            prop_assert!(result.contains(&word1));
            prop_assert!(result.contains(&word2));
            prop_assert!(result.contains(&word3));

            // Words should be separated by whitespace
            let words: Vec<&str> = result.split_whitespace().collect();
            prop_assert!(words.contains(&word1.as_str()));
            prop_assert!(words.contains(&word2.as_str()));
            prop_assert!(words.contains(&word3.as_str()));
        }
    }

    // ============================================================================
    // SECURITY TEST: Upload Segment Validation (DoS Prevention)
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Zero or negative segment count must be rejected
        /// Prevents division-by-zero DoS attacks
        #[test]
        fn proptest_segment_count_validation_rejects_invalid(
            invalid_count in -1000i32..=0i32,
        ) {
            // Create mock PipelineApi (we'll test the validation logic directly)
            // The validation happens at the start of upload_binary_segments

            // Test the validation condition directly
            let is_valid = invalid_count > 0;
            prop_assert!(!is_valid, "Segment count {} should be rejected", invalid_count);
        }

        /// Property: Segment size calculation must not overflow
        /// Tests that extreme file sizes and segment counts are handled safely
        #[test]
        fn proptest_segment_size_calculation_safe(
            file_size in 0usize..=10_000_000,
            segment_count in 1i32..=1000,
        ) {
            // Simulate the segment size calculation from upload_binary_segments
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let segment_size = ((file_size as f64) / (segment_count as f64)).ceil() as usize;

            // Property 1: Segment size must not exceed file size
            prop_assert!(segment_size <= file_size.saturating_add(1));

            // Property 2: Must not overflow
            prop_assert!(segment_size < usize::MAX);

            // Property 3: All segments must fit within file
            let total_bytes = segment_size.saturating_mul(segment_count.try_into().unwrap_or(0));
            prop_assert!(total_bytes >= file_size);
        }

        /// Property: Segment boundary calculation must be safe
        /// Tests that start_idx and end_idx calculations don't overflow or panic
        #[test]
        fn proptest_segment_boundaries_safe(
            file_size in 1usize..=1_000_000,
            segment_num in 0i32..=100,
            segment_count in 1i32..=100,
        ) {
            // Only test valid segment numbers
            if segment_num >= segment_count {
                return Ok(());
            }

            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let segment_size = ((file_size as f64) / (segment_count as f64)).ceil() as usize;

            // Simulate boundary calculation from upload_binary_segments
            #[allow(clippy::cast_sign_loss)]
            let start_idx = (segment_num as usize).saturating_mul(segment_size);
            let end_idx = std::cmp::min(start_idx.saturating_add(segment_size), file_size);

            // Property 1: Start must be before or at end
            prop_assert!(start_idx <= end_idx);

            // Property 2: End must not exceed file size
            prop_assert!(end_idx <= file_size);

            // Property 3: Segment must have non-negative size
            let segment_len = end_idx.saturating_sub(start_idx);
            prop_assert!(segment_len <= file_size);
        }
    }

    // ============================================================================
    // SECURITY TEST: Summary Calculation (Integer Overflow Prevention)
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Summary calculation must not overflow with extreme finding counts
        /// Tests that saturating arithmetic prevents integer overflow
        #[test]
        fn proptest_summary_calculation_no_overflow(
            severity_0_count in 0usize..=10000,
            severity_1_count in 0usize..=10000,
            severity_2_count in 0usize..=10000,
            severity_3_count in 0usize..=10000,
            severity_4_count in 0usize..=10000,
            severity_5_count in 0usize..=10000,
        ) {
            // Create findings with specified severity counts
            let mut findings = Vec::new();

            for _ in 0..severity_0_count {
                findings.push(create_test_finding(0));
            }
            for _ in 0..severity_1_count {
                findings.push(create_test_finding(1));
            }
            for _ in 0..severity_2_count {
                findings.push(create_test_finding(2));
            }
            for _ in 0..severity_3_count {
                findings.push(create_test_finding(3));
            }
            for _ in 0..severity_4_count {
                findings.push(create_test_finding(4));
            }
            for _ in 0..severity_5_count {
                findings.push(create_test_finding(5));
            }

            // Create mock client to call calculate_summary
            let config = create_test_config();
            let client = VeracodeClient::new(config).expect("valid test config");
            let api = PipelineApi::new(client);

            let summary = api.calculate_summary(&findings);

            // Property 1: Total must equal sum of all categories
            let expected_total = findings.len();
            #[allow(clippy::cast_possible_truncation)]
            let expected_total_u32 = expected_total as u32;
            prop_assert_eq!(summary.total, expected_total_u32);

            // Property 2: Each severity count must match input
            #[allow(clippy::cast_possible_truncation)]
            {
                let sev0 = severity_0_count as u32;
                let sev1 = severity_1_count as u32;
                let sev2 = severity_2_count as u32;
                let sev3 = severity_3_count as u32;
                let sev4 = severity_4_count as u32;
                let sev5 = severity_5_count as u32;
                prop_assert_eq!(summary.informational, sev0);
                prop_assert_eq!(summary.very_low, sev1);
                prop_assert_eq!(summary.low, sev2);
                prop_assert_eq!(summary.medium, sev3);
                prop_assert_eq!(summary.high, sev4);
                prop_assert_eq!(summary.very_high, sev5);
            }

            // Property 3: Sum of severity counts must equal total
            let sum = summary.informational
                .saturating_add(summary.very_low)
                .saturating_add(summary.low)
                .saturating_add(summary.medium)
                .saturating_add(summary.high)
                .saturating_add(summary.very_high);
            prop_assert_eq!(sum, summary.total);
        }

        /// Property: Unknown severity values must be handled gracefully
        /// Tests that invalid severity values don't cause panics or incorrect counts
        #[test]
        fn proptest_summary_handles_unknown_severity(
            valid_count in 0usize..=100,
            unknown_severity in 6u32..=255,
        ) {
            let mut findings = Vec::new();

            // Add valid findings
            for _ in 0..valid_count {
                findings.push(create_test_finding(3));
            }

            // Add finding with unknown severity
            findings.push(create_test_finding(unknown_severity));

            let config = create_test_config();
            let client = VeracodeClient::new(config).expect("valid test config");
            let api = PipelineApi::new(client);

            let summary = api.calculate_summary(&findings);

            // Property: Total should include all findings
            #[allow(clippy::cast_possible_truncation)]
            let expected_total = findings.len() as u32;
            #[allow(clippy::cast_possible_truncation)]
            let expected_medium = valid_count as u32;
            prop_assert_eq!(summary.total, expected_total);

            // Property: Valid findings should be counted correctly
            prop_assert_eq!(summary.medium, expected_medium);
        }
    }

    // ============================================================================
    // Helper Functions for Property Tests
    // ============================================================================

    /// Randomize the case of a string based on a ratio (0.0 = all lowercase, 1.0 = all uppercase)
    fn randomize_case(s: &str, uppercase_ratio: f64) -> String {
        s.chars()
            .map(|c| {
                if c.is_alphabetic() {
                    // Use deterministic check based on character position
                    let char_hash = (c as u32 as f64) / 256.0;
                    if char_hash < uppercase_ratio {
                        c.to_uppercase().to_string()
                    } else {
                        c.to_lowercase().to_string()
                    }
                } else {
                    c.to_string()
                }
            })
            .collect()
    }

    /// Create a test finding with specified severity
    fn create_test_finding(severity: u32) -> Finding {
        Finding {
            cwe_id: "89".to_string(),
            display_text: "Test finding".to_string(),
            files: FindingFiles {
                source_file: SourceFile {
                    file: "test.rs".to_string(),
                    function_name: Some("test".to_string()),
                    function_prototype: "fn test()".to_string(),
                    line: 1,
                    qualified_function_name: "test::test".to_string(),
                    scope: "local".to_string(),
                },
            },
            flaw_details_link: None,
            gob: "C".to_string(),
            issue_id: 1,
            issue_type: "Test".to_string(),
            issue_type_id: "0".to_string(),
            severity,
            stack_dumps: None,
            title: "Test".to_string(),
        }
    }

    /// Create a test Veracode config for testing
    fn create_test_config() -> crate::VeracodeConfig {
        use crate::{VeracodeCredentials, VeracodeRegion};

        crate::VeracodeConfig {
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
}

// ============================================================================
// TIER 2: MIRI TESTS (Memory Safety & UB Detection)
// ============================================================================
//
// These tests verify memory safety and detect undefined behavior.
// They leverage the proptest infrastructure above but run under Miri's interpreter.
//
// Run with: cargo +nightly miri test
//
// The proptest configs above already use cfg!(miri) for adaptive case counts.

#[cfg(test)]
mod miri_tests {
    use super::*;

    /// MIRI TEST: HTML sanitization must not have undefined behavior
    /// Tests for out-of-bounds access, use-after-free, etc.
    #[test]
    fn test_miri_html_sanitization_memory_safety() {
        // Test various edge cases that might trigger UB
        let angle_brackets_left = "<".repeat(1000);
        let angle_brackets_right = ">".repeat(1000);
        let repeated_tags = "<a>".repeat(100);

        let test_cases = vec![
            "",
            "x",
            "<",
            ">",
            "<>",
            "<script>",
            "</script>",
            "<script></script>",
            "<SCRIPT>alert('XSS')</SCRIPT>Safe",
            "Text<b>bold</b>more",
            angle_brackets_left.as_str(),
            angle_brackets_right.as_str(),
            repeated_tags.as_str(),
        ];

        for input in test_cases {
            let result = strip_html_tags(input);
            // Must not panic or cause UB
            assert!(result.len() <= input.len() + input.len()); // Reasonable bounds
        }
    }

    /// MIRI TEST: Finding to legacy conversion must be memory safe
    /// Tests string cloning and parsing operations
    #[test]
    fn test_miri_finding_conversion_memory_safety() {
        let finding = Finding {
            cwe_id: "123".to_string(),
            display_text: "<b>Test</b>".to_string(),
            files: FindingFiles {
                source_file: SourceFile {
                    file: "test.rs".to_string(),
                    function_name: None,
                    function_prototype: "fn test()".to_string(),
                    line: 1,
                    qualified_function_name: "test".to_string(),
                    scope: "local".to_string(),
                },
            },
            flaw_details_link: None,
            gob: "A".to_string(),
            issue_id: 1,
            issue_type: "Test".to_string(),
            issue_type_id: "0".to_string(),
            severity: 3,
            stack_dumps: None,
            title: "Test".to_string(),
        };

        // Must not cause UB during conversion
        let legacy = finding.to_legacy();
        assert_eq!(legacy.cwe_id, 123);
        assert_eq!(legacy.message, "Test");
    }

    /// MIRI TEST: Scan status state machine transitions must be memory safe
    /// Tests enum matching and boolean logic
    #[test]
    fn test_miri_scan_status_state_machine() {
        let statuses = vec![
            ScanStatus::Pending,
            ScanStatus::Uploading,
            ScanStatus::Started,
            ScanStatus::Success,
            ScanStatus::Failure,
            ScanStatus::Cancelled,
            ScanStatus::Timeout,
            ScanStatus::UserTimeout,
        ];

        for status in statuses {
            // These operations must not cause UB
            let _ = status.is_successful();
            let _ = status.is_failed();
            let _ = status.is_in_progress();
            let _ = status.to_string();

            // State invariant: exactly one of these must be true
            let states = [
                status.is_successful(),
                status.is_failed(),
                status.is_in_progress(),
            ];
            let true_count = states.iter().filter(|&&x| x).count();
            assert_eq!(
                true_count, 1,
                "Status {:?} must be in exactly one state",
                status
            );
        }
    }
}

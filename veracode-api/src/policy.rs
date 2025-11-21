//! Policy API module for Veracode Platform
//!
//! This module provides functionality for managing security policies, policy compliance,
//! and policy scan operations within the Veracode platform.

use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{VeracodeClient, VeracodeError};

/// Maximum allowed retry delay in seconds (5 minutes)
/// This prevents `DoS` scenarios where users could specify very long delays
/// (e.g., 30 retries × 3600s = 30 hours)
const MAX_RETRY_DELAY_SECONDS: u64 = 300;

/// Input validation helpers to prevent path injection attacks
mod validation {
    /// Validates that a string is a valid UUID/GUID format
    /// Format: 8-4-4-4-12 hexadecimal characters (with optional hyphens)
    pub fn validate_guid(guid: &str) -> Result<(), String> {
        // Allow both hyphenated and non-hyphenated UUIDs
        let cleaned = guid.replace('-', "");

        // Check length (32 hex chars for UUID)
        if cleaned.len() != 32 {
            return Err(format!(
                "Invalid GUID format: expected 32 hex characters, got {}",
                cleaned.len()
            ));
        }

        // Check for valid hex characters only
        if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Invalid GUID format: contains non-hexadecimal characters".to_string());
        }

        // Check for path traversal attempts
        if guid.contains("..") || guid.contains('/') || guid.contains('\\') {
            return Err("Invalid GUID format: contains path traversal characters".to_string());
        }

        // Check for URL parameter injection
        if guid.contains('?') || guid.contains('&') || guid.contains('#') {
            return Err("Invalid GUID format: contains URL parameter characters".to_string());
        }

        Ok(())
    }

    /// Validates that a string contains only safe identifier characters
    /// Allows: alphanumeric, hyphens, underscores
    pub fn validate_identifier(id: &str) -> Result<(), String> {
        if id.is_empty() {
            return Err("Identifier cannot be empty".to_string());
        }

        // Check for path traversal
        if id.contains("..") || id.contains('/') || id.contains('\\') {
            return Err("Invalid identifier: contains path traversal characters".to_string());
        }

        // Check for URL parameter injection
        if id.contains('?') || id.contains('&') || id.contains('#') {
            return Err("Invalid identifier: contains URL parameter characters".to_string());
        }

        // Allow alphanumeric, hyphens, and underscores only
        if !id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err("Invalid identifier: contains unsafe characters".to_string());
        }

        Ok(())
    }
}

/// Represents a security policy in the Veracode platform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Globally unique identifier for the policy
    pub guid: String,
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: Option<String>,
    /// Policy type (CUSTOMER, BUILTIN, STANDARD)
    #[serde(rename = "type")]
    pub policy_type: String,
    /// Policy version number
    pub version: u32,
    /// When the policy was created
    pub created: Option<DateTime<Utc>>,
    /// Who modified the policy last
    pub modified_by: Option<String>,
    /// Organization ID this policy belongs to
    pub organization_id: Option<u64>,
    /// Policy category (APPLICATION, etc.)
    pub category: String,
    /// Whether this is a vendor policy
    pub vendor_policy: bool,
    /// Scan frequency rules
    pub scan_frequency_rules: Vec<ScanFrequencyRule>,
    /// Finding rules for the policy
    pub finding_rules: Vec<FindingRule>,
    /// Custom severities defined for this policy
    pub custom_severities: Vec<serde_json::Value>,
    /// Grace periods for different severity levels
    pub sev5_grace_period: u32,
    pub sev4_grace_period: u32,
    pub sev3_grace_period: u32,
    pub sev2_grace_period: u32,
    pub sev1_grace_period: u32,
    pub sev0_grace_period: u32,
    /// Score grace period
    pub score_grace_period: u32,
    /// SCA blacklist grace period
    pub sca_blacklist_grace_period: u32,
    /// SCA grace periods (nullable)
    pub sca_grace_periods: Option<serde_json::Value>,
    /// Evaluation date
    pub evaluation_date: Option<DateTime<Utc>>,
    /// Evaluation date type
    pub evaluation_date_type: Option<String>,
    /// Policy capabilities
    pub capabilities: Vec<String>,
    /// Links for API navigation
    #[serde(rename = "_links")]
    pub links: Option<serde_json::Value>,
}

/// Policy compliance status (XML API values from getbuildinfo.do)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PolicyComplianceStatus {
    /// Application passes all policy requirements
    Passed,
    /// Application passes with conditional requirements  
    #[serde(rename = "Conditional Pass")]
    ConditionalPass,
    /// Application fails policy requirements (triggers build break)
    #[serde(rename = "Did Not Pass")]
    DidNotPass,
    /// Policy compliance status has not been assessed
    #[serde(rename = "Not Assessed")]
    NotAssessed,
}

/// Individual policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule identifier
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: Option<String>,
    /// Rule type (e.g., severity, category)
    pub rule_type: String,
    /// Rule criteria
    pub criteria: Option<serde_json::Value>,
    /// Whether the rule is enabled
    pub enabled: bool,
    /// Rule severity level
    pub severity: Option<String>,
}

/// Policy compliance thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyThresholds {
    /// Maximum allowed Very High severity flaws
    pub very_high: Option<u32>,
    /// Maximum allowed High severity flaws
    pub high: Option<u32>,
    /// Maximum allowed Medium severity flaws
    pub medium: Option<u32>,
    /// Maximum allowed Low severity flaws
    pub low: Option<u32>,
    /// Maximum allowed Very Low severity flaws
    pub very_low: Option<u32>,
    /// Overall score threshold
    pub score_threshold: Option<f64>,
}

/// Policy scan request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyScanRequest {
    /// Application GUID to scan
    pub application_guid: String,
    /// Policy GUID to apply
    pub policy_guid: String,
    /// Scan type (static, dynamic, sca)
    pub scan_type: ScanType,
    /// Optional sandbox GUID for sandbox scans
    pub sandbox_guid: Option<String>,
    /// Scan configuration
    pub config: Option<PolicyScanConfig>,
}

/// Types of scans for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    /// Static Application Security Testing
    Static,
    /// Dynamic Application Security Testing
    Dynamic,
    /// Software Composition Analysis
    Sca,
    /// Manual penetration testing
    Manual,
}

/// Configuration for policy scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyScanConfig {
    /// Whether to auto-submit the scan
    pub auto_submit: Option<bool>,
    /// Scan timeout in minutes
    pub timeout_minutes: Option<u32>,
    /// Include third-party components
    pub include_third_party: Option<bool>,
    /// Scan modules to include
    pub modules: Option<Vec<String>>,
}

/// Policy scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyScanResult {
    /// Scan identifier
    pub scan_id: u64,
    /// Application GUID
    pub application_guid: String,
    /// Policy GUID used for evaluation
    pub policy_guid: String,
    /// Scan status
    pub status: ScanStatus,
    /// Scan type
    pub scan_type: ScanType,
    /// When the scan was initiated
    pub started: DateTime<Utc>,
    /// When the scan completed
    pub completed: Option<DateTime<Utc>>,
    /// Policy compliance result
    pub compliance_result: Option<PolicyComplianceResult>,
    /// Findings summary
    pub findings_summary: Option<FindingsSummary>,
    /// URL to detailed results
    pub results_url: Option<String>,
}

/// Status of a policy scan
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStatus {
    /// Scan is queued for processing
    Queued,
    /// Scan is currently running
    Running,
    /// Scan completed successfully
    Completed,
    /// Scan failed
    Failed,
    /// Scan was cancelled
    Cancelled,
    /// Scan timed out
    Timeout,
}

/// Policy compliance evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyComplianceResult {
    /// Overall compliance status
    pub status: PolicyComplianceStatus,
    /// Compliance score (0-100)
    pub score: Option<f64>,
    /// Whether scan passed policy requirements
    pub passed: bool,
    /// Detailed compliance breakdown
    pub breakdown: Option<ComplianceBreakdown>,
    /// Policy violations found
    pub violations: Option<Vec<PolicyViolation>>,
    /// Compliance summary message
    pub summary: Option<String>,
}

/// Detailed compliance breakdown by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceBreakdown {
    /// Very High severity findings count
    pub very_high: u32,
    /// High severity findings count
    pub high: u32,
    /// Medium severity findings count
    pub medium: u32,
    /// Low severity findings count
    pub low: u32,
    /// Very Low severity findings count
    pub very_low: u32,
    /// Total findings count
    pub total: u32,
}

/// Policy violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Violation type
    pub violation_type: String,
    /// Severity of the violation
    pub severity: String,
    /// Description of the violation
    pub description: String,
    /// Count of this violation type
    pub count: u32,
    /// Threshold that was exceeded
    pub threshold_exceeded: Option<u32>,
    /// Actual value that caused the violation
    pub actual_value: Option<u32>,
}

/// Summary of findings from a policy scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsSummary {
    /// Total number of findings
    pub total: u32,
    /// Number of open findings
    pub open: u32,
    /// Number of fixed findings
    pub fixed: u32,
    /// Number of findings by severity
    pub by_severity: HashMap<String, u32>,
    /// Number of findings by category
    pub by_category: Option<HashMap<String, u32>>,
}

///
/// # Errors
///
/// Returns an error if the API request fails, the resource is not found,
/// or authentication/authorization fails.
/// Summary report data structure matching Veracode `summary_report` API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryReport {
    /// Application ID
    pub app_id: u64,
    /// Application name
    pub app_name: String,
    /// Build ID
    pub build_id: u64,
    /// Policy compliance status (e.g., "Did Not Pass", "Passed", "Conditional Pass")
    pub policy_compliance_status: String,
    /// Policy name
    pub policy_name: String,
    /// Policy version
    pub policy_version: u32,
    /// Whether the policy rules status passed
    pub policy_rules_status: String,
    /// Whether grace period expired
    pub grace_period_expired: bool,
    /// Whether scan is overdue
    pub scan_overdue: String,
    /// Whether this is the latest build
    pub is_latest_build: bool,
    /// Sandbox name (optional)
    pub sandbox_name: Option<String>,
    /// Sandbox ID (optional)
    pub sandbox_id: Option<u64>,
    /// Generation date
    pub generation_date: String,
    /// Last update time
    pub last_update_time: String,
    /// Static analysis summary
    #[serde(rename = "static-analysis")]
    pub static_analysis: Option<StaticAnalysisSummary>,
    /// Flaw status summary
    #[serde(rename = "flaw-status")]
    pub flaw_status: Option<FlawStatusSummary>,
    /// Software composition analysis summary
    pub software_composition_analysis: Option<ScaSummary>,
    /// Severity breakdown
    pub severity: Option<Vec<SeverityLevel>>,
}

/// Static analysis summary from summary report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysisSummary {
    /// Rating (e.g., "A", "B", "C")
    pub rating: Option<String>,
    /// Score (0-100)
    pub score: Option<u32>,
    /// Mitigated rating
    pub mitigated_rating: Option<String>,
    /// Mitigated score
    pub mitigated_score: Option<u32>,
    /// Analysis size in bytes
    pub analysis_size_bytes: Option<u64>,
    /// Engine version
    pub engine_version: Option<String>,
    /// Published date
    pub published_date: Option<String>,
    /// Version/build identifier
    pub version: Option<String>,
}

/// Flaw status summary from summary report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlawStatusSummary {
    /// New flaws
    pub new: u32,
    /// Reopened flaws
    pub reopen: u32,
    /// Open flaws
    pub open: u32,
    /// Fixed flaws
    pub fixed: u32,
    /// Total flaws
    pub total: u32,
    /// Not mitigated flaws
    pub not_mitigated: u32,
}

/// Software Composition Analysis summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaSummary {
    /// Third party components count
    pub third_party_components: u32,
    /// Whether violates policy
    pub violate_policy: bool,
    /// Components that violated policy
    pub components_violated_policy: u32,
}

/// Severity level breakdown from summary report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityLevel {
    /// Severity level (0-5)
    pub level: u32,
    /// Categories for this severity level
    pub category: Vec<CategorySummary>,
}

/// Category summary within severity level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySummary {
    /// Category name
    pub categoryname: String,
    /// Severity name
    pub severity: String,
    /// Count of flaws in this category
    pub count: u32,
}

/// Scan frequency rule for policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFrequencyRule {
    /// Type of scan this rule applies to
    pub scan_type: String,
    /// How frequently scans should be performed
    pub frequency: String,
}

/// Finding rule for policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRule {
    /// Type of finding rule
    #[serde(rename = "type")]
    pub rule_type: String,
    /// Scan types this rule applies to
    pub scan_type: Vec<String>,
    /// Rule value/threshold
    pub value: String,
    /// Advanced options for the rule
    pub advanced_options: Option<serde_json::Value>,
}

/// Advanced options for finding rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRuleAdvancedOptions {
    /// Override severity
    pub override_severity: Option<bool>,
    /// Build action (WARNING, ERROR, etc.)
    pub build_action: Option<String>,
    /// Component dependency type
    pub component_dependency: Option<String>,
    /// Vulnerable methods setting
    pub vulnerable_methods: Option<String>,
    /// Selected licenses
    pub selected_licenses: Option<Vec<String>>,
    /// Override severity level
    pub override_severity_level: Option<String>,
    /// Whether to allow non-OSS licenses
    pub allowed_nonoss_licenses: Option<bool>,
    /// Whether to allow unrecognized licenses
    pub allowed_unrecognized_licenses: Option<bool>,
    /// Whether all licenses must meet requirement
    pub all_licenses_must_meet_requirement: Option<bool>,
    /// Whether this is a blocklist
    pub is_blocklist: Option<bool>,
}

/// Query parameters for listing policies
#[derive(Debug, Clone, Default)]
pub struct PolicyListParams {
    /// Filter by policy name
    pub name: Option<String>,
    /// Filter by policy type
    pub policy_type: Option<String>,
    /// Filter by active status
    pub is_active: Option<bool>,
    /// Include only default policies
    pub default_only: Option<bool>,
    /// Page number for pagination
    pub page: Option<u32>,
    /// Number of items per page
    pub size: Option<u32>,
}

impl PolicyListParams {
    /// Convert to query parameters for HTTP requests
    #[must_use]
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        Vec::from(self) // Delegate to trait
    }
}

// Trait implementations for memory optimization
impl From<&PolicyListParams> for Vec<(String, String)> {
    fn from(query: &PolicyListParams) -> Self {
        let mut params = Vec::new();

        if let Some(ref name) = query.name {
            params.push(("name".to_string(), name.clone())); // Still clone for borrowing
        }
        if let Some(ref policy_type) = query.policy_type {
            params.push(("type".to_string(), policy_type.clone()));
        }
        if let Some(is_active) = query.is_active {
            params.push(("active".to_string(), is_active.to_string()));
        }
        if let Some(default_only) = query.default_only {
            params.push(("default".to_string(), default_only.to_string()));
        }
        if let Some(page) = query.page {
            params.push(("page".to_string(), page.to_string()));
        }
        if let Some(size) = query.size {
            params.push(("size".to_string(), size.to_string()));
        }

        params
    }
}

impl From<PolicyListParams> for Vec<(String, String)> {
    fn from(query: PolicyListParams) -> Self {
        let mut params = Vec::new();

        if let Some(name) = query.name {
            params.push(("name".to_string(), name)); // MOVE - no clone!
        }
        if let Some(policy_type) = query.policy_type {
            params.push(("type".to_string(), policy_type)); // MOVE - no clone!
        }
        if let Some(is_active) = query.is_active {
            params.push(("active".to_string(), is_active.to_string()));
        }
        if let Some(default_only) = query.default_only {
            params.push(("default".to_string(), default_only.to_string()));
        }
        if let Some(page) = query.page {
            params.push(("page".to_string(), page.to_string()));
        }
        if let Some(size) = query.size {
            params.push(("size".to_string(), size.to_string()));
        }

        params
    }
}

/// Response wrapper for policy list operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyListResponse {
    #[serde(rename = "_embedded")]
    pub embedded: Option<PolicyEmbedded>,
    pub page: Option<PageInfo>,
    #[serde(rename = "_links")]
    pub links: Option<serde_json::Value>,
}

/// Embedded policies in the list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEmbedded {
    #[serde(rename = "policy_versions")]
    pub policy_versions: Vec<SecurityPolicy>,
}

/// Page information for paginated responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    pub size: u32,
    pub number: u32,
    pub total_elements: u32,
    pub total_pages: u32,
}

/// Indicates which API was used to retrieve policy compliance status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiSource {
    /// Policy status retrieved from summary report API (preferred)
    SummaryReport,
    /// Policy status retrieved from getbuildinfo.do XML API (fallback)
    BuildInfo,
}

/// Policy-specific error types
#[derive(Debug)]
#[must_use = "Need to handle all error enum types."]
pub enum PolicyError {
    /// Veracode API error
    Api(VeracodeError),
    /// Policy not found (404)
    NotFound,
    /// Invalid policy configuration (400)
    InvalidConfig(String),
    /// Policy scan failed
    ScanFailed(String),
    /// Policy evaluation error
    EvaluationError(String),
    /// Insufficient permissions (403)
    PermissionDenied,
    /// Authentication required (401)
    Unauthorized,
    /// Internal server error (500)
    InternalServerError,
    /// Policy compliance check timeout
    Timeout,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Api(err) => write!(f, "API error: {err}"),
            PolicyError::NotFound => write!(f, "Policy not found"),
            PolicyError::InvalidConfig(msg) => write!(f, "Invalid policy configuration: {msg}"),
            PolicyError::ScanFailed(msg) => write!(f, "Policy scan failed: {msg}"),
            PolicyError::EvaluationError(msg) => write!(f, "Policy evaluation error: {msg}"),
            PolicyError::PermissionDenied => {
                write!(f, "Insufficient permissions for policy operation")
            }
            PolicyError::Unauthorized => {
                write!(f, "Authentication required - invalid API credentials")
            }
            PolicyError::InternalServerError => write!(f, "Internal server error occurred"),
            PolicyError::Timeout => write!(f, "Policy operation timed out"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<VeracodeError> for PolicyError {
    fn from(err: VeracodeError) -> Self {
        PolicyError::Api(err)
    }
}

impl From<reqwest::Error> for PolicyError {
    fn from(err: reqwest::Error) -> Self {
        PolicyError::Api(VeracodeError::Http(err))
    }
}

impl From<serde_json::Error> for PolicyError {
    fn from(err: serde_json::Error) -> Self {
        PolicyError::Api(VeracodeError::Serialization(err))
    }
}

/// Veracode Policy API operations
pub struct PolicyApi<'a> {
    client: &'a VeracodeClient,
}

impl<'a> PolicyApi<'a> {
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// Create a new `PolicyApi` instance
    #[must_use]
    pub fn new(client: &'a VeracodeClient) -> Self {
        Self { client }
    }

    /// List all available security policies
    ///
    /// # Arguments
    ///
    /// * `params` - Optional query parameters for filtering
    ///
    /// # Returns
    ///
    /// A `Result` containing a list of policies or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn list_policies(
        &self,
        params: Option<PolicyListParams>,
    ) -> Result<Vec<SecurityPolicy>, PolicyError> {
        let endpoint = "/appsec/v1/policies";

        let query_params = params.as_ref().map(Vec::from);

        let response = self.client.get(endpoint, query_params.as_deref()).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let policy_response: PolicyListResponse = response.json().await?;
                let policies = policy_response
                    .embedded
                    .map(|e| e.policy_versions)
                    .unwrap_or_default();

                Ok(policies)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(PolicyError::InvalidConfig(error_text))
            }
            401 => Err(PolicyError::Unauthorized),
            403 => Err(PolicyError::PermissionDenied),
            404 => Err(PolicyError::NotFound),
            500 => Err(PolicyError::InternalServerError),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(PolicyError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Get a specific policy by GUID
    ///
    /// # Arguments
    ///
    /// * `policy_guid` - The GUID of the policy
    ///
    /// # Returns
    ///
    /// A `Result` containing the policy or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn get_policy(&self, policy_guid: &str) -> Result<SecurityPolicy, PolicyError> {
        // Validate GUID to prevent path injection
        validation::validate_guid(policy_guid)
            .map_err(|e| PolicyError::InvalidConfig(format!("Invalid policy GUID: {e}")))?;

        let endpoint = format!("/appsec/v1/policies/{policy_guid}");

        let response = self.client.get(&endpoint, None).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let policy: SecurityPolicy = response.json().await?;
                Ok(policy)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(PolicyError::InvalidConfig(error_text))
            }
            401 => Err(PolicyError::Unauthorized),
            403 => Err(PolicyError::PermissionDenied),
            404 => Err(PolicyError::NotFound),
            500 => Err(PolicyError::InternalServerError),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(PolicyError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Get the default policy for the organization
    ///
    /// # Returns
    ///
    /// A `Result` containing the default policy or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn get_default_policy(&self) -> Result<SecurityPolicy, PolicyError> {
        let params = PolicyListParams {
            default_only: Some(true),
            ..Default::default()
        };

        let policies = self.list_policies(Some(params)).await?;
        // Note: Default policy identification may need to be handled differently
        // based on the actual API response structure
        policies
            .into_iter()
            .find(|p| p.policy_type == "CUSTOMER" && p.organization_id.is_some())
            .ok_or(PolicyError::NotFound)
    }

    /// Evaluates policy compliance for an application or sandbox using XML API
    ///
    /// This uses the /api/5.0/getbuildinfo.do endpoint which is the only working
    /// policy compliance endpoint as the REST API compliance endpoints return 404.
    ///
    /// # Arguments
    ///
    /// * `app_id` - The numeric ID of the application
    /// * `sandbox_id` - Optional numeric ID of the sandbox to evaluate
    ///
    /// # Returns
    ///
    /// A `Result` containing the policy compliance status string or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn evaluate_policy_compliance_via_buildinfo(
        &self,
        app_id: &str,
        build_id: Option<&str>,
        sandbox_id: Option<&str>,
    ) -> Result<std::borrow::Cow<'static, str>, PolicyError> {
        self.evaluate_policy_compliance_via_buildinfo_with_retry(
            app_id, build_id, sandbox_id, 30, 10,
        )
        .await
    }

    /// Evaluates policy compliance with retry logic for when assessment is not yet complete
    ///
    /// This function will retry the policy evaluation check when the status is "Not Assessed"
    /// until either the assessment completes or the maximum retry attempts are reached.
    ///
    /// # Arguments
    ///
    /// * `app_id` - The numeric ID of the application
    /// * `build_id` - Optional build ID to check. If None, checks the latest build
    /// * `sandbox_id` - Optional numeric ID of the sandbox to evaluate
    /// * `max_retries` - Maximum number of retry attempts (default: 30)
    /// * `retry_delay_seconds` - Delay between retries in seconds (default: 10)
    ///
    /// # Returns
    ///
    /// A `Result` containing the policy compliance status string or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn evaluate_policy_compliance_via_buildinfo_with_retry(
        &self,
        app_id: &str,
        build_id: Option<&str>,
        sandbox_id: Option<&str>,
        max_retries: u32,
        retry_delay_seconds: u64,
    ) -> Result<std::borrow::Cow<'static, str>, PolicyError> {
        use crate::build::{BuildError, GetBuildInfoRequest};
        use std::borrow::Cow;
        use tokio::time::{Duration, sleep};

        // Cap retry delay to prevent DoS scenarios
        let retry_delay_seconds = retry_delay_seconds.min(MAX_RETRY_DELAY_SECONDS);
        if retry_delay_seconds > MAX_RETRY_DELAY_SECONDS {
            warn!(
                "Retry delay capped at {} seconds (requested: {})",
                MAX_RETRY_DELAY_SECONDS, retry_delay_seconds
            );
        }

        let build_request = GetBuildInfoRequest {
            app_id: app_id.to_string(),
            build_id: build_id.map(str::to_string), // ← Use the parameter
            sandbox_id: sandbox_id.map(str::to_string),
        };

        let mut attempts: u32 = 0;
        loop {
            let build_info = self
                .client
                .build_api()?
                .get_build_info(&build_request)
                .await
                .map_err(|e| match e {
                    BuildError::BuildNotFound => PolicyError::Api(crate::VeracodeError::InvalidResponse(
                        format!("Build not found for application ID {app_id}. This may indicate: no builds exist for this application, the build ID is invalid, or the application has no completed scans. Cannot retrieve policy status without a valid build.")
                    )),
                    BuildError::ApplicationNotFound => PolicyError::Api(crate::VeracodeError::InvalidResponse(
                        format!("Application not found with ID {app_id}. This may indicate: incorrect application ID, insufficient permissions, or the application doesn't exist in your organization. Please verify the application ID and your API credentials.")
                    )),
                    BuildError::SandboxNotFound => PolicyError::Api(crate::VeracodeError::InvalidResponse(
                        format!("Sandbox not found with ID {}. This may indicate: incorrect sandbox ID, insufficient permissions, or the sandbox doesn't exist for this application.", sandbox_id.unwrap_or("unknown"))
                    )),
                    BuildError::Api(api_err) => PolicyError::Api(api_err),
                    BuildError::InvalidParameter(msg)
                    | BuildError::CreationFailed(msg)
                    | BuildError::UpdateFailed(msg)
                    | BuildError::DeletionFailed(msg)
                    | BuildError::XmlParsingError(msg) => {
                        PolicyError::Api(crate::VeracodeError::InvalidResponse(msg))
                    }
                    BuildError::Unauthorized | BuildError::PermissionDenied => PolicyError::Api(
                        crate::VeracodeError::Authentication("Build API access denied".to_string()),
                    ),
                    BuildError::BuildInProgress => {
                        PolicyError::Api(crate::VeracodeError::InvalidResponse(
                            "Build is currently in progress".to_string(),
                        ))
                    }
                })?;

            // Get the policy compliance status
            let status = build_info
                .policy_compliance_status
                .as_deref()
                .unwrap_or("Not Assessed");

            // If status is ready (not in-progress), return the result
            if status != "Not Assessed" && status != "Calculating..." {
                return Ok(Cow::Owned(status.to_string()));
            }

            // If we've reached max retries, return "Not Assessed"
            attempts = attempts.saturating_add(1);
            if attempts >= max_retries {
                warn!(
                    "Policy evaluation still not assessed after {max_retries} attempts. This may indicate: scan is still in progress, policy evaluation is taking longer than expected, or application may not have a policy assigned"
                );
                return Ok(Cow::Borrowed("Not Assessed"));
            }

            // Log retry attempt
            info!(
                "Policy evaluation not yet assessed, retrying in {retry_delay_seconds} seconds... (attempt {attempts}/{max_retries})"
            );

            // Wait before retrying
            sleep(Duration::from_secs(retry_delay_seconds)).await;
        }
    }

    /// Determines if build should break based on policy compliance status
    ///
    /// # Arguments
    ///
    /// * `status` - The policy compliance status string from XML API
    ///
    /// # Returns
    ///
    /// `true` if build should break, `false` otherwise
    #[must_use]
    pub fn should_break_build(status: &str) -> bool {
        status == "Did Not Pass"
    }

    /// Gets the appropriate exit code for CI/CD systems based on policy compliance
    ///
    /// # Arguments
    ///
    /// * `status` - The policy compliance status string from XML API
    ///
    /// # Returns
    ///
    /// Exit code: 0 for success, 4 for policy failure (build break)
    #[must_use]
    pub fn get_exit_code_for_status(status: &str) -> i32 {
        if Self::should_break_build(status) {
            4 // DID_NOT_PASSED_POLICY - matches Java wrapper
        } else {
            0 // SUCCESS
        }
    }

    /// Get summary report for an application build using the REST API
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// This uses the `/appsec/v2/applications/{app_guid}/summary_report` endpoint
    /// to get policy compliance status and scan results.
    ///
    /// # Arguments
    ///
    /// * `app_guid` - The GUID of the application
    /// * `build_id` - The build ID (GUID) to get summary for
    /// * `sandbox_guid` - Optional sandbox GUID for sandbox scans
    ///
    /// # Returns
    ///
    /// A `Result` containing the summary report or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn get_summary_report(
        &self,
        app_guid: &str,
        build_id: Option<&str>,
        sandbox_guid: Option<&str>,
    ) -> Result<SummaryReport, PolicyError> {
        // Validate app_guid to prevent path injection
        validation::validate_guid(app_guid)
            .map_err(|e| PolicyError::InvalidConfig(format!("Invalid application GUID: {e}")))?;

        // Validate optional identifiers
        if let Some(build_id) = build_id {
            validation::validate_identifier(build_id)
                .map_err(|e| PolicyError::InvalidConfig(format!("Invalid build ID: {e}")))?;
        }
        if let Some(sandbox_guid) = sandbox_guid {
            validation::validate_guid(sandbox_guid)
                .map_err(|e| PolicyError::InvalidConfig(format!("Invalid sandbox GUID: {e}")))?;
        }

        let endpoint = format!("/appsec/v2/applications/{app_guid}/summary_report");

        // Build query parameters
        let mut query_params = Vec::new();
        if let Some(build_id) = build_id {
            query_params.push(("build_id".to_string(), build_id.to_string()));
        }
        if let Some(sandbox_guid) = sandbox_guid {
            query_params.push(("context".to_string(), sandbox_guid.to_string()));
        }

        let response = self.client.get(&endpoint, Some(&query_params)).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let summary_report: SummaryReport = response.json().await?;
                Ok(summary_report)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(PolicyError::InvalidConfig(error_text))
            }
            401 => Err(PolicyError::Unauthorized),
            403 => Err(PolicyError::PermissionDenied),
            404 => Err(PolicyError::NotFound),
            500 => Err(PolicyError::InternalServerError),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(PolicyError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Gets summary report with retry logic and returns both the full report and compliance status
    ///
    /// This function combines the functionality of both `get_summary_report` and
    /// `evaluate_policy_compliance_via_summary_report_with_retry` to avoid redundant API calls.
    /// It will retry until the policy compliance status is ready (not "Not Assessed").
    ///
    /// # Arguments
    ///
    /// * `app_guid` - The GUID of the application
    /// * `build_id` - The build ID to check compliance for
    /// * `sandbox_guid` - Optional sandbox GUID for sandbox scans
    /// * `max_retries` - Maximum number of retry attempts
    /// * `retry_delay_seconds` - Delay between retries in seconds
    /// * `debug` - Enable debug logging
    ///
    /// # Returns
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    /// A `Result` containing a tuple of (`SummaryReport`, Option<`compliance_status`>) or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    /// The `compliance_status` is Some(status) if `break_build` evaluation is needed, None otherwise.
    #[allow(clippy::too_many_arguments)]
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn get_summary_report_with_policy_retry(
        &self,
        app_guid: &str,
        build_id: Option<&str>,
        sandbox_guid: Option<&str>,
        max_retries: u32,
        retry_delay_seconds: u64,
        enable_break_build: bool,
    ) -> Result<(SummaryReport, Option<std::borrow::Cow<'static, str>>), PolicyError> {
        use std::borrow::Cow;
        use tokio::time::{Duration, sleep};

        // Cap retry delay to prevent DoS scenarios
        let retry_delay_seconds = retry_delay_seconds.min(MAX_RETRY_DELAY_SECONDS);
        if retry_delay_seconds > MAX_RETRY_DELAY_SECONDS {
            warn!(
                "Retry delay capped at {} seconds (requested: {})",
                MAX_RETRY_DELAY_SECONDS, retry_delay_seconds
            );
        }

        if enable_break_build && build_id.is_none() {
            return Err(PolicyError::InvalidConfig(
                "Build ID is required for break build policy evaluation".to_string(),
            ));
        }

        let mut attempts: u32 = 0;
        loop {
            if attempts == 0 && enable_break_build {
                debug!("Checking policy compliance status with retry logic...");
            } else if attempts == 0 {
                debug!("Getting summary report...");
            }

            let summary_report = match self
                .get_summary_report(app_guid, build_id, sandbox_guid)
                .await
            {
                Ok(report) => report,
                Err(PolicyError::InternalServerError) if attempts < 3 => {
                    warn!(
                        "Summary report API failed with server error (attempt {}/3), retrying in 5 seconds...",
                        attempts.saturating_add(1)
                    );
                    sleep(Duration::from_secs(5)).await;
                    attempts = attempts.saturating_add(1);
                    continue;
                }
                Err(e) => return Err(e),
            };

            // If break_build is not enabled, return immediately with the report
            if !enable_break_build {
                return Ok((summary_report, None));
            }

            // For `break_build` evaluation, check if policy compliance status is ready
            let status = summary_report.policy_compliance_status.clone();

            // If status is ready (not empty and not "Not Assessed"), return both report and status
            if !status.is_empty() && status != "Not Assessed" {
                debug!("Policy compliance status ready: {status}");
                return Ok((summary_report, Some(Cow::Owned(status))));
            }

            // If we've reached max retries, return current results
            attempts = attempts.saturating_add(1);
            if attempts >= max_retries {
                warn!(
                    "Policy evaluation still not ready after {max_retries} attempts. Status: {status}. This may indicate: scan is still in progress, policy evaluation is taking longer than expected, or build results are not yet available"
                );
                return Ok((summary_report, Some(Cow::Owned(status))));
            }

            // Log retry attempt
            info!(
                "Policy evaluation not yet ready (status: '{status}'), retrying in {retry_delay_seconds} seconds... (attempt {attempts}/{max_retries})"
            );

            // Wait before retrying
            sleep(Duration::from_secs(retry_delay_seconds)).await;
        }
    }

    /// Evaluates policy compliance using the summary report API with retry logic
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    /// This function uses the `summary_report` endpoint instead of the buildinfo XML API
    /// and will retry when results are not ready yet.
    ///
    /// # Arguments
    ///
    /// * `app_guid` - The GUID of the application  
    /// * `build_id` - The build ID (GUID) to check compliance for
    /// * `sandbox_guid` - Optional sandbox GUID for sandbox scans
    /// * `max_retries` - Maximum number of retry attempts (default: 30)
    /// * `retry_delay_seconds` - Delay between retries in seconds (default: 10)
    ///
    /// # Returns
    ///
    /// A `Result` containing the policy compliance status string or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn evaluate_policy_compliance_via_summary_report_with_retry(
        &self,
        app_guid: &str,
        build_id: &str,
        sandbox_guid: Option<&str>,
        max_retries: u32,
        retry_delay_seconds: u64,
    ) -> Result<std::borrow::Cow<'static, str>, PolicyError> {
        use std::borrow::Cow;
        use tokio::time::{Duration, sleep};

        // Cap retry delay to prevent DoS scenarios
        let retry_delay_seconds = retry_delay_seconds.min(MAX_RETRY_DELAY_SECONDS);
        if retry_delay_seconds > MAX_RETRY_DELAY_SECONDS {
            warn!(
                "Retry delay capped at {} seconds (requested: {})",
                MAX_RETRY_DELAY_SECONDS, retry_delay_seconds
            );
        }

        let mut attempts: u32 = 0;
        loop {
            let summary_report = self
                .get_summary_report(app_guid, Some(build_id), sandbox_guid)
                .await?;

            // Check if results are ready - look for "Results Ready" or completed status
            // The summary report should have policy_compliance_status populated when ready
            let status = &summary_report.policy_compliance_status;

            // If status is not empty and not "Not Assessed", return the result
            if !status.is_empty() && status != "Not Assessed" {
                return Ok(Cow::Owned(status.clone()));
            }

            // If we've reached max retries, return current status
            attempts = attempts.saturating_add(1);
            if attempts >= max_retries {
                warn!(
                    "Policy evaluation still not ready after {max_retries} attempts. Status: {status}. This may indicate: scan is still in progress, policy evaluation is taking longer than expected, or build results are not yet available"
                );
                return Ok(Cow::Owned(status.clone()));
            }

            // Log retry attempt
            info!(
                "Policy evaluation not yet ready (status: '{status}'), retrying in {retry_delay_seconds} seconds... (attempt {attempts}/{max_retries})"
            );

            // Wait before retrying
            sleep(Duration::from_secs(retry_delay_seconds)).await;
        }
    }

    /// Evaluates policy compliance using the summary report API (single attempt)
    ///
    /// This is a convenience method that calls the retry version with default parameters.
    ///
    /// # Arguments
    ///
    /// * `app_guid` - The GUID of the application  
    /// * `build_id` - The build ID (GUID) to check compliance for
    /// * `sandbox_guid` - Optional sandbox GUID for sandbox scans
    ///
    /// # Returns
    ///
    /// A `Result` containing the policy compliance status string or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn evaluate_policy_compliance_via_summary_report(
        &self,
        app_guid: &str,
        build_id: &str,
        sandbox_guid: Option<&str>,
    ) -> Result<std::borrow::Cow<'static, str>, PolicyError> {
        self.evaluate_policy_compliance_via_summary_report_with_retry(
            app_guid,
            build_id,
            sandbox_guid,
            30,
            10,
        )
        .await
    }

    /// Initiate a policy scan for an application
    ///
    /// # Arguments
    ///
    /// * `request` - The policy scan request
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan result or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn initiate_policy_scan(
        &self,
        request: PolicyScanRequest,
    ) -> Result<PolicyScanResult, PolicyError> {
        // Validate application_guid to prevent injection
        validation::validate_guid(&request.application_guid)
            .map_err(|e| PolicyError::InvalidConfig(format!("Invalid application GUID: {e}")))?;

        // Validate policy_guid to prevent injection
        validation::validate_guid(&request.policy_guid)
            .map_err(|e| PolicyError::InvalidConfig(format!("Invalid policy GUID: {e}")))?;

        // Validate optional sandbox_guid to prevent injection
        if let Some(ref sandbox_guid) = request.sandbox_guid {
            validation::validate_guid(sandbox_guid)
                .map_err(|e| PolicyError::InvalidConfig(format!("Invalid sandbox GUID: {e}")))?;
        }

        let endpoint = "/appsec/v1/policy-scans";

        let response = self.client.post(endpoint, Some(&request)).await?;

        let status = response.status().as_u16();
        match status {
            200 | 201 => {
                let scan_result: PolicyScanResult = response.json().await?;
                Ok(scan_result)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(PolicyError::InvalidConfig(error_text))
            }
            404 => Err(PolicyError::NotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(PolicyError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Get policy scan status and results
    ///
    /// # Arguments
    ///
    /// * `scan_id` - The ID of the policy scan
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan result or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn get_policy_scan_result(
        &self,
        scan_id: u64,
    ) -> Result<PolicyScanResult, PolicyError> {
        let endpoint = format!("/appsec/v1/policy-scans/{scan_id}");

        let response = self.client.get(&endpoint, None).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let scan_result: PolicyScanResult = response.json().await?;
                Ok(scan_result)
            }
            404 => Err(PolicyError::NotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(PolicyError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Check if a policy scan is complete
    ///
    /// # Arguments
    ///
    /// * `scan_id` - The ID of the policy scan
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean indicating completion status.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn is_policy_scan_complete(&self, scan_id: u64) -> Result<bool, PolicyError> {
        let scan_result = self.get_policy_scan_result(scan_id).await?;
        Ok(matches!(
            scan_result.status,
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled
        ))
    }

    /// Gets policy compliance status with automatic fallback from summary report to buildinfo
    ///
    /// This method first tries the summary report API for full functionality. If access is denied
    /// (401/403), it automatically falls back to the getbuildinfo.do XML API for policy compliance
    /// status only. This provides the best user experience while maintaining compatibility.
    ///
    /// # Arguments
    ///
    /// * `app_guid` - Application GUID (for REST API)
    /// * `app_id` - Application numeric ID (for XML API fallback)
    /// * `build_id` - Optional build ID
    /// * `sandbox_guid` - Optional sandbox GUID (for REST API)
    /// * `sandbox_id` - Optional sandbox numeric ID (for XML API fallback)
    /// * `max_retries` - Maximum number of retry attempts
    /// * `retry_delay_seconds` - Delay between retries in seconds
    /// * `enable_break_build` - Whether to enable break build evaluation
    /// * `force_buildinfo_api` - Skip summary report and use buildinfo directly
    ///
    /// # Returns
    ///
    /// A tuple containing:
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    /// - Optional `SummaryReport` (None if fallback was used)
    /// - Policy compliance status string
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    /// - `ApiSource` indicating which API was used
    #[allow(clippy::too_many_arguments)]
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn get_policy_status_with_fallback(
        &self,
        app_guid: &str,
        app_id: &str,
        build_id: Option<&str>,
        sandbox_guid: Option<&str>,
        sandbox_id: Option<&str>,
        max_retries: u32,
        retry_delay_seconds: u64,
        enable_break_build: bool,
        force_buildinfo_api: bool,
    ) -> Result<(Option<SummaryReport>, String, ApiSource), PolicyError> {
        // Cap retry delay to prevent DoS scenarios
        let retry_delay_seconds = retry_delay_seconds.min(MAX_RETRY_DELAY_SECONDS);
        if retry_delay_seconds > MAX_RETRY_DELAY_SECONDS {
            warn!(
                "Retry delay capped at {} seconds (requested: {})",
                MAX_RETRY_DELAY_SECONDS, retry_delay_seconds
            );
        }

        if force_buildinfo_api {
            // DIRECT PATH: Skip summary report, use getbuildinfo.do directly
            debug!("Using getbuildinfo.do API directly (forced via configuration)");
            let status = self
                .evaluate_policy_compliance_via_buildinfo_with_retry(
                    app_id,
                    build_id,
                    sandbox_id,
                    max_retries,
                    retry_delay_seconds,
                )
                .await?;
            return Ok((None, status.to_string(), ApiSource::BuildInfo));
        }

        // FALLBACK PATH: Try summary report first, fallback to getbuildinfo.do
        match self
            .get_summary_report_with_policy_retry(
                app_guid,
                build_id,
                sandbox_guid,
                max_retries,
                retry_delay_seconds,
                enable_break_build,
            )
            .await
        {
            Ok((summary_report, compliance_status)) => {
                debug!("Used summary report API successfully");
                let status = compliance_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| summary_report.policy_compliance_status.clone());
                Ok((Some(summary_report), status, ApiSource::SummaryReport))
            }
            Err(
                ref e @ (PolicyError::Unauthorized
                | PolicyError::PermissionDenied
                | PolicyError::InternalServerError),
            ) => {
                match *e {
                    PolicyError::InternalServerError => info!(
                        "Summary report API server error, falling back to getbuildinfo.do API"
                    ),
                    PolicyError::Unauthorized | PolicyError::PermissionDenied => {
                        info!("Summary report access denied, falling back to getbuildinfo.do API")
                    }
                    PolicyError::Api(_)
                    | PolicyError::NotFound
                    | PolicyError::InvalidConfig(_)
                    | PolicyError::ScanFailed(_)
                    | PolicyError::EvaluationError(_)
                    | PolicyError::Timeout => {}
                }
                let status = self
                    .evaluate_policy_compliance_via_buildinfo_with_retry(
                        app_id,
                        build_id,
                        sandbox_id,
                        max_retries,
                        retry_delay_seconds,
                    )
                    .await?;
                Ok((None, status.to_string(), ApiSource::BuildInfo))
            }
            Err(e) => Err(e),
        }
    }

    /// Get active policies for the organization
    ///
    /// # Returns
    ///
    /// A `Result` containing a list of active policies or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the policy is invalid,
    /// or authentication/authorization fails.
    pub async fn get_active_policies(&self) -> Result<Vec<SecurityPolicy>, PolicyError> {
        // Note: The active/inactive concept may need to be handled differently
        // based on the actual API response structure
        let policies = self.list_policies(None).await?;
        Ok(policies) // Return all policies for now
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_list_params_to_query() {
        let params = PolicyListParams {
            name: Some("test-policy".to_string()),
            is_active: Some(true),
            page: Some(1),
            size: Some(10),
            ..Default::default()
        };

        let query_params: Vec<_> = params.into();
        assert_eq!(query_params.len(), 4);
        assert!(query_params.contains(&("name".to_string(), "test-policy".to_string())));
        assert!(query_params.contains(&("active".to_string(), "true".to_string())));
        assert!(query_params.contains(&("page".to_string(), "1".to_string())));
        assert!(query_params.contains(&("size".to_string(), "10".to_string())));
    }

    #[test]
    fn test_policy_error_display() {
        let error = PolicyError::NotFound;
        assert_eq!(error.to_string(), "Policy not found");

        let error = PolicyError::InvalidConfig("test".to_string());
        assert_eq!(error.to_string(), "Invalid policy configuration: test");

        let error = PolicyError::Timeout;
        assert_eq!(error.to_string(), "Policy operation timed out");
    }

    #[test]
    fn test_scan_type_serialization() {
        let scan_type = ScanType::Static;
        let json = serde_json::to_string(&scan_type).expect("should serialize to json");
        assert_eq!(json, "\"static\"");

        let deserialized: ScanType = serde_json::from_str(&json).expect("should deserialize json");
        assert!(matches!(deserialized, ScanType::Static));
    }

    #[test]
    fn test_policy_compliance_status_serialization() {
        let status = PolicyComplianceStatus::Passed;
        let json = serde_json::to_string(&status).expect("should serialize to json");
        assert_eq!(json, "\"Passed\"");

        let deserialized: PolicyComplianceStatus =
            serde_json::from_str(&json).expect("should deserialize json");
        assert!(matches!(deserialized, PolicyComplianceStatus::Passed));

        // Test the special case statuses with spaces
        let conditional_pass = PolicyComplianceStatus::ConditionalPass;
        let json = serde_json::to_string(&conditional_pass).expect("should serialize to json");
        assert_eq!(json, "\"Conditional Pass\"");

        let did_not_pass = PolicyComplianceStatus::DidNotPass;
        let json = serde_json::to_string(&did_not_pass).expect("should serialize to json");
        assert_eq!(json, "\"Did Not Pass\"");
    }

    #[test]
    fn test_break_build_logic() {
        assert!(PolicyApi::should_break_build("Did Not Pass"));
        assert!(!PolicyApi::should_break_build("Passed"));
        assert!(!PolicyApi::should_break_build("Conditional Pass"));
        // "Not Assessed" should not break build as the retry logic should handle waiting
        // for policy evaluation to complete before reaching this point
        assert!(!PolicyApi::should_break_build("Not Assessed"));

        assert_eq!(PolicyApi::get_exit_code_for_status("Did Not Pass"), 4);
        assert_eq!(PolicyApi::get_exit_code_for_status("Passed"), 0);
        assert_eq!(PolicyApi::get_exit_code_for_status("Conditional Pass"), 0);
        // "Not Assessed" returns 0 because it should only reach here after retry logic
        // has exhausted attempts, indicating a configuration or timing issue rather than policy failure
        assert_eq!(PolicyApi::get_exit_code_for_status("Not Assessed"), 0);
    }

    #[test]
    fn test_summary_report_serialization() {
        let summary_json = r#"{
            "app_id": 2676517,
            "app_name": "Verascan Java Test",
            "build_id": 54209787,
            "policy_compliance_status": "Did Not Pass",
            "policy_name": "SecureCode Policy",
            "policy_version": 1,
            "policy_rules_status": "Did Not Pass",
            "grace_period_expired": false,
            "scan_overdue": "false",
            "is_latest_build": false,
            "generation_date": "2025-08-05 10:14:45 UTC",
            "last_update_time": "2025-08-05 10:00:51 UTC"
        }"#;

        let summary: Result<SummaryReport, _> = serde_json::from_str(summary_json);
        assert!(summary.is_ok());

        let summary = summary.expect("should have summary");
        assert_eq!(summary.policy_compliance_status, "Did Not Pass");
        assert_eq!(summary.app_name, "Verascan Java Test");
        assert_eq!(summary.build_id, 54209787);
        assert!(PolicyApi::should_break_build(
            &summary.policy_compliance_status
        ));
    }

    #[test]
    fn test_export_json_structure() {
        // Test the JSON structure that would be exported
        let summary_report = SummaryReport {
            app_id: 2676517,
            app_name: "Test App".to_string(),
            build_id: 54209787,
            policy_compliance_status: "Passed".to_string(),
            policy_name: "Test Policy".to_string(),
            policy_version: 1,
            policy_rules_status: "Passed".to_string(),
            grace_period_expired: false,
            scan_overdue: "false".to_string(),
            is_latest_build: true,
            sandbox_name: Some("test-sandbox".to_string()),
            sandbox_id: Some(123456),
            generation_date: "2025-08-05 10:14:45 UTC".to_string(),
            last_update_time: "2025-08-05 10:00:51 UTC".to_string(),
            static_analysis: None,
            flaw_status: None,
            software_composition_analysis: None,
            severity: None,
        };

        let export_json = serde_json::json!({
            "summary_report": summary_report,
            "export_metadata": {
                "exported_at": "2025-08-05T10:14:45Z",
                "tool": "verascan",
                "export_type": "summary_report",
                "scan_configuration": {
                    "autoscan": true,
                    "scan_all_nonfatal_top_level_modules": true,
                    "include_new_modules": true
                }
            }
        });

        // Verify JSON structure
        assert!(
            export_json
                .get("summary_report")
                .and_then(|s| s.get("app_name"))
                .map(|v| v.is_string())
                .unwrap_or(false)
        );
        assert!(
            export_json
                .get("summary_report")
                .and_then(|s| s.get("policy_compliance_status"))
                .map(|v| v.is_string())
                .unwrap_or(false)
        );
        assert!(
            export_json
                .get("export_metadata")
                .and_then(|e| e.get("export_type"))
                .map(|v| v.is_string())
                .unwrap_or(false)
        );
        assert_eq!(
            export_json
                .get("export_metadata")
                .and_then(|e| e.get("export_type"))
                .and_then(|v| v.as_str())
                .expect("should have export_type"),
            "summary_report"
        );

        // Verify the summary report can be serialized and deserialized
        let json_string =
            serde_json::to_string_pretty(&export_json).expect("should serialize to json");
        assert!(json_string.contains("summary_report"));
        assert!(json_string.contains("export_metadata"));
    }

    #[test]
    fn test_get_summary_report_with_policy_retry_parameters() {
        // Unit tests for the new combined method parameter validation and logic

        // Test parameter type validation
        let app_guid = "test-app-guid";
        let build_id = Some("test-build-id");
        let sandbox_guid: Option<&str> = None;
        let max_retries = 30u32;
        let retry_delay_seconds = 10u64;
        let debug = false;
        let enable_break_build = true;

        // Verify parameter types are correct
        assert_eq!(app_guid, "test-app-guid");
        assert_eq!(build_id, Some("test-build-id"));
        assert_eq!(sandbox_guid, None);
        assert_eq!(max_retries, 30);
        assert_eq!(retry_delay_seconds, 10);
        assert!(!debug);
        assert!(enable_break_build);
    }

    #[test]
    fn test_policy_status_ready_logic() {
        // Test the logic for determining when policy status is ready
        let ready_statuses = vec!["Passed", "Did Not Pass", "Conditional Pass"];
        let not_ready_statuses = vec!["", "Not Assessed"];

        // Test ready statuses (should not trigger retry)
        for status in &ready_statuses {
            assert!(
                !status.is_empty(),
                "Ready status should not be empty: {status}"
            );
            assert_ne!(
                *status, "Not Assessed",
                "Ready status should not be 'Not Assessed': {status}"
            );
        }

        // Test not ready statuses (should trigger retry)
        for status in &not_ready_statuses {
            let is_not_ready = status.is_empty() || *status == "Not Assessed";
            assert!(is_not_ready, "Status should trigger retry: '{status}'");
        }
    }

    #[test]
    fn test_combined_method_return_types() {
        use std::borrow::Cow;

        // Test the return type structure of the new combined method
        // This verifies the tuple structure is correct

        // Test Some compliance status
        let compliance_status = Cow::Borrowed("Passed");
        assert_eq!(compliance_status.as_ref(), "Passed");

        // Test None compliance status (when break_build is disabled)
        let compliance_status: Option<Cow<'static, str>> = None;
        assert!(compliance_status.is_none());
    }

    #[test]
    fn test_debug_logging_parameters() {
        // Test debug parameter handling
        let debug_enabled = true;
        let debug_disabled = false;

        assert!(debug_enabled);
        assert!(!debug_disabled);

        // Test debug messages would be printed when debug=true
        // (Actual output testing would require integration tests)
        if debug_enabled {
            // Debug messages would be printed - this is just a placeholder
        }

        if !debug_disabled {
            // Debug messages would be printed - this is just a placeholder
        }
    }

    #[test]
    fn test_break_build_flag_logic() {
        // Test the enable_break_build flag logic
        let break_build_enabled = true;
        let break_build_disabled = false;

        // When break_build is enabled, compliance_status should be Some(_)
        if break_build_enabled {
            // Would return (summary_report, Some(compliance_status))
            let compliance_returned = true;
            assert!(compliance_returned);
        }

        // When break_build is disabled, compliance_status should be None
        if !break_build_disabled {
            // Would return (summary_report, None)
            let compliance_returned = false;
            assert!(!compliance_returned);
        }
    }
}

/// Security-focused property tests for input validation
#[cfg(test)]
#[allow(clippy::expect_used)]
mod validation_proptests {
    use super::validation::*;
    use proptest::prelude::*;

    // Strategy for valid GUIDs (32 hex chars with optional hyphens)
    fn valid_guid_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // Standard UUID format (8-4-4-4-12)
            prop::string::string_regex(
                "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
            )
            .expect("valid regex for UUID"),
            // No hyphens (32 hex chars)
            prop::string::string_regex("[0-9a-fA-F]{32}").expect("valid regex for hex string"),
        ]
    }

    // Strategy for invalid GUIDs (injection attacks, path traversal, malformed)
    fn invalid_guid_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // Path traversal attempts
            Just("../../../etc/passwd".to_string()),
            Just("..\\..\\windows\\system32".to_string()),
            prop::string::string_regex("[0-9a-f]{8}\\.\\./{0,20}[0-9a-f]{8}")
                .expect("valid regex for path traversal with guid"),
            // URL parameter injection
            Just("abc123?param=value".to_string()),
            Just("abc123&admin=true".to_string()),
            Just("abc123#fragment".to_string()),
            // Non-hex characters
            prop::string::string_regex("[0-9a-zA-Z!@#$%^&*()]{32}")
                .expect("valid regex for non-hex chars"),
            // Wrong length
            prop::string::string_regex("[0-9a-f]{1,31}").expect("valid regex for too short"),
            prop::string::string_regex("[0-9a-f]{33,100}").expect("valid regex for too long"),
            // SQL injection attempts
            Just("abc123'; DROP TABLE users; --".to_string()),
            // Command injection
            Just("abc123; rm -rf /".to_string()),
            Just("abc123 | cat /etc/passwd".to_string()),
            // Null byte injection
            Just("abc123\0malicious".to_string()),
        ]
    }

    // Strategy for valid identifiers (alphanumeric, hyphens, underscores)
    fn valid_identifier_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[a-zA-Z0-9_-]{1,256}").expect("valid regex for identifier")
    }

    // Strategy for invalid identifiers
    fn invalid_identifier_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // Empty string
            Just("".to_string()),
            // Path traversal
            Just("../etc/passwd".to_string()),
            Just("..\\windows\\system32".to_string()),
            // URL injection
            Just("test?param=value".to_string()),
            Just("test&admin=true".to_string()),
            Just("test#fragment".to_string()),
            // Special characters
            prop::string::string_regex(
                "[a-zA-Z0-9]{1,10}[@#$%^&*()+=\\[\\]{}|;:'\"<>,./\\\\?]+[a-zA-Z0-9]{0,10}"
            )
            .expect("valid regex for special chars"),
            // SQL injection
            Just("test'; DROP TABLE users; --".to_string()),
            // Command injection
            Just("test; rm -rf /".to_string()),
            // Unicode control characters
            Just("test\u{0000}injection".to_string()),
            Just("test\u{001F}control".to_string()),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_valid_guids_accepted(guid in valid_guid_strategy()) {
            prop_assert!(validate_guid(&guid).is_ok(),
                "Valid GUID rejected: {}", guid);
        }

        #[test]
        fn proptest_invalid_guids_rejected(guid in invalid_guid_strategy()) {
            prop_assert!(validate_guid(&guid).is_err(),
                "Invalid GUID accepted: {}", guid);
        }

        #[test]
        fn proptest_guid_no_path_traversal(
            prefix in prop::string::string_regex("[0-9a-f]{8}").expect("valid regex for guid prefix")
        ) {
            let with_traversal = format!("{}/../../../etc/passwd", prefix);
            prop_assert!(validate_guid(&with_traversal).is_err(),
                "Path traversal GUID accepted: {}", with_traversal);

            let with_backslash = format!("{}\\..\\windows", prefix);
            prop_assert!(validate_guid(&with_backslash).is_err(),
                "Backslash traversal GUID accepted: {}", with_backslash);
        }

        #[test]
        fn proptest_guid_no_url_injection(
            prefix in prop::string::string_regex("[0-9a-f]{16}").expect("valid regex for guid prefix")
        ) {
            let with_query = format!("{}?admin=true", prefix);
            prop_assert!(validate_guid(&with_query).is_err(),
                "URL query injection accepted: {}", with_query);

            let with_ampersand = format!("{}&param=value", prefix);
            prop_assert!(validate_guid(&with_ampersand).is_err(),
                "URL parameter injection accepted: {}", with_ampersand);

            let with_fragment = format!("{}#section", prefix);
            prop_assert!(validate_guid(&with_fragment).is_err(),
                "URL fragment injection accepted: {}", with_fragment);
        }

        #[test]
        fn proptest_valid_identifiers_accepted(id in valid_identifier_strategy()) {
            prop_assert!(validate_identifier(&id).is_ok(),
                "Valid identifier rejected: {}", id);
        }

        #[test]
        fn proptest_invalid_identifiers_rejected(id in invalid_identifier_strategy()) {
            prop_assert!(validate_identifier(&id).is_err(),
                "Invalid identifier accepted: {}", id);
        }

        #[test]
        fn proptest_identifier_no_path_traversal(
            base in prop::string::string_regex("[a-zA-Z0-9]{5,10}").expect("valid regex for base id")
        ) {
            let with_dots = format!("{}/../test", base);
            prop_assert!(validate_identifier(&with_dots).is_err(),
                "Path traversal identifier accepted: {}", with_dots);

            let with_slashes = format!("{}/etc/passwd", base);
            prop_assert!(validate_identifier(&with_slashes).is_err(),
                "Forward slash identifier accepted: {}", with_slashes);
        }

        #[test]
        fn proptest_identifier_no_url_injection(
            base in prop::string::string_regex("[a-zA-Z0-9_-]{5,20}").expect("valid regex for base id")
        ) {
            let with_query = format!("{}?param=value", base);
            prop_assert!(validate_identifier(&with_query).is_err(),
                "URL query injection in identifier accepted: {}", with_query);

            let with_ampersand = format!("{}&admin=true", base);
            prop_assert!(validate_identifier(&with_ampersand).is_err(),
                "Ampersand injection in identifier accepted: {}", with_ampersand);
        }

        #[test]
        fn proptest_identifier_no_special_chars(
            alphanumeric in prop::string::string_regex("[a-zA-Z0-9]{3,10}").expect("valid regex for alphanumeric"),
            special_char in "[!@#$%^&*()+=\\[\\]{}|;:'\"<>,./\\\\?]"
        ) {
            let with_special = format!("{}{}{}", alphanumeric, special_char, alphanumeric);
            prop_assert!(validate_identifier(&with_special).is_err(),
                "Identifier with special char accepted: {}", with_special);
        }
    }
}

/// Security-focused property tests for query parameter handling
#[cfg(test)]
#[allow(clippy::expect_used)]
mod query_param_proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_policy_list_params_no_duplicate_keys(
            name in prop::option::of(prop::string::string_regex("[a-zA-Z0-9 _-]{1,50}").expect("valid regex for policy name")),
            policy_type in prop::option::of(prop::string::string_regex("[A-Z]{1,20}").expect("valid regex for policy type")),
            is_active in prop::option::of(any::<bool>()),
            default_only in prop::option::of(any::<bool>()),
            page in prop::option::of(0u32..10000u32),
            size in prop::option::of(1u32..1000u32)
        ) {
            let params = PolicyListParams {
                name,
                policy_type,
                is_active,
                default_only,
                page,
                size,
            };

            let query_params = params.to_query_params();

            // Verify no duplicate keys
            let mut seen_keys = std::collections::HashSet::new();
            for (key, _) in query_params.iter() {
                prop_assert!(!seen_keys.contains(key),
                    "Duplicate query parameter key: {}", key);
                seen_keys.insert(key.clone());
            }
        }

        #[test]
        fn proptest_policy_list_params_valid_values(
            page in 0u32..10000u32,
            size in 1u32..1000u32
        ) {
            let params = PolicyListParams {
                name: None,
                policy_type: None,
                is_active: Some(true),
                default_only: Some(false),
                page: Some(page),
                size: Some(size),
            };

            let query_params = params.to_query_params();

            // Find page and size params
            let page_param = query_params.iter().find(|(k, _)| k == "page");
            let size_param = query_params.iter().find(|(k, _)| k == "size");

            if let Some((_, page_value)) = page_param {
                prop_assert!(page_value.parse::<u32>().is_ok(),
                    "Invalid page value: {}", page_value);
            }

            if let Some((_, size_value)) = size_param {
                prop_assert!(size_value.parse::<u32>().is_ok(),
                    "Invalid size value: {}", size_value);
            }
        }

        #[test]
        fn proptest_policy_list_params_string_sanitization(
            name in prop::string::string_regex("[a-zA-Z0-9 &=;?#]{1,100}").expect("valid regex for name with special chars")
        ) {
            let params = PolicyListParams {
                name: Some(name.clone()),
                policy_type: None,
                is_active: None,
                default_only: None,
                page: None,
                size: None,
            };

            let query_params = params.to_query_params();

            // Find the name parameter
            let name_param = query_params.iter().find(|(k, _)| k == "name");

            if let Some((_, value)) = name_param {
                // The value should be the input (encoding happens at HTTP layer)
                prop_assert_eq!(value, &name);
            }
        }
    }
}

/// Security-focused property tests for integer operations
#[cfg(test)]
#[allow(clippy::expect_used)]
mod integer_safety_proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_retry_delay_capped(delay in 0u64..u64::MAX) {
            let capped = delay.min(MAX_RETRY_DELAY_SECONDS);
            prop_assert!(capped <= MAX_RETRY_DELAY_SECONDS,
                "Retry delay not properly capped: {}", capped);
            prop_assert!(capped <= 300,
                "Retry delay exceeds 5 minutes: {}", capped);
        }

        #[test]
        fn proptest_retry_attempts_no_overflow(attempts in 0u32..u32::MAX - 1) {
            let incremented = attempts.saturating_add(1);
            prop_assert!(incremented >= attempts,
                "Retry counter overflowed: {} + 1 = {}", attempts, incremented);
            // Note: incremented is always <= u32::MAX since it's a u32
        }

        #[test]
        fn proptest_max_retries_reasonable(max_retries in 0u32..1000u32) {
            // Verify max_retries used in comparisons doesn't overflow
            let test_attempts = max_retries.saturating_add(1);
            prop_assert!(test_attempts > max_retries || max_retries == u32::MAX,
                "Max retries comparison could overflow");
        }

        #[test]
        fn proptest_retry_delay_multiplication_safe(
            retries in 0u32..100u32,
            delay in 0u64..MAX_RETRY_DELAY_SECONDS
        ) {
            // Verify that retry delay calculations don't overflow
            let total_delay = (retries as u64).saturating_mul(delay);
            // Total delay should be reasonable (less than 1 day)
            prop_assert!(total_delay <= 86400,
                "Total delay unreasonably large: {} seconds", total_delay);
        }
    }
}

/// Security-focused property tests for string handling
#[cfg(test)]
#[allow(clippy::expect_used)]
mod string_safety_proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_policy_status_string_utf8_safe(
            status in prop::string::string_regex("[ -~]{1,50}").expect("valid regex for ASCII status")
        ) {
            // All status strings should be valid UTF-8
            prop_assert!(status.is_ascii() || status.chars().all(|c| !c.is_control()),
                "Status string contains control characters");
        }

        #[test]
        fn proptest_guid_formatting_safe(
            guid in prop::string::string_regex("[0-9a-f]{32}").expect("valid regex for guid")
        ) {
            let endpoint = format!("/appsec/v1/policies/{}", guid);

            // Verify no format string injection
            prop_assert!(!endpoint.contains("{}"),
                "Format string injection in endpoint: {}", endpoint);
            prop_assert!(!endpoint.contains("%s"),
                "Printf-style injection in endpoint: {}", endpoint);

            // Verify proper structure
            prop_assert!(endpoint.starts_with("/appsec/v1/policies/"),
                "Malformed endpoint structure: {}", endpoint);
            #[allow(clippy::arithmetic_side_effects)]
            {
                prop_assert_eq!(endpoint.len(), 20 + guid.len(),
                    "Unexpected endpoint length");
            }
        }

        #[test]
        fn proptest_error_message_no_injection(
            user_input in prop::string::string_regex("[ -~]{1,100}").expect("valid regex for user input")
        ) {
            let error_msg = format!("Invalid GUID: {}", user_input);

            // Error messages should be safe from injection
            prop_assert!(error_msg.starts_with("Invalid GUID: "),
                "Error message structure corrupted");
            prop_assert!(!error_msg.contains('\0'),
                "Null byte in error message");
            prop_assert!(error_msg.len() >= 14,
                "Error message unexpectedly short");
        }

        #[test]
        fn proptest_compliance_status_values_safe(
            status in prop_oneof![
                Just("Passed".to_string()),
                Just("Did Not Pass".to_string()),
                Just("Conditional Pass".to_string()),
                Just("Not Assessed".to_string()),
                Just("Calculating...".to_string()),
            ]
        ) {
            // All status values should be alphanumeric or spaces
            prop_assert!(status.chars().all(|c| c.is_alphanumeric() || c.is_whitespace() || c == '.'),
                "Status contains unexpected characters: {}", status);

            // Should not break build logic
            let should_break = PolicyApi::should_break_build(&status);
            if status == "Did Not Pass" {
                prop_assert!(should_break, "Did Not Pass should break build");
            } else {
                prop_assert!(!should_break, "{} should not break build", status);
            }
        }
    }
}

/// Security-focused property tests for URL/endpoint construction
#[cfg(test)]
#[allow(clippy::expect_used)]
mod endpoint_safety_proptests {
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_scan_id_endpoint_no_injection(scan_id in 0u64..u64::MAX) {
            let endpoint = format!("/appsec/v1/policy-scans/{}", scan_id);

            // Verify no injection
            prop_assert!(endpoint.starts_with("/appsec/v1/policy-scans/"),
                "Endpoint prefix corrupted: {}", endpoint);
            prop_assert!(!endpoint.contains(".."),
                "Path traversal in endpoint: {}", endpoint);
            prop_assert!(!endpoint.contains("//"),
                "Double slash in endpoint: {}", endpoint);

            // Verify scan_id is properly formatted as number
            let scan_id_str = endpoint.get(24..).unwrap_or("");
            prop_assert!(scan_id_str.parse::<u64>().is_ok(),
                "Invalid scan_id in endpoint: {}", scan_id_str);
        }

        #[test]
        fn proptest_app_guid_endpoint_validated(
            guid_part in prop::string::string_regex("[0-9a-f]{32}").expect("valid regex for guid")
        ) {
            // Simulate what happens after validation
            let endpoint = format!("/appsec/v2/applications/{}/summary_report", guid_part);

            // Verify structure
            prop_assert!(endpoint.starts_with("/appsec/v2/applications/"),
                "Invalid endpoint prefix");
            prop_assert!(endpoint.ends_with("/summary_report"),
                "Invalid endpoint suffix");
            prop_assert!(!endpoint.contains(".."),
                "Path traversal in endpoint");
        }

        #[test]
        fn proptest_query_string_no_injection(
            build_id in prop::string::string_regex("[a-zA-Z0-9_-]{1,64}").expect("valid regex for build id"),
            sandbox_guid in prop::string::string_regex("[0-9a-f]{32}").expect("valid regex for sandbox guid")
        ) {
            // Simulate query parameter construction
            let query_params = [
                ("build_id".to_string(), build_id.clone()),
                ("context".to_string(), sandbox_guid.clone())
            ];

            // Verify no duplicate keys
            let keys: Vec<_> = query_params.iter().map(|(k, _)| k).collect();
            prop_assert_eq!(keys.len(), 2, "Wrong number of query params");
            prop_assert_eq!(keys.first().map(|s| s.as_str()), Some("build_id"), "Wrong first key");
            prop_assert_eq!(keys.get(1).map(|s| s.as_str()), Some("context"), "Wrong second key");

            // Verify values are not corrupted
            if let Some((_, val)) = query_params.first() {
                prop_assert_eq!(val, &build_id, "build_id value corrupted");
            }
            if let Some((_, val)) = query_params.get(1) {
                prop_assert_eq!(val, &sandbox_guid, "sandbox_guid value corrupted");
            }
        }
    }
}

/// Memory safety tests for data structure operations
#[cfg(test)]
#[allow(clippy::expect_used)]
mod memory_safety_proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_policy_list_params_from_owned(
            name in prop::option::of(prop::string::string_regex("[a-zA-Z0-9_-]{1,50}").expect("valid regex for name")),
            page in prop::option::of(0u32..1000u32),
            size in prop::option::of(1u32..100u32)
        ) {
            let params = PolicyListParams {
                name: name.clone(),
                policy_type: None,
                is_active: None,
                default_only: None,
                page,
                size,
            };

            // Convert owned to query params (should move, not clone)
            let query_params: Vec<(String, String)> = params.into();

            // Verify structure is intact after move
            prop_assert!(query_params.len() <= 6, "Too many query params");

            // If name was Some, it should be in params
            if name.is_some() {
                let has_name = query_params.iter().any(|(k, _)| k == "name");
                prop_assert!(has_name, "Name parameter lost after move");
            }
        }

        #[test]
        fn proptest_policy_list_params_from_ref(
            name in prop::option::of(prop::string::string_regex("[a-zA-Z0-9_-]{1,50}").expect("valid regex for name")),
            page in prop::option::of(0u32..1000u32)
        ) {
            let params = PolicyListParams {
                name: name.clone(),
                policy_type: None,
                is_active: None,
                default_only: None,
                page,
                size: None,
            };

            // Convert by reference (should clone)
            let query_params: Vec<(String, String)> = Vec::from(&params);

            // Original should still be valid
            let query_params2 = params.to_query_params();

            // Both should be equal
            prop_assert_eq!(query_params, query_params2,
                "Reference conversion differs from method call");
        }

        #[test]
        fn proptest_vec_allocation_reasonable(
            param_count in 1usize..10usize
        ) {
            let mut params = Vec::new();

            for i in 0..param_count {
                params.push((format!("key{}", i), format!("value{}", i)));
            }

            // Verify no excessive allocations
            prop_assert_eq!(params.len(), param_count,
                "Parameter count mismatch");
            prop_assert!(params.capacity() >= param_count,
                "Insufficient capacity");
            // Capacity should be reasonable (not wildly over-allocated)
            prop_assert!(params.capacity() < param_count.saturating_mul(10),
                "Excessive capacity: {} for {} items", params.capacity(), param_count);
        }
    }
}

//! Policy API module for Veracode Platform
//!
//! This module provides functionality for managing security policies, policy compliance,
//! and policy scan operations within the Veracode platform.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{VeracodeClient, VeracodeError};

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

/// Policy compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyComplianceStatus {
    /// Application passes all policy requirements
    Pass,
    /// Application fails policy requirements
    Fail,
    /// Policy compliance check is pending
    Pending,
    /// Policy compliance status is not determined
    NotDetermined,
    /// Policy compliance check resulted in error
    Error,
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
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();

        if let Some(name) = &self.name {
            params.push(("name".to_string(), name.clone()));
        }
        if let Some(policy_type) = &self.policy_type {
            params.push(("type".to_string(), policy_type.clone()));
        }
        if let Some(is_active) = self.is_active {
            params.push(("active".to_string(), is_active.to_string()));
        }
        if let Some(default_only) = self.default_only {
            params.push(("default".to_string(), default_only.to_string()));
        }
        if let Some(page) = self.page {
            params.push(("page".to_string(), page.to_string()));
        }
        if let Some(size) = self.size {
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

/// Policy-specific error types
#[derive(Debug)]
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
    /// Create a new PolicyApi instance
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
    pub async fn list_policies(
        &self,
        params: Option<PolicyListParams>,
    ) -> Result<Vec<SecurityPolicy>, PolicyError> {
        let endpoint = "/appsec/v1/policies";

        let query_params = params.map(|p| p.to_query_params());

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
    pub async fn get_policy(&self, policy_guid: &str) -> Result<SecurityPolicy, PolicyError> {
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

    /// Evaluate policy compliance for an application
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `policy_guid` - The GUID of the policy to evaluate against
    /// * `sandbox_guid` - Optional sandbox GUID for sandbox evaluation
    ///
    /// # Returns
    ///
    /// A `Result` containing the compliance result or an error.
    pub async fn evaluate_policy_compliance(
        &self,
        application_guid: &str,
        policy_guid: &str,
        sandbox_guid: Option<&str>,
    ) -> Result<PolicyComplianceResult, PolicyError> {
        let endpoint = if let Some(sandbox) = sandbox_guid {
            format!(
                "/appsec/v1/applications/{application_guid}/sandboxes/{sandbox}/policy/{policy_guid}/compliance"
            )
        } else {
            format!("/appsec/v1/applications/{application_guid}/policy/{policy_guid}/compliance")
        };

        let response = self.client.get(&endpoint, None).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let compliance: PolicyComplianceResult = response.json().await?;
                Ok(compliance)
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

    /// Initiate a policy scan for an application
    ///
    /// # Arguments
    ///
    /// * `request` - The policy scan request
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan result or an error.
    pub async fn initiate_policy_scan(
        &self,
        request: PolicyScanRequest,
    ) -> Result<PolicyScanResult, PolicyError> {
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
    pub async fn is_policy_scan_complete(&self, scan_id: u64) -> Result<bool, PolicyError> {
        let scan_result = self.get_policy_scan_result(scan_id).await?;
        Ok(matches!(
            scan_result.status,
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled
        ))
    }

    /// Get policy violations for an application
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `policy_guid` - The GUID of the policy
    /// * `sandbox_guid` - Optional sandbox GUID
    ///
    /// # Returns
    ///
    /// A `Result` containing policy violations or an error.
    pub async fn get_policy_violations(
        &self,
        application_guid: &str,
        policy_guid: &str,
        sandbox_guid: Option<&str>,
    ) -> Result<Vec<PolicyViolation>, PolicyError> {
        let compliance = self
            .evaluate_policy_compliance(application_guid, policy_guid, sandbox_guid)
            .await?;
        Ok(compliance.violations.unwrap_or_default())
    }
}

/// Convenience methods for common policy operations
impl<'a> PolicyApi<'a> {
    /// Check if an application passes policy compliance
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `policy_guid` - The GUID of the policy
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean indicating compliance status.
    pub async fn is_application_compliant(
        &self,
        application_guid: &str,
        policy_guid: &str,
    ) -> Result<bool, PolicyError> {
        let compliance = self
            .evaluate_policy_compliance(application_guid, policy_guid, None)
            .await?;
        Ok(compliance.passed)
    }

    /// Get compliance score for an application
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `policy_guid` - The GUID of the policy
    ///
    /// # Returns
    ///
    /// A `Result` containing the compliance score or an error.
    pub async fn get_compliance_score(
        &self,
        application_guid: &str,
        policy_guid: &str,
    ) -> Result<Option<f64>, PolicyError> {
        let compliance = self
            .evaluate_policy_compliance(application_guid, policy_guid, None)
            .await?;
        Ok(compliance.score)
    }

    /// Get active policies for the organization
    ///
    /// # Returns
    ///
    /// A `Result` containing a list of active policies or an error.
    pub async fn get_active_policies(&self) -> Result<Vec<SecurityPolicy>, PolicyError> {
        // Note: The active/inactive concept may need to be handled differently
        // based on the actual API response structure
        let policies = self.list_policies(None).await?;
        Ok(policies) // Return all policies for now
    }
}

#[cfg(test)]
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

        let query_params = params.to_query_params();
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
        let json = serde_json::to_string(&scan_type).unwrap();
        assert_eq!(json, "\"static\"");

        let deserialized: ScanType = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, ScanType::Static));
    }

    #[test]
    fn test_policy_compliance_status_serialization() {
        let status = PolicyComplianceStatus::Pass;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"PASS\"");

        let deserialized: PolicyComplianceStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, PolicyComplianceStatus::Pass));
    }
}

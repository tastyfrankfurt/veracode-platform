//! GitLab SAST report mapping system for different Veracode scan types
//!
//! This module provides a unified interface for mapping Veracode scan results
//! from different sources (pipeline, policy, sandbox) to GitLab SAST report format.

use crate::findings::FindingWithSource;
use crate::gitlab_report::{
    GitLabIdentifier, GitLabLink, GitLabLocation, GitLabSeverity, GitLabSignature, GitLabTracking,
    GitLabTrackingItem, GitLabVulnerability,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
// use veracode_platform::pipeline::{Finding, SourceFile}; // Used in tests
use veracode_platform::findings::RestFinding;

/// Supported Veracode scan types
#[derive(Debug, Clone, PartialEq)]
pub enum ScanType {
    /// Pipeline scan results from veracode-pipeline-scan
    Pipeline,
    /// Policy scan results from Findings API
    Policy,
    /// Sandbox scan results from Findings API
    Sandbox,
}

/// Scan type detector for identifying the source format
pub struct ScanTypeDetector;

impl ScanTypeDetector {
    /// Detect scan type from raw JSON data
    pub fn detect(data: &serde_json::Value) -> ScanType {
        // Check for pipeline scan structure
        if data.get("findings").is_some() && data.get("scan_id").is_some() {
            return ScanType::Pipeline;
        }

        // Check for Findings API structure
        if let Some(embedded) = data.get("_embedded") {
            if embedded.get("findings").is_some() {
                // Check if it's a sandbox scan by looking for sandbox context
                if let Some(findings) = embedded.get("findings").and_then(|f| f.as_array()) {
                    if !findings.is_empty() {
                        if let Some(context_type) = findings[0].get("context_type") {
                            if context_type == "SANDBOX" {
                                return ScanType::Sandbox;
                            } else if context_type == "POLICY" {
                                return ScanType::Policy;
                            }
                        }
                    }
                }
                // Default to Policy if no specific context found
                return ScanType::Policy;
            }
        }

        // Default fallback
        ScanType::Pipeline
    }

    /// Validate that the detected scan type has the expected data structure
    pub fn validate_structure(data: &serde_json::Value, scan_type: &ScanType) -> bool {
        match scan_type {
            ScanType::Pipeline => {
                data.get("findings").is_some() && data.get("scan_status").is_some()
            }
            ScanType::Policy | ScanType::Sandbox => data
                .get("_embedded")
                .and_then(|e| e.get("findings"))
                .is_some(),
        }
    }
}

/// Configuration for URL filtering and replacement
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MappingConfig {
    /// URL pattern replacements (pattern -> replacement)
    pub url_replacements: HashMap<String, String>,
    /// URL patterns to block/remove entirely
    pub blocked_url_patterns: Vec<String>,
    /// Allowed identifier types in GitLab output
    pub identifier_types: Vec<String>,
    /// Include tracking information in GitLab output
    pub include_tracking: bool,
    /// Include solution text in GitLab output
    pub include_solutions: bool,
    /// Include links section in GitLab output
    pub include_links: bool,
}

impl Default for MappingConfig {
    fn default() -> Self {
        let mut url_replacements = HashMap::new();
        url_replacements.insert(
            "api.veracode.com/appsec/v1/cwes/".to_string(),
            "cwe.mitre.org/data/definitions/".to_string(),
        );

        Self {
            url_replacements,
            blocked_url_patterns: vec![
                "api.veracode.com".to_string(),
                "analysiscenter.veracode.com".to_string(),
            ],
            identifier_types: vec!["cwe".to_string(), "veracode".to_string()],
            include_tracking: true,
            include_solutions: true,
            include_links: true,
        }
    }
}

/// URL filtering and validation utilities
pub struct UrlFilter {
    config: MappingConfig,
}

impl UrlFilter {
    pub fn new(config: MappingConfig) -> Self {
        Self { config }
    }

    /// Check if a URL is valid for external access (no network calls)
    pub fn is_valid_external_url(&self, url: &str) -> bool {
        // Pattern-based filtering - no network calls
        for blocked_pattern in &self.config.blocked_url_patterns {
            if url.contains(blocked_pattern) {
                return false;
            }
        }

        url.starts_with("https://") && self.is_known_good_domain(url)
    }

    /// Check if domain is in our whitelist of known good domains
    fn is_known_good_domain(&self, url: &str) -> bool {
        // Whitelist of known good domains - no network calls
        url.contains("cwe.mitre.org")
            || url.contains("help.veracode.com")
            || url.contains("docs.veracode.com")
            || url.contains("owasp.org")
            || url.contains("nvd.nist.gov")
    }

    /// Filter and replace URLs according to configuration
    pub fn filter_and_replace_url(&self, source_url: &str, cwe_id: Option<&str>) -> Option<String> {
        // Check for URL replacements
        for (pattern, replacement) in &self.config.url_replacements {
            if source_url.contains(pattern) && pattern.contains("cwes") {
                if let Some(cwe_id) = cwe_id {
                    if !cwe_id.is_empty() && cwe_id != "0" {
                        return Some(format!("https://{replacement}{cwe_id}.html"));
                    }
                }
                // If no valid CWE ID, remove the URL
                return None;
            }
        }

        // Filter blocked URLs
        if !self.is_valid_external_url(source_url) {
            return None;
        }

        Some(source_url.to_string())
    }

    /// Generate a CWE URL from CWE ID
    pub fn generate_cwe_url(cwe_id: &str) -> Option<String> {
        if !cwe_id.is_empty() && cwe_id != "0" {
            Some(format!(
                "https://cwe.mitre.org/data/definitions/{cwe_id}.html"
            ))
        } else {
            None
        }
    }
}

/// Extract CWE ID from various URL formats
pub fn extract_cwe_id_from_url(url: &str) -> Option<String> {
    if let Some(start) = url.find("/cwes/") {
        let after_cwes = &url[start + 6..];
        if let Some(end) = after_cwes.find('/').or_else(|| after_cwes.find('?')) {
            Some(after_cwes[..end].to_string())
        } else {
            Some(after_cwes.to_string())
        }
    } else {
        None
    }
}

/// Abstract interface for mapping different scan result types to GitLab format
pub trait GitLabFieldMapper {
    /// Map vulnerability name/title
    fn map_vulnerability_name(&self, data: &dyn ScanResultData) -> String;

    /// Map vulnerability description with HTML cleanup
    fn map_description(&self, data: &dyn ScanResultData) -> String;

    /// Map file location information
    fn map_location(&self, data: &dyn ScanResultData, url_filter: &UrlFilter) -> GitLabLocation;

    /// Map identifiers (CWE, Veracode, etc.)
    fn map_identifiers(
        &self,
        data: &dyn ScanResultData,
        url_filter: &UrlFilter,
    ) -> Vec<GitLabIdentifier>;

    /// Map severity level
    fn map_severity(&self, data: &dyn ScanResultData) -> GitLabSeverity;

    /// Map links to external resources
    fn map_links(
        &self,
        data: &dyn ScanResultData,
        url_filter: &UrlFilter,
    ) -> Option<Vec<GitLabLink>>;

    /// Map tracking information
    fn map_tracking(
        &self,
        data: &dyn ScanResultData,
        url_filter: &UrlFilter,
    ) -> Option<GitLabTracking>;

    /// Generate solution text
    fn map_solution(&self, data: &dyn ScanResultData) -> Option<String>;

    /// Map details (additional metadata)
    fn map_details(&self, data: &dyn ScanResultData)
    -> Option<crate::gitlab_report::GitLabDetails>;
}

/// Trait for abstracting different scan result data sources
pub trait ScanResultData {
    fn get_issue_id(&self) -> u32;
    fn get_cwe_id(&self) -> String;
    fn get_cwe_name(&self) -> Option<String>;
    fn get_severity(&self) -> u32;
    fn get_file_path(&self) -> String;
    fn get_file_line(&self) -> u32;
    fn get_function_name(&self) -> Option<String>;
    fn get_issue_type(&self) -> String;
    fn get_description(&self) -> String;
    fn get_scan_id(&self) -> String;
    fn get_project_name(&self) -> String;
    fn get_finding_category_id(&self) -> Option<u32>;
    fn get_finding_category_name(&self) -> Option<String>;
    fn get_exploitability(&self) -> Option<u32>;
}

/// Implementation for Pipeline scan findings
impl ScanResultData for FindingWithSource {
    fn get_issue_id(&self) -> u32 {
        self.finding.issue_id
    }

    fn get_cwe_id(&self) -> String {
        self.finding.cwe_id.clone()
    }

    fn get_cwe_name(&self) -> Option<String> {
        // Pipeline scans don't typically include CWE names
        None
    }

    fn get_severity(&self) -> u32 {
        self.finding.severity
    }

    fn get_file_path(&self) -> String {
        self.finding.files.source_file.file.clone()
    }

    fn get_file_line(&self) -> u32 {
        self.finding.files.source_file.line
    }

    fn get_function_name(&self) -> Option<String> {
        self.finding.files.source_file.function_name.clone()
    }

    fn get_issue_type(&self) -> String {
        self.finding.issue_type.clone()
    }

    fn get_description(&self) -> String {
        self.finding.display_text.clone()
    }

    fn get_scan_id(&self) -> String {
        self.source_scan.scan_id.clone()
    }

    fn get_project_name(&self) -> String {
        self.source_scan.project_name.clone()
    }

    fn get_finding_category_id(&self) -> Option<u32> {
        // Pipeline scan findings don't have explicit category IDs
        // We could map issue_type_id to a category if needed
        None
    }

    fn get_finding_category_name(&self) -> Option<String> {
        // Use issue_type as the category name for pipeline scans
        Some(self.finding.issue_type.clone())
    }

    fn get_exploitability(&self) -> Option<u32> {
        // Pipeline scans don't currently expose exploitability in the struct
        // This would need to be added to the pipeline Finding struct
        None
    }
}

/// Wrapper for REST API findings (Policy/Sandbox scans)
#[derive(Debug, Clone)]
pub struct RestFindingWrapper {
    pub finding: RestFinding,
    pub scan_id: String,
    pub project_name: String,
}

impl ScanResultData for RestFindingWrapper {
    fn get_issue_id(&self) -> u32 {
        self.finding.issue_id
    }

    fn get_cwe_id(&self) -> String {
        self.finding.finding_details.cwe.id.to_string()
    }

    fn get_cwe_name(&self) -> Option<String> {
        Some(self.finding.finding_details.cwe.name.clone())
    }

    fn get_severity(&self) -> u32 {
        self.finding.finding_details.severity
    }

    fn get_file_path(&self) -> String {
        self.finding.finding_details.file_path.clone()
    }

    fn get_file_line(&self) -> u32 {
        self.finding.finding_details.file_line_number
    }

    fn get_function_name(&self) -> Option<String> {
        if self.finding.finding_details.procedure.is_empty()
            || self.finding.finding_details.procedure == "UNKNOWN"
        {
            None
        } else {
            Some(self.finding.finding_details.procedure.clone())
        }
    }

    fn get_issue_type(&self) -> String {
        self.finding.finding_details.finding_category.name.clone()
    }

    fn get_description(&self) -> String {
        // Remove HTML tags from description
        strip_html_tags(&self.finding.description)
    }

    fn get_scan_id(&self) -> String {
        self.scan_id.clone()
    }

    fn get_project_name(&self) -> String {
        self.project_name.clone()
    }

    fn get_finding_category_id(&self) -> Option<u32> {
        Some(self.finding.finding_details.finding_category.id)
    }

    fn get_finding_category_name(&self) -> Option<String> {
        Some(self.finding.finding_details.finding_category.name.clone())
    }

    fn get_exploitability(&self) -> Option<u32> {
        Some(self.finding.finding_details.exploitability as u32)
    }
}

/// Strip HTML tags from text (simple implementation)
fn strip_html_tags(html: &str) -> String {
    // Simple regex-free HTML tag removal
    let mut result = String::new();
    let mut inside_tag = false;

    for ch in html.chars() {
        match ch {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if !inside_tag => result.push(ch),
            _ => {} // Skip characters inside tags
        }
    }

    result
}

/// Pipeline scan mapper implementation
pub struct PipelineScanMapper {
    config: MappingConfig,
}

impl PipelineScanMapper {
    pub fn new(config: MappingConfig) -> Self {
        Self { config }
    }
}

impl GitLabFieldMapper for PipelineScanMapper {
    fn map_vulnerability_name(&self, data: &dyn ScanResultData) -> String {
        data.get_issue_type()
    }

    fn map_description(&self, data: &dyn ScanResultData) -> String {
        format!(
            "Veracode Pipeline Scan identified a {} vulnerability in {}.\n\n\
            Issue Type: {}\n\
            Severity: {} ({})\n\
            File: {}\n\
            Line: {}\n\
            Function: {}\n\
            Scan ID: {}\n\
            Project: {}",
            data.get_issue_type(),
            data.get_file_path(),
            data.get_issue_type(),
            severity_to_string(data.get_severity()),
            data.get_severity(),
            data.get_file_path(),
            data.get_file_line(),
            data.get_function_name().as_deref().unwrap_or("N/A"),
            data.get_scan_id(),
            data.get_project_name()
        )
    }

    fn map_location(&self, data: &dyn ScanResultData, _url_filter: &UrlFilter) -> GitLabLocation {
        GitLabLocation {
            file: Some(data.get_file_path()),
            start_line: Some(data.get_file_line()),
            end_line: Some(data.get_file_line()),
            class: None,
            method: data.get_function_name(),
        }
    }

    fn map_identifiers(
        &self,
        data: &dyn ScanResultData,
        url_filter: &UrlFilter,
    ) -> Vec<GitLabIdentifier> {
        let mut identifiers = Vec::new();

        // Add Veracode identifier
        if self
            .config
            .identifier_types
            .contains(&"veracode".to_string())
        {
            let veracode_value = format!(
                "{}:{}:{}",
                data.get_finding_category_id().unwrap_or(0),
                data.get_file_path(),
                data.get_file_line()
            );
            identifiers.push(GitLabIdentifier {
                identifier_type: "veracode".to_string(),
                name: data
                    .get_finding_category_name()
                    .unwrap_or("Unknown Category".to_string()),
                value: veracode_value,
                url: None,
            });
        }

        // Add CWE identifier with proper URL filtering
        if self.config.identifier_types.contains(&"cwe".to_string()) {
            let cwe_id = data.get_cwe_id();
            if !cwe_id.is_empty() && cwe_id != "0" {
                // Try filtering first, fallback to direct CWE URL generation
                let url = url_filter
                    .filter_and_replace_url(
                        &format!("https://api.veracode.com/appsec/v1/cwes/{cwe_id}"),
                        Some(&cwe_id),
                    )
                    .or_else(|| UrlFilter::generate_cwe_url(&cwe_id));

                identifiers.push(GitLabIdentifier {
                    identifier_type: "cwe".to_string(),
                    name: format!("CWE-{cwe_id}"),
                    value: cwe_id.clone(),
                    url,
                });
            }
        }

        identifiers
    }

    fn map_severity(&self, data: &dyn ScanResultData) -> GitLabSeverity {
        convert_severity(data.get_severity())
    }

    fn map_links(
        &self,
        data: &dyn ScanResultData,
        _url_filter: &UrlFilter,
    ) -> Option<Vec<GitLabLink>> {
        if !self.config.include_links {
            return None;
        }

        let mut links = Vec::new();
        let cwe_id = data.get_cwe_id();

        if !cwe_id.is_empty() && cwe_id != "0" {
            links.push(GitLabLink {
                name: format!("CWE-{cwe_id} Details"),
                url: format!("https://cwe.mitre.org/data/definitions/{cwe_id}.html"),
            });
        }

        if links.is_empty() { None } else { Some(links) }
    }

    fn map_tracking(
        &self,
        data: &dyn ScanResultData,
        _url_filter: &UrlFilter,
    ) -> Option<GitLabTracking> {
        if !self.config.include_tracking {
            return None;
        }

        Some(GitLabTracking {
            tracking_type: "source".to_string(),
            items: vec![GitLabTrackingItem {
                file: data.get_file_path(),
                line_start: data.get_file_line(),
                line_end: data.get_file_line(),
                signatures: vec![GitLabSignature {
                    algorithm: "scope_offset".to_string(),
                    value: format!(
                        "{}|{}[0]:1",
                        data.get_file_path(),
                        data.get_function_name().as_deref().unwrap_or("unknown")
                    ),
                }],
            }],
        })
    }

    fn map_solution(&self, data: &dyn ScanResultData) -> Option<String> {
        if !self.config.include_solutions {
            return None;
        }

        Some(format!(
            "Review and remediate this {} vulnerability found in {}. \
            Consider consulting Veracode documentation for specific remediation guidance for this issue type.",
            data.get_issue_type(),
            data.get_file_path()
        ))
    }

    fn map_details(
        &self,
        data: &dyn ScanResultData,
    ) -> Option<crate::gitlab_report::GitLabDetails> {
        let mut details = std::collections::HashMap::new();

        // Add exploitability if available
        if let Some(exploitability) = data.get_exploitability() {
            details.insert(
                "exploitability".to_string(),
                serde_json::Value::Number(exploitability.into()),
            );
            details.insert(
                "exploitability_text".to_string(),
                serde_json::Value::String(exploitability_to_string(exploitability).to_string()),
            );
        }

        // Add Veracode-specific metadata
        details.insert(
            "veracode_issue_id".to_string(),
            serde_json::Value::Number(data.get_issue_id().into()),
        );
        details.insert(
            "scan_id".to_string(),
            serde_json::Value::String(data.get_scan_id()),
        );

        if details.is_empty() {
            None
        } else {
            Some(crate::gitlab_report::GitLabDetails { items: details })
        }
    }
}

/// Policy/Sandbox scan mapper implementation
pub struct PolicyScanMapper {
    config: MappingConfig,
}

impl PolicyScanMapper {
    pub fn new(config: MappingConfig) -> Self {
        Self { config }
    }
}

impl GitLabFieldMapper for PolicyScanMapper {
    fn map_vulnerability_name(&self, data: &dyn ScanResultData) -> String {
        data.get_issue_type()
    }

    fn map_description(&self, data: &dyn ScanResultData) -> String {
        let base_description = data.get_description();

        format!(
            "{}\n\n\
            Issue Type: {}\n\
            Severity: {} ({})\n\
            File: {}\n\
            Line: {}\n\
            Function: {}\n\
            CWE: {}\n\
            Scan ID: {}\n\
            Project: {}",
            base_description,
            data.get_issue_type(),
            severity_to_string(data.get_severity()),
            data.get_severity(),
            data.get_file_path(),
            data.get_file_line(),
            data.get_function_name().as_deref().unwrap_or("N/A"),
            data.get_cwe_name().as_deref().unwrap_or(&data.get_cwe_id()),
            data.get_scan_id(),
            data.get_project_name()
        )
    }

    fn map_location(&self, data: &dyn ScanResultData, _url_filter: &UrlFilter) -> GitLabLocation {
        GitLabLocation {
            file: Some(data.get_file_path()),
            start_line: Some(data.get_file_line()),
            end_line: Some(data.get_file_line()),
            class: None,
            method: data.get_function_name(),
        }
    }

    fn map_identifiers(
        &self,
        data: &dyn ScanResultData,
        url_filter: &UrlFilter,
    ) -> Vec<GitLabIdentifier> {
        let mut identifiers = Vec::new();

        // Add Veracode identifier
        if self
            .config
            .identifier_types
            .contains(&"veracode".to_string())
        {
            let veracode_value = format!(
                "{}:{}:{}",
                data.get_finding_category_id().unwrap_or(0),
                data.get_file_path(),
                data.get_file_line()
            );
            identifiers.push(GitLabIdentifier {
                identifier_type: "veracode".to_string(),
                name: data
                    .get_finding_category_name()
                    .unwrap_or("Unknown Category".to_string()),
                value: veracode_value,
                url: None,
            });
        }

        // Add CWE identifier with proper URL filtering
        if self.config.identifier_types.contains(&"cwe".to_string()) {
            let cwe_id = data.get_cwe_id();
            if !cwe_id.is_empty() && cwe_id != "0" {
                // Try filtering first, fallback to direct CWE URL generation
                let url = url_filter
                    .filter_and_replace_url(
                        &format!("https://api.veracode.com/appsec/v1/cwes/{cwe_id}"),
                        Some(&cwe_id),
                    )
                    .or_else(|| UrlFilter::generate_cwe_url(&cwe_id));

                identifiers.push(GitLabIdentifier {
                    identifier_type: "cwe".to_string(),
                    name: format!("CWE-{cwe_id}"),
                    value: cwe_id.clone(),
                    url,
                });
            }
        }

        identifiers
    }

    fn map_severity(&self, data: &dyn ScanResultData) -> GitLabSeverity {
        convert_severity(data.get_severity())
    }

    fn map_links(
        &self,
        data: &dyn ScanResultData,
        url_filter: &UrlFilter,
    ) -> Option<Vec<GitLabLink>> {
        if !self.config.include_links {
            return None;
        }

        let mut links = Vec::new();
        let cwe_id = data.get_cwe_id();

        if !cwe_id.is_empty() && cwe_id != "0" {
            // Use url_filter to generate proper URLs instead of hardcoding
            if let Some(cwe_url) = url_filter
                .filter_and_replace_url(
                    &format!("https://api.veracode.com/appsec/v1/cwes/{cwe_id}"),
                    Some(&cwe_id),
                )
                .or_else(|| UrlFilter::generate_cwe_url(&cwe_id))
            {
                links.push(GitLabLink {
                    name: format!("CWE-{cwe_id} Details"),
                    url: cwe_url,
                });
            }
        }

        if links.is_empty() { None } else { Some(links) }
    }

    fn map_tracking(
        &self,
        data: &dyn ScanResultData,
        _url_filter: &UrlFilter,
    ) -> Option<GitLabTracking> {
        if !self.config.include_tracking {
            return None;
        }

        Some(GitLabTracking {
            tracking_type: "source".to_string(),
            items: vec![GitLabTrackingItem {
                file: data.get_file_path(),
                line_start: data.get_file_line(),
                line_end: data.get_file_line(),
                signatures: vec![GitLabSignature {
                    algorithm: "scope_offset".to_string(),
                    value: format!(
                        "{}|{}[0]:1",
                        data.get_file_path(),
                        data.get_function_name().as_deref().unwrap_or("unknown")
                    ),
                }],
            }],
        })
    }

    fn map_solution(&self, data: &dyn ScanResultData) -> Option<String> {
        if !self.config.include_solutions {
            return None;
        }

        Some(format!(
            "Review and remediate this {} vulnerability found in {}. \
            Consider consulting Veracode documentation for specific remediation guidance for this issue type.",
            data.get_issue_type(),
            data.get_file_path()
        ))
    }

    fn map_details(
        &self,
        data: &dyn ScanResultData,
    ) -> Option<crate::gitlab_report::GitLabDetails> {
        let mut details = std::collections::HashMap::new();

        // Add exploitability if available
        if let Some(exploitability) = data.get_exploitability() {
            details.insert(
                "exploitability".to_string(),
                serde_json::Value::Number(exploitability.into()),
            );
            details.insert(
                "exploitability_text".to_string(),
                serde_json::Value::String(exploitability_to_string(exploitability).to_string()),
            );
        }

        // Add Veracode-specific metadata
        details.insert(
            "veracode_issue_id".to_string(),
            serde_json::Value::Number(data.get_issue_id().into()),
        );
        details.insert(
            "scan_id".to_string(),
            serde_json::Value::String(data.get_scan_id()),
        );

        // Add finding category information
        if let Some(category_id) = data.get_finding_category_id() {
            details.insert(
                "finding_category_id".to_string(),
                serde_json::Value::Number(category_id.into()),
            );
        }
        if let Some(category_name) = data.get_finding_category_name() {
            details.insert(
                "finding_category_name".to_string(),
                serde_json::Value::String(category_name),
            );
        }

        if details.is_empty() {
            None
        } else {
            Some(crate::gitlab_report::GitLabDetails { items: details })
        }
    }
}

/// Convert Veracode severity to GitLab severity
/// Based on Veracode documentation: https://docs.veracode.com/r/review_severity_exploitability
/// 0: Informational, 1: Very Low, 2: Low, 3: Medium, 4: High, 5: Very High (Critical)
fn convert_severity(veracode_severity: u32) -> GitLabSeverity {
    match veracode_severity {
        5 => GitLabSeverity::Critical, // Very High -> Critical
        4 => GitLabSeverity::High,     // High -> High
        3 => GitLabSeverity::Medium,   // Medium -> Medium
        2 => GitLabSeverity::Low,      // Low -> Low
        1 => GitLabSeverity::Low,      // Very Low -> Low (GitLab doesn't have "Very Low")
        0 => GitLabSeverity::Info,     // Informational -> Info
        _ => GitLabSeverity::Unknown,
    }
}

/// Convert severity number to string
/// Based on Veracode documentation: https://docs.veracode.com/r/review_severity_exploitability
fn severity_to_string(severity: u32) -> &'static str {
    match severity {
        5 => "Very High",     // Critical weakness
        4 => "High",          // Serious weakness
        3 => "Medium",        // Moderate weakness
        2 => "Low",           // Low weakness
        1 => "Very Low",      // Very low weakness
        0 => "Informational", // No impact on security
        _ => "Unknown",
    }
}

/// Convert exploitability number to string
/// Based on Veracode documentation: https://docs.veracode.com/r/review_severity_exploitability
fn exploitability_to_string(exploitability: u32) -> &'static str {
    match exploitability {
        4 => "Very High", // Very easily exploitable
        3 => "High",      // Easily exploitable
        2 => "Medium",    // Moderately difficult to exploit
        1 => "Low",       // Difficult to exploit
        0 => "Very Low",  // Very difficult to exploit
        _ => "Unknown",
    }
}

/// Unified GitLab mapper that handles all scan types
pub struct UnifiedGitLabMapper {
    pipeline_mapper: PipelineScanMapper,
    policy_mapper: PolicyScanMapper,
    url_filter: UrlFilter,
    config: MappingConfig,
}

impl UnifiedGitLabMapper {
    /// Create a new unified mapper with the provided configuration
    pub fn new(config: MappingConfig) -> Self {
        let pipeline_mapper = PipelineScanMapper::new(config.clone());
        let policy_mapper = PolicyScanMapper::new(config.clone());
        let url_filter = UrlFilter::new(config.clone());

        Self {
            pipeline_mapper,
            policy_mapper,
            url_filter,
            config,
        }
    }

    /// Map pipeline scan findings to GitLab vulnerabilities
    pub fn map_pipeline_findings(
        &self,
        findings: &[FindingWithSource],
    ) -> Result<Vec<GitLabVulnerability>, Box<dyn std::error::Error>> {
        let mut vulnerabilities = Vec::with_capacity(findings.len());

        for finding in findings {
            let vulnerability = self.create_gitlab_vulnerability(finding, &self.pipeline_mapper)?;
            vulnerabilities.push(vulnerability);
        }

        Ok(vulnerabilities)
    }

    /// Map policy/sandbox scan findings to GitLab vulnerabilities
    pub fn map_policy_findings(
        &self,
        rest_findings: &[RestFinding],
        scan_id: &str,
        project_name: &str,
    ) -> Result<Vec<GitLabVulnerability>, Box<dyn std::error::Error>> {
        let mut vulnerabilities = Vec::with_capacity(rest_findings.len());

        for rest_finding in rest_findings {
            let wrapper = RestFindingWrapper {
                finding: rest_finding.clone(),
                scan_id: scan_id.to_string(),
                project_name: project_name.to_string(),
            };
            let vulnerability = self.create_gitlab_vulnerability(&wrapper, &self.policy_mapper)?;
            vulnerabilities.push(vulnerability);
        }

        Ok(vulnerabilities)
    }

    /// Auto-detect scan type and map accordingly
    pub fn map_scan_data(
        &self,
        scan_data: &serde_json::Value,
    ) -> Result<Vec<GitLabVulnerability>, Box<dyn std::error::Error>> {
        let scan_type = ScanTypeDetector::detect(scan_data);

        if !ScanTypeDetector::validate_structure(scan_data, &scan_type) {
            return Err("Invalid data structure for detected scan type".into());
        }

        match scan_type {
            ScanType::Pipeline => self.map_pipeline_scan_data(),
            ScanType::Policy | ScanType::Sandbox => self.map_policy_scan_data(scan_data),
        }
    }

    /// Map pipeline scan JSON data
    fn map_pipeline_scan_data(
        &self,
    ) -> Result<Vec<GitLabVulnerability>, Box<dyn std::error::Error>> {
        // This would require deserializing the JSON into pipeline structures
        // For now, we'll return an error suggesting the typed approach
        Err("Use map_pipeline_findings() with typed FindingWithSource structures for better type safety".into())
    }

    /// Map policy/sandbox scan JSON data
    fn map_policy_scan_data(
        &self,
        data: &serde_json::Value,
    ) -> Result<Vec<GitLabVulnerability>, Box<dyn std::error::Error>> {
        let findings = data
            .get("_embedded")
            .and_then(|e| e.get("findings"))
            .and_then(|f| f.as_array())
            .ok_or("Invalid policy/sandbox scan data structure")?;

        let mut rest_findings = Vec::new();
        for finding_json in findings {
            let rest_finding: RestFinding = serde_json::from_value(finding_json.clone())?;
            rest_findings.push(rest_finding);
        }

        // Extract scan metadata
        let scan_id = "unknown".to_string(); // Would need to be extracted from context
        let project_name = "Unknown Project".to_string(); // Would need to be extracted from context

        self.map_policy_findings(&rest_findings, &scan_id, &project_name)
    }

    /// Create a GitLab vulnerability from scan result data
    fn create_gitlab_vulnerability<T: ScanResultData>(
        &self,
        data: &T,
        mapper: &dyn GitLabFieldMapper,
    ) -> Result<GitLabVulnerability, Box<dyn std::error::Error>> {
        let vulnerability_id = Uuid::new_v4().to_string();

        Ok(GitLabVulnerability {
            id: vulnerability_id,
            identifiers: mapper.map_identifiers(data, &self.url_filter),
            location: mapper.map_location(data, &self.url_filter),
            name: Some(mapper.map_vulnerability_name(data)),
            description: Some(mapper.map_description(data)),
            severity: Some(mapper.map_severity(data)),
            solution: mapper.map_solution(data),
            cvss_vectors: None,
            links: mapper.map_links(data, &self.url_filter),
            details: mapper.map_details(data),
            tracking: mapper.map_tracking(data, &self.url_filter),
            flags: None,
            raw_source_code_extract: None,
        })
    }

    /// Get the configuration being used
    pub fn get_config(&self) -> &MappingConfig {
        &self.config
    }

    /// Update configuration (creates a new mapper)
    pub fn with_config(config: MappingConfig) -> Self {
        Self::new(config)
    }
}

impl Default for UnifiedGitLabMapper {
    fn default() -> Self {
        Self::new(MappingConfig::default())
    }
}

/// Factory for creating mappers with common configurations
pub struct GitLabMapperFactory;

impl GitLabMapperFactory {
    /// Create mapper optimized for CI/CD pipelines
    pub fn for_cicd() -> UnifiedGitLabMapper {
        let config = MappingConfig {
            include_tracking: true,
            include_solutions: true,
            include_links: true,
            ..Default::default()
        };
        UnifiedGitLabMapper::new(config)
    }

    /// Create mapper optimized for security dashboards
    pub fn for_security_dashboard() -> UnifiedGitLabMapper {
        let config = MappingConfig {
            include_tracking: false, // Reduce noise in dashboard
            include_solutions: true,
            include_links: true,
            ..Default::default()
        };
        UnifiedGitLabMapper::new(config)
    }

    /// Create mapper with minimal output
    pub fn minimal() -> UnifiedGitLabMapper {
        let config = MappingConfig {
            include_tracking: false,
            include_solutions: false,
            include_links: false,
            ..Default::default()
        };
        UnifiedGitLabMapper::new(config)
    }

    /// Create mapper with custom identifier types
    pub fn with_identifiers(identifier_types: Vec<String>) -> UnifiedGitLabMapper {
        let config = MappingConfig {
            identifier_types,
            ..Default::default()
        };
        UnifiedGitLabMapper::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::ScanSource;
    use serde_json::json;
    use veracode_platform::findings::{
        CweInfo, FindingCategory, FindingDetails, FindingStatus, RestFinding,
    };
    use veracode_platform::pipeline::{Finding, FindingFiles, SourceFile};

    #[test]
    fn test_scan_type_detection_pipeline() {
        let pipeline_data = json!({
            "scan_id": "test-scan-123",
            "scan_status": "SUCCESS",
            "findings": []
        });

        assert_eq!(ScanTypeDetector::detect(&pipeline_data), ScanType::Pipeline);
        assert!(ScanTypeDetector::validate_structure(
            &pipeline_data,
            &ScanType::Pipeline
        ));
    }

    #[test]
    fn test_scan_type_detection_sandbox() {
        let sandbox_data = json!({
            "_embedded": {
                "findings": [
                    {
                        "issue_id": 1,
                        "context_type": "SANDBOX"
                    }
                ]
            }
        });

        assert_eq!(ScanTypeDetector::detect(&sandbox_data), ScanType::Sandbox);
        assert!(ScanTypeDetector::validate_structure(
            &sandbox_data,
            &ScanType::Sandbox
        ));
    }

    #[test]
    fn test_scan_type_detection_policy() {
        let policy_data = json!({
            "_embedded": {
                "findings": [
                    {
                        "issue_id": 1,
                        "context_type": "POLICY"
                    }
                ]
            }
        });

        assert_eq!(ScanTypeDetector::detect(&policy_data), ScanType::Policy);
        assert!(ScanTypeDetector::validate_structure(
            &policy_data,
            &ScanType::Policy
        ));
    }

    #[test]
    fn test_url_filtering() {
        let config = MappingConfig::default();
        let url_filter = UrlFilter::new(config);

        // Should filter out API URLs
        assert!(!url_filter.is_valid_external_url("https://api.veracode.com/appsec/v1/cwes/259"));
        assert!(
            !url_filter.is_valid_external_url("https://analysiscenter.veracode.com/auth/index.jsp")
        );

        // Should allow good URLs
        assert!(url_filter.is_valid_external_url("https://cwe.mitre.org/data/definitions/79.html"));
        assert!(url_filter.is_valid_external_url("https://help.veracode.com/r/c_all_cweid"));
    }

    #[test]
    fn test_url_replacement() {
        let config = MappingConfig::default();
        let url_filter = UrlFilter::new(config);

        // Should replace CWE API URLs
        let result = url_filter
            .filter_and_replace_url("https://api.veracode.com/appsec/v1/cwes/259", Some("259"));
        assert_eq!(
            result,
            Some("https://cwe.mitre.org/data/definitions/259.html".to_string())
        );

        // Should remove blocked URLs
        let result = url_filter
            .filter_and_replace_url("https://api.veracode.com/appsec/v1/categories/10", None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_cwe_id_extraction() {
        assert_eq!(
            extract_cwe_id_from_url("https://api.veracode.com/appsec/v1/cwes/259"),
            Some("259".to_string())
        );
        assert_eq!(
            extract_cwe_id_from_url("https://api.veracode.com/appsec/v1/cwes/79/details"),
            Some("79".to_string())
        );
        assert_eq!(extract_cwe_id_from_url("https://other.com/something"), None);
    }

    fn create_test_pipeline_finding() -> FindingWithSource {
        let finding = Finding {
            issue_id: 123,
            cwe_id: "79".to_string(),
            issue_type: "Cross-Site Scripting".to_string(),
            issue_type_id: "XSS".to_string(),
            severity: 4,
            title: "XSS vulnerability".to_string(),
            gob: "B".to_string(),
            display_text: "Cross-site scripting vulnerability detected".to_string(),
            flaw_details_link: None,
            stack_dumps: None,
            files: FindingFiles {
                source_file: SourceFile {
                    file: "src/main.js".to_string(),
                    line: 42,
                    function_name: Some("processInput".to_string()),
                    qualified_function_name: "processInput".to_string(),
                    function_prototype: "function processInput(input)".to_string(),
                    scope: "global".to_string(),
                },
            },
        };

        FindingWithSource {
            finding_id: "test-id".to_string(),
            finding,
            source_scan: ScanSource {
                scan_id: "test-scan-123".to_string(),
                project_name: "Test Project".to_string(),
                source_file: "test.jar".to_string(),
            },
        }
    }

    fn create_test_rest_finding() -> RestFinding {
        RestFinding {
            issue_id: 456,
            scan_type: "STATIC".to_string(),
            description: "<span>This variable assignment uses a hard-coded password</span>"
                .to_string(),
            count: 1,
            context_type: "POLICY".to_string(),
            context_guid: "test-guid".to_string(),
            violates_policy: true,
            finding_status: FindingStatus {
                first_found_date: "2023-01-01".to_string(),
                status: "OPEN".to_string(),
                resolution: "UNRESOLVED".to_string(),
                mitigation_review_status: "NONE".to_string(),
                new: true,
                resolution_status: "NONE".to_string(),
                last_seen_date: "2023-01-01".to_string(),
            },
            finding_details: FindingDetails {
                severity: 3,
                cwe: CweInfo {
                    id: 259,
                    name: "Use of Hard-coded Password".to_string(),
                    href: "https://api.veracode.com/appsec/v1/cwes/259".to_string(),
                },
                file_path: "com/example/VulnerableApp.java".to_string(),
                file_name: "VulnerableApp.java".to_string(),
                module: "app.jar".to_string(),
                relative_location: -1,
                finding_category: FindingCategory {
                    id: 10,
                    name: "Credentials Management".to_string(),
                    href: "https://api.veracode.com/appsec/v1/categories/10".to_string(),
                },
                procedure: "UNKNOWN".to_string(),
                exploitability: 1,
                attack_vector: "DB_PASSWORD initializer".to_string(),
                file_line_number: 15,
            },
            build_id: 987654321,
        }
    }

    #[test]
    fn test_pipeline_mapping() {
        let config = MappingConfig::default();
        let mapper = PipelineScanMapper::new(config.clone());
        let url_filter = UrlFilter::new(config);
        let finding = create_test_pipeline_finding();

        // Test vulnerability name mapping
        assert_eq!(
            mapper.map_vulnerability_name(&finding),
            "Cross-Site Scripting"
        );

        // Test severity mapping
        assert!(matches!(
            mapper.map_severity(&finding),
            GitLabSeverity::High
        ));

        // Test location mapping
        let location = mapper.map_location(&finding, &url_filter);
        assert_eq!(location.file, Some("src/main.js".to_string()));
        assert_eq!(location.start_line, Some(42));
        assert_eq!(location.method, Some("processInput".to_string()));

        // Test identifier mapping
        let identifiers = mapper.map_identifiers(&finding, &url_filter);
        assert!(identifiers.len() >= 2); // Should have veracode and cwe identifiers

        let veracode_id = identifiers
            .iter()
            .find(|id| id.identifier_type == "veracode");
        assert!(veracode_id.is_some());

        let cwe_id = identifiers.iter().find(|id| id.identifier_type == "cwe");
        assert!(cwe_id.is_some());
        assert_eq!(cwe_id.unwrap().value, "79");

        // Test links mapping
        let links = mapper.map_links(&finding, &url_filter);
        assert!(links.is_some());
        let links = links.unwrap();
        assert!(!links.is_empty());
        assert!(links[0].url.contains("cwe.mitre.org"));

        // Test tracking mapping
        let tracking = mapper.map_tracking(&finding, &url_filter);
        assert!(tracking.is_some());
    }

    #[test]
    fn test_policy_mapping() {
        let config = MappingConfig::default();
        let mapper = PolicyScanMapper::new(config.clone());
        let url_filter = UrlFilter::new(config);
        let rest_finding = create_test_rest_finding();
        let wrapper = RestFindingWrapper {
            finding: rest_finding,
            scan_id: "test-scan-456".to_string(),
            project_name: "Policy Test Project".to_string(),
        };

        // Test vulnerability name mapping
        assert_eq!(
            mapper.map_vulnerability_name(&wrapper),
            "Credentials Management"
        );

        // Test severity mapping
        assert!(matches!(
            mapper.map_severity(&wrapper),
            GitLabSeverity::Medium
        ));

        // Test location mapping
        let location = mapper.map_location(&wrapper, &url_filter);
        assert_eq!(
            location.file,
            Some("com/example/VulnerableApp.java".to_string())
        );
        assert_eq!(location.start_line, Some(15));

        // Test description includes HTML cleanup
        let description = mapper.map_description(&wrapper);
        assert!(!description.contains("<span>"));
        assert!(description.contains("hard-coded password"));

        // Test identifiers include CWE
        let identifiers = mapper.map_identifiers(&wrapper, &url_filter);
        let cwe_id = identifiers.iter().find(|id| id.identifier_type == "cwe");
        assert!(cwe_id.is_some());
        assert_eq!(cwe_id.unwrap().value, "259");
    }

    #[test]
    fn test_unified_mapper() {
        let mapper = UnifiedGitLabMapper::default();

        // Test pipeline mapping
        let pipeline_findings = vec![create_test_pipeline_finding()];
        let vulnerabilities = mapper.map_pipeline_findings(&pipeline_findings).unwrap();
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(
            vulnerabilities[0].name,
            Some("Cross-Site Scripting".to_string())
        );

        // Test policy mapping
        let rest_findings = vec![create_test_rest_finding()];
        let vulnerabilities = mapper
            .map_policy_findings(&rest_findings, "scan-123", "Test App")
            .unwrap();
        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(
            vulnerabilities[0].name,
            Some("Credentials Management".to_string())
        );
    }

    #[test]
    fn test_factory_configurations() {
        // Test CI/CD configuration
        let cicd_mapper = GitLabMapperFactory::for_cicd();
        assert!(cicd_mapper.get_config().include_tracking);
        assert!(cicd_mapper.get_config().include_solutions);
        assert!(cicd_mapper.get_config().include_links);

        // Test security dashboard configuration
        let dashboard_mapper = GitLabMapperFactory::for_security_dashboard();
        assert!(!dashboard_mapper.get_config().include_tracking);
        assert!(dashboard_mapper.get_config().include_solutions);
        assert!(dashboard_mapper.get_config().include_links);

        // Test minimal configuration
        let minimal_mapper = GitLabMapperFactory::minimal();
        assert!(!minimal_mapper.get_config().include_tracking);
        assert!(!minimal_mapper.get_config().include_solutions);
        assert!(!minimal_mapper.get_config().include_links);

        // Test custom identifiers
        let custom_mapper = GitLabMapperFactory::with_identifiers(vec!["cwe".to_string()]);
        assert_eq!(custom_mapper.get_config().identifier_types.len(), 1);
        assert_eq!(custom_mapper.get_config().identifier_types[0], "cwe");
    }

    #[test]
    fn test_html_stripping() {
        let html = "<span>This is <b>bold</b> text</span>";
        let stripped = strip_html_tags(html);
        assert_eq!(stripped, "This is bold text");

        let complex_html = "<span>Start</span><a href=\"link\">Link</a><br/>End";
        let stripped = strip_html_tags(complex_html);
        assert_eq!(stripped, "StartLinkEnd");
    }

    #[test]
    fn test_severity_conversion() {
        // Test based on Veracode documentation: https://docs.veracode.com/r/review_severity_exploitability
        assert!(matches!(convert_severity(5), GitLabSeverity::Critical)); // Very High -> Critical
        assert!(matches!(convert_severity(4), GitLabSeverity::High)); // High -> High
        assert!(matches!(convert_severity(3), GitLabSeverity::Medium)); // Medium -> Medium
        assert!(matches!(convert_severity(2), GitLabSeverity::Low)); // Low -> Low
        assert!(matches!(convert_severity(1), GitLabSeverity::Low)); // Very Low -> Low
        assert!(matches!(convert_severity(0), GitLabSeverity::Info)); // Informational -> Info
        assert!(matches!(convert_severity(999), GitLabSeverity::Unknown));
    }

    #[test]
    fn test_url_filtering_comprehensive() {
        let config = MappingConfig::default();
        let url_filter = UrlFilter::new(config);

        // Test CWE URL replacement
        let cwe_api_url = "https://api.veracode.com/appsec/v1/cwes/79";
        let filtered = url_filter.filter_and_replace_url(cwe_api_url, Some("79"));
        assert_eq!(
            filtered,
            Some("https://cwe.mitre.org/data/definitions/79.html".to_string())
        );

        // Test blocked URL removal
        let category_url = "https://api.veracode.com/appsec/v1/categories/10";
        let filtered = url_filter.filter_and_replace_url(category_url, None);
        assert_eq!(filtered, None);

        // Test analysis center URL blocking
        let analysis_url = "https://analysiscenter.veracode.com/auth/index.jsp";
        let filtered = url_filter.filter_and_replace_url(analysis_url, None);
        assert_eq!(filtered, None);

        // Test good URL pass-through
        let good_url = "https://cwe.mitre.org/data/definitions/79.html";
        let filtered = url_filter.filter_and_replace_url(good_url, None);
        assert_eq!(filtered, Some(good_url.to_string()));
    }

    #[test]
    fn test_scan_type_detection_comprehensive() {
        // Test pipeline detection
        let pipeline_data = json!({
            "scan_id": "test",
            "findings": [],
            "scan_status": "SUCCESS"
        });
        assert_eq!(ScanTypeDetector::detect(&pipeline_data), ScanType::Pipeline);

        // Test sandbox detection
        let sandbox_data = json!({
            "_embedded": {
                "findings": [{"context_type": "SANDBOX"}]
            }
        });
        assert_eq!(ScanTypeDetector::detect(&sandbox_data), ScanType::Sandbox);

        // Test policy detection
        let policy_data = json!({
            "_embedded": {
                "findings": [{"context_type": "POLICY"}]
            }
        });
        assert_eq!(ScanTypeDetector::detect(&policy_data), ScanType::Policy);

        // Test default fallback
        let unknown_data = json!({
            "some_field": "value"
        });
        assert_eq!(ScanTypeDetector::detect(&unknown_data), ScanType::Pipeline);
    }

    #[test]
    fn test_mapping_config_serialization() {
        let config = MappingConfig::default();

        // Test serialization
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(serialized.contains("identifier_types"));
        assert!(serialized.contains("include_tracking"));

        // Test deserialization
        let deserialized: MappingConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config.identifier_types, deserialized.identifier_types);
        assert_eq!(config.include_tracking, deserialized.include_tracking);
    }

    #[test]
    fn test_rest_finding_wrapper() {
        let rest_finding = create_test_rest_finding();
        let wrapper = RestFindingWrapper {
            finding: rest_finding.clone(),
            scan_id: "test-scan".to_string(),
            project_name: "Test Project".to_string(),
        };

        assert_eq!(wrapper.get_issue_id(), 456);
        assert_eq!(wrapper.get_cwe_id(), "259");
        assert_eq!(
            wrapper.get_cwe_name(),
            Some("Use of Hard-coded Password".to_string())
        );
        assert_eq!(wrapper.get_severity(), 3);
        assert_eq!(wrapper.get_file_path(), "com/example/VulnerableApp.java");
        assert_eq!(wrapper.get_file_line(), 15);
        assert_eq!(wrapper.get_function_name(), None); // Should be None for "UNKNOWN"
        assert_eq!(wrapper.get_issue_type(), "Credentials Management");
        assert_eq!(wrapper.get_scan_id(), "test-scan");
        assert_eq!(wrapper.get_project_name(), "Test Project");

        // Test HTML stripping in description
        let description = wrapper.get_description();
        assert!(!description.contains("<span>"));
        assert!(description.contains("hard-coded password"));
    }

    #[test]
    fn test_identifier_filtering() {
        let config = MappingConfig {
            identifier_types: vec!["cwe".to_string()], // Only CWE identifiers
            ..Default::default()
        };

        let mapper = PipelineScanMapper::new(config.clone());
        let url_filter = UrlFilter::new(config);
        let finding = create_test_pipeline_finding();

        let identifiers = mapper.map_identifiers(&finding, &url_filter);

        // Should only have CWE identifier, not Veracode identifier
        assert_eq!(identifiers.len(), 1);
        assert_eq!(identifiers[0].identifier_type, "cwe");
    }

    #[test]
    fn test_exploitability_in_details() {
        let config = MappingConfig::default();
        let mapper = PolicyScanMapper::new(config);
        let rest_finding = create_test_rest_finding();
        let wrapper = RestFindingWrapper {
            finding: rest_finding.clone(),
            scan_id: "test-scan".to_string(),
            project_name: "Test Project".to_string(),
        };

        let details = mapper.map_details(&wrapper);
        assert!(details.is_some());

        let details = details.unwrap();
        assert!(details.items.contains_key("exploitability"));
        assert!(details.items.contains_key("exploitability_text"));
        assert!(details.items.contains_key("veracode_issue_id"));
        assert!(details.items.contains_key("finding_category_id"));
        assert!(details.items.contains_key("finding_category_name"));

        // Check exploitability value
        let exploitability = details.items.get("exploitability").unwrap();
        assert_eq!(exploitability.as_u64(), Some(1));

        let exploitability_text = details.items.get("exploitability_text").unwrap();
        assert_eq!(exploitability_text.as_str(), Some("Low"));
    }

    #[test]
    fn test_pipeline_details_always_included() {
        let config = MappingConfig::default();
        let mapper = PipelineScanMapper::new(config);
        let finding = create_test_pipeline_finding();

        let details = mapper.map_details(&finding);
        assert!(
            details.is_some(),
            "Pipeline details should always be included"
        );

        let details = details.unwrap();
        assert!(details.items.contains_key("veracode_issue_id"));
        assert!(details.items.contains_key("scan_id"));

        // Pipeline scans don't have exploitability, but should still have details
        assert!(!details.items.contains_key("exploitability"));

        // Check that issue ID is correct
        let issue_id = details.items.get("veracode_issue_id").unwrap();
        assert_eq!(issue_id.as_u64(), Some(123));
    }

    #[test]
    fn test_empty_findings_handling() {
        let mapper = UnifiedGitLabMapper::default();

        // Test empty pipeline findings
        let empty_pipeline: Vec<FindingWithSource> = vec![];
        let vulnerabilities = mapper.map_pipeline_findings(&empty_pipeline).unwrap();
        assert_eq!(vulnerabilities.len(), 0);

        // Test empty policy findings
        let empty_policy: Vec<RestFinding> = vec![];
        let vulnerabilities = mapper
            .map_policy_findings(&empty_policy, "scan", "project")
            .unwrap();
        assert_eq!(vulnerabilities.len(), 0);
    }
}

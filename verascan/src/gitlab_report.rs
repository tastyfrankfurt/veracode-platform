//! GitLab SAST report export functionality
//!
//! This module provides functionality to export Veracode pipeline scan results
//! in GitLab SAST report format, compatible with GitLab security dashboards.

use crate::findings::AggregatedFindings;
use crate::gitlab_common::resolve_file_path;
use crate::gitlab_mapping::UnifiedGitLabMapper;
use crate::path_resolver::{PathResolver, PathResolverConfig};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// GitLab SAST report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSASTReport {
    pub version: String,
    pub vulnerabilities: Vec<GitLabVulnerability>,
    pub scan: GitLabScan,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
}

/// GitLab vulnerability object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabVulnerability {
    pub id: String,
    pub identifiers: Vec<GitLabIdentifier>,
    pub location: GitLabLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<GitLabSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_vectors: Option<Vec<GitLabCvssVector>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<GitLabLink>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<GitLabDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking: Option<GitLabTracking>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<GitLabFlag>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_source_code_extract: Option<String>,
}

/// GitLab severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GitLabSeverity {
    Info,
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

/// GitLab identifier for vulnerability references
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabIdentifier {
    #[serde(rename = "type")]
    pub identifier_type: String,
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// GitLab location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// GitLab link to external documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabLink {
    pub name: String,
    pub url: String,
}

/// GitLab tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabTracking {
    #[serde(rename = "type")]
    pub tracking_type: String,
    pub items: Vec<GitLabTrackingItem>,
}

/// GitLab tracking item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabTrackingItem {
    pub file: String,
    pub line_start: u32,
    pub line_end: u32,
    pub signatures: Vec<GitLabSignature>,
}

/// GitLab tracking signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSignature {
    pub algorithm: String,
    pub value: String,
}

/// GitLab scan metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabScan {
    pub analyzer: GitLabAnalyzer,
    pub scanner: GitLabScanner,
    #[serde(rename = "type")]
    pub scan_type: String,
    pub start_time: String,
    pub end_time: String,
    pub status: GitLabScanStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<GitLabMessage>>,
}

/// GitLab analyzer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabAnalyzer {
    pub id: String,
    pub name: String,
    pub version: String,
    pub vendor: GitLabVendor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// GitLab scanner information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabScanner {
    pub id: String,
    pub name: String,
    pub version: String,
    pub vendor: GitLabVendor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// GitLab vendor information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabVendor {
    pub name: String,
}

/// GitLab scan status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GitLabScanStatus {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "failure")]
    Failure,
}

/// GitLab scan message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabMessage {
    pub level: GitLabMessageLevel,
    pub value: String,
}

/// GitLab message levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GitLabMessageLevel {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "fatal")]
    Fatal,
}

/// GitLab CVSS vector information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabCvssVector {
    pub vendor: String,
    pub vector: String,
}

/// GitLab vulnerability details (named list structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabDetails {
    #[serde(flatten)]
    pub items: std::collections::HashMap<String, serde_json::Value>,
}

/// GitLab vulnerability flag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabFlag {
    #[serde(rename = "type")]
    pub flag_type: String,
    pub origin: String,
    pub description: String,
}

/// GitLab export configuration
#[derive(Debug, Clone)]
pub struct GitLabExportConfig {
    pub include_tracking: bool,
    pub include_links: bool,
    pub include_solutions: bool,
    pub analyzer_version: String,
    pub scanner_version: String,
    pub project_dir: Option<PathBuf>,
    pub path_resolver: Option<PathResolver>,
}

impl Default for GitLabExportConfig {
    fn default() -> Self {
        Self {
            include_tracking: true,
            include_links: true,
            include_solutions: true,
            analyzer_version: "1.0.0".to_string(),
            scanner_version: "1.0.0".to_string(),
            project_dir: None,
            path_resolver: None,
        }
    }
}

/// GitLab exporter for converting Veracode findings to GitLab SAST format
pub struct GitLabExporter {
    config: GitLabExportConfig,
    debug: bool,
}

impl GitLabExporter {
    /// Create a new GitLab exporter
    pub fn new(config: GitLabExportConfig, debug: bool) -> Self {
        Self { config, debug }
    }

    /// Set the project directory for resolving file paths
    pub fn with_project_dir<P: AsRef<Path>>(mut self, project_dir: P) -> Self {
        let path = project_dir.as_ref();
        let absolute_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            // Convert relative path to absolute path
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
                .canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
        };

        self.config.project_dir = Some(absolute_path.clone());

        // Create path resolver when project dir is set
        let resolver_config = PathResolverConfig::new(&absolute_path, self.debug);
        self.config.path_resolver = Some(PathResolver::new(resolver_config));

        self
    }

    /// Export aggregated findings to GitLab SAST format
    pub fn export_to_gitlab_sast(
        &self,
        aggregated: &AggregatedFindings,
        output_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.debug {
            println!(
                "💾 Exporting aggregated findings to GitLab SAST format: {}",
                output_path.display()
            );
        }

        let gitlab_report = self.convert_to_gitlab_format(aggregated)?;
        let json_string = serde_json::to_string_pretty(&gitlab_report)?;
        std::fs::write(output_path, json_string)?;

        println!(
            "✅ GitLab SAST report exported to: {}",
            output_path.display()
        );
        Ok(())
    }

    /// Convert aggregated findings to GitLab SAST report format
    fn convert_to_gitlab_format(
        &self,
        aggregated: &AggregatedFindings,
    ) -> Result<GitLabSASTReport, Box<dyn std::error::Error>> {
        let now = Utc::now();
        let start_time = now.format("%Y-%m-%dT%H:%M:%S").to_string();
        let end_time = now.format("%Y-%m-%dT%H:%M:%S").to_string();

        let vulnerabilities = if let Some(ref rest_findings) = aggregated.original_rest_findings {
            // Use original REST findings to preserve exploitability data
            if self.debug {
                println!("🔄 Using original REST findings to preserve exploitability data");
            }
            let scan_id = aggregated
                .scan_metadata
                .first()
                .map(|m| m.scan_id.as_str())
                .unwrap_or("unknown");
            let project_name = aggregated
                .scan_metadata
                .first()
                .map(|m| m.project_name.as_str())
                .unwrap_or("Unknown Project");

            rest_findings
                .iter()
                .map(|rest_finding| {
                    self.convert_rest_finding_to_vulnerability(rest_finding, scan_id, project_name)
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            // Use converted pipeline findings
            aggregated
                .findings
                .iter()
                .map(|finding_with_source| {
                    self.convert_finding_to_vulnerability(finding_with_source)
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let report = GitLabSASTReport {
            version: "15.2.2".to_string(),
            schema: Some("https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/sast-report-format.json".to_string()),
            vulnerabilities,
            scan: GitLabScan {
                analyzer: GitLabAnalyzer {
                    id: "verascan".to_string(),
                    name: "Verascan".to_string(),
                    version: self.config.analyzer_version.clone(),
                    vendor: GitLabVendor {
                        name: "Veracode".to_string(),
                    },
                    url: Some("https://github.com/veracode/verascan".to_string()),
                },
                scanner: GitLabScanner {
                    id: "veracode-pipeline".to_string(),
                    name: "Veracode Pipeline Scan".to_string(),
                    version: self.config.scanner_version.clone(),
                    vendor: GitLabVendor {
                        name: "Veracode".to_string(),
                    },
                    url: Some("https://www.veracode.com/products/binary-static-analysis-sast".to_string()),
                },
                scan_type: "sast".to_string(),
                start_time,
                end_time,
                status: GitLabScanStatus::Success,
                messages: None,
            },
        };

        Ok(report)
    }

    /// Resolve file path using shared utility
    fn resolve_file_path(&self, file_path: &str) -> String {
        resolve_file_path(file_path, self.config.path_resolver.as_ref(), self.debug).into_owned()
    }

    /// Convert a Veracode finding to GitLab vulnerability format using the unified mapper
    fn convert_finding_to_vulnerability(
        &self,
        finding_with_source: &crate::findings::FindingWithSource,
    ) -> Result<GitLabVulnerability, Box<dyn std::error::Error>> {
        // Create a mapping configuration that matches the GitLabExportConfig
        let mapping_config = crate::gitlab_mapping::MappingConfig {
            url_replacements: std::collections::HashMap::new(),
            blocked_url_patterns: vec![
                "api.veracode.com".to_string(),
                "analysiscenter.veracode.com".to_string(),
            ],
            identifier_types: vec!["cwe".to_string(), "veracode".to_string()],
            include_tracking: self.config.include_tracking,
            include_solutions: self.config.include_solutions,
            include_links: self.config.include_links,
        };

        // Use the unified mapper for consistency
        let unified_mapper = UnifiedGitLabMapper::new(mapping_config);
        let findings_vec = vec![finding_with_source.clone()];
        let vulnerabilities = unified_mapper.map_pipeline_findings(&findings_vec)?;

        if vulnerabilities.is_empty() {
            return Err("Failed to map finding to GitLab vulnerability".into());
        }

        // Apply file path resolution to the mapped vulnerability
        let mut vulnerability = vulnerabilities.into_iter().next().unwrap();
        if let Some(ref file) = vulnerability.location.file {
            let resolved_file_path = self.resolve_file_path(file);
            vulnerability.location.file = Some(resolved_file_path.clone());

            // Update tracking file path if present
            if let Some(ref mut tracking) = vulnerability.tracking {
                for item in &mut tracking.items {
                    item.file = resolved_file_path.clone();
                }
            }

            // Update Veracode identifier to use resolved file path
            for identifier in &mut vulnerability.identifiers {
                if identifier.identifier_type == "veracode" {
                    // Extract the original components from the value
                    let parts: Vec<&str> = identifier.value.split(':').collect();
                    if parts.len() == 3 {
                        let category_id = parts[0];
                        let line_number = parts[2];
                        // Reconstruct with resolved file path
                        identifier.value =
                            format!("{category_id}:{resolved_file_path}:{line_number}");
                    }
                }
            }
        }

        Ok(vulnerability)
    }

    /// Convert REST API finding (policy/sandbox scan) to GitLab vulnerability format
    pub fn convert_rest_finding_to_vulnerability(
        &self,
        rest_finding: &veracode_platform::findings::RestFinding,
        scan_id: &str,
        project_name: &str,
    ) -> Result<GitLabVulnerability, Box<dyn std::error::Error>> {
        // Create a mapping configuration that matches the GitLabExportConfig
        let mapping_config = crate::gitlab_mapping::MappingConfig {
            url_replacements: std::collections::HashMap::new(),
            blocked_url_patterns: vec![
                "api.veracode.com".to_string(),
                "analysiscenter.veracode.com".to_string(),
            ],
            identifier_types: vec!["cwe".to_string(), "veracode".to_string()],
            include_tracking: self.config.include_tracking,
            include_solutions: self.config.include_solutions,
            include_links: self.config.include_links,
        };

        // Use the unified mapper for policy scans (preserves exploitability data)
        let unified_mapper = UnifiedGitLabMapper::new(mapping_config);
        let rest_findings_vec = vec![rest_finding.clone()];
        let vulnerabilities =
            unified_mapper.map_policy_findings(&rest_findings_vec, scan_id, project_name)?;

        if vulnerabilities.is_empty() {
            return Err("Failed to map REST finding to GitLab vulnerability".into());
        }

        // Apply file path resolution to the mapped vulnerability
        let mut vulnerability = vulnerabilities.into_iter().next().unwrap();
        if let Some(ref file) = vulnerability.location.file {
            let resolved_file_path = self.resolve_file_path(file);
            vulnerability.location.file = Some(resolved_file_path.clone());

            // Update tracking file path if present
            if let Some(ref mut tracking) = vulnerability.tracking {
                for item in &mut tracking.items {
                    item.file = resolved_file_path.clone();
                }
            }

            // Update Veracode identifier to use resolved file path
            for identifier in &mut vulnerability.identifiers {
                if identifier.identifier_type == "veracode" {
                    // Extract the original components from the value
                    let parts: Vec<&str> = identifier.value.split(':').collect();
                    if parts.len() == 3 {
                        let category_id = parts[0];
                        let line_number = parts[2];
                        // Reconstruct with resolved file path
                        identifier.value =
                            format!("{category_id}:{resolved_file_path}:{line_number}");
                    }
                }
            }
        }

        Ok(vulnerability)
    }

    // Note: convert_severity and severity_to_string methods removed as they are now
    // handled by the unified GitLab mapper system for consistency
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{FindingWithSource, ScanSource};
    use veracode_platform::pipeline::{Finding, FindingFiles, SourceFile};

    // Note: Severity conversion test removed as severity mapping is now
    // handled by the UnifiedGitLabMapper for consistency across scan types

    #[test]
    fn test_gitlab_export_config_default() {
        let config = GitLabExportConfig::default();
        assert!(config.include_tracking);
        assert!(config.include_links);
        assert!(config.include_solutions);
        assert_eq!(config.analyzer_version, "1.0.0");
        assert_eq!(config.scanner_version, "1.0.0");
    }

    #[test]
    fn test_convert_finding_to_vulnerability() {
        let exporter = GitLabExporter::new(GitLabExportConfig::default(), false);

        let finding = Finding {
            issue_id: 123,
            cwe_id: "79".to_string(),
            issue_type: "Cross-Site Scripting".to_string(),
            issue_type_id: "XSS".to_string(),
            severity: 4,
            title: "Cross-Site Scripting vulnerability".to_string(),
            gob: "B".to_string(),
            display_text: "XSS vulnerability detected".to_string(),
            flaw_details_link: Some("https://analysiscenter.veracode.com/auth/index.jsp#ViewReportsResultDetail:123:79:XSS".to_string()),
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

        let source = ScanSource {
            scan_id: "test-scan-123".to_string(),
            project_name: "Test Project".to_string(),
            source_file: "test.jar".to_string(),
        };

        let finding_with_source = FindingWithSource {
            finding_id: "test:test.jar:123:abcd1234".to_string(), // Mock finding ID for test
            finding,
            source_scan: source,
        };

        let vulnerability = exporter
            .convert_finding_to_vulnerability(&finding_with_source)
            .unwrap();

        assert_eq!(vulnerability.name, Some("Cross-Site Scripting".to_string()));
        assert!(matches!(vulnerability.severity, Some(GitLabSeverity::High)));
        assert_eq!(vulnerability.location.file, Some("src/main.js".to_string()));
        assert_eq!(vulnerability.location.start_line, Some(42));
        assert!(vulnerability.identifiers.len() >= 2); // Should have CVE and CWE identifiers
        assert!(vulnerability.tracking.is_some());
        // Check for CWE and Veracode identifiers
        assert!(
            vulnerability
                .identifiers
                .iter()
                .any(|id| id.identifier_type == "cwe")
        );
        assert!(
            vulnerability
                .identifiers
                .iter()
                .any(|id| id.identifier_type == "veracode")
        );

        // Check that details are included
        assert!(
            vulnerability.details.is_some(),
            "Details should be included in GitLab vulnerability"
        );
        let details = vulnerability.details.unwrap();
        assert!(details.items.contains_key("veracode_issue_id"));
        assert!(details.items.contains_key("scan_id"));
    }

    #[test]
    fn test_full_gitlab_report_serialization() {
        let exporter = GitLabExporter::new(GitLabExportConfig::default(), false);

        let finding = Finding {
            issue_id: 123,
            cwe_id: "79".to_string(),
            issue_type: "Cross-Site Scripting".to_string(),
            issue_type_id: "XSS".to_string(),
            severity: 4,
            title: "Cross-Site Scripting vulnerability".to_string(),
            gob: "B".to_string(),
            display_text: "XSS vulnerability detected".to_string(),
            flaw_details_link: Some("https://analysiscenter.veracode.com/auth/index.jsp#ViewReportsResultDetail:123:79:XSS".to_string()),
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

        let source = ScanSource {
            scan_id: "test-scan-123".to_string(),
            project_name: "Test Project".to_string(),
            source_file: "test.jar".to_string(),
        };

        let finding_with_source = FindingWithSource {
            finding_id: "test:test.jar:123:abcd1234".to_string(),
            finding,
            source_scan: source,
        };

        let vulnerability = exporter
            .convert_finding_to_vulnerability(&finding_with_source)
            .unwrap();

        // Serialize to JSON to verify the details are included
        let json = serde_json::to_string_pretty(&vulnerability).unwrap();
        println!("GitLab Vulnerability JSON:\n{json}");

        // Check that details are in the JSON
        assert!(json.contains("\"details\""));
        assert!(json.contains("\"veracode_issue_id\""));
        assert!(json.contains("\"scan_id\""));
    }
}

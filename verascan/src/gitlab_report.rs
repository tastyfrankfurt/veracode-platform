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

use log::{debug, info};

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
    pub schema_version: String,
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
            schema_version: "15.2.1".to_string(),
            project_dir: None,
            path_resolver: None,
        }
    }
}

/// GitLab exporter for converting Veracode findings to GitLab SAST format
pub struct GitLabExporter {
    config: GitLabExportConfig,
}

impl GitLabExporter {
    /// Create a new GitLab exporter
    #[must_use]
    pub fn new(config: GitLabExportConfig) -> Self {
        Self { config }
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
        let resolver_config = PathResolverConfig::new(&absolute_path);
        self.config.path_resolver = Some(PathResolver::new(resolver_config));

        self
    }

    /// Export aggregated findings to GitLab SAST format
    pub async fn export_to_gitlab_sast(
        &self,
        aggregated: &AggregatedFindings,
        output_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!(
            "💾 Exporting aggregated findings to GitLab SAST format: {}",
            output_path.display()
        );

        let gitlab_report = self.convert_to_gitlab_format(aggregated)?;
        let json_string = serde_json::to_string_pretty(&gitlab_report)?;
        tokio::fs::write(output_path, json_string).await?;

        info!(
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
            debug!("🔄 Using original REST findings to preserve exploitability data");
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
            version: self.config.schema_version.clone(),
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
        resolve_file_path(file_path, self.config.path_resolver.as_ref()).into_owned()
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
        let exporter = GitLabExporter::new(GitLabExportConfig::default());

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
        let exporter = GitLabExporter::new(GitLabExportConfig::default());

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
        info!("GitLab Vulnerability JSON:\n{json}");

        // Check that details are in the JSON
        assert!(json.contains("\"details\""));
        assert!(json.contains("\"veracode_issue_id\""));
        assert!(json.contains("\"scan_id\""));
    }

    // Helper function to create test data for schema validation
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn create_test_gitlab_report() -> GitLabSASTReport {
        let source = ScanSource {
            scan_id: "schema-test-scan-456".to_string(),
            project_name: "Schema Validation Test Project".to_string(),
            source_file: "test-app.jar".to_string(),
        };

        // Create multiple findings with different severities and types
        // This provides comprehensive schema validation coverage

        // Finding 1: Very High severity - SQL Injection (CWE-89)
        let finding_1 = FindingWithSource {
            finding_id: "test:test-app.jar:456:sqli".to_string(),
            finding: Finding {
                issue_id: 456,
                cwe_id: "89".to_string(),
                issue_type: "SQL Injection".to_string(),
                issue_type_id: "SQLI".to_string(),
                severity: 5,
                title: "SQL Injection vulnerability".to_string(),
                gob: "B".to_string(),
                display_text: "SQL Injection in user query".to_string(),
                flaw_details_link: Some("https://analysiscenter.veracode.com/auth/index.jsp#ViewReportsResultDetail:456:89:SQLI".to_string()),
                stack_dumps: None,
                files: FindingFiles {
                    source_file: SourceFile {
                        file: "src/database/users.js".to_string(),
                        line: 15,
                        function_name: Some("getUserById".to_string()),
                        qualified_function_name: "getUserById".to_string(),
                        function_prototype: "function getUserById(id)".to_string(),
                        scope: "UserService".to_string(),
                    },
                },
            },
            source_scan: source.clone(),
        };

        // Finding 2: High severity - Cross-Site Scripting (CWE-79)
        let finding_2 = FindingWithSource {
            finding_id: "test:test-app.jar:123:xss".to_string(),
            finding: Finding {
                issue_id: 123,
                cwe_id: "79".to_string(),
                issue_type: "Cross-Site Scripting".to_string(),
                issue_type_id: "XSS".to_string(),
                severity: 4,
                title: "XSS vulnerability".to_string(),
                gob: "B".to_string(),
                display_text: "Cross-site scripting in output".to_string(),
                flaw_details_link: None,
                stack_dumps: None,
                files: FindingFiles {
                    source_file: SourceFile {
                        file: "src/views/profile.js".to_string(),
                        line: 42,
                        function_name: Some("renderUserProfile".to_string()),
                        qualified_function_name: "renderUserProfile".to_string(),
                        function_prototype: "function renderUserProfile(data)".to_string(),
                        scope: "ProfileView".to_string(),
                    },
                },
            },
            source_scan: source.clone(),
        };

        // Finding 3: Medium severity - Use of Hard-coded Password (CWE-259)
        let finding_3 = FindingWithSource {
            finding_id: "test:test-app.jar:789:hardcoded".to_string(),
            finding: Finding {
                issue_id: 789,
                cwe_id: "259".to_string(),
                issue_type: "Use of Hard-coded Password".to_string(),
                issue_type_id: "HARDCODED".to_string(),
                severity: 3,
                title: "Hard-coded credential detected".to_string(),
                gob: "B".to_string(),
                display_text: "Hard-coded password in configuration".to_string(),
                flaw_details_link: None,
                stack_dumps: None,
                files: FindingFiles {
                    source_file: SourceFile {
                        file: "src/config/database.js".to_string(),
                        line: 8,
                        function_name: None,
                        qualified_function_name: "initialize".to_string(),
                        function_prototype: "function initialize()".to_string(),
                        scope: "global".to_string(),
                    },
                },
            },
            source_scan: source.clone(),
        };

        // Finding 4: Low severity - Information Exposure (CWE-200)
        let finding_4 = FindingWithSource {
            finding_id: "test:test-app.jar:234:info-leak".to_string(),
            finding: Finding {
                issue_id: 234,
                cwe_id: "200".to_string(),
                issue_type: "Information Exposure".to_string(),
                issue_type_id: "INFO_LEAK".to_string(),
                severity: 2,
                title: "Information exposure through error messages".to_string(),
                gob: "B".to_string(),
                display_text: "Detailed error messages exposed to users".to_string(),
                flaw_details_link: None,
                stack_dumps: None,
                files: FindingFiles {
                    source_file: SourceFile {
                        file: "src/middleware/error-handler.js".to_string(),
                        line: 25,
                        function_name: Some("handleError".to_string()),
                        qualified_function_name: "handleError".to_string(),
                        function_prototype: "function handleError(err, req, res)".to_string(),
                        scope: "ErrorHandler".to_string(),
                    },
                },
            },
            source_scan: source.clone(),
        };

        // Finding 5: Very Low severity - Missing Security Headers (CWE-693)
        let finding_5 = FindingWithSource {
            finding_id: "test:test-app.jar:567:headers".to_string(),
            finding: Finding {
                issue_id: 567,
                cwe_id: "693".to_string(),
                issue_type: "Protection Mechanism Failure".to_string(),
                issue_type_id: "SEC_HEADERS".to_string(),
                severity: 1,
                title: "Missing security headers".to_string(),
                gob: "B".to_string(),
                display_text: "HTTP security headers not configured".to_string(),
                flaw_details_link: None,
                stack_dumps: None,
                files: FindingFiles {
                    source_file: SourceFile {
                        file: "src/server.js".to_string(),
                        line: 10,
                        function_name: Some("configureMiddleware".to_string()),
                        qualified_function_name: "configureMiddleware".to_string(),
                        function_prototype: "function configureMiddleware(app)".to_string(),
                        scope: "Server".to_string(),
                    },
                },
            },
            source_scan: source.clone(),
        };

        // Finding 6: Informational - Code Quality (CWE-1071)
        let finding_6 = FindingWithSource {
            finding_id: "test:test-app.jar:891:quality".to_string(),
            finding: Finding {
                issue_id: 891,
                cwe_id: "1071".to_string(),
                issue_type: "Empty Code Block".to_string(),
                issue_type_id: "QUALITY".to_string(),
                severity: 0,
                title: "Code quality issue".to_string(),
                gob: "B".to_string(),
                display_text: "Empty catch block detected".to_string(),
                flaw_details_link: None,
                stack_dumps: None,
                files: FindingFiles {
                    source_file: SourceFile {
                        file: "src/utils/helper.js".to_string(),
                        line: 33,
                        function_name: Some("parseData".to_string()),
                        qualified_function_name: "parseData".to_string(),
                        function_prototype: "function parseData(input)".to_string(),
                        scope: "Utils".to_string(),
                    },
                },
            },
            source_scan: source.clone(),
        };

        let findings = vec![
            finding_1, finding_2, finding_3, finding_4, finding_5, finding_6,
        ];

        // Create aggregated findings structure with comprehensive stats
        let aggregated = crate::findings::AggregatedFindings {
            findings,
            scan_metadata: vec![crate::findings::ScanMetadata {
                scan_id: "schema-test-scan-456".to_string(),
                project_name: "Schema Validation Test Project".to_string(),
                scan_status: veracode_platform::pipeline::ScanStatus::Success,
                project_uri: Some("https://example.com/project".to_string()),
                source_file: "test-app.jar".to_string(),
                finding_count: 6,
            }],
            summary: veracode_platform::pipeline::FindingsSummary {
                very_high: 1,
                high: 1,
                medium: 1,
                low: 1,
                very_low: 1,
                informational: 1,
                total: 6,
            },
            stats: crate::findings::AggregationStats {
                total_scans: 1,
                total_findings: 6,
                unique_cwe_count: 6,
                unique_files_count: 6,
                top_cwe_ids: vec![
                    crate::findings::CweStatistic {
                        cwe_id: "89".to_string(),
                        count: 1,
                        percentage: 16.67,
                    },
                    crate::findings::CweStatistic {
                        cwe_id: "79".to_string(),
                        count: 1,
                        percentage: 16.67,
                    },
                    crate::findings::CweStatistic {
                        cwe_id: "259".to_string(),
                        count: 1,
                        percentage: 16.67,
                    },
                ],
                severity_distribution: {
                    let mut map = std::collections::HashMap::new();
                    map.insert("Very High".to_string(), 1);
                    map.insert("High".to_string(), 1);
                    map.insert("Medium".to_string(), 1);
                    map.insert("Low".to_string(), 1);
                    map.insert("Very Low".to_string(), 1);
                    map.insert("Informational".to_string(), 1);
                    map
                },
            },
            original_rest_findings: None,
        };

        // Convert to GitLab format
        let exporter = GitLabExporter::new(GitLabExportConfig::default());
        exporter
            .convert_to_gitlab_format(&aggregated)
            .expect("Failed to convert findings to GitLab format")
    }

    // Helper function to validate report against a specific schema version
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    async fn validate_against_schema(
        schema_version: &str,
        report: &GitLabSASTReport,
    ) -> Result<(), String> {
        // Download schema from GitLab instead of reading from local file
        let schema_url = format!(
            "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v{}/dist/sast-report-format.json?ref_type=tags&inline=false",
            schema_version
        );

        info!("📥 Downloading schema from: {}", schema_url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        let schema_content = client
            .get(&schema_url)
            .send()
            .await
            .map_err(|e| format!("Failed to download schema from {}: {}", schema_url, e))?
            .text()
            .await
            .map_err(|e| format!("Failed to read schema response: {}", e))?;

        let schema_json: serde_json::Value = serde_json::from_str(&schema_content)
            .map_err(|e| format!("Failed to parse schema JSON: {}", e))?;

        let compiled_schema = jsonschema::validator_for(&schema_json)
            .map_err(|e| format!("Failed to compile JSON schema: {}", e))?;

        // Serialize the report to JSON
        let report_json = serde_json::to_value(report)
            .map_err(|e| format!("Failed to serialize GitLab report to JSON: {}", e))?;

        // Validate the report against the schema
        match compiled_schema.validate(&report_json) {
            Ok(_) => {
                info!(
                    "✅ GitLab SAST report successfully validated against schema {}!",
                    schema_version
                );
                Ok(())
            }
            Err(error) => {
                eprintln!(
                    "\n❌ GitLab SAST report failed schema validation for version {}!",
                    schema_version
                );
                eprintln!("\nValidation error:");
                eprintln!("  {}", error);
                eprintln!("  Instance path: {}", error.instance_path);
                eprintln!("  Schema path: {}\n", error.schema_path);
                Err(format!(
                    "Schema validation failed for version {}",
                    schema_version
                ))
            }
        }
    }

    #[tokio::test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    async fn test_gitlab_sast_report_schema_validation() {
        // List of schema versions to test against
        // Add new versions here as they become available
        let schema_versions = vec!["15.2.1", "15.2.2", "15.2.3"];

        let report = create_test_gitlab_report();

        // Test against all schema versions
        for version in &schema_versions {
            info!("🔍 Testing against schema version {}", version);

            // Write test output for inspection
            let output_path = format!("gitlab/test-output-report-{}.json", version);
            if let Ok(json_string) = serde_json::to_string_pretty(&report) {
                let _ = std::fs::write(&output_path, json_string);
                info!("📝 Test report ({}) written to: {}", version, output_path);
            }

            match validate_against_schema(version, &report).await {
                Ok(_) => info!("✅ Schema {} validation passed!", version),
                Err(e) => panic!("Schema {} validation failed: {}", version, e),
            }
        }

        info!(
            "🎉 All schema validations passed! Tested {} versions",
            schema_versions.len()
        );
    }
}

//! GitLab SAST report export functionality
//!
//! This module provides functionality to export Veracode pipeline scan results
//! in GitLab SAST report format, compatible with GitLab security dashboards.

use crate::findings::AggregatedFindings;
use crate::path_resolver::{PathResolver, PathResolverConfig};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

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

        let vulnerabilities = aggregated
            .findings
            .iter()
            .map(|finding_with_source| self.convert_finding_to_vulnerability(finding_with_source))
            .collect::<Result<Vec<_>, _>>()?;

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

    /// Resolve file path using the configured path resolver
    fn resolve_file_path(&self, file_path: &str) -> String {
        match &self.config.path_resolver {
            Some(resolver) => resolver.resolve_file_path(file_path).into_owned(),
            None => {
                if self.debug {
                    println!(
                        "   No path resolver configured, returning original path: '{file_path}'"
                    );
                }
                file_path.to_string()
            }
        }
    }

    /// Convert a Veracode finding to GitLab vulnerability format
    fn convert_finding_to_vulnerability(
        &self,
        finding_with_source: &crate::findings::FindingWithSource,
    ) -> Result<GitLabVulnerability, Box<dyn std::error::Error>> {
        let finding = &finding_with_source.finding;
        let source = &finding_with_source.source_scan;

        // Generate a unique ID for this vulnerability
        let vulnerability_id = Uuid::new_v4().to_string();

        // Convert severity
        let severity = self.convert_severity(finding.severity);

        // Create identifiers
        let mut identifiers = Vec::new();

        // Add CVE identifier (moved from standalone field to identifiers array)
        let cve_value = format!(
            "veracode:{}:{}:{}",
            finding.title, finding.files.source_file.line, finding.files.source_file.line
        );
        identifiers.push(GitLabIdentifier {
            identifier_type: "cve".to_string(),
            name: format!("Veracode CVE Reference {}", finding.title),
            value: cve_value,
            url: None,
        });

        // Add CWE identifier
        if !finding.cwe_id.is_empty() && finding.cwe_id != "0" {
            identifiers.push(GitLabIdentifier {
                identifier_type: "cwe".to_string(),
                name: format!("CWE-{}", finding.cwe_id),
                value: finding.cwe_id.clone(),
                url: Some(format!(
                    "https://cwe.mitre.org/data/definitions/{}.html",
                    finding.cwe_id
                )),
            });
        }

        // Add Veracode-specific identifier
        identifiers.push(GitLabIdentifier {
            identifier_type: "veracode_issue_id".to_string(),
            name: format!("Veracode Issue ID {}", finding.issue_id),
            value: finding.issue_id.to_string(),
            url: None,
        });

        // Add issue type identifier
        identifiers.push(GitLabIdentifier {
            identifier_type: "veracode_issue_type".to_string(),
            name: format!("Veracode Issue Type {}", finding.issue_type),
            value: finding.issue_type_id.clone(),
            url: None,
        });

        // Create location with resolved file path
        let resolved_file_path = self.resolve_file_path(&finding.files.source_file.file);
        let location = GitLabLocation {
            file: Some(resolved_file_path.clone()),
            start_line: Some(finding.files.source_file.line),
            end_line: Some(finding.files.source_file.line),
            class: None,
            method: finding.files.source_file.function_name.clone(),
        };

        // Create tracking information if enabled
        let tracking = if self.config.include_tracking {
            Some(GitLabTracking {
                tracking_type: "source".to_string(),
                items: vec![GitLabTrackingItem {
                    file: resolved_file_path.clone(),
                    line_start: finding.files.source_file.line,
                    line_end: finding.files.source_file.line,
                    signatures: vec![GitLabSignature {
                        algorithm: "scope_offset".to_string(),
                        value: format!(
                            "{}|{}[0]:1",
                            resolved_file_path,
                            finding
                                .files
                                .source_file
                                .function_name
                                .as_deref()
                                .unwrap_or("unknown")
                        ),
                    }],
                }],
            })
        } else {
            None
        };

        // Create links if enabled
        let links = if self.config.include_links {
            let mut link_vec = Vec::new();

            // Add CWE link if available
            if !finding.cwe_id.is_empty() && finding.cwe_id != "0" {
                link_vec.push(GitLabLink {
                    name: format!("CWE-{} Details", finding.cwe_id),
                    url: format!(
                        "https://cwe.mitre.org/data/definitions/{}.html",
                        finding.cwe_id
                    ),
                });
            }

            if !link_vec.is_empty() {
                Some(link_vec)
            } else {
                None
            }
        } else {
            None
        };

        // Create solution text if enabled
        let solution = if self.config.include_solutions {
            Some(format!(
                "Review and remediate this {} vulnerability found in {}. \
                Consider consulting Veracode documentation for specific remediation guidance for this issue type.",
                finding.issue_type, resolved_file_path
            ))
        } else {
            None
        };

        Ok(GitLabVulnerability {
            id: vulnerability_id,
            identifiers,
            location,
            name: Some(finding.issue_type.clone()),
            description: Some(format!(
                "Veracode Pipeline Scan identified a {} vulnerability in {}.\n\n\
                Issue Type: {}\n\
                Severity: {} ({})\n\
                File: {}\n\
                Line: {}\n\
                Function: {}\n\
                Scan ID: {}\n\
                Project: {}",
                finding.issue_type,
                resolved_file_path,
                finding.issue_type,
                self.severity_to_string(finding.severity),
                finding.severity,
                resolved_file_path,
                finding.files.source_file.line,
                finding
                    .files
                    .source_file
                    .function_name
                    .as_deref()
                    .unwrap_or("N/A"),
                source.scan_id,
                source.project_name
            )),
            severity: Some(severity),
            solution,
            cvss_vectors: None,
            links,
            details: None,
            tracking,
            flags: None,
            raw_source_code_extract: None,
        })
    }

    /// Convert Veracode severity to GitLab severity
    fn convert_severity(&self, veracode_severity: u32) -> GitLabSeverity {
        match veracode_severity {
            5 => GitLabSeverity::Critical,
            4 => GitLabSeverity::High,
            3 => GitLabSeverity::Medium,
            2 => GitLabSeverity::Low,
            1 => GitLabSeverity::Low,
            0 => GitLabSeverity::Info,
            _ => GitLabSeverity::Unknown,
        }
    }

    /// Convert severity number to string
    fn severity_to_string(&self, severity: u32) -> &'static str {
        match severity {
            5 => "Very High",
            4 => "High",
            3 => "Medium",
            2 => "Low",
            1 => "Very Low",
            0 => "Informational",
            _ => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{FindingWithSource, ScanSource};
    use veracode_platform::pipeline::{Finding, FindingFiles, SourceFile};

    #[test]
    fn test_severity_conversion() {
        let exporter = GitLabExporter::new(GitLabExportConfig::default(), false);

        assert!(matches!(
            exporter.convert_severity(5),
            GitLabSeverity::Critical
        ));
        assert!(matches!(exporter.convert_severity(4), GitLabSeverity::High));
        assert!(matches!(
            exporter.convert_severity(3),
            GitLabSeverity::Medium
        ));
        assert!(matches!(exporter.convert_severity(2), GitLabSeverity::Low));
        assert!(matches!(exporter.convert_severity(1), GitLabSeverity::Low));
        assert!(matches!(exporter.convert_severity(0), GitLabSeverity::Info));
    }

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
        assert!(vulnerability.identifiers.len() >= 3); // Should have CVE, CWE and Veracode identifiers
        assert!(vulnerability.tracking.is_some());
        // Check for CVE identifier
        assert!(
            vulnerability
                .identifiers
                .iter()
                .any(|id| id.identifier_type == "cve")
        );
    }
}

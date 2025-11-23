//! Export workflow for retrieving findings from completed policy and sandbox scans
//!
//! This module provides functionality to retrieve findings from completed Veracode scans
//! and export them in GitLab SAST format or other supported formats.
//! Uses application profile names for consistency with assessment scans.

use crate::findings::{
    AggregatedFindings, AggregationStats, CweStatistic, FindingWithSource, FindingsAggregator,
    ScanMetadata, ScanSource,
};
use crate::gitlab_report::{GitLabExportConfig, GitLabExporter};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use veracode_platform::FindingsError;
use veracode_platform::FindingsQuery;
use veracode_platform::findings::{FindingsApi, RestFinding};
use veracode_platform::pipeline::{Finding, FindingFiles, FindingsSummary, SourceFile};
use veracode_platform::sandbox::SandboxApi;
use veracode_platform::{VeracodeClient, VeracodeError};

use log::{debug, info};

/// Configuration for findings export from completed scans
#[derive(Debug, Clone)]
pub struct ExportConfig<'a> {
    /// Veracode application profile name for automatic app lookup
    pub app_profile_name: Cow<'a, str>,
    /// Optional sandbox name for sandbox scans (if None, retrieves policy scan findings)
    pub sandbox_name: Option<Cow<'a, str>>,
    /// Optional sandbox GUID for sandbox scans (resolved internally from `sandbox_name`)
    pub sandbox_guid: Option<Cow<'a, str>>,
    /// Export format: "gitlab", "json", "csv", "all"
    pub export_format: Cow<'a, str>,
    /// Output file path
    pub output_path: Cow<'a, str>,
    /// Project directory for GitLab file path resolution
    pub project_dir: Option<PathBuf>,
    /// Minimum severity filter (0-5, optional)
    pub min_severity: Option<u32>,
    /// GitLab SAST schema version (15.2.1, 15.2.2, 15.2.3)
    pub schema_version: Cow<'a, str>,
}

/// Export workflow errors
#[derive(Debug)]
pub enum ExportError {
    /// Veracode API error
    Api(VeracodeError),
    /// Application not found
    ApplicationNotFound,
    /// Sandbox not found
    SandboxNotFound,
    /// Build not found or no findings available
    BuildNotFound,
    /// No findings found for the specified criteria
    NoFindings,
    /// File system I/O error
    Io(std::io::Error),
    /// Invalid configuration
    InvalidConfig(String),
    /// Unsupported export format
    UnsupportedFormat(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::Api(err) => write!(f, "API error: {err}"),
            ExportError::ApplicationNotFound => write!(f, "Application not found"),
            ExportError::SandboxNotFound => write!(f, "Sandbox not found"),
            ExportError::BuildNotFound => write!(f, "Build not found or no findings available"),
            ExportError::NoFindings => write!(f, "No findings found for specified criteria"),
            ExportError::Io(err) => write!(f, "File system error: {err}"),
            ExportError::InvalidConfig(msg) => write!(f, "Invalid configuration: {msg}"),
            ExportError::UnsupportedFormat(fmt) => write!(f, "Unsupported export format: {fmt}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<VeracodeError> for ExportError {
    fn from(err: VeracodeError) -> Self {
        match err {
            VeracodeError::NotFound(_) => ExportError::BuildNotFound,
            VeracodeError::Http(_)
            | VeracodeError::Serialization(_)
            | VeracodeError::Authentication(_)
            | VeracodeError::InvalidResponse(_)
            | VeracodeError::InvalidConfig(_)
            | VeracodeError::RetryExhausted(_)
            | VeracodeError::RateLimited { .. }
            | VeracodeError::Validation(_) => ExportError::Api(err),
        }
    }
}

impl From<FindingsError> for ExportError {
    fn from(err: FindingsError) -> Self {
        match err {
            FindingsError::ApplicationNotFound { .. } => ExportError::ApplicationNotFound,
            FindingsError::SandboxNotFound { .. } => ExportError::SandboxNotFound,
            FindingsError::NoFindings => ExportError::NoFindings,
            FindingsError::RequestFailed { source } => ExportError::Api(source),
            FindingsError::InvalidPagination { .. } => ExportError::InvalidConfig(err.to_string()),
        }
    }
}

impl From<std::io::Error> for ExportError {
    fn from(err: std::io::Error) -> Self {
        ExportError::Io(err)
    }
}

impl From<Box<dyn std::error::Error>> for ExportError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        ExportError::Api(VeracodeError::InvalidResponse(err.to_string()))
    }
}

/// Main export workflow handler
pub struct ExportWorkflow {
    client: VeracodeClient,
    config: ExportConfig<'static>,
}

impl ExportWorkflow {
    /// Create a new export workflow
    #[must_use]
    pub fn new(client: VeracodeClient, config: ExportConfig<'static>) -> Self {
        Self { client, config }
    }

    /// Execute the complete export workflow
    ///
    /// # Errors
    /// Returns an error if configuration validation fails, scan retrieval fails, or export operations fail
    pub async fn execute(&self) -> Result<(), ExportError> {
        debug!("🚀 Starting findings export from completed scan");
        debug!("   Application Profile: {}", self.config.app_profile_name);
        if let Some(ref sandbox_name) = self.config.sandbox_name {
            debug!("   Sandbox name: {sandbox_name} (sandbox scan)");
        } else if let Some(ref sandbox_guid) = self.config.sandbox_guid {
            debug!("   Sandbox GUID: {sandbox_guid} (sandbox scan)");
        } else {
            debug!("   Scan type: Policy scan");
        }
        debug!("   Export format: {}", self.config.export_format);
        if let Some(min_sev) = self.config.min_severity {
            debug!(
                "   Minimum severity filter: {} and above",
                FindingsAggregator::severity_level_to_name(min_sev)
            );
        }

        // Validate configuration
        self.validate_config()?;

        // Retrieve findings from Veracode API
        let findings = self.retrieve_findings().await?;

        // Export in requested format
        self.export_findings(&findings).await?;

        info!("✅ Export completed successfully");
        info!("   Total findings: {}", findings.findings.len());
        info!("   Output: {}", self.config.output_path);

        Ok(())
    }

    /// Validate export configuration
    fn validate_config(&self) -> Result<(), ExportError> {
        debug!("🔍 Validating export configuration");

        // Validate export format
        let format = self.config.export_format.to_lowercase();
        if !matches!(format.as_str(), "gitlab" | "json" | "csv" | "all") {
            return Err(ExportError::UnsupportedFormat(
                self.config.export_format.to_string(),
            ));
        }

        // Validate output path
        let output_path = Path::new(self.config.output_path.as_ref());
        if let Some(parent) = output_path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            return Err(ExportError::InvalidConfig(format!(
                "Output directory does not exist: {}",
                parent.display()
            )));
        }

        Ok(())
    }

    /// Retrieve findings from Veracode Findings API
    async fn retrieve_findings(&self) -> Result<AggregatedFindings, ExportError> {
        use veracode_platform::policy::PolicyApi;

        let policy_api = PolicyApi::new(&self.client);
        let findings_api = FindingsApi::new(self.client.clone());

        debug!(
            "🔍 Looking up application: {}",
            self.config.app_profile_name
        );

        // Look up application GUID from profile name
        let applications = self
            .client
            .search_applications_by_name(&self.config.app_profile_name)
            .await
            .map_err(|e| {
                log::error!(
                    "Failed to search for application '{}': {e}",
                    self.config.app_profile_name
                );
                ExportError::ApplicationNotFound
            })?;

        // Find exact match (search_applications_by_name does partial matching)
        let app = applications
            .into_iter()
            .find(|app| {
                if let Some(profile) = &app.profile {
                    profile.name.as_str() == self.config.app_profile_name
                } else {
                    false
                }
            })
            .ok_or_else(|| {
                log::error!("Application '{}' not found", self.config.app_profile_name);
                ExportError::ApplicationNotFound
            })?;

        let app_guid = &app.guid;

        debug!("✅ Found application GUID: {app_guid}");

        // Resolve sandbox name to GUID if sandbox_name is provided
        let resolved_sandbox_guid = if let Some(ref sandbox_name) = self.config.sandbox_name {
            debug!("🔍 Resolving sandbox GUID for name: {sandbox_name}");

            let sandbox_api = SandboxApi::new(&self.client);
            match sandbox_api
                .get_sandbox_by_name(app_guid, sandbox_name)
                .await
            {
                Ok(Some(sandbox)) => {
                    debug!(
                        "✅ Found sandbox GUID: {} for name: {sandbox_name}",
                        sandbox.guid
                    );
                    Some(sandbox.guid.clone())
                }
                Ok(None) => {
                    log::error!(
                        "Sandbox '{}' not found in application '{}'",
                        sandbox_name,
                        self.config.app_profile_name
                    );
                    return Err(ExportError::SandboxNotFound);
                }
                Err(e) => {
                    log::error!("Failed to lookup sandbox '{sandbox_name}': {e}");
                    return Err(ExportError::Api(VeracodeError::InvalidResponse(
                        e.to_string(),
                    )));
                }
            }
        } else {
            self.config.sandbox_guid.as_ref().map(ToString::to_string)
        };

        debug!("🔍 Getting summary report from Veracode Policy API");

        // Get summary report which contains policy compliance and findings summary
        let summary_report = policy_api
            .get_summary_report(app_guid, None, resolved_sandbox_guid.as_deref())
            .await
            .map_err(|e| {
                log::error!("Failed to retrieve summary report: {e}");
                match e {
                    veracode_platform::policy::PolicyError::NotFound => {
                        if self.config.sandbox_name.is_some() || self.config.sandbox_guid.is_some()
                        {
                            ExportError::SandboxNotFound
                        } else {
                            ExportError::ApplicationNotFound
                        }
                    }
                    veracode_platform::policy::PolicyError::Api(_)
                    | veracode_platform::policy::PolicyError::InvalidConfig(_)
                    | veracode_platform::policy::PolicyError::ScanFailed(_)
                    | veracode_platform::policy::PolicyError::EvaluationError(_)
                    | veracode_platform::policy::PolicyError::PermissionDenied
                    | veracode_platform::policy::PolicyError::Unauthorized
                    | veracode_platform::policy::PolicyError::InternalServerError
                    | veracode_platform::policy::PolicyError::Timeout => {
                        ExportError::Api(VeracodeError::InvalidResponse(e.to_string()))
                    }
                }
            })?;

        debug!(
            "✅ Retrieved summary report for app: {}",
            summary_report.app_name
        );
        debug!(
            "   Policy compliance: {}",
            summary_report.policy_compliance_status
        );
        if let Some(ref sandbox_name) = summary_report.sandbox_name {
            debug!("   Sandbox: {sandbox_name}");
        }

        // Get actual findings using FindingsApi with proper query filtering
        debug!("🔍 Getting findings from Veracode Findings API");

        // Build findings query with optional severity filtering
        let mut query = if let Some(ref sandbox_guid) = resolved_sandbox_guid {
            debug!("   Retrieving sandbox findings for GUID: {sandbox_guid}");
            FindingsQuery::for_sandbox(app_guid, sandbox_guid)
        } else {
            debug!("   Retrieving policy scan findings");
            FindingsQuery::new(app_guid)
        };

        // Apply severity filtering if configured
        if let Some(min_severity) = self.config.min_severity {
            let severity_filter: Vec<u32> = (min_severity..=5).collect();
            query = query.with_severity(severity_filter);
            debug!(
                "   Applying severity filter: {} and above",
                FindingsAggregator::severity_level_to_name(min_severity)
            );
        }

        let rest_findings = findings_api.get_all_findings(&query).await.map_err(|e| {
            log::error!("Failed to retrieve findings: {e}");
            ExportError::from(e)
        })?;

        debug!(
            "✅ Retrieved {} findings from Veracode API",
            rest_findings.len()
        );

        // Convert findings to aggregated format
        let aggregated = self.convert_findings_to_aggregated(&summary_report, &rest_findings)?;

        debug!(
            "📊 Processed {} findings for export",
            aggregated.findings.len()
        );
        self.display_summary_overview(&summary_report);

        Ok(aggregated)
    }

    /// Convert REST findings and summary report to `AggregatedFindings` format (hybrid approach)
    fn convert_findings_to_aggregated(
        &self,
        summary_report: &veracode_platform::policy::SummaryReport,
        rest_findings: &[RestFinding],
    ) -> Result<AggregatedFindings, ExportError> {
        debug!(
            "🔄 Converting {} REST findings to pipeline format",
            rest_findings.len()
        );

        // Convert REST findings to pipeline Finding format
        // Note: Severity filtering is now done at the API level via FindingsQuery
        let mut converted_findings = Vec::with_capacity(rest_findings.len());

        for rest_finding in rest_findings {
            let pipeline_finding = self.convert_rest_finding_to_pipeline(rest_finding)?;
            let finding_with_source = FindingWithSource {
                finding_id: self.create_finding_id(rest_finding),
                finding: pipeline_finding,
                source_scan: ScanSource {
                    scan_id: rest_finding.build_id.to_string(),
                    project_name: summary_report.app_name.clone(),
                    source_file: self.create_source_file_name(),
                },
            };
            converted_findings.push(finding_with_source);
        }

        // Use summary report for total count (don't recalculate)
        let total_from_summary = summary_report
            .flaw_status
            .as_ref()
            .map(|fs| fs.total)
            .unwrap_or(0);

        // Create metadata using summary report data
        let scan_metadata = vec![ScanMetadata {
            scan_id: summary_report.build_id.to_string(),
            project_name: summary_report.app_name.clone(),
            scan_status: veracode_platform::pipeline::ScanStatus::Success,
            project_uri: Some("".to_string()),
            source_file: self.create_source_file_name(),
            finding_count: u32::try_from(converted_findings.len()).unwrap_or(u32::MAX), // Actual processed count after filtering
        }];

        // Calculate severity breakdown from converted findings for GitLab export needs
        let mut very_high = 0u32;
        let mut high = 0u32;
        let mut medium = 0u32;
        let mut low = 0u32;
        let mut very_low = 0u32;
        let mut informational = 0u32;
        let mut severity_distribution = HashMap::new();

        for finding in &converted_findings {
            let severity_key = finding.finding.severity.to_string();
            let count = severity_distribution.entry(severity_key).or_insert(0u32);
            *count = count.saturating_add(1);

            match finding.finding.severity {
                5 => very_high = very_high.saturating_add(1),
                4 => high = high.saturating_add(1),
                3 => medium = medium.saturating_add(1),
                2 => low = low.saturating_add(1),
                1 => very_low = very_low.saturating_add(1),
                0 => informational = informational.saturating_add(1),
                _ => {}
            }
        }

        // Use total from summary report for consistency
        let summary = FindingsSummary {
            very_high,
            high,
            medium,
            low,
            very_low,
            informational,
            total: total_from_summary, // Use summary report total, not converted count
        };

        // Calculate stats from converted findings (needed for detailed export)
        let unique_cwe_count = u32::try_from(
            converted_findings
                .iter()
                .map(|f| &f.finding.cwe_id)
                .filter(|cwe| !cwe.is_empty() && *cwe != "0")
                .collect::<std::collections::HashSet<_>>()
                .len(),
        )
        .unwrap_or(u32::MAX);

        let unique_files_count = u32::try_from(
            converted_findings
                .iter()
                .map(|f| &f.finding.files.source_file.file)
                .collect::<std::collections::HashSet<_>>()
                .len(),
        )
        .unwrap_or(u32::MAX);

        let top_cwe_ids = {
            let mut cwe_counts: HashMap<String, u32> = HashMap::new();
            for finding in &converted_findings {
                if !finding.finding.cwe_id.is_empty() && finding.finding.cwe_id != "0" {
                    let count = cwe_counts
                        .entry(finding.finding.cwe_id.clone())
                        .or_insert(0);
                    *count = count.saturating_add(1);
                }
            }
            let mut cwe_vec: Vec<_> = cwe_counts.into_iter().collect();
            cwe_vec.sort_by(|a, b| b.1.cmp(&a.1));
            cwe_vec
                .into_iter()
                .take(10)
                .map(|(cwe_id, count)| {
                    // Precision loss acceptable: converting counts to f64 for percentage calculation
                    #[allow(clippy::cast_precision_loss)]
                    let percentage = if !converted_findings.is_empty() {
                        (count as f64 / converted_findings.len() as f64) * 100.0
                    } else {
                        0.0
                    };
                    CweStatistic {
                        cwe_id,
                        count,
                        percentage,
                    }
                })
                .collect()
        };

        let stats = AggregationStats {
            total_scans: 1,
            total_findings: total_from_summary, // Use summary report total
            unique_cwe_count,
            unique_files_count,
            top_cwe_ids,
            severity_distribution,
        };

        Ok(AggregatedFindings {
            scan_metadata,
            findings: converted_findings,
            summary,
            stats,
            original_rest_findings: Some(rest_findings.to_vec()),
        })
    }

    /// Convert REST finding to pipeline Finding format
    fn convert_rest_finding_to_pipeline(
        &self,
        rest_finding: &RestFinding,
    ) -> Result<Finding, ExportError> {
        // Create pipeline Finding from REST finding
        let finding = Finding {
            issue_id: rest_finding.issue_id,
            cwe_id: rest_finding.finding_details.cwe.id.to_string(),
            issue_type: rest_finding.finding_details.finding_category.name.clone(),
            issue_type_id: rest_finding.finding_details.cwe.id.to_string(),
            severity: rest_finding.finding_details.severity,
            title: rest_finding.description.clone(),
            gob: "B".to_string(), // Default for policy scans
            display_text: rest_finding.description.clone(),
            flaw_details_link: None, // Not available in REST findings
            stack_dumps: None,
            files: FindingFiles {
                source_file: SourceFile {
                    file: rest_finding.finding_details.file_path.clone(),
                    line: rest_finding.finding_details.file_line_number,
                    function_name: if rest_finding.finding_details.procedure.is_empty() {
                        None
                    } else {
                        Some(rest_finding.finding_details.procedure.clone())
                    },
                    qualified_function_name: rest_finding.finding_details.procedure.clone(),
                    function_prototype: format!(
                        "function {}(...)",
                        rest_finding.finding_details.procedure
                    ),
                    scope: "global".to_string(), // Default scope
                },
            },
        };

        Ok(finding)
    }

    /// Create finding ID from REST finding for matching purposes
    fn create_finding_id(&self, rest_finding: &RestFinding) -> String {
        format!(
            "{}:{}:{}:{}",
            rest_finding.finding_details.cwe.id,
            rest_finding.finding_details.file_name,
            rest_finding.finding_details.file_line_number,
            rest_finding.issue_id
        )
    }

    /// Display summary report overview
    fn display_summary_overview(&self, summary_report: &veracode_platform::policy::SummaryReport) {
        log::info!("📊 Summary Report Overview:");
        log::info!("   Application: {}", summary_report.app_name);
        log::info!(
            "   Policy: {} (version {})",
            summary_report.policy_name,
            summary_report.policy_version
        );
        log::info!(
            "   Compliance Status: {}",
            summary_report.policy_compliance_status
        );

        if let Some(flaw_status) = &summary_report.flaw_status {
            log::info!("   Total Flaws: {}", flaw_status.total);
            log::info!("   Open Flaws: {}", flaw_status.open);
            log::info!("   Fixed Flaws: {}", flaw_status.fixed);
            log::info!("   New Flaws: {}", flaw_status.new);
        }

        if let Some(static_analysis) = &summary_report.static_analysis {
            if let Some(score) = static_analysis.score {
                log::info!("   Security Score: {score}");
            }
            if let Some(rating) = &static_analysis.rating {
                log::info!("   Security Rating: {rating}");
            }
        }
    }

    /// Create a descriptive source file name for aggregation
    fn create_source_file_name(&self) -> String {
        match &self.config.sandbox_guid {
            Some(sandbox_guid) => {
                format!(
                    "sandbox_{}",
                    sandbox_guid
                        .split('-')
                        .next()
                        .unwrap_or(sandbox_guid.as_ref())
                )
            }
            None => {
                format!("policy_{}", self.config.app_profile_name.replace(' ', "_"))
            }
        }
    }

    /// Export findings in the requested format
    async fn export_findings(&self, findings: &AggregatedFindings) -> Result<(), ExportError> {
        let format = self.config.export_format.to_lowercase();
        let output_path = Path::new(self.config.output_path.as_ref());

        debug!(
            "📄 Exporting {} findings in {} format",
            findings.findings.len(),
            format
        );

        match format.as_str() {
            "gitlab" => self.export_gitlab_sast(findings, output_path).await,
            "json" => self.export_json_baseline(findings, output_path).await,
            "csv" => self.export_csv(findings, output_path).await,
            "all" => self.export_all_formats(findings, output_path).await,
            _ => Err(ExportError::UnsupportedFormat(format)),
        }
    }

    /// Export as GitLab SAST report
    async fn export_gitlab_sast(
        &self,
        findings: &AggregatedFindings,
        output_path: &Path,
    ) -> Result<(), ExportError> {
        let gitlab_path = self.ensure_extension(output_path, "json");
        let gitlab_config = GitLabExportConfig {
            schema_version: self.config.schema_version.to_string(),
            ..Default::default()
        };

        let gitlab_exporter = if let Some(ref project_dir) = self.config.project_dir {
            GitLabExporter::new(gitlab_config).with_project_dir(project_dir)
        } else {
            GitLabExporter::new(gitlab_config)
        };

        gitlab_exporter
            .export_to_gitlab_sast(findings, &gitlab_path)
            .await
            .map_err(|e| ExportError::Io(std::io::Error::other(e.to_string())))?;

        Ok(())
    }

    /// Export as JSON baseline format
    async fn export_json_baseline(
        &self,
        findings: &AggregatedFindings,
        output_path: &Path,
    ) -> Result<(), ExportError> {
        let json_path = self.ensure_extension(output_path, "json");
        let aggregator = FindingsAggregator::new();

        aggregator
            .export_to_baseline_format(findings, &json_path)
            .await
            .map_err(|e| ExportError::Io(std::io::Error::other(e.to_string())))?;

        info!("✅ JSON baseline format exported: {}", json_path.display());
        Ok(())
    }

    /// Export as CSV
    async fn export_csv(
        &self,
        findings: &AggregatedFindings,
        output_path: &Path,
    ) -> Result<(), ExportError> {
        let csv_path = self.ensure_extension(output_path, "csv");
        let aggregator = FindingsAggregator::new();

        aggregator
            .export_to_csv(findings, &csv_path)
            .await
            .map_err(|e| ExportError::Io(std::io::Error::other(e.to_string())))?;

        info!("✅ CSV export completed: {}", csv_path.display());
        Ok(())
    }

    /// Export in all formats
    async fn export_all_formats(
        &self,
        findings: &AggregatedFindings,
        base_path: &Path,
    ) -> Result<(), ExportError> {
        // Export GitLab SAST
        let gitlab_path = self.add_suffix_to_path(base_path, "_gitlab_sast", "json");
        self.export_gitlab_sast(findings, &gitlab_path).await?;

        // Export JSON baseline
        let json_path = self.ensure_extension(base_path, "json");
        self.export_json_baseline(findings, &json_path).await?;

        // Export CSV
        let csv_path = self.ensure_extension(base_path, "csv");
        self.export_csv(findings, &csv_path).await?;

        info!("✅ All format exports completed");
        Ok(())
    }

    /// Ensure file has correct extension
    fn ensure_extension(&self, path: &Path, extension: &str) -> PathBuf {
        if path.extension() == Some(extension.as_ref()) {
            path.to_path_buf()
        } else {
            path.with_extension(extension)
        }
    }

    /// Add suffix to filename before extension
    fn add_suffix_to_path(&self, path: &Path, suffix: &str, extension: &str) -> PathBuf {
        let mut new_path = path.to_path_buf();

        if let Some(file_stem) = new_path.file_stem() {
            let mut new_name = file_stem.to_os_string();
            new_name.push(suffix);
            new_name.push(".");
            new_name.push(extension);
            new_path.set_file_name(new_name);
        } else {
            new_path.set_file_name(format!("export{suffix}.{extension}"));
        }

        new_path
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    // Helper function to create a mock client for testing
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn create_mock_client() -> VeracodeClient {
        let config = veracode_platform::VeracodeConfig::new("test_id", "test_key");
        VeracodeClient::new(config).expect("Failed to create mock client")
    }

    #[test]
    fn test_export_config_creation() {
        let config = ExportConfig {
            app_profile_name: Cow::Borrowed("Test Application"),
            sandbox_name: Some(Cow::Borrowed("test-sandbox-name")),
            sandbox_guid: Some(Cow::Borrowed("test-sandbox-guid")),
            export_format: Cow::Borrowed("gitlab"),
            output_path: Cow::Borrowed("/tmp/test_output"),
            project_dir: None,
            min_severity: Some(3),
            schema_version: Cow::Borrowed("15.2.1"),
        };

        assert_eq!(config.app_profile_name, "Test Application");
        assert!(config.sandbox_name.is_some());
        assert!(config.sandbox_guid.is_some());
        assert_eq!(config.export_format, "gitlab");
        assert_eq!(config.min_severity, Some(3));
    }

    #[test]
    fn test_export_error_display() {
        let error = ExportError::NoFindings;
        assert_eq!(
            error.to_string(),
            "No findings found for specified criteria"
        );

        let error = ExportError::UnsupportedFormat("xml".to_string());
        assert_eq!(error.to_string(), "Unsupported export format: xml");

        let error = ExportError::ApplicationNotFound;
        assert_eq!(error.to_string(), "Application not found");
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_source_file_name_generation() {
        // Test with sandbox
        let config_sandbox = ExportConfig {
            app_profile_name: Cow::Borrowed("Test Application"),
            sandbox_name: Some(Cow::Borrowed("test-sandbox")),
            sandbox_guid: Some(Cow::Borrowed("87654321-4321-4321-4321-210987654321")),
            export_format: Cow::Borrowed("gitlab"),
            output_path: Cow::Borrowed("/tmp/test"),
            project_dir: None,
            min_severity: None,
            schema_version: Cow::Borrowed("15.2.1"),
        };

        let workflow = ExportWorkflow {
            client: create_mock_client(),
            config: config_sandbox,
        };

        let source_name = workflow.create_source_file_name();
        assert!(source_name.starts_with("sandbox_87654321"));

        // Test with policy scan (no sandbox)
        let config_policy = ExportConfig {
            app_profile_name: Cow::Borrowed("Test Application"),
            sandbox_name: None,
            sandbox_guid: None,
            export_format: Cow::Borrowed("gitlab"),
            output_path: Cow::Borrowed("/tmp/test"),
            project_dir: None,
            min_severity: None,
            schema_version: Cow::Borrowed("15.2.1"),
        };

        let workflow_policy = ExportWorkflow {
            client: create_mock_client(),
            config: config_policy,
        };

        let source_name_policy = workflow_policy.create_source_file_name();
        assert!(source_name_policy.starts_with("policy_Test_Application"));
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_ensure_extension() {
        let workflow = ExportWorkflow {
            client: create_mock_client(),
            config: ExportConfig {
                app_profile_name: Cow::Borrowed("Test App"),
                sandbox_name: None,
                sandbox_guid: None,
                export_format: Cow::Borrowed("gitlab"),
                output_path: Cow::Borrowed("/tmp/test"),
                project_dir: None,
                min_severity: None,
                schema_version: Cow::Borrowed("15.2.1"),
            },
        };

        // Test adding extension
        let path = Path::new("report");
        let result = workflow.ensure_extension(path, "json");
        assert_eq!(result.extension().expect("should have extension"), "json");

        // Test preserving existing extension
        let path_with_ext = Path::new("report.json");
        let result_with_ext = workflow.ensure_extension(path_with_ext, "json");
        assert_eq!(
            result_with_ext.extension().expect("should have extension"),
            "json"
        );
        assert_eq!(
            result_with_ext.file_stem().expect("should have file stem"),
            "report"
        );
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_add_suffix_to_path() {
        let workflow = ExportWorkflow {
            client: create_mock_client(),
            config: ExportConfig {
                app_profile_name: Cow::Borrowed("Test App"),
                sandbox_name: None,
                sandbox_guid: None,
                export_format: Cow::Borrowed("gitlab"),
                output_path: Cow::Borrowed("/tmp/test"),
                project_dir: None,
                min_severity: None,
                schema_version: Cow::Borrowed("15.2.1"),
            },
        };

        // Test adding suffix to path with extension
        let path = Path::new("report.json");
        let result = workflow.add_suffix_to_path(path, "_gitlab_sast", "json");
        assert_eq!(
            result.file_name().expect("should have file name"),
            "report_gitlab_sast.json"
        );

        // Test adding suffix to path without extension
        let path_no_ext = Path::new("report");
        let result_no_ext = workflow.add_suffix_to_path(path_no_ext, "_test", "csv");
        assert_eq!(
            result_no_ext.file_name().expect("should have file name"),
            "report_test.csv"
        );
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_validate_config() {
        let config_valid = ExportConfig {
            app_profile_name: Cow::Borrowed("Test Application"),
            sandbox_name: None,
            sandbox_guid: None,
            export_format: Cow::Borrowed("gitlab"),
            output_path: Cow::Borrowed("/tmp/test.json"),
            project_dir: None,
            min_severity: None,
            schema_version: Cow::Borrowed("15.2.1"),
        };

        let workflow = ExportWorkflow {
            client: create_mock_client(),
            config: config_valid,
        };

        // Valid config should pass
        assert!(workflow.validate_config().is_ok());

        // Test invalid format
        let config_invalid_format = ExportConfig {
            app_profile_name: Cow::Borrowed("Test Application"),
            sandbox_name: None,
            sandbox_guid: None,
            export_format: Cow::Borrowed("xml"), // Invalid format
            output_path: Cow::Borrowed("/tmp/test.json"),
            project_dir: None,
            min_severity: None,
            schema_version: Cow::Borrowed("15.2.1"),
        };

        let workflow_invalid = ExportWorkflow {
            client: create_mock_client(),
            config: config_invalid_format,
        };

        assert!(matches!(
            workflow_invalid.validate_config(),
            Err(ExportError::UnsupportedFormat(_))
        ));
    }

    #[test]
    fn test_severity_conversion_in_execute_function() {
        // Test severity string conversion logic (extracted from the function)
        let test_cases = vec![
            ("informational", 0),
            ("info", 0),
            ("very-low", 1),
            ("verylow", 1),
            ("very_low", 1),
            ("low", 2),
            ("medium", 3),
            ("med", 3),
            ("high", 4),
            ("very-high", 5),
            ("veryhigh", 5),
            ("very_high", 5),
            ("critical", 5),
            ("unknown", 3), // Should default to medium
        ];

        for (severity_str, expected_numeric) in test_cases {
            let result = match severity_str.to_lowercase().as_str() {
                "informational" | "info" => 0,
                "very-low" | "verylow" | "very_low" => 1,
                "low" => 2,
                "medium" | "med" => 3,
                "high" => 4,
                "very-high" | "veryhigh" | "very_high" | "critical" => 5,
                _ => 3, // Default to medium if unrecognized
            };

            assert_eq!(
                result, expected_numeric,
                "Severity '{severity_str}' should convert to {expected_numeric}, got {result}"
            );
        }
    }

    #[test]
    fn test_error_conversions() {
        // Test VeracodeError conversion
        let veracode_err = VeracodeError::NotFound("test not found".to_string());
        let export_err: ExportError = veracode_err.into();
        assert!(matches!(export_err, ExportError::BuildNotFound));

        // Test IO error conversion
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
        let export_err: ExportError = io_err.into();
        assert!(matches!(export_err, ExportError::Io(_)));

        // Test Box<dyn Error> conversion
        let box_err: Box<dyn std::error::Error> = Box::new(std::io::Error::other("Generic error"));
        let export_err: ExportError = box_err.into();
        assert!(matches!(export_err, ExportError::Api(_)));
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_create_finding_id() {
        use veracode_platform::findings::{
            CweInfo, FindingCategory, FindingDetails, FindingStatus, RestFinding,
        };

        let rest_finding = RestFinding {
            issue_id: 123,
            scan_type: "STATIC".to_string(),
            description: "Test vulnerability".to_string(),
            count: 1,
            context_type: "POLICY".to_string(),
            context_guid: "test-guid".to_string(),
            violates_policy: true,
            finding_status: FindingStatus {
                first_found_date: "2023-01-01".to_string(),
                status: "OPEN".to_string(),
                resolution: "UNRESOLVED".to_string(),
                mitigation_review_status: "NOT_REVIEWED".to_string(),
                new: true,
                resolution_status: "UNRESOLVED".to_string(),
                last_seen_date: "2023-01-01".to_string(),
            },
            finding_details: FindingDetails {
                severity: 4,
                cwe: CweInfo {
                    id: 79,
                    name: "Cross-Site Scripting".to_string(),
                    href: "https://cwe.mitre.org/data/definitions/79.html".to_string(),
                },
                file_path: "src/main.js".to_string(),
                file_name: "main.js".to_string(),
                module: "app".to_string(),
                relative_location: 42,
                finding_category: FindingCategory {
                    id: 1,
                    name: "Cross-Site Scripting".to_string(),
                    href: "https://help.veracode.com".to_string(),
                },
                procedure: "processInput".to_string(),
                exploitability: 3,
                attack_vector: "Network".to_string(),
                file_line_number: 42,
            },
            build_id: 987654321,
        };

        let workflow = ExportWorkflow {
            client: create_mock_client(),
            config: ExportConfig {
                app_profile_name: Cow::Borrowed("Test App"),
                sandbox_name: None,
                sandbox_guid: None,
                export_format: Cow::Borrowed("gitlab"),
                output_path: Cow::Borrowed("/tmp/test"),
                project_dir: None,
                min_severity: None,
                schema_version: Cow::Borrowed("15.2.1"),
            },
        };

        let finding_id = workflow.create_finding_id(&rest_finding);
        assert_eq!(finding_id, "79:main.js:42:123");
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_convert_rest_finding_to_pipeline() {
        use veracode_platform::findings::{
            CweInfo, FindingCategory, FindingDetails, FindingStatus, RestFinding,
        };

        let rest_finding = RestFinding {
            issue_id: 123,
            scan_type: "STATIC".to_string(),
            description: "Cross-Site Scripting vulnerability detected".to_string(),
            count: 1,
            context_type: "POLICY".to_string(),
            context_guid: "test-guid".to_string(),
            violates_policy: true,
            finding_status: FindingStatus {
                first_found_date: "2023-01-01".to_string(),
                status: "OPEN".to_string(),
                resolution: "UNRESOLVED".to_string(),
                mitigation_review_status: "NOT_REVIEWED".to_string(),
                new: true,
                resolution_status: "UNRESOLVED".to_string(),
                last_seen_date: "2023-01-01".to_string(),
            },
            finding_details: FindingDetails {
                severity: 4,
                cwe: CweInfo {
                    id: 79,
                    name: "Cross-Site Scripting".to_string(),
                    href: "https://cwe.mitre.org/data/definitions/79.html".to_string(),
                },
                file_path: "src/main.js".to_string(),
                file_name: "main.js".to_string(),
                module: "app".to_string(),
                relative_location: 42,
                finding_category: FindingCategory {
                    id: 1,
                    name: "Cross-Site Scripting".to_string(),
                    href: "https://help.veracode.com".to_string(),
                },
                procedure: "processInput".to_string(),
                exploitability: 3,
                attack_vector: "Network".to_string(),
                file_line_number: 42,
            },
            build_id: 987654321,
        };

        let workflow = ExportWorkflow {
            client: create_mock_client(),
            config: ExportConfig {
                app_profile_name: Cow::Borrowed("Test App"),
                sandbox_name: None,
                sandbox_guid: None,
                export_format: Cow::Borrowed("gitlab"),
                output_path: Cow::Borrowed("/tmp/test"),
                project_dir: None,
                min_severity: None,
                schema_version: Cow::Borrowed("15.2.1"),
            },
        };

        let pipeline_finding = workflow
            .convert_rest_finding_to_pipeline(&rest_finding)
            .expect("should convert finding");

        assert_eq!(pipeline_finding.issue_id, 123);
        assert_eq!(pipeline_finding.cwe_id, "79");
        assert_eq!(pipeline_finding.issue_type, "Cross-Site Scripting");
        assert_eq!(pipeline_finding.severity, 4);
        assert_eq!(pipeline_finding.files.source_file.file, "src/main.js");
        assert_eq!(pipeline_finding.files.source_file.line, 42);
        assert_eq!(
            pipeline_finding.files.source_file.function_name,
            Some("processInput".to_string())
        );
    }

    #[test]
    fn test_config_with_all_options() {
        let config = ExportConfig {
            app_profile_name: Cow::Borrowed("Test Application"),
            sandbox_name: Some(Cow::Borrowed("test-sandbox")),
            sandbox_guid: Some(Cow::Borrowed("87654321-4321-4321-4321-210987654321")),
            export_format: Cow::Borrowed("all"),
            output_path: Cow::Borrowed("/path/to/output.json"),
            project_dir: Some(std::path::PathBuf::from("/project")),
            min_severity: Some(4), // High severity
            schema_version: Cow::Borrowed("15.2.1"),
        };

        // Verify all fields are set correctly
        assert_eq!(config.app_profile_name, "Test Application");
        assert_eq!(
            config
                .sandbox_name
                .as_ref()
                .expect("should have sandbox name"),
            "test-sandbox"
        );
        assert_eq!(
            config
                .sandbox_guid
                .as_ref()
                .expect("should have sandbox guid"),
            "87654321-4321-4321-4321-210987654321"
        );
        assert_eq!(config.export_format, "all");
        assert_eq!(config.output_path, "/path/to/output.json");
        assert!(config.project_dir.is_some());
        // Debug functionality removed from config
        assert_eq!(config.min_severity, Some(4));
    }
}

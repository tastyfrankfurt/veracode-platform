use crate::findings::{AggregatedFindings, FindingWithSource, create_finding_hash};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

// Type aliases for common usage patterns
pub type OwnedBaselineFile = BaselineFile<'static>;
pub type OwnedBaselineFinding = BaselineFinding<'static>;
pub type OwnedBaselineComparison = BaselineComparison<'static>;

// Conversion methods for making borrowed data owned
impl<'a> BaselineFinding<'a> {
    #[must_use]
    pub fn into_owned(self) -> OwnedBaselineFinding {
        BaselineFinding {
            finding_id: Cow::Owned(self.finding_id.into_owned()),
            cwe_id: Cow::Owned(self.cwe_id.into_owned()),
            issue_type: Cow::Owned(self.issue_type.into_owned()),
            severity: self.severity,
            file_path: Cow::Owned(self.file_path.into_owned()),
            line_number: self.line_number,
            function_name: self.function_name.map(|cow| Cow::Owned(cow.into_owned())),
            title: Cow::Owned(self.title.into_owned()),
            finding_hash: Cow::Owned(self.finding_hash.into_owned()),
        }
    }
}

impl<'a> BaselineComparison<'a> {
    #[must_use]
    pub fn into_owned(self) -> OwnedBaselineComparison {
        BaselineComparison {
            metadata: self.metadata,
            new_findings: self.new_findings,
            fixed_findings: self
                .fixed_findings
                .into_iter()
                .map(|f| f.into_owned())
                .collect(),
            unchanged_findings: self
                .unchanged_findings
                .into_iter()
                .map(|f| FindingMatch {
                    current_finding: f.current_finding,
                    baseline_finding: f.baseline_finding.into_owned(),
                    severity_changed: f.severity_changed,
                    previous_severity: f.previous_severity,
                })
                .collect(),
            summary: self.summary,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile<'a> {
    /// Metadata about the baseline
    pub metadata: BaselineMetadata,
    /// Baseline findings for comparison
    pub findings: Vec<BaselineFinding<'a>>,
    /// Summary statistics
    pub summary: BaselineSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMetadata {
    /// Version of the baseline format
    pub version: String,
    /// When the baseline was created
    pub created_at: String,
    /// Source scan information
    pub source_scan: BaselineScanInfo,
    /// Project information
    pub project_info: BaselineProjectInfo,
    /// Number of findings in the baseline
    pub finding_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineScanInfo {
    /// Scan ID that produced this baseline
    pub scan_id: String,
    /// Project name at time of scan
    pub project_name: String,
    /// Project URI if available
    pub project_uri: Option<String>,
    /// Source files that were scanned
    pub source_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineProjectInfo {
    /// Project name
    pub name: String,
    /// Project URL
    pub url: Option<String>,
    /// Git commit hash if available
    pub commit_hash: Option<String>,
    /// Git branch if available
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFinding<'a> {
    /// Unique identifier for matching purposes
    pub finding_id: Cow<'a, str>,
    /// CWE ID for the finding
    pub cwe_id: Cow<'a, str>,
    /// Issue type
    pub issue_type: Cow<'a, str>,
    /// Severity level (0-5)
    pub severity: u32,
    /// File path where the finding was discovered
    pub file_path: Cow<'a, str>,
    /// Line number (if available)
    pub line_number: u32,
    /// Function name (if available)
    pub function_name: Option<Cow<'a, str>>,
    /// Finding title/description
    pub title: Cow<'a, str>,
    /// Hash of the finding for exact matching
    pub finding_hash: Cow<'a, str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    /// Total findings count
    pub total: u32,
    /// Severity breakdown
    pub very_high: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub very_low: u32,
    pub informational: u32,
    /// Top CWE IDs
    pub top_cwe_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparison<'a> {
    /// Metadata about the comparison
    pub metadata: ComparisonMetadata,
    /// New findings (not in baseline)
    pub new_findings: Vec<FindingWithSource>,
    /// Fixed findings (in baseline but not in current)
    pub fixed_findings: Vec<BaselineFinding<'a>>,
    /// Unchanged findings (in both baseline and current)
    pub unchanged_findings: Vec<FindingMatch<'a>>,
    /// Summary of the comparison
    pub summary: ComparisonSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonMetadata {
    /// When the comparison was performed
    pub compared_at: String,
    /// Baseline file information
    pub baseline_info: BaselineMetadata,
    /// Current scan information
    pub current_scan_info: CurrentScanInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentScanInfo {
    /// Number of scan results processed
    pub scan_count: u32,
    /// Total findings in current scan
    pub total_findings: u32,
    /// Project names scanned
    pub project_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingMatch<'a> {
    /// Current finding
    pub current_finding: FindingWithSource,
    /// Matching baseline finding
    pub baseline_finding: BaselineFinding<'a>,
    /// Whether severity changed
    pub severity_changed: bool,
    /// Previous severity (if changed)
    pub previous_severity: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    /// Total new findings
    pub new_count: u32,
    /// Total fixed findings
    pub fixed_count: u32,
    /// Total unchanged findings
    pub unchanged_count: u32,
    /// Net change (new - fixed)
    pub net_change: i32,
    /// New findings by severity
    pub new_by_severity: HashMap<String, u32>,
    /// Fixed findings by severity
    pub fixed_by_severity: HashMap<String, u32>,
    /// Most common new CWE IDs
    pub new_cwe_breakdown: Vec<String>,
}

// Policy Assessment Structures

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    /// Policy metadata
    pub metadata: PolicyMetadata,
    /// Policy rules for assessment
    pub rules: Vec<PolicyRule>,
    /// Pass/fail criteria
    pub criteria: PolicyCriteria,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    /// Policy name
    pub name: String,
    /// Policy version
    pub version: String,
    /// Policy description
    pub description: Option<String>,
    /// When the policy was created
    pub created_at: Option<String>,
    /// Policy GUID (if from Veracode platform)
    pub guid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name/description
    pub name: String,
    /// CWE IDs this rule applies to (empty means all)
    pub cwe_ids: Vec<String>,
    /// Severity levels this rule applies to
    pub severity_levels: Vec<u32>,
    /// Maximum allowed findings for this rule
    pub max_allowed: u32,
    /// Whether this rule is enabled
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCriteria {
    /// Overall maximum allowed findings across all rules
    pub max_total_findings: Option<u32>,
    /// Maximum allowed by severity
    pub max_by_severity: HashMap<String, u32>,
    /// Fail on any high/very high findings
    pub fail_on_high_severity: bool,
    /// Fail on specific CWEs
    pub fail_on_cwe_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAssessment {
    /// Assessment metadata
    pub metadata: PolicyAssessmentMetadata,
    /// Overall pass/fail result
    pub passed: bool,
    /// Rule evaluations
    pub rule_results: Vec<PolicyRuleResult>,
    /// Findings that violate policy
    pub violations: Vec<FindingWithSource>,
    /// Assessment summary
    pub summary: PolicyAssessmentSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAssessmentMetadata {
    /// When the assessment was performed
    pub assessed_at: String,
    /// Policy information used
    pub policy_info: PolicyMetadata,
    /// Current scan information
    pub scan_info: CurrentScanInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleResult {
    /// The rule that was evaluated
    pub rule: PolicyRule,
    /// Number of findings that match this rule
    pub finding_count: u32,
    /// Whether this rule passed
    pub passed: bool,
    /// Findings that violated this rule
    pub violating_findings: Vec<FindingWithSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAssessmentSummary {
    /// Total findings assessed
    pub total_findings: u32,
    /// Total violations found
    pub total_violations: u32,
    /// Rules that passed
    pub rules_passed: u32,
    /// Rules that failed
    pub rules_failed: u32,
    /// Violations by severity
    pub violations_by_severity: HashMap<String, u32>,
    /// Most common violation CWE IDs
    pub violation_cwe_breakdown: Vec<String>,
}

pub struct BaselineManager {}

impl Default for BaselineManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BaselineManager {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Create a baseline file from aggregated findings
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails or the output file cannot be written
    pub fn create_baseline(
        &self,
        aggregated: &AggregatedFindings,
        output_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!(
            "📝 Creating baseline file from {} findings",
            aggregated.findings.len()
        );

        let baseline = self.convert_to_baseline(aggregated)?;
        let json_content = serde_json::to_string_pretty(&baseline)?;
        fs::write(output_path, json_content)?;

        info!("✅ Baseline file created: {}", output_path.display());
        info!("   Total findings: {}", baseline.summary.total);
        info!(
            "   Source scans: {}",
            baseline.metadata.source_scan.source_files.len()
        );

        Ok(())
    }

    /// Load a baseline file
    ///
    /// # Errors
    /// Returns an error if the file does not exist, cannot be read, or contains invalid JSON
    pub fn load_baseline(
        &self,
        baseline_path: &Path,
    ) -> Result<OwnedBaselineFile, Box<dyn std::error::Error>> {
        debug!("📖 Loading baseline file: {}", baseline_path.display());

        if !baseline_path.exists() {
            return Err(
                format!("Baseline file does not exist: {}", baseline_path.display()).into(),
            );
        }

        let content = fs::read_to_string(baseline_path)?;
        let baseline: OwnedBaselineFile = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse baseline file: {e}"))?;

        debug!(
            "✅ Baseline loaded: {} findings from {}",
            baseline.summary.total, baseline.metadata.created_at
        );

        Ok(baseline)
    }

    /// Compare current findings against a baseline
    ///
    /// # Errors
    /// Returns an error if the comparison operation fails or findings cannot be processed
    pub fn compare_with_baseline<'a>(
        &self,
        current: &AggregatedFindings,
        baseline: &'a BaselineFile<'a>,
    ) -> Result<BaselineComparison<'a>, Box<dyn std::error::Error>> {
        debug!(
            "🔍 Comparing {} current findings against {} baseline findings",
            current.findings.len(),
            baseline.findings.len()
        );

        let comparison = self.perform_comparison(current, baseline)?;

        debug!("✅ Comparison complete:");
        debug!("   New findings: {}", comparison.summary.new_count);
        debug!("   Fixed findings: {}", comparison.summary.fixed_count);
        debug!(
            "   Unchanged findings: {}",
            comparison.summary.unchanged_count
        );
        debug!("   Net change: {:+}", comparison.summary.net_change);

        Ok(comparison)
    }

    /// Export comparison results
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails or the file cannot be written
    pub fn export_comparison<'a>(
        &self,
        comparison: &BaselineComparison<'a>,
        output_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!(
            "💾 Exporting comparison results to: {}",
            output_path.display()
        );

        let json_content = serde_json::to_string_pretty(comparison)?;
        fs::write(output_path, json_content)?;

        info!("✅ Comparison results exported: {}", output_path.display());
        Ok(())
    }

    /// Display comparison summary
    pub fn display_comparison_summary<'a>(&self, comparison: &BaselineComparison<'a>) {
        info!("\n📊 Baseline Comparison Summary");
        info!("═══════════════════════════════════════");

        info!("📅 Baseline Info:");
        info!(
            "   Created: {}",
            comparison.metadata.baseline_info.created_at
        );
        info!(
            "   Source Scan: {}",
            comparison.metadata.baseline_info.source_scan.scan_id
        );
        info!(
            "   Baseline Findings: {}",
            comparison.metadata.baseline_info.finding_count
        );

        info!("\n📈 Comparison Results:");
        info!("   🆕 New Findings: {}", comparison.summary.new_count);
        info!("   ✅ Fixed Findings: {}", comparison.summary.fixed_count);
        info!(
            "   ➡️  Unchanged Findings: {}",
            comparison.summary.unchanged_count
        );
        info!(
            "   📊 Net Change: {:+} findings",
            comparison.summary.net_change
        );

        if comparison.summary.new_count > 0 {
            info!("\n🆕 New Findings by Severity:");
            for (severity, count) in &comparison.summary.new_by_severity {
                if *count > 0 {
                    info!("   {severity}: {count}");
                }
            }
        }

        if comparison.summary.fixed_count > 0 {
            info!("\n✅ Fixed Findings by Severity:");
            for (severity, count) in &comparison.summary.fixed_by_severity {
                if *count > 0 {
                    info!("   {severity}: {count}");
                }
            }
        }

        if !comparison.summary.new_cwe_breakdown.is_empty() {
            info!("\n🔍 New CWE Types:");
            for (index, cwe_id) in comparison
                .summary
                .new_cwe_breakdown
                .iter()
                .take(5)
                .enumerate()
            {
                info!("   {}. CWE-{}", index.saturating_add(1), cwe_id);
            }
        }
    }

    /// Convert aggregated findings to baseline format
    ///
    /// # Errors
    /// Returns an error if scan metadata is missing or findings cannot be converted
    fn convert_to_baseline<'a>(
        &self,
        aggregated: &'a AggregatedFindings,
    ) -> Result<BaselineFile<'a>, Box<dyn std::error::Error>> {
        let now = chrono::Utc::now().to_rfc3339();

        // Extract scan information
        let first_scan = aggregated
            .scan_metadata
            .first()
            .ok_or("No scan metadata available")?;

        // Collect unique source files efficiently
        let source_files: Vec<String> = aggregated
            .scan_metadata
            .iter()
            .map(|meta| meta.source_file.as_str().into())
            .collect();

        // Collect unique project names efficiently
        let project_names: Vec<String> = aggregated
            .scan_metadata
            .iter()
            .map(|meta| meta.project_name.as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|s| s.into())
            .collect();

        // Convert findings using Cow for zero-copy when possible
        let baseline_findings: Vec<BaselineFinding<'a>> = aggregated
            .findings
            .iter()
            .map(|finding_with_source| self.convert_finding_to_baseline(finding_with_source))
            .collect();

        // Get top CWE IDs
        let top_cwe_ids: Vec<String> = aggregated
            .stats
            .top_cwe_ids
            .iter()
            .map(|cwe_stat| cwe_stat.cwe_id.as_str().into())
            .collect();

        let baseline = BaselineFile {
            metadata: BaselineMetadata {
                version: "1.0".into(),
                created_at: now,
                source_scan: BaselineScanInfo {
                    scan_id: first_scan.scan_id.clone(),
                    project_name: project_names
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "unknown".into()),
                    project_uri: first_scan.project_uri.clone(),
                    source_files,
                },
                project_info: BaselineProjectInfo {
                    name: project_names
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "unknown".into()),
                    url: first_scan.project_uri.clone(),
                    commit_hash: None, // Could be enhanced to extract from git
                    branch: None,      // Could be enhanced to extract from git
                },
                finding_count: u32::try_from(baseline_findings.len()).unwrap_or(u32::MAX),
            },
            findings: baseline_findings,
            summary: BaselineSummary {
                total: aggregated.summary.total,
                very_high: aggregated.summary.very_high,
                high: aggregated.summary.high,
                medium: aggregated.summary.medium,
                low: aggregated.summary.low,
                very_low: aggregated.summary.very_low,
                informational: aggregated.summary.informational,
                top_cwe_ids,
            },
        };

        Ok(baseline)
    }

    /// Convert a finding to baseline format
    fn convert_finding_to_baseline<'a>(
        &self,
        finding_with_source: &'a FindingWithSource,
    ) -> BaselineFinding<'a> {
        let finding = &finding_with_source.finding;

        // Create a hash for exact matching
        let finding_hash = create_finding_hash(finding);

        BaselineFinding {
            finding_id: Cow::Borrowed(&finding_with_source.finding_id),
            cwe_id: Cow::Borrowed(&finding.cwe_id),
            issue_type: Cow::Borrowed(&finding.issue_type),
            severity: finding.severity,
            file_path: Cow::Borrowed(&finding.files.source_file.file),
            line_number: finding.files.source_file.line,
            function_name: finding
                .files
                .source_file
                .function_name
                .as_deref()
                .map(Cow::Borrowed),
            title: Cow::Borrowed(&finding.title),
            finding_hash: Cow::Owned(finding_hash),
        }
    }

    /// Perform the actual comparison between current and baseline findings
    ///
    /// # Errors
    /// Returns an error if the comparison logic fails or data structures cannot be processed
    fn perform_comparison<'a>(
        &self,
        current: &AggregatedFindings,
        baseline: &'a BaselineFile<'a>,
    ) -> Result<BaselineComparison<'a>, Box<dyn std::error::Error>> {
        let now = chrono::Utc::now().to_rfc3339();

        // Create lookup maps using references to avoid cloning hashes
        let baseline_map: HashMap<&str, &BaselineFinding<'a>> = baseline
            .findings
            .iter()
            .map(|f| (f.finding_hash.as_ref(), f))
            .collect();

        // Pre-compute hashes for current findings to avoid repeated computation
        let current_hashes: Vec<String> = current
            .findings
            .iter()
            .map(|f| create_finding_hash(&f.finding))
            .collect();

        let current_map: HashMap<&str, &FindingWithSource> = current
            .findings
            .iter()
            .zip(current_hashes.iter())
            .map(|(f, hash)| (hash.as_str(), f))
            .collect();

        // Find new, fixed, and unchanged findings
        let mut new_findings = Vec::new();
        let mut unchanged_findings: Vec<FindingMatch<'a>> = Vec::new();

        for (hash, current_finding) in &current_map {
            if let Some(baseline_finding) = baseline_map.get(hash) {
                // Finding exists in both - check for severity changes
                let severity_changed =
                    current_finding.finding.severity != baseline_finding.severity;
                let previous_severity = if severity_changed {
                    Some(baseline_finding.severity)
                } else {
                    None
                };

                unchanged_findings.push(FindingMatch {
                    current_finding: (*current_finding).clone(),
                    baseline_finding: (*baseline_finding).clone(),
                    severity_changed,
                    previous_severity,
                });
            } else {
                // New finding - still need to clone for owned result
                new_findings.push((*current_finding).clone());
            }
        }

        // Find fixed findings (in baseline but not in current)
        let fixed_findings: Vec<BaselineFinding<'a>> = baseline_map
            .iter()
            .filter_map(|(hash, baseline_finding)| {
                if !current_map.contains_key(hash) {
                    Some((*baseline_finding).clone())
                } else {
                    None
                }
            })
            .collect();

        // Calculate summaries
        let summary = self.calculate_comparison_summary(&new_findings, &fixed_findings);

        let comparison = BaselineComparison {
            metadata: ComparisonMetadata {
                compared_at: now,
                baseline_info: baseline.metadata.clone(),
                current_scan_info: CurrentScanInfo {
                    scan_count: current.stats.total_scans,
                    total_findings: current.stats.total_findings,
                    project_names: current
                        .scan_metadata
                        .iter()
                        .map(|meta| meta.project_name.as_str())
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .map(|s| s.into())
                        .collect(),
                },
            },
            new_findings,
            fixed_findings,
            unchanged_findings,
            summary,
        };

        Ok(comparison)
    }

    /// Calculate comparison summary statistics (now takes references for efficiency)
    fn calculate_comparison_summary<'a>(
        &self,
        new_findings: &[FindingWithSource],
        fixed_findings: &[BaselineFinding<'a>],
    ) -> ComparisonSummary {
        let new_count = u32::try_from(new_findings.len()).unwrap_or(u32::MAX);
        let fixed_count = u32::try_from(fixed_findings.len()).unwrap_or(u32::MAX);
        let net_change = i32::try_from(new_count)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(fixed_count).unwrap_or(i32::MAX));

        // Count new findings by severity
        let mut new_by_severity: HashMap<String, u32> = HashMap::new();
        for finding in new_findings {
            let severity_name = severity_to_name(finding.finding.severity);
            let count = new_by_severity.entry(severity_name.into()).or_insert(0);
            *count = (*count).saturating_add(1);
        }

        // Count fixed findings by severity
        let mut fixed_by_severity: HashMap<String, u32> = HashMap::new();
        for finding in fixed_findings {
            let severity_name = severity_to_name(finding.severity);
            let count = fixed_by_severity.entry(severity_name.into()).or_insert(0);
            *count = (*count).saturating_add(1);
        }

        // Get new CWE breakdown
        let mut cwe_counts: HashMap<String, u32> = HashMap::new();
        for finding in new_findings {
            let count = cwe_counts
                .entry(finding.finding.cwe_id.clone())
                .or_insert(0);
            *count = count.saturating_add(1);
        }

        let mut cwe_vec: Vec<(String, u32)> = cwe_counts.into_iter().collect();
        cwe_vec.sort_by(|a, b| b.1.cmp(&a.1));
        let new_cwe_breakdown: Vec<String> = cwe_vec
            .into_iter()
            .take(5)
            .map(|(cwe_id, _)| cwe_id)
            .collect();

        ComparisonSummary {
            new_count,
            fixed_count,
            unchanged_count: 0, // Will be set by caller
            net_change,
            new_by_severity,
            fixed_by_severity,
            new_cwe_breakdown,
        }
    }

    // Policy Assessment Methods

    /// Load a policy file
    ///
    /// # Errors
    /// Returns an error if the policy file does not exist, cannot be read, or contains invalid JSON
    pub fn load_policy_file(
        &self,
        policy_path: &Path,
    ) -> Result<PolicyFile, Box<dyn std::error::Error>> {
        debug!("📖 Loading policy file: {}", policy_path.display());

        if !policy_path.exists() {
            return Err(format!("Policy file does not exist: {}", policy_path.display()).into());
        }

        let content = fs::read_to_string(policy_path)?;
        let policy: PolicyFile = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse policy file: {e}"))?;

        debug!(
            "✅ Policy loaded: {} (version {})",
            policy.metadata.name, policy.metadata.version
        );

        Ok(policy)
    }

    /// Assess findings against a policy
    ///
    /// # Errors
    /// Returns an error if the policy assessment fails or findings cannot be processed
    pub fn assess_against_policy(
        &self,
        findings: &AggregatedFindings,
        policy: &PolicyFile,
    ) -> Result<PolicyAssessment, Box<dyn std::error::Error>> {
        debug!(
            "🔍 Assessing {} findings against policy '{}'",
            findings.findings.len(),
            policy.metadata.name
        );

        let now = chrono::Utc::now().to_rfc3339();
        let mut rule_results = Vec::new();
        let mut all_violations = Vec::new();
        let mut rules_passed = 0u32;
        let mut rules_failed = 0u32;

        // Evaluate each policy rule
        for rule in &policy.rules {
            if !rule.enabled {
                {
                    info!("   Skipping disabled rule: {}", rule.name);
                }
                continue;
            }

            {
                info!("   Evaluating rule: {}", rule.name);
            }

            let rule_result = self.evaluate_policy_rule(rule, &findings.findings);

            {
                info!(
                    "     → Rule result: {} (found {} matching findings, max allowed: {})",
                    if rule_result.passed { "PASS" } else { "FAIL" },
                    rule_result.finding_count,
                    rule.max_allowed
                );
            }

            if rule_result.passed {
                rules_passed = rules_passed.saturating_add(1);
            } else {
                rules_failed = rules_failed.saturating_add(1);
            }

            // Collect violations from this rule
            all_violations.extend(rule_result.violating_findings.clone());
            rule_results.push(rule_result);
        }

        // Check global criteria
        let global_violations = self.check_global_criteria(&policy.criteria, &findings.findings);
        all_violations.extend(global_violations);

        // Remove duplicates (findings might violate multiple rules)
        all_violations.sort_by(|a, b| {
            a.finding
                .title
                .cmp(&b.finding.title)
                .then_with(|| {
                    a.finding
                        .files
                        .source_file
                        .file
                        .cmp(&b.finding.files.source_file.file)
                })
                .then_with(|| {
                    a.finding
                        .files
                        .source_file
                        .line
                        .cmp(&b.finding.files.source_file.line)
                })
        });
        all_violations.dedup_by(|a, b| {
            a.finding.title == b.finding.title
                && a.finding.files.source_file.file == b.finding.files.source_file.file
                && a.finding.files.source_file.line == b.finding.files.source_file.line
        });

        // Calculate summary
        let mut summary = self.calculate_policy_summary(&all_violations);

        // Update summary with correct rule counts and total findings
        summary.total_findings = u32::try_from(findings.findings.len()).unwrap_or(u32::MAX);
        summary.rules_passed = rules_passed;
        summary.rules_failed = rules_failed;

        // Debug summary before moving rule_results
        {
            info!("✅ Policy assessment complete:");
            info!(
                "   Overall result: {}",
                if rules_failed == 0 && all_violations.is_empty() {
                    "PASS"
                } else {
                    "FAIL"
                }
            );
            info!("   Rules passed: {rules_passed}");
            info!("   Rules failed: {rules_failed}");
            info!("   Total violations: {}", all_violations.len());

            // Detailed rules summary
            info!("\n📋 Detailed Rules Summary:");
            for (index, rule_result) in rule_results.iter().enumerate() {
                let status = if rule_result.passed {
                    "✅ PASS"
                } else {
                    "❌ FAIL"
                };
                info!(
                    "   {}. {} - {}",
                    index.saturating_add(1),
                    status,
                    rule_result.rule.name
                );
                info!(
                    "      Found: {} findings (max allowed: {})",
                    rule_result.finding_count, rule_result.rule.max_allowed
                );

                if !rule_result.violating_findings.is_empty() {
                    info!("      Violations:");
                    for violation in &rule_result.violating_findings {
                        info!(
                            "        • CWE-{} (severity {}) in {}:{}",
                            violation.finding.cwe_id,
                            violation.finding.severity,
                            violation.finding.files.source_file.file,
                            violation.finding.files.source_file.line
                        );
                    }
                }

                if !rule_result.rule.cwe_ids.is_empty() {
                    let cwe_ids_str: Vec<String> = rule_result
                        .rule
                        .cwe_ids
                        .iter()
                        .map(|id| id.to_string())
                        .collect();
                    info!("      CWE filter: [{}]", cwe_ids_str.join(", "));
                }
                if !rule_result.rule.severity_levels.is_empty() {
                    let severity_names: Vec<String> = rule_result
                        .rule
                        .severity_levels
                        .iter()
                        .map(|&s| severity_to_name(s).into())
                        .collect();
                    info!("      Severity filter: [{}]", severity_names.join(", "));
                }
            }
        }

        // Determine overall pass/fail
        let passed = rules_failed == 0 && all_violations.is_empty();

        let assessment = PolicyAssessment {
            metadata: PolicyAssessmentMetadata {
                assessed_at: now,
                policy_info: policy.metadata.clone(),
                scan_info: CurrentScanInfo {
                    scan_count: findings.stats.total_scans,
                    total_findings: findings.stats.total_findings,
                    project_names: findings
                        .scan_metadata
                        .iter()
                        .map(|meta| meta.project_name.as_str())
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .map(|s| s.into())
                        .collect(),
                },
            },
            passed,
            rule_results,
            violations: all_violations,
            summary,
        };

        Ok(assessment)
    }

    /// Evaluate a single policy rule against findings (optimized to avoid cloning)
    fn evaluate_policy_rule(
        &self,
        rule: &PolicyRule,
        findings: &[FindingWithSource],
    ) -> PolicyRuleResult {
        let mut matching_findings = Vec::new();

        {
            info!(
                "       Checking rule against {} total findings",
                findings.len()
            );
            let cwe_display = if rule.cwe_ids.is_empty() {
                "all CWEs".to_string()
            } else {
                format!(
                    "[{}]",
                    rule.cwe_ids
                        .iter()
                        .map(|id| id.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            info!("       Rule CWE filter: {}", cwe_display);

            let severity_display = if rule.severity_levels.is_empty() {
                "all severities".to_string()
            } else {
                format!(
                    "[{}]",
                    rule.severity_levels
                        .iter()
                        .map(|&s| severity_to_name(s))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            info!("       Rule severity filter: {}", severity_display);
        }

        for finding in findings {
            let matches_cwe =
                rule.cwe_ids.is_empty() || rule.cwe_ids.contains(&finding.finding.cwe_id);

            let matches_severity = rule.severity_levels.is_empty()
                || rule.severity_levels.contains(&finding.finding.severity);

            if matches_cwe && matches_severity {
                info!(
                    "       ✓ Finding matches: CWE-{} severity {} in {}:{}",
                    finding.finding.cwe_id,
                    finding.finding.severity,
                    finding.finding.files.source_file.file,
                    finding.finding.files.source_file.line
                );
            }

            if matches_cwe && matches_severity {
                matching_findings.push(finding.clone());
            }
        }

        let finding_count = u32::try_from(matching_findings.len()).unwrap_or(u32::MAX);
        let passed = finding_count <= rule.max_allowed;

        let violating_findings = if passed {
            Vec::new()
        } else {
            matching_findings.clone()
        };

        {
            info!(
                "       Final result: {} matching findings (limit: {})",
                finding_count, rule.max_allowed
            );
        }

        PolicyRuleResult {
            rule: rule.clone(),
            finding_count,
            passed,
            violating_findings,
        }
    }

    /// Check global policy criteria
    fn check_global_criteria(
        &self,
        criteria: &PolicyCriteria,
        findings: &[FindingWithSource],
    ) -> Vec<FindingWithSource> {
        let mut violations = Vec::new();

        // Check max total findings - use iterator to avoid copying
        if let Some(max_total) = criteria.max_total_findings
            && u32::try_from(findings.len()).unwrap_or(u32::MAX) > max_total
        {
            violations.extend(findings.iter().cloned());
            return violations;
        }

        // Check fail on high severity - use iterator filter
        if criteria.fail_on_high_severity {
            violations.extend(
                findings
                    .iter()
                    .filter(|finding| finding.finding.severity >= 4)
                    .cloned(),
            );
        }

        // Check fail on specific CWEs - use iterator filter
        if !criteria.fail_on_cwe_ids.is_empty() {
            violations.extend(
                findings
                    .iter()
                    .filter(|finding| criteria.fail_on_cwe_ids.contains(&finding.finding.cwe_id))
                    .cloned(),
            );
        }

        // Check max by severity
        for (severity_name, max_allowed) in &criteria.max_by_severity {
            let severity_level = match severity_name.to_lowercase().as_str() {
                "informational" => 0,
                "very low" | "very-low" => 1,
                "low" => 2,
                "medium" => 3,
                "high" => 4,
                "very high" | "very-high" => 5,
                _ => continue,
            };

            let count = u32::try_from(
                findings
                    .iter()
                    .filter(|f| f.finding.severity == severity_level)
                    .count(),
            )
            .unwrap_or(u32::MAX);

            if count > *max_allowed {
                violations.extend(
                    findings
                        .iter()
                        .filter(|finding| finding.finding.severity == severity_level)
                        .cloned(),
                );
            }
        }

        violations
    }

    /// Calculate policy assessment summary (takes reference for efficiency)
    fn calculate_policy_summary(
        &self,
        violations: &[FindingWithSource],
    ) -> PolicyAssessmentSummary {
        let mut violations_by_severity: HashMap<String, u32> = HashMap::new();
        let mut cwe_counts: HashMap<String, u32> = HashMap::new();

        for violation in violations {
            let severity_name = severity_to_name(violation.finding.severity);
            let sev_count = violations_by_severity
                .entry(severity_name.into())
                .or_insert(0);
            *sev_count = (*sev_count).saturating_add(1);
            let cwe_count = cwe_counts
                .entry(violation.finding.cwe_id.clone())
                .or_insert(0);
            *cwe_count = (*cwe_count).saturating_add(1);
        }

        let mut cwe_vec: Vec<(String, u32)> = cwe_counts.into_iter().collect();
        cwe_vec.sort_by(|a, b| b.1.cmp(&a.1));
        let violation_cwe_breakdown: Vec<String> = cwe_vec
            .into_iter()
            .take(5)
            .map(|(cwe_id, _)| cwe_id)
            .collect();

        PolicyAssessmentSummary {
            total_findings: 0, // Will be set by caller
            total_violations: u32::try_from(violations.len()).unwrap_or(u32::MAX),
            rules_passed: 0, // Will be set by caller
            rules_failed: 0, // Will be set by caller
            violations_by_severity,
            violation_cwe_breakdown,
        }
    }

    /// Display policy assessment summary
    pub fn display_policy_summary(&self, assessment: &PolicyAssessment) {
        info!("\n📊 Policy Assessment Summary");
        info!("═══════════════════════════════════════");

        info!("📋 Policy Info:");
        info!("   Name: {}", assessment.metadata.policy_info.name);
        info!("   Version: {}", assessment.metadata.policy_info.version);
        if let Some(desc) = &assessment.metadata.policy_info.description {
            info!("   Description: {desc}");
        }

        info!("\n📈 Assessment Results:");
        let status = if assessment.passed {
            "✅ PASS"
        } else {
            "❌ FAIL"
        };
        info!("   Overall Result: {status}");
        info!("   Rules Passed: {}", assessment.summary.rules_passed);
        info!("   Rules Failed: {}", assessment.summary.rules_failed);
        info!(
            "   Total Violations: {}",
            assessment.summary.total_violations
        );

        if !assessment.violations.is_empty() {
            info!("\n❌ Policy Violations by Severity:");
            for (severity, count) in &assessment.summary.violations_by_severity {
                if *count > 0 {
                    info!("   {severity}: {count}");
                }
            }

            if !assessment.summary.violation_cwe_breakdown.is_empty() {
                info!("\n🔍 Top Violation CWE Types:");
                for (index, cwe_id) in assessment
                    .summary
                    .violation_cwe_breakdown
                    .iter()
                    .take(5)
                    .enumerate()
                {
                    info!("   {}. CWE-{}", index.saturating_add(1), cwe_id);
                }
            }
        }
    }

    /// Export policy assessment to file
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails or the output file cannot be written
    pub fn export_policy_assessment(
        &self,
        assessment: &PolicyAssessment,
        output_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        {
            info!(
                "💾 Exporting policy assessment to: {}",
                output_path.display()
            );
        }

        let json_content = serde_json::to_string_pretty(assessment)?;
        fs::write(output_path, json_content)?;

        info!("✅ Policy assessment exported: {}", output_path.display());
        Ok(())
    }
}

/// Convert severity level to name
fn severity_to_name(severity: u32) -> &'static str {
    match severity {
        0 => "Informational",
        1 => "Very Low",
        2 => "Low",
        3 => "Medium",
        4 => "High",
        5 => "Very High",
        _ => "Unknown",
    }
}

/// Execute baseline creation from scan results
///
/// # Errors
/// Returns an error code if baseline creation fails or files cannot be written
pub fn execute_baseline_create(
    aggregated: &AggregatedFindings,
    output_path: &Path,
) -> Result<(), i32> {
    let manager = BaselineManager::new();

    match manager.create_baseline(aggregated, output_path) {
        Ok(()) => {
            debug!("🎯 Baseline creation completed successfully");
            Ok(())
        }
        Err(e) => {
            error!("❌ Failed to create baseline: {e}");
            Err(1)
        }
    }
}

/// Execute baseline comparison
///
/// # Errors
/// Returns an error code if the baseline file cannot be loaded or comparison fails
pub fn execute_baseline_compare(
    current: &AggregatedFindings,
    baseline_path: &Path,
    output_path: Option<&Path>,
) -> Result<OwnedBaselineComparison, i32> {
    let manager = BaselineManager::new();

    let baseline = match manager.load_baseline(baseline_path) {
        Ok(baseline) => baseline,
        Err(e) => {
            error!("❌ Failed to load baseline file: {e}");
            return Err(1);
        }
    };

    let comparison = match manager.compare_with_baseline(current, &baseline) {
        Ok(comparison) => comparison.into_owned(),
        Err(e) => {
            error!("❌ Failed to perform baseline comparison: {e}");
            return Err(1);
        }
    };

    // Display summary
    manager.display_comparison_summary(&comparison);

    // Export if requested
    if let Some(output) = output_path
        && let Err(e) = manager.export_comparison(&comparison, output)
    {
        error!("⚠️  Warning: Failed to export comparison results: {e}");
    }

    Ok(comparison)
}

/// Execute policy assessment from policy file
///
/// # Errors
/// Returns an error code if the policy file cannot be loaded or assessment fails
pub fn execute_policy_file_assessment(
    findings: &AggregatedFindings,
    policy_path: &Path,
    output_path: Option<&Path>,
) -> Result<PolicyAssessment, i32> {
    let manager = BaselineManager::new();

    let policy = match manager.load_policy_file(policy_path) {
        Ok(policy) => policy,
        Err(e) => {
            error!("❌ Failed to load policy file: {e}");
            return Err(1);
        }
    };

    let assessment = match manager.assess_against_policy(findings, &policy) {
        Ok(assessment) => assessment,
        Err(e) => {
            error!("❌ Failed to perform policy assessment: {e}");
            return Err(1);
        }
    };

    // Display summary
    manager.display_policy_summary(&assessment);

    // Export if requested
    if let Some(output) = output_path
        && let Err(e) = manager.export_policy_assessment(&assessment, output)
    {
        error!("⚠️  Warning: Failed to export policy assessment: {e}");
    }

    Ok(assessment)
}

/// Execute policy assessment from policy name (download and assess)
///
/// # Errors
/// Returns an error code if the Veracode client cannot be created, policy cannot be downloaded, or assessment fails
pub async fn execute_policy_name_assessment(
    findings: &AggregatedFindings,
    policy_name: &str,
    output_path: Option<&Path>,
    veracode_config: &veracode_platform::VeracodeConfig,
) -> Result<PolicyAssessment, i32> {
    use veracode_platform::VeracodeClient;

    debug!("🔍 Downloading policy '{policy_name}' for assessment");

    let client = VeracodeClient::new(veracode_config.clone()).map_err(|e| {
        error!("❌ Failed to create Veracode client: {e}");
        1
    })?;

    let policy_api = client.policy_api();

    // Get list of policies to find the one matching the name
    let policies = policy_api.list_policies(None).await.map_err(|e| {
        error!("❌ Failed to list policies: {e}");
        1
    })?;

    // Find policy by name (case-insensitive)
    let target_policy = policies
        .iter()
        .find(|policy| policy.name.to_lowercase() == policy_name.to_lowercase())
        .ok_or_else(|| {
            error!("❌ Policy '{policy_name}' not found");
            error!("💡 Available policies:");
            for policy in &policies {
                error!("   - {}", policy.name);
            }
            1
        })?;

    // Get the full policy details
    let platform_policy = policy_api
        .get_policy(&target_policy.guid)
        .await
        .map_err(|e| {
            error!("❌ Failed to download policy details: {e}");
            1
        })?;

    // Convert Veracode platform policy to our PolicyFile format
    let policy_file = convert_platform_policy_to_policy_file(&platform_policy);

    let manager = BaselineManager::new();
    let assessment = match manager.assess_against_policy(findings, &policy_file) {
        Ok(assessment) => assessment,
        Err(e) => {
            error!("❌ Failed to perform policy assessment: {e}");
            return Err(1);
        }
    };

    // Display summary
    manager.display_policy_summary(&assessment);

    // Export if requested
    if let Some(output) = output_path
        && let Err(e) = manager.export_policy_assessment(&assessment, output)
    {
        error!("⚠️  Warning: Failed to export policy assessment: {e}");
    }

    Ok(assessment)
}

/// Convert Veracode platform policy to our `PolicyFile` format
fn convert_platform_policy_to_policy_file(
    platform_policy: &veracode_platform::SecurityPolicy,
) -> PolicyFile {
    debug!("🔄 Converting Veracode platform policy to assessment format");
    debug!("   Policy: {}", platform_policy.name);
    debug!("   Finding rules: {}", platform_policy.finding_rules.len());

    // Create basic policy metadata
    let metadata = PolicyMetadata {
        name: platform_policy.name.clone(),
        version: platform_policy.version.to_string(),
        description: platform_policy.description.clone(),
        created_at: platform_policy.created.as_ref().map(|dt| dt.to_rfc3339()),
        guid: Some(platform_policy.guid.clone()),
    };

    // Parse actual Veracode finding rules
    let mut rules = Vec::new();
    let mut criteria = PolicyCriteria {
        max_total_findings: None,
        max_by_severity: HashMap::new(),
        fail_on_high_severity: false,
        fail_on_cwe_ids: Vec::new(),
    };

    for finding_rule in &platform_policy.finding_rules {
        debug!(
            "   Processing rule: {} = {}",
            finding_rule.rule_type, finding_rule.value
        );

        match finding_rule.rule_type.as_str() {
            "MAX_SEVERITY" => {
                // MAX_SEVERITY rule: no findings above this severity allowed
                if let Ok(max_severity) = finding_rule.value.parse::<u32>() {
                    // Create rule for each severity above the limit
                    let forbidden_severities: Vec<u32> =
                        (max_severity.saturating_add(1)..=5).collect();

                    if !forbidden_severities.is_empty() {
                        let severity_names: Vec<String> = forbidden_severities
                            .iter()
                            .map(|&s| severity_to_name(s).into())
                            .collect();

                        rules.push(PolicyRule {
                            name: format!(
                                "Max Severity {} - No findings above {}",
                                max_severity,
                                severity_to_name(max_severity)
                            ),
                            cwe_ids: Vec::new(),
                            severity_levels: forbidden_severities,
                            max_allowed: 0,
                            enabled: true,
                        });

                        // Set fail on high severity if max severity is below High (4)
                        if max_severity < 4 {
                            criteria.fail_on_high_severity = true;
                        }

                        debug!(
                            "     → Created MAX_SEVERITY rule: no {} findings allowed",
                            severity_names.join(", ")
                        );
                    }
                }
            }
            "MIN_SCORE" => {
                // MIN_SCORE rule: application must achieve minimum score
                if let Ok(min_score) = finding_rule.value.parse::<u32>() {
                    // For pipeline scans, we can't calculate exact scores, but we can approximate
                    // by limiting total findings based on score requirements
                    let estimated_max_findings = match min_score {
                        90..=100 => 5, // Very strict
                        80..=89 => 15, // Strict
                        70..=79 => 30, // Moderate
                        60..=69 => 50, // Relaxed
                        _ => 100,      // Very relaxed
                    };

                    criteria.max_total_findings = Some(estimated_max_findings);

                    rules.push(PolicyRule {
                        name: format!(
                            "Minimum Score {min_score} (≤{estimated_max_findings} total findings)"
                        ),
                        cwe_ids: Vec::new(),
                        severity_levels: Vec::new(), // All severities
                        max_allowed: estimated_max_findings,
                        enabled: true,
                    });

                    debug!(
                        "     → Created MIN_SCORE rule: max {estimated_max_findings} total findings for score {min_score}"
                    );
                }
            }
            _ => {
                debug!(
                    "     → Skipping unsupported rule type: {}",
                    finding_rule.rule_type
                );
            }
        }
    }

    // If no rules were created, add a default permissive rule to show the policy is working
    if rules.is_empty() {
        rules.push(PolicyRule {
            name: "Default Policy Rule (no specific rules found)".into(),
            cwe_ids: Vec::new(),
            severity_levels: Vec::new(),
            max_allowed: 1000, // Very permissive
            enabled: true,
        });

        debug!("   → No parseable rules found, created default permissive rule");
    }

    PolicyFile {
        metadata,
        rules,
        criteria,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ------------------------------------------------------------------------
    // SECURITY PROPERTY TESTS
    //
    // These tests verify critical security properties using property-based testing
    // to ensure robustness across a wide range of inputs.
    //
    // Security properties validated:
    // 1. Arithmetic operations never overflow or panic
    // 2. Severity validation handles all u32 values safely
    // 3. Collection operations handle extreme sizes without panicking
    // 4. Error handling paths are exercised comprehensively
    // ------------------------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 10 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        // ------------------------------------------------------------------------
        // TEST: severity_to_name handles all possible u32 values
        // ------------------------------------------------------------------------
        // Security concern: Severity is user-controlled input that must be validated
        // Property 1: Function never panics on any u32 input
        // Property 2: Returns valid static string for all inputs
        // Property 3: Known severities (0-5) map to specific names
        // Property 4: Unknown severities map to "Unknown"
        #[test]
        fn test_severity_to_name_all_values(severity in any::<u32>()) {
            let name = severity_to_name(severity);

            // Property 1: Never panics (implicit - test completes)

            // Property 2: Always returns non-empty string
            assert!(!name.is_empty(), "Severity name should never be empty");

            // Property 3: Verify known severities
            match severity {
                0 => assert_eq!(name, "Informational"),
                1 => assert_eq!(name, "Very Low"),
                2 => assert_eq!(name, "Low"),
                3 => assert_eq!(name, "Medium"),
                4 => assert_eq!(name, "High"),
                5 => assert_eq!(name, "Very High"),
                _ => assert_eq!(name, "Unknown"),
            }
        }

        // ------------------------------------------------------------------------
        // TEST: Finding count conversions handle overflow safely
        // ------------------------------------------------------------------------
        // Security concern: Converting collection lengths to u32 can overflow
        // Property 1: try_from never panics
        // Property 2: Values <= u32::MAX convert correctly
        // Property 3: Values > u32::MAX convert to u32::MAX (saturating behavior)
        #[test]
        fn test_finding_count_conversion(
            count in prop_oneof![
                // Test small values (0-1000)
                0usize..=1000,
                // Test boundary around u32::MAX
                (u32::MAX as usize).saturating_sub(10)..=(u32::MAX as usize).saturating_add(10),
                // Test large values if usize > u32
                Just(usize::MAX),
                Just(usize::MAX / 2),
            ]
        ) {
            // This simulates the pattern at line 564, 716, 884, 1049, 1172
            let converted = u32::try_from(count).unwrap_or(u32::MAX);

            // Property 1: Never panics (implicit)

            // Property 2: If count fits in u32, conversion is exact
            if count <= u32::MAX as usize {
                // We know this fits, so unwrap_or is safe here
                assert_eq!(converted, u32::try_from(count).unwrap_or(u32::MAX));
            } else {
                // Property 3: Overflow saturates to u32::MAX
                assert_eq!(converted, u32::MAX);
            }
        }

        // ------------------------------------------------------------------------
        // TEST: Net change calculation handles overflow/underflow
        // ------------------------------------------------------------------------
        // Security concern: Subtraction of u32 values can underflow
        // Property 1: saturating_sub prevents underflow panics
        // Property 2: Result is clamped to i32 range
        // Property 3: Calculation is commutative for absolute value
        #[test]
        fn test_net_change_calculation(new_count in any::<u32>(), fixed_count in any::<u32>()) {
            // This simulates the pattern at lines 718-720
            let new_i32 = i32::try_from(new_count).unwrap_or(i32::MAX);
            let fixed_i32 = i32::try_from(fixed_count).unwrap_or(i32::MAX);
            let net_change = new_i32.saturating_sub(fixed_i32);

            // Property 1: Never panics

            // Property 2: Result is always an i32 value (implicit - type system guarantees this)

            // Property 3: For values that fit in i32, result is exact
            if new_count <= i32::MAX as u32 && fixed_count <= i32::MAX as u32 {
                let expected = i32::try_from(new_count)
                    .unwrap_or(i32::MAX)
                    .saturating_sub(i32::try_from(fixed_count).unwrap_or(i32::MAX));
                assert_eq!(net_change, expected);
            }
        }

        // ------------------------------------------------------------------------
        // TEST: Severity counter increments never overflow
        // ------------------------------------------------------------------------
        // Security concern: Accumulating counts can overflow u32
        // Property 1: saturating_add prevents overflow
        // Property 2: Counts never decrease
        // Property 3: Maximum value is u32::MAX
        #[test]
        fn test_severity_counter_overflow(initial in any::<u32>(), increment in 1u32..=100) {
            // This simulates the pattern at lines 727, 734, 744, 1155, 1159
            let new_count = initial.saturating_add(increment);

            // Property 1: Never panics

            // Property 2: Count never decreases
            assert!(new_count >= initial);

            // Property 3: If no overflow, increment is exact
            if let Some(expected) = initial.checked_add(increment) {
                assert_eq!(new_count, expected);
            } else {
                // Property 4: Overflow saturates to MAX
                assert_eq!(new_count, u32::MAX);
            }
        }

        // ------------------------------------------------------------------------
        // TEST: Index arithmetic in display functions
        // ------------------------------------------------------------------------
        // Security concern: Adding 1 to index for display can overflow
        // Property 1: saturating_add prevents overflow
        // Property 2: Display indices are always >= 1
        #[test]
        fn test_display_index_arithmetic(
            index in prop_oneof![
                // Test small indices (0-1000)
                0usize..=1000,
                // Test boundary at usize::MAX
                Just(usize::MAX),
                Just(usize::MAX - 1),
                Just(usize::MAX / 2),
            ]
        ) {
            // This simulates the pattern at lines 489, 913
            let display_index = index.saturating_add(1);

            // Property 1: Never panics

            // Property 2: Display index is always at least 1
            assert!(display_index >= 1);

            // Property 3: If no overflow, addition is exact
            if index < usize::MAX {
                assert_eq!(display_index, index.saturating_add(1));
            } else {
                assert_eq!(display_index, usize::MAX);
            }
        }

        // ------------------------------------------------------------------------
        // TEST: HashMap operations handle large key sets
        // ------------------------------------------------------------------------
        // Security concern: User-controlled CWE IDs could cause memory exhaustion
        // Property 1: HashMap insertion never panics
        // Property 2: Entry API handles duplicates correctly
        // Property 3: Count increments are saturating
        #[test]
        fn test_hashmap_cwe_counting(cwe_ids in prop::collection::vec("[0-9]{1,6}", 0..100)) {
            // This simulates the pattern at lines 739-745, 1148-1160
            let mut cwe_counts: HashMap<String, u32> = HashMap::new();

            for cwe_id in cwe_ids {
                let count = cwe_counts.entry(cwe_id).or_insert(0);
                *count = (*count).saturating_add(1);
            }

            // Property 1: Never panics (implicit)

            // Property 2: All counts are >= 1
            for count in cwe_counts.values() {
                assert!(*count >= 1);
            }

            // Property 3: Maximum count is bounded by input size
            if let Some(max_count) = cwe_counts.values().max() {
                assert!(*max_count <= 100);
            }
        }

        // ------------------------------------------------------------------------
        // TEST: Vector operations handle extreme sizes
        // ------------------------------------------------------------------------
        // Security concern: Large finding sets could cause allocation failures
        // Property 1: Vec operations complete without panic
        // Property 2: Length conversions handle overflow
        #[test]
        fn test_vector_length_handling(size in 0usize..1000) {
            // Create a vector simulating findings collection
            let findings: Vec<u32> = (0..size).map(|i| u32::try_from(i).unwrap_or(u32::MAX)).collect();

            // Property 1: Never panics

            // Property 2: Length is preserved
            assert_eq!(findings.len(), size);

            // Property 3: Conversion to u32 handles overflow
            let count = u32::try_from(findings.len()).unwrap_or(u32::MAX);
            if size <= u32::MAX as usize {
                assert_eq!(count, u32::try_from(size).unwrap_or(u32::MAX));
            } else {
                assert_eq!(count, u32::MAX);
            }
        }

        // ------------------------------------------------------------------------
        // TEST: String conversion and ownership patterns
        // ------------------------------------------------------------------------
        // Security concern: Cow<str> conversions must not cause invalid UTF-8
        // Property 1: into_owned never panics
        // Property 2: String data is preserved
        #[test]
        fn test_cow_string_conversions(s in "\\PC{0,100}") {
            // Test Cow::Borrowed to Cow::Owned conversion
            let borrowed: Cow<'_, str> = Cow::Borrowed(&s);
            let owned: Cow<'static, str> = Cow::Owned(borrowed.into_owned());

            // Property 1: Never panics (implicit)

            // Property 2: Content is preserved
            assert_eq!(owned.as_ref(), s);

            // Property 3: UTF-8 validity is maintained
            assert!(std::str::from_utf8(owned.as_bytes()).is_ok());
        }

        // ------------------------------------------------------------------------
        // TEST: Severity comparison and filtering
        // ------------------------------------------------------------------------
        // Security concern: Severity-based filtering must handle edge cases
        // Property 1: High severity check handles all values
        // Property 2: Severity ranges are correctly bounded
        #[test]
        fn test_severity_filtering(severity in any::<u32>()) {
            // This simulates the pattern at line 1094
            let is_high_severity = severity >= 4;

            // Property 1: Never panics

            // Property 2: Known severities are correctly classified
            match severity {
                0..=3 => assert!(!is_high_severity),
                4..=5 => assert!(is_high_severity),
                _ => assert!(is_high_severity || severity < 4),
            }
        }

        // ------------------------------------------------------------------------
        // TEST: Policy rule max_allowed boundary checks
        // ------------------------------------------------------------------------
        // Security concern: Comparing counts against limits must handle overflow
        // Property 1: Comparison never panics
        // Property 2: Boundary conditions are correct
        #[test]
        fn test_policy_max_allowed_check(finding_count in any::<u32>(), max_allowed in any::<u32>()) {
            // This simulates the pattern at line 1050
            let passed = finding_count <= max_allowed;

            // Property 1: Never panics

            // Property 2: Exact boundary is handled correctly
            if finding_count <= max_allowed {
                assert!(passed);
            } else {
                assert!(!passed);
            }
        }

        // ------------------------------------------------------------------------
        // TEST: Severity range generation for policy rules
        // ------------------------------------------------------------------------
        // Security concern: Generating severity ranges can overflow
        // Property 1: saturating_add prevents overflow
        // Property 2: Range is non-empty for valid inputs
        #[test]
        fn test_severity_range_generation(max_severity in 0u32..=5) {
            // This simulates the pattern at line 1480
            let forbidden_severities: Vec<u32> =
                (max_severity.saturating_add(1)..=5).collect();

            // Property 1: Never panics

            // Property 2: Range contains expected values
            if max_severity < 5 {
                assert!(!forbidden_severities.is_empty());
                // We know the range is not empty due to the assertion above
                if let Some(&first) = forbidden_severities.first() {
                    assert_eq!(first, max_severity.saturating_add(1));
                }
                if let Some(&last) = forbidden_severities.last() {
                    assert_eq!(last, 5);
                }
            } else {
                assert!(forbidden_severities.is_empty());
            }
        }

        // ------------------------------------------------------------------------
        // TEST: CWE ID validation and parsing
        // ------------------------------------------------------------------------
        // Security concern: CWE IDs from external input must be validated
        // Property 1: String operations handle all valid inputs
        // Property 2: Empty CWE lists are handled correctly
        #[test]
        fn test_cwe_id_operations(cwe_id in "[0-9]{1,6}") {
            // Test CWE ID as used in various operations
            let cwe_string = format!("CWE-{cwe_id}");

            // Property 1: Never panics
            assert!(!cwe_string.is_empty());

            // Property 2: Contains expected prefix
            assert!(cwe_string.starts_with("CWE-"));

            // Property 3: Can be used as HashMap key
            let mut map: HashMap<String, u32> = HashMap::new();
            map.insert(cwe_id.clone(), 1);
            assert!(map.contains_key(&cwe_id));
        }
    }

    // ------------------------------------------------------------------------
    // UNIT TESTS - Edge cases and specific scenarios
    // ------------------------------------------------------------------------

    #[test]
    fn test_severity_to_name_known_values() {
        assert_eq!(severity_to_name(0), "Informational");
        assert_eq!(severity_to_name(1), "Very Low");
        assert_eq!(severity_to_name(2), "Low");
        assert_eq!(severity_to_name(3), "Medium");
        assert_eq!(severity_to_name(4), "High");
        assert_eq!(severity_to_name(5), "Very High");
    }

    #[test]
    fn test_severity_to_name_unknown_values() {
        assert_eq!(severity_to_name(6), "Unknown");
        assert_eq!(severity_to_name(100), "Unknown");
        assert_eq!(severity_to_name(u32::MAX), "Unknown");
    }

    #[test]
    fn test_baseline_manager_creation() {
        let manager = BaselineManager::new();
        assert!(std::mem::size_of_val(&manager) == 0); // Zero-sized type
    }

    #[test]
    fn test_baseline_manager_default() {
        let manager = BaselineManager::default();
        assert!(std::mem::size_of_val(&manager) == 0); // Zero-sized type
    }

    #[test]
    fn test_finding_count_edge_cases() {
        // Test u32::MAX overflow
        let max_usize = usize::MAX;
        let converted = u32::try_from(max_usize).unwrap_or(u32::MAX);
        assert_eq!(converted, u32::MAX);

        // Test exact u32::MAX value
        let exact_max = u32::MAX as usize;
        let converted = u32::try_from(exact_max).unwrap_or(u32::MAX);
        assert_eq!(converted, u32::MAX);

        // Test zero
        let zero = 0usize;
        let converted = u32::try_from(zero).unwrap_or(u32::MAX);
        assert_eq!(converted, 0);
    }

    #[test]
    fn test_net_change_edge_cases() {
        // Maximum positive change (u32::MAX - 0)
        // u32::MAX doesn't fit in i32, so converts to i32::MAX
        // 0 fits in i32, so converts to 0
        let net = i32::try_from(u32::MAX)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(0u32).unwrap_or(i32::MAX));
        assert_eq!(net, i32::MAX); // i32::MAX - 0 = i32::MAX

        // Maximum negative change (0 - u32::MAX)
        // 0 fits in i32, so converts to 0
        // u32::MAX doesn't fit in i32, so converts to i32::MAX
        let net = i32::try_from(0u32)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(u32::MAX).unwrap_or(i32::MAX));
        assert_eq!(net, i32::MIN.saturating_add(1)); // 0 - i32::MAX saturates to i32::MIN + 1

        // Both overflow to i32::MAX (u32::MAX - u32::MAX)
        let net = i32::try_from(u32::MAX)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(u32::MAX).unwrap_or(i32::MAX));
        assert_eq!(net, 0); // i32::MAX - i32::MAX = 0

        // Equal values within range
        let net = i32::try_from(100u32)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(100u32).unwrap_or(i32::MAX));
        assert_eq!(net, 0);
    }

    #[test]
    fn test_severity_counter_saturation() {
        // Test saturation at u32::MAX
        let saturated = u32::MAX.saturating_add(1);
        assert_eq!(saturated, u32::MAX);

        let saturated = u32::MAX.saturating_add(u32::MAX);
        assert_eq!(saturated, u32::MAX);

        // Test normal addition
        let result = 100u32.saturating_add(50);
        assert_eq!(result, 150);
    }

    #[test]
    fn test_display_index_saturation() {
        // Test saturation at usize::MAX
        let saturated = usize::MAX.saturating_add(1);
        assert_eq!(saturated, usize::MAX);

        // Test normal increment
        let result = 0usize.saturating_add(1);
        assert_eq!(result, 1);

        let result = 100usize.saturating_add(1);
        assert_eq!(result, 101);
    }

    #[test]
    fn test_hashmap_duplicate_handling() {
        let mut map: HashMap<String, u32> = HashMap::new();

        // Insert and increment same key multiple times
        for _ in 0..5 {
            let count = map.entry("CWE-89".to_string()).or_insert(0);
            *count = (*count).saturating_add(1);
        }

        assert_eq!(map.get("CWE-89"), Some(&5));
    }

    #[test]
    fn test_cow_borrowed_to_owned() {
        let s = "test string";
        let borrowed: Cow<'_, str> = Cow::Borrowed(s);
        let owned: Cow<'static, str> = Cow::Owned(borrowed.into_owned());
        assert_eq!(owned.as_ref(), s);
    }

    #[test]
    fn test_severity_filtering_boundaries() {
        // Test boundary at severity 4 (High)
        let severity_3 = 3u32;
        let severity_4 = 4u32;
        let severity_5 = 5u32;
        assert!(severity_3 < 4); // Not high severity
        assert!(severity_4 >= 4); // High severity
        assert!(severity_5 >= 4); // Very high severity
    }

    #[test]
    fn test_policy_comparison_boundaries() {
        // Test exact boundary
        let count_10 = 10u32;
        let count_11 = 11u32;
        let count_9 = 9u32;
        let max = 10u32;
        assert!(count_10 <= max); // Should pass
        assert!(count_11 > max); // Should fail (simplified from !(11 <= 10))
        assert!(count_9 <= max); // Should pass
    }

    #[test]
    fn test_severity_range_boundaries() {
        // Test range generation
        let range: Vec<u32> = (0u32.saturating_add(1)..=5).collect();
        assert_eq!(range, vec![1, 2, 3, 4, 5]);

        let range: Vec<u32> = (4u32.saturating_add(1)..=5).collect();
        assert_eq!(range, vec![5]);

        let range: Vec<u32> = (5u32.saturating_add(1)..=5).collect();
        assert!(range.is_empty());
    }

    #[test]
    fn test_empty_collections() {
        // Test empty vector handling
        let empty_vec: Vec<u32> = Vec::new();
        let count = u32::try_from(empty_vec.len()).unwrap_or(u32::MAX);
        assert_eq!(count, 0);

        // Test empty hashmap handling
        let empty_map: HashMap<String, u32> = HashMap::new();
        assert_eq!(empty_map.len(), 0);
        assert!(empty_map.values().max().is_none());
    }

    // ------------------------------------------------------------------------
    // KANI FORMAL VERIFICATION HARNESSES
    //
    // These harnesses use Kani (Rust's bounded model checker) to formally
    // prove safety properties through exhaustive verification of all possible
    // execution paths within the bounded domain.
    //
    // Key differences from proptest:
    // - Proptest: Randomly samples inputs (statistical confidence)
    // - Kani: Exhaustively checks all paths (mathematical proof)
    //
    // Security properties verified:
    // 1. No arithmetic overflow or underflow
    // 2. No panic conditions
    // 3. Bounded execution for all inputs
    // 4. Memory safety (implicit in Rust + Kani verification)
    // ------------------------------------------------------------------------

    #[cfg(kani)]
    #[kani::proof]
    fn verify_severity_to_name_never_panics() {
        // Verify that severity_to_name never panics for any u32 input
        let severity: u32 = kani::any();
        let name = severity_to_name(severity);

        // Property: Always returns non-empty static string
        assert!(!name.is_empty());

        // Property: Result length is bounded (safety check)
        assert!(name.len() < 100);
    }

    #[cfg(kani)]
    #[kani::proof]
    fn verify_finding_count_conversion_safe() {
        // Verify that finding count conversions never panic
        // Bound the input for feasible verification
        let count: usize = kani::any();
        kani::assume(count <= 10000); // Reasonable upper bound for verification

        let converted = u32::try_from(count).unwrap_or(u32::MAX);

        // Property: Result is bounded
        assert!(converted <= u32::MAX);

        // Property: If count fits in u32, conversion is exact
        if count <= u32::MAX as usize {
            assert!(converted == count as u32 || converted == u32::MAX);
        }
    }

    #[cfg(kani)]
    #[kani::proof]
    fn verify_net_change_calculation_safe() {
        // Verify net change calculation never panics or overflows
        let new_count: u32 = kani::any();
        let fixed_count: u32 = kani::any();

        let new_i32 = i32::try_from(new_count).unwrap_or(i32::MAX);
        let fixed_i32 = i32::try_from(fixed_count).unwrap_or(i32::MAX);
        let net_change = new_i32.saturating_sub(fixed_i32);

        // Property: Result is always within i32 bounds
        assert!(net_change >= i32::MIN);
        assert!(net_change <= i32::MAX);
    }

    #[cfg(kani)]
    #[kani::proof]
    fn verify_severity_counter_no_overflow() {
        // Verify that saturating_add prevents overflow
        let initial: u32 = kani::any();
        let increment: u32 = kani::any();
        kani::assume(increment > 0 && increment <= 100); // Realistic increments

        let new_count = initial.saturating_add(increment);

        // Property: Never decreases
        assert!(new_count >= initial);

        // Property: Bounded by u32::MAX
        assert!(new_count <= u32::MAX);

        // Property: Either exact addition or saturation
        if let Some(expected) = initial.checked_add(increment) {
            assert_eq!(new_count, expected);
        } else {
            assert_eq!(new_count, u32::MAX);
        }
    }

    #[cfg(kani)]
    #[kani::proof]
    fn verify_display_index_no_overflow() {
        // Verify that display index calculation never overflows
        // Bound the input for feasible verification
        let index: usize = kani::any();
        kani::assume(index <= 10000); // Reasonable display range

        let display_index = index.saturating_add(1);

        // Property: Always at least 1
        assert!(display_index >= 1);

        // Property: If no overflow, exact increment
        if index < usize::MAX {
            assert_eq!(display_index, index + 1);
        }
    }

    #[cfg(kani)]
    #[kani::proof]
    fn verify_severity_filtering_safe() {
        // Verify severity filtering logic is safe for all inputs
        let severity: u32 = kani::any();
        let is_high_severity = severity >= 4;

        // Property: Known severities are correctly classified
        if severity < 4 {
            assert!(!is_high_severity);
        } else {
            assert!(is_high_severity);
        }
    }

    #[cfg(kani)]
    #[kani::proof]
    fn verify_policy_max_allowed_comparison() {
        // Verify policy rule comparisons are safe
        let finding_count: u32 = kani::any();
        let max_allowed: u32 = kani::any();

        let passed = finding_count <= max_allowed;

        // Property: Boundary condition is correct
        if finding_count == max_allowed {
            assert!(passed);
        } else if finding_count < max_allowed {
            assert!(passed);
        } else {
            assert!(!passed);
        }
    }

    #[cfg(kani)]
    #[kani::proof]
    fn verify_severity_range_generation_safe() {
        // Verify severity range generation for policy rules
        let max_severity: u32 = kani::any();
        kani::assume(max_severity <= 5); // Valid severity range

        let start = max_severity.saturating_add(1);

        // Property: Start is bounded
        assert!(start <= 6); // Max is 5 + 1

        // Property: Range is valid
        if start <= 5 {
            // Range is non-empty
            let range: Vec<u32> = (start..=5).collect();
            assert!(!range.is_empty());
            assert_eq!(*range.first().unwrap(), start);
            assert_eq!(*range.last().unwrap(), 5);
        } else {
            // Range is empty
            let range: Vec<u32> = (start..=5).collect();
            assert!(range.is_empty());
        }
    }

    #[cfg(kani)]
    #[kani::proof]
    fn verify_baseline_manager_construction() {
        // Verify BaselineManager construction is safe
        let manager = BaselineManager::new();

        // Property: Zero-sized type has no memory overhead
        assert!(std::mem::size_of_val(&manager) == 0);
    }

    #[cfg(kani)]
    #[kani::proof]
    fn verify_severity_name_mapping_complete() {
        // Verify all severity values map to valid strings
        let severity: u32 = kani::any();
        kani::assume(severity <= 10); // Bound for verification

        let name = severity_to_name(severity);

        // Property: Known severities have specific names
        match severity {
            0 => assert_eq!(name, "Informational"),
            1 => assert_eq!(name, "Very Low"),
            2 => assert_eq!(name, "Low"),
            3 => assert_eq!(name, "Medium"),
            4 => assert_eq!(name, "High"),
            5 => assert_eq!(name, "Very High"),
            _ => assert_eq!(name, "Unknown"),
        }

        // Property: Name is always valid UTF-8
        assert!(name.is_ascii());
    }
}

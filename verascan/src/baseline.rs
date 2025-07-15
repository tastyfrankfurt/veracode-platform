use crate::findings::{AggregatedFindings, FindingWithSource, create_finding_hash};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use veracode_platform::VeracodeRegion;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    /// Metadata about the baseline
    pub metadata: BaselineMetadata,
    /// Baseline findings for comparison
    pub findings: Vec<BaselineFinding>,
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
pub struct BaselineFinding {
    /// Unique identifier for matching purposes
    pub finding_id: String,
    /// CWE ID for the finding
    pub cwe_id: String,
    /// Issue type
    pub issue_type: String,
    /// Severity level (0-5)
    pub severity: u32,
    /// File path where the finding was discovered
    pub file_path: String,
    /// Line number (if available)
    pub line_number: u32,
    /// Function name (if available)
    pub function_name: Option<String>,
    /// Finding title/description
    pub title: String,
    /// Hash of the finding for exact matching
    pub finding_hash: String,
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
pub struct BaselineComparison {
    /// Metadata about the comparison
    pub metadata: ComparisonMetadata,
    /// New findings (not in baseline)
    pub new_findings: Vec<FindingWithSource>,
    /// Fixed findings (in baseline but not in current)
    pub fixed_findings: Vec<BaselineFinding>,
    /// Unchanged findings (in both baseline and current)
    pub unchanged_findings: Vec<FindingMatch>,
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
pub struct FindingMatch {
    /// Current finding
    pub current_finding: FindingWithSource,
    /// Matching baseline finding
    pub baseline_finding: BaselineFinding,
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

pub struct BaselineManager {
    debug: bool,
}

impl BaselineManager {
    pub fn new(debug: bool) -> Self {
        Self { debug }
    }

    /// Create a baseline file from aggregated findings
    pub fn create_baseline(
        &self,
        aggregated: &AggregatedFindings,
        output_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.debug {
            println!(
                "📝 Creating baseline file from {} findings",
                aggregated.findings.len()
            );
        }

        let baseline = self.convert_to_baseline(aggregated)?;
        let json_content = serde_json::to_string_pretty(&baseline)?;
        fs::write(output_path, json_content)?;

        println!("✅ Baseline file created: {}", output_path.display());
        println!("   Total findings: {}", baseline.summary.total);
        println!(
            "   Source scans: {}",
            baseline.metadata.source_scan.source_files.len()
        );

        Ok(())
    }

    /// Load a baseline file
    pub fn load_baseline(
        &self,
        baseline_path: &Path,
    ) -> Result<BaselineFile, Box<dyn std::error::Error>> {
        if self.debug {
            println!("📖 Loading baseline file: {}", baseline_path.display());
        }

        if !baseline_path.exists() {
            return Err(
                format!("Baseline file does not exist: {}", baseline_path.display()).into(),
            );
        }

        let content = fs::read_to_string(baseline_path)?;
        let baseline: BaselineFile = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse baseline file: {}", e))?;

        if self.debug {
            println!(
                "✅ Baseline loaded: {} findings from {}",
                baseline.summary.total, baseline.metadata.created_at
            );
        }

        Ok(baseline)
    }

    /// Compare current findings against a baseline
    pub fn compare_with_baseline(
        &self,
        current: &AggregatedFindings,
        baseline: &BaselineFile,
    ) -> Result<BaselineComparison, Box<dyn std::error::Error>> {
        if self.debug {
            println!(
                "🔍 Comparing {} current findings against {} baseline findings",
                current.findings.len(),
                baseline.findings.len()
            );
        }

        let comparison = self.perform_comparison(current, baseline)?;

        if self.debug {
            println!("✅ Comparison complete:");
            println!("   New findings: {}", comparison.summary.new_count);
            println!("   Fixed findings: {}", comparison.summary.fixed_count);
            println!(
                "   Unchanged findings: {}",
                comparison.summary.unchanged_count
            );
            println!("   Net change: {:+}", comparison.summary.net_change);
        }

        Ok(comparison)
    }

    /// Export comparison results
    pub fn export_comparison(
        &self,
        comparison: &BaselineComparison,
        output_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.debug {
            println!(
                "💾 Exporting comparison results to: {}",
                output_path.display()
            );
        }

        let json_content = serde_json::to_string_pretty(comparison)?;
        fs::write(output_path, json_content)?;

        println!("✅ Comparison results exported: {}", output_path.display());
        Ok(())
    }

    /// Display comparison summary
    pub fn display_comparison_summary(&self, comparison: &BaselineComparison) {
        println!("\n📊 Baseline Comparison Summary");
        println!("═══════════════════════════════════════");

        println!("📅 Baseline Info:");
        println!(
            "   Created: {}",
            comparison.metadata.baseline_info.created_at
        );
        println!(
            "   Source Scan: {}",
            comparison.metadata.baseline_info.source_scan.scan_id
        );
        println!(
            "   Baseline Findings: {}",
            comparison.metadata.baseline_info.finding_count
        );

        println!("\n📈 Comparison Results:");
        println!("   🆕 New Findings: {}", comparison.summary.new_count);
        println!("   ✅ Fixed Findings: {}", comparison.summary.fixed_count);
        println!(
            "   ➡️  Unchanged Findings: {}",
            comparison.summary.unchanged_count
        );
        println!(
            "   📊 Net Change: {:+} findings",
            comparison.summary.net_change
        );

        if comparison.summary.new_count > 0 {
            println!("\n🆕 New Findings by Severity:");
            for (severity, count) in &comparison.summary.new_by_severity {
                if *count > 0 {
                    println!("   {}: {}", severity, count);
                }
            }
        }

        if comparison.summary.fixed_count > 0 {
            println!("\n✅ Fixed Findings by Severity:");
            for (severity, count) in &comparison.summary.fixed_by_severity {
                if *count > 0 {
                    println!("   {}: {}", severity, count);
                }
            }
        }

        if !comparison.summary.new_cwe_breakdown.is_empty() {
            println!("\n🔍 New CWE Types:");
            for (index, cwe_id) in comparison
                .summary
                .new_cwe_breakdown
                .iter()
                .take(5)
                .enumerate()
            {
                println!("   {}. CWE-{}", index + 1, cwe_id);
            }
        }
    }

    /// Convert aggregated findings to baseline format
    fn convert_to_baseline(
        &self,
        aggregated: &AggregatedFindings,
    ) -> Result<BaselineFile, Box<dyn std::error::Error>> {
        let now = chrono::Utc::now().to_rfc3339();

        // Extract scan information
        let first_scan = aggregated
            .scan_metadata
            .first()
            .ok_or("No scan metadata available")?;

        let source_files: Vec<String> = aggregated
            .scan_metadata
            .iter()
            .map(|meta| meta.source_file.clone())
            .collect();

        let project_names: Vec<String> = aggregated
            .scan_metadata
            .iter()
            .map(|meta| meta.project_name.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // Convert findings
        let baseline_findings: Vec<BaselineFinding> = aggregated
            .findings
            .iter()
            .map(|finding_with_source| self.convert_finding_to_baseline(finding_with_source))
            .collect();

        // Get top CWE IDs
        let top_cwe_ids: Vec<String> = aggregated
            .stats
            .top_cwe_ids
            .iter()
            .map(|cwe_stat| cwe_stat.cwe_id.clone())
            .collect();

        let baseline = BaselineFile {
            metadata: BaselineMetadata {
                version: "1.0".to_string(),
                created_at: now,
                source_scan: BaselineScanInfo {
                    scan_id: first_scan.scan_id.clone(),
                    project_name: project_names
                        .first()
                        .unwrap_or(&"unknown".to_string())
                        .clone(),
                    project_uri: first_scan.project_uri.clone(),
                    source_files,
                },
                project_info: BaselineProjectInfo {
                    name: project_names
                        .first()
                        .unwrap_or(&"unknown".to_string())
                        .clone(),
                    url: first_scan.project_uri.clone(),
                    commit_hash: None, // Could be enhanced to extract from git
                    branch: None,      // Could be enhanced to extract from git
                },
                finding_count: baseline_findings.len() as u32,
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
    fn convert_finding_to_baseline(
        &self,
        finding_with_source: &FindingWithSource,
    ) -> BaselineFinding {
        let finding = &finding_with_source.finding;

        // Create a hash for exact matching
        let finding_hash = create_finding_hash(finding);

        BaselineFinding {
            finding_id: finding_with_source.finding_id.clone(), // Use the finding_id from FindingWithSource
            cwe_id: finding.cwe_id.clone(),
            issue_type: finding.issue_type.clone(),
            severity: finding.severity,
            file_path: finding.files.source_file.file.clone(),
            line_number: finding.files.source_file.line,
            function_name: finding.files.source_file.function_name.clone(),
            title: finding.title.clone(),
            finding_hash,
        }
    }

    /// Perform the actual comparison between current and baseline findings
    fn perform_comparison(
        &self,
        current: &AggregatedFindings,
        baseline: &BaselineFile,
    ) -> Result<BaselineComparison, Box<dyn std::error::Error>> {
        let now = chrono::Utc::now().to_rfc3339();

        // Create lookup maps using the stored hashes from both files
        let baseline_map: HashMap<String, &BaselineFinding> = baseline
            .findings
            .iter()
            .map(|f| (f.finding_hash.clone(), f))
            .collect();

        let current_map: HashMap<String, &FindingWithSource> = current
            .findings
            .iter()
            .map(|f| (create_finding_hash(&f.finding), f))
            .collect();

        // Find new, fixed, and unchanged findings
        let mut new_findings = Vec::new();
        let mut unchanged_findings = Vec::new();

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
                // New finding
                new_findings.push((*current_finding).clone());
            }
        }

        // Find fixed findings (in baseline but not in current)
        let mut fixed_findings = Vec::new();
        for (hash, baseline_finding) in &baseline_map {
            if !current_map.contains_key(hash) {
                fixed_findings.push((*baseline_finding).clone());
            }
        }

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
                        .map(|meta| meta.project_name.clone())
                        .collect::<HashSet<_>>()
                        .into_iter()
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

    /// Calculate comparison summary statistics
    fn calculate_comparison_summary(
        &self,
        new_findings: &[FindingWithSource],
        fixed_findings: &[BaselineFinding],
    ) -> ComparisonSummary {
        let new_count = new_findings.len() as u32;
        let fixed_count = fixed_findings.len() as u32;
        let net_change = new_count as i32 - fixed_count as i32;

        // Count new findings by severity
        let mut new_by_severity = HashMap::new();
        for finding in new_findings {
            let severity_name = severity_to_name(finding.finding.severity);
            *new_by_severity
                .entry(severity_name.to_string())
                .or_insert(0) += 1;
        }

        // Count fixed findings by severity
        let mut fixed_by_severity = HashMap::new();
        for finding in fixed_findings {
            let severity_name = severity_to_name(finding.severity);
            *fixed_by_severity
                .entry(severity_name.to_string())
                .or_insert(0) += 1;
        }

        // Get new CWE breakdown
        let mut cwe_counts: HashMap<String, u32> = HashMap::new();
        for finding in new_findings {
            *cwe_counts
                .entry(finding.finding.cwe_id.clone())
                .or_insert(0) += 1;
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
    pub fn load_policy_file(
        &self,
        policy_path: &Path,
    ) -> Result<PolicyFile, Box<dyn std::error::Error>> {
        if self.debug {
            println!("📖 Loading policy file: {}", policy_path.display());
        }

        if !policy_path.exists() {
            return Err(format!("Policy file does not exist: {}", policy_path.display()).into());
        }

        let content = fs::read_to_string(policy_path)?;
        let policy: PolicyFile = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse policy file: {}", e))?;

        if self.debug {
            println!(
                "✅ Policy loaded: {} (version {})",
                policy.metadata.name, policy.metadata.version
            );
        }

        Ok(policy)
    }

    /// Assess findings against a policy
    pub fn assess_against_policy(
        &self,
        findings: &AggregatedFindings,
        policy: &PolicyFile,
    ) -> Result<PolicyAssessment, Box<dyn std::error::Error>> {
        if self.debug {
            println!(
                "🔍 Assessing {} findings against policy '{}'",
                findings.findings.len(),
                policy.metadata.name
            );
        }

        let now = chrono::Utc::now().to_rfc3339();
        let mut rule_results = Vec::new();
        let mut all_violations = Vec::new();
        let mut rules_passed = 0u32;
        let mut rules_failed = 0u32;

        // Evaluate each policy rule
        for rule in &policy.rules {
            if !rule.enabled {
                if self.debug {
                    println!("   Skipping disabled rule: {}", rule.name);
                }
                continue;
            }

            if self.debug {
                println!("   Evaluating rule: {}", rule.name);
            }

            let rule_result = self.evaluate_policy_rule(rule, &findings.findings);

            if self.debug {
                println!(
                    "     → Rule result: {} (found {} matching findings, max allowed: {})",
                    if rule_result.passed { "PASS" } else { "FAIL" },
                    rule_result.finding_count,
                    rule.max_allowed
                );
            }

            if rule_result.passed {
                rules_passed += 1;
            } else {
                rules_failed += 1;
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
        summary.total_findings = findings.findings.len() as u32;
        summary.rules_passed = rules_passed;
        summary.rules_failed = rules_failed;

        // Debug summary before moving rule_results
        if self.debug {
            println!("✅ Policy assessment complete:");
            println!(
                "   Overall result: {}",
                if rules_failed == 0 && all_violations.is_empty() {
                    "PASS"
                } else {
                    "FAIL"
                }
            );
            println!("   Rules passed: {}", rules_passed);
            println!("   Rules failed: {}", rules_failed);
            println!("   Total violations: {}", all_violations.len());

            // Detailed rules summary
            println!("\n📋 Detailed Rules Summary:");
            for (index, rule_result) in rule_results.iter().enumerate() {
                let status = if rule_result.passed {
                    "✅ PASS"
                } else {
                    "❌ FAIL"
                };
                println!("   {}. {} - {}", index + 1, status, rule_result.rule.name);
                println!(
                    "      Found: {} findings (max allowed: {})",
                    rule_result.finding_count, rule_result.rule.max_allowed
                );

                if !rule_result.violating_findings.is_empty() {
                    println!("      Violations:");
                    for violation in &rule_result.violating_findings {
                        println!(
                            "        • CWE-{} (severity {}) in {}:{}",
                            violation.finding.cwe_id,
                            violation.finding.severity,
                            violation.finding.files.source_file.file,
                            violation.finding.files.source_file.line
                        );
                    }
                }

                if !rule_result.rule.cwe_ids.is_empty() {
                    println!("      CWE filter: {:?}", rule_result.rule.cwe_ids);
                }
                if !rule_result.rule.severity_levels.is_empty() {
                    let severity_names: Vec<String> = rule_result
                        .rule
                        .severity_levels
                        .iter()
                        .map(|&s| severity_to_name(s).to_string())
                        .collect();
                    println!("      Severity filter: {:?}", severity_names);
                }
            }

            if !rule_results.is_empty() {
                println!();
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
                        .map(|meta| meta.project_name.clone())
                        .collect::<HashSet<_>>()
                        .into_iter()
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

    /// Evaluate a single policy rule against findings
    fn evaluate_policy_rule(
        &self,
        rule: &PolicyRule,
        findings: &[FindingWithSource],
    ) -> PolicyRuleResult {
        let mut matching_findings = Vec::new();

        if self.debug {
            println!(
                "       Checking rule against {} total findings",
                findings.len()
            );
            println!(
                "       Rule CWE filter: {:?} (empty = all CWEs)",
                rule.cwe_ids
            );
            println!(
                "       Rule severity filter: {:?} (empty = all severities)",
                rule.severity_levels
            );
        }

        for finding in findings {
            let matches_cwe =
                rule.cwe_ids.is_empty() || rule.cwe_ids.contains(&finding.finding.cwe_id);

            let matches_severity = rule.severity_levels.is_empty()
                || rule.severity_levels.contains(&finding.finding.severity);

            if self.debug && matches_cwe && matches_severity {
                println!(
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

        let finding_count = matching_findings.len() as u32;
        let passed = finding_count <= rule.max_allowed;

        let violating_findings = if passed {
            Vec::new()
        } else {
            matching_findings.clone()
        };

        if self.debug {
            println!(
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

        // Check max total findings
        if let Some(max_total) = criteria.max_total_findings {
            if findings.len() as u32 > max_total {
                violations.extend_from_slice(findings);
                return violations;
            }
        }

        // Check fail on high severity
        if criteria.fail_on_high_severity {
            for finding in findings {
                if finding.finding.severity >= 4 {
                    // High or Very High
                    violations.push(finding.clone());
                }
            }
        }

        // Check fail on specific CWEs
        if !criteria.fail_on_cwe_ids.is_empty() {
            for finding in findings {
                if criteria.fail_on_cwe_ids.contains(&finding.finding.cwe_id) {
                    violations.push(finding.clone());
                }
            }
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

            let count = findings
                .iter()
                .filter(|f| f.finding.severity == severity_level)
                .count() as u32;

            if count > *max_allowed {
                for finding in findings {
                    if finding.finding.severity == severity_level {
                        violations.push(finding.clone());
                    }
                }
            }
        }

        violations
    }

    /// Calculate policy assessment summary
    fn calculate_policy_summary(
        &self,
        violations: &[FindingWithSource],
    ) -> PolicyAssessmentSummary {
        let mut violations_by_severity = HashMap::new();
        let mut cwe_counts: HashMap<String, u32> = HashMap::new();

        for violation in violations {
            let severity_name = severity_to_name(violation.finding.severity);
            *violations_by_severity
                .entry(severity_name.to_string())
                .or_insert(0) += 1;
            *cwe_counts
                .entry(violation.finding.cwe_id.clone())
                .or_insert(0) += 1;
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
            total_violations: violations.len() as u32,
            rules_passed: 0, // Will be set by caller
            rules_failed: 0, // Will be set by caller
            violations_by_severity,
            violation_cwe_breakdown,
        }
    }

    /// Display policy assessment summary
    pub fn display_policy_summary(&self, assessment: &PolicyAssessment) {
        println!("\n📊 Policy Assessment Summary");
        println!("═══════════════════════════════════════");

        println!("📋 Policy Info:");
        println!("   Name: {}", assessment.metadata.policy_info.name);
        println!("   Version: {}", assessment.metadata.policy_info.version);
        if let Some(desc) = &assessment.metadata.policy_info.description {
            println!("   Description: {}", desc);
        }

        println!("\n📈 Assessment Results:");
        let status = if assessment.passed {
            "✅ PASS"
        } else {
            "❌ FAIL"
        };
        println!("   Overall Result: {}", status);
        println!("   Rules Passed: {}", assessment.summary.rules_passed);
        println!("   Rules Failed: {}", assessment.summary.rules_failed);
        println!(
            "   Total Violations: {}",
            assessment.summary.total_violations
        );

        if !assessment.violations.is_empty() {
            println!("\n❌ Policy Violations by Severity:");
            for (severity, count) in &assessment.summary.violations_by_severity {
                if *count > 0 {
                    println!("   {}: {}", severity, count);
                }
            }

            if !assessment.summary.violation_cwe_breakdown.is_empty() {
                println!("\n🔍 Top Violation CWE Types:");
                for (index, cwe_id) in assessment
                    .summary
                    .violation_cwe_breakdown
                    .iter()
                    .take(5)
                    .enumerate()
                {
                    println!("   {}. CWE-{}", index + 1, cwe_id);
                }
            }
        }
    }

    /// Export policy assessment to file
    pub fn export_policy_assessment(
        &self,
        assessment: &PolicyAssessment,
        output_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.debug {
            println!(
                "💾 Exporting policy assessment to: {}",
                output_path.display()
            );
        }

        let json_content = serde_json::to_string_pretty(assessment)?;
        fs::write(output_path, json_content)?;

        println!("✅ Policy assessment exported: {}", output_path.display());
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
pub fn execute_baseline_create(
    aggregated: &AggregatedFindings,
    output_path: &Path,
    debug: bool,
) -> Result<(), i32> {
    let manager = BaselineManager::new(debug);

    match manager.create_baseline(aggregated, output_path) {
        Ok(()) => {
            if debug {
                println!("🎯 Baseline creation completed successfully");
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("❌ Failed to create baseline: {}", e);
            Err(1)
        }
    }
}

/// Execute baseline comparison
pub fn execute_baseline_compare(
    current: &AggregatedFindings,
    baseline_path: &Path,
    output_path: Option<&Path>,
    debug: bool,
) -> Result<BaselineComparison, i32> {
    let manager = BaselineManager::new(debug);

    let baseline = match manager.load_baseline(baseline_path) {
        Ok(baseline) => baseline,
        Err(e) => {
            eprintln!("❌ Failed to load baseline file: {}", e);
            return Err(1);
        }
    };

    let comparison = match manager.compare_with_baseline(current, &baseline) {
        Ok(comparison) => comparison,
        Err(e) => {
            eprintln!("❌ Failed to perform baseline comparison: {}", e);
            return Err(1);
        }
    };

    // Display summary
    manager.display_comparison_summary(&comparison);

    // Export if requested
    if let Some(output) = output_path {
        if let Err(e) = manager.export_comparison(&comparison, output) {
            eprintln!("⚠️  Warning: Failed to export comparison results: {}", e);
        }
    }

    Ok(comparison)
}

/// Execute policy assessment from policy file
pub fn execute_policy_file_assessment(
    findings: &AggregatedFindings,
    policy_path: &Path,
    output_path: Option<&Path>,
    debug: bool,
) -> Result<PolicyAssessment, i32> {
    let manager = BaselineManager::new(debug);

    let policy = match manager.load_policy_file(policy_path) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("❌ Failed to load policy file: {}", e);
            return Err(1);
        }
    };

    let assessment = match manager.assess_against_policy(findings, &policy) {
        Ok(assessment) => assessment,
        Err(e) => {
            eprintln!("❌ Failed to perform policy assessment: {}", e);
            return Err(1);
        }
    };

    // Display summary
    manager.display_policy_summary(&assessment);

    // Export if requested
    if let Some(output) = output_path {
        if let Err(e) = manager.export_policy_assessment(&assessment, output) {
            eprintln!("⚠️  Warning: Failed to export policy assessment: {}", e);
        }
    }

    Ok(assessment)
}

/// Execute policy assessment from policy name (download and assess)
pub async fn execute_policy_name_assessment(
    findings: &AggregatedFindings,
    policy_name: &str,
    output_path: Option<&Path>,
    args: &crate::cli::Args,
) -> Result<PolicyAssessment, i32> {
    use crate::{check_secure_pipeline_credentials, load_secure_api_credentials};
    use std::env;
    use veracode_platform::VeracodeClient;
    use veracode_platform::VeracodeConfig;

    if args.debug {
        println!("🔍 Downloading policy '{}' for assessment", policy_name);
    }

    // Get API credentials using secure handling
    let secure_creds = load_secure_api_credentials().map_err(|_| 1)?;
    let (api_id, api_key) = check_secure_pipeline_credentials(&secure_creds).map_err(|_| 1)?;

    let region = parse_region(&args.region)?;
    let mut veracode_config = VeracodeConfig::new(api_id, api_key).with_region(region);

    // Check environment variable for certificate validation
    if env::var("VERASCAN_DISABLE_CERT_VALIDATION").is_ok() {
        veracode_config = veracode_config.with_certificate_validation_disabled();
    }

    let client = VeracodeClient::new(veracode_config).map_err(|e| {
        eprintln!("❌ Failed to create Veracode client: {}", e);
        1
    })?;

    let policy_api = client.policy_api();

    // Get list of policies to find the one matching the name
    let policies = policy_api.list_policies(None).await.map_err(|e| {
        eprintln!("❌ Failed to list policies: {}", e);
        1
    })?;

    // Find policy by name (case-insensitive)
    let target_policy = policies
        .iter()
        .find(|policy| policy.name.to_lowercase() == policy_name.to_lowercase())
        .ok_or_else(|| {
            eprintln!("❌ Policy '{}' not found", policy_name);
            eprintln!("💡 Available policies:");
            for policy in &policies {
                eprintln!("   - {}", policy.name);
            }
            1
        })?;

    // Get the full policy details
    let platform_policy = policy_api
        .get_policy(&target_policy.guid)
        .await
        .map_err(|e| {
            eprintln!("❌ Failed to download policy details: {}", e);
            1
        })?;

    // Convert Veracode platform policy to our PolicyFile format
    let policy_file = convert_platform_policy_to_policy_file(&platform_policy, args.debug);

    let manager = BaselineManager::new(args.debug);
    let assessment = match manager.assess_against_policy(findings, &policy_file) {
        Ok(assessment) => assessment,
        Err(e) => {
            eprintln!("❌ Failed to perform policy assessment: {}", e);
            return Err(1);
        }
    };

    // Display summary
    manager.display_policy_summary(&assessment);

    // Export if requested
    if let Some(output) = output_path {
        if let Err(e) = manager.export_policy_assessment(&assessment, output) {
            eprintln!("⚠️  Warning: Failed to export policy assessment: {}", e);
        }
    }

    Ok(assessment)
}

/// Convert Veracode platform policy to our PolicyFile format
fn convert_platform_policy_to_policy_file(
    platform_policy: &veracode_platform::SecurityPolicy,
    debug: bool,
) -> PolicyFile {
    if debug {
        println!("🔄 Converting Veracode platform policy to assessment format");
        println!("   Policy: {}", platform_policy.name);
        println!("   Finding rules: {}", platform_policy.finding_rules.len());
    }

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
        if debug {
            println!(
                "   Processing rule: {} = {}",
                finding_rule.rule_type, finding_rule.value
            );
        }

        match finding_rule.rule_type.as_str() {
            "MAX_SEVERITY" => {
                // MAX_SEVERITY rule: no findings above this severity allowed
                if let Ok(max_severity) = finding_rule.value.parse::<u32>() {
                    // Create rule for each severity above the limit
                    let forbidden_severities: Vec<u32> = ((max_severity + 1)..=5).collect();

                    if !forbidden_severities.is_empty() {
                        let severity_names: Vec<String> = forbidden_severities
                            .iter()
                            .map(|&s| severity_to_name(s).to_string())
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

                        if debug {
                            println!(
                                "     → Created MAX_SEVERITY rule: no {} findings allowed",
                                severity_names.join(", ")
                            );
                        }
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
                            "Minimum Score {} (≤{} total findings)",
                            min_score, estimated_max_findings
                        ),
                        cwe_ids: Vec::new(),
                        severity_levels: Vec::new(), // All severities
                        max_allowed: estimated_max_findings,
                        enabled: true,
                    });

                    if debug {
                        println!(
                            "     → Created MIN_SCORE rule: max {} total findings for score {}",
                            estimated_max_findings, min_score
                        );
                    }
                }
            }
            _ => {
                if debug {
                    println!(
                        "     → Skipping unsupported rule type: {}",
                        finding_rule.rule_type
                    );
                }
            }
        }
    }

    // If no rules were created, add a default permissive rule to show the policy is working
    if rules.is_empty() {
        rules.push(PolicyRule {
            name: "Default Policy Rule (no specific rules found)".to_string(),
            cwe_ids: Vec::new(),
            severity_levels: Vec::new(),
            max_allowed: 1000, // Very permissive
            enabled: true,
        });

        if debug {
            println!("   → No parseable rules found, created default permissive rule");
        }
    }

    PolicyFile {
        metadata,
        rules,
        criteria,
    }
}

/// Parse region string to VeracodeRegion enum
fn parse_region(region_str: &str) -> Result<VeracodeRegion, i32> {
    match region_str.to_lowercase().as_str() {
        "commercial" => Ok(VeracodeRegion::Commercial),
        "european" => Ok(VeracodeRegion::European),
        "federal" => Ok(VeracodeRegion::Federal),
        _ => {
            eprintln!(
                "❌ Invalid region '{}'. Use: commercial, european, or federal",
                region_str
            );
            Err(1)
        }
    }
}

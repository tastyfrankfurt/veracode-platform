use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use veracode_platform::pipeline::{ScanResults, Finding, FindingsSummary, ScanStatus};
use std::path::Path;

/// Create a standardized hash for finding comparison across the codebase
pub fn create_finding_hash(finding: &Finding) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    finding.cwe_id.hash(&mut hasher);
    finding.issue_type.hash(&mut hasher);
    finding.title.hash(&mut hasher);
    finding.files.source_file.file.hash(&mut hasher);
    finding.files.source_file.line.hash(&mut hasher);
    if let Some(function_name) = &finding.files.source_file.function_name {
        function_name.hash(&mut hasher);
    }
    
    format!("{:x}", hasher.finish())
}

/// Extract hash from finding_id (format: "cwe_id:file:line:hash")
pub fn extract_hash_from_finding_id(finding_id: &str) -> String {
    finding_id.split(':').last().unwrap_or("").to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedFindings {
    /// Combined metadata about all scans
    pub scan_metadata: Vec<ScanMetadata>,
    /// All findings from all scans
    pub findings: Vec<FindingWithSource>,
    /// Aggregated summary across all scans
    pub summary: FindingsSummary,
    /// Statistics about the aggregation
    pub stats: AggregationStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// Scan ID
    pub scan_id: String,
    /// Project name
    pub project_name: String,
    /// Scan status
    pub scan_status: ScanStatus,
    /// Project URI if available
    pub project_uri: Option<String>,
    /// Source file that was scanned
    pub source_file: String,
    /// Number of findings in this scan
    pub finding_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingWithSource {
    /// Unique identifier for matching purposes (compatible with baseline files)
    pub finding_id: String,
    /// Original finding data
    #[serde(flatten)]
    pub finding: Finding,
    /// Source scan information
    pub source_scan: ScanSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSource {
    /// Scan ID where this finding was discovered
    pub scan_id: String,
    /// Project name
    pub project_name: String,
    /// Source file that was scanned
    pub source_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationStats {
    /// Total number of scans processed
    pub total_scans: u32,
    /// Total number of findings across all scans
    pub total_findings: u32,
    /// Number of unique CWE IDs found
    pub unique_cwe_count: u32,
    /// Number of unique files with findings
    pub unique_files_count: u32,
    /// Top 5 most common CWE IDs
    pub top_cwe_ids: Vec<CweStatistic>,
    /// Findings distribution by severity
    pub severity_distribution: HashMap<String, u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweStatistic {
    /// CWE ID
    pub cwe_id: String,
    /// Number of occurrences
    pub count: u32,
    /// Percentage of total findings
    pub percentage: f64,
}

pub struct FindingsAggregator {
    debug: bool,
}

impl FindingsAggregator {
    pub fn new(debug: bool) -> Self {
        Self { debug }
    }

    /// Generate a unique finding ID compatible with baseline files
    fn generate_finding_id(&self, finding: &Finding) -> String {
        let finding_hash = create_finding_hash(finding);
        
        // Create a unique ID for this finding (format: cwe_id:file:line:hash_prefix)
        format!("{}:{}:{}:{}", 
            finding.cwe_id,
            finding.files.source_file.file,
            finding.files.source_file.line,
            &finding_hash[..8]
        )
    }

    /// Aggregate findings from multiple scan results
    pub fn aggregate_findings(&self, scan_results: &[ScanResults], source_files: &[String]) -> AggregatedFindings {
        self.aggregate_findings_with_filter(scan_results, source_files, None)
    }

    /// Aggregate findings from multiple scan results with optional severity filtering
    pub fn aggregate_findings_with_filter(&self, scan_results: &[ScanResults], source_files: &[String], min_severity_filter: Option<u32>) -> AggregatedFindings {
        if self.debug {
            println!("🔍 Aggregating findings from {} scans", scan_results.len());
            if let Some(min_sev) = min_severity_filter {
                println!("🔽 Filtering out findings below severity level: {} ({})", min_sev, self.severity_to_name(min_sev));
            }
        }

        let mut all_findings = Vec::new();
        let mut scan_metadata = Vec::new();

        // Process each scan result
        for (index, results) in scan_results.iter().enumerate() {
            let source_file = source_files.get(index)
                .unwrap_or(&format!("file_{}", index + 1))
                .clone();

            if self.debug {
                println!("📊 Processing scan {} of {}: {} findings", 
                    index + 1, scan_results.len(), results.findings.len());
            }

            // Create scan metadata
            let metadata = ScanMetadata {
                scan_id: results.scan.scan_id.clone(),
                project_name: results.scan.project_name.clone(),
                scan_status: results.scan.scan_status,
                project_uri: results.scan.project_uri.clone(),
                source_file: source_file.clone(),
                finding_count: results.findings.len() as u32,
            };
            scan_metadata.push(metadata);

            // Add findings with source information, applying severity filter if specified
            for finding in &results.findings {
                // Apply severity filter if specified
                if let Some(min_severity) = min_severity_filter {
                    if finding.severity < min_severity {
                        if self.debug {
                            println!("🔽 Filtered out finding: {} (severity {} < {})", 
                                finding.title, finding.severity, min_severity);
                        }
                        continue;
                    }
                }
                
                let finding_with_source = FindingWithSource {
                    finding_id: self.generate_finding_id(&finding),
                    finding: finding.clone(),
                    source_scan: ScanSource {
                        scan_id: results.scan.scan_id.clone(),
                        project_name: results.scan.project_name.clone(),
                        source_file: source_file.clone(),
                    },
                };
                all_findings.push(finding_with_source);
            }

            // Note: Summary will be recalculated from filtered findings at the end
            // to ensure accuracy when severity filtering is applied
        }

        // Calculate summary from the actual filtered findings
        let total_summary = self.calculate_summary_from_findings(&all_findings);
        
        // Generate statistics
        let stats = self.calculate_statistics(&all_findings, scan_results.len());

        if self.debug {
            println!("✅ Aggregation complete: {} total findings from {} scans", 
                total_summary.total, scan_results.len());
            if min_severity_filter.is_some() {
                println!("   (After severity filtering)");
            }
        }

        AggregatedFindings {
            scan_metadata,
            findings: all_findings,
            summary: total_summary,
            stats,
        }
    }

    /// Calculate summary from filtered findings
    pub fn calculate_summary_from_findings(&self, findings: &[FindingWithSource]) -> FindingsSummary {
        let mut summary = FindingsSummary {
            very_high: 0,
            high: 0,
            medium: 0,
            low: 0,
            very_low: 0,
            informational: 0,
            total: findings.len() as u32,
        };

        for finding_with_source in findings {
            let finding = &finding_with_source.finding;
            match finding.severity {
                5 => summary.very_high += 1,
                4 => summary.high += 1,
                3 => summary.medium += 1,
                2 => summary.low += 1,
                1 => summary.very_low += 1,
                0 => summary.informational += 1,
                _ => {} // Unknown severity
            }
        }

        summary
    }

    /// Calculate aggregation statistics
    fn calculate_statistics(&self, findings: &[FindingWithSource], scan_count: usize) -> AggregationStats {
        let mut cwe_counts: HashMap<String, u32> = HashMap::new();
        let mut file_counts: HashMap<String, u32> = HashMap::new();
        let mut severity_counts: HashMap<String, u32> = HashMap::new();

        // Count occurrences
        for finding_with_source in findings {
            let finding = &finding_with_source.finding;
            
            // Count CWE IDs
            *cwe_counts.entry(finding.cwe_id.clone()).or_insert(0) += 1;
            
            // Count files with findings
            *file_counts.entry(finding.files.source_file.file.clone()).or_insert(0) += 1;
            
            // Count by severity
            let severity_name = match finding.severity {
                5 => "Very High",
                4 => "High", 
                3 => "Medium",
                2 => "Low",
                1 => "Very Low",
                0 => "Informational",
                _ => "Unknown",
            };
            *severity_counts.entry(severity_name.to_string()).or_insert(0) += 1;
        }

        // Get top 5 CWE IDs
        let mut cwe_vec: Vec<(String, u32)> = cwe_counts.into_iter().collect();
        cwe_vec.sort_by(|a, b| b.1.cmp(&a.1));
        
        let total_findings = findings.len() as u32;
        let top_cwe_ids: Vec<CweStatistic> = cwe_vec.into_iter()
            .take(5)
            .map(|(cwe_id, count)| CweStatistic {
                cwe_id,
                count,
                percentage: if total_findings > 0 { (count as f64 / total_findings as f64) * 100.0 } else { 0.0 },
            })
            .collect();

        AggregationStats {
            total_scans: scan_count as u32,
            total_findings,
            unique_cwe_count: top_cwe_ids.len() as u32,
            unique_files_count: file_counts.len() as u32,
            top_cwe_ids,
            severity_distribution: severity_counts,
        }
    }

    /// Export aggregated findings to JSON file
    pub fn export_to_json(&self, aggregated: &AggregatedFindings, output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if self.debug {
            println!("💾 Exporting aggregated findings to: {}", output_path.display());
        }

        let json_string = serde_json::to_string_pretty(aggregated)?;
        std::fs::write(output_path, json_string)?;

        println!("✅ Aggregated findings exported to: {}", output_path.display());
        Ok(())
    }

    /// Export aggregated findings in baseline-compatible format
    pub fn export_to_baseline_format(&self, aggregated: &AggregatedFindings, output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if self.debug {
            println!("💾 Exporting findings in baseline format to: {}", output_path.display());
        }

        // Convert to baseline format
        let baseline_file = self.convert_to_baseline_format(aggregated)?;
        
        let json_string = serde_json::to_string_pretty(&baseline_file)?;
        std::fs::write(output_path, json_string)?;

        println!("✅ Findings exported in baseline format to: {}", output_path.display());
        Ok(())
    }

    /// Convert AggregatedFindings to BaselineFile format
    fn convert_to_baseline_format(&self, aggregated: &AggregatedFindings) -> Result<crate::baseline::BaselineFile, Box<dyn std::error::Error>> {
        use crate::baseline::*;
        use chrono::Utc;

        // Convert findings to baseline format
        let baseline_findings: Vec<BaselineFinding> = aggregated.findings.iter()
            .map(|finding_with_source| self.convert_to_baseline_finding(finding_with_source))
            .collect();

        // Create metadata from the first scan if available
        let first_scan = aggregated.scan_metadata.first()
            .ok_or("No scan metadata available for baseline creation")?;

        let metadata = BaselineMetadata {
            version: "1.0".to_string(),
            created_at: Utc::now().to_rfc3339(),
            source_scan: BaselineScanInfo {
                scan_id: first_scan.scan_id.clone(),
                project_name: first_scan.project_name.clone(),
                project_uri: None,
                source_files: aggregated.scan_metadata.iter()
                    .map(|scan| scan.source_file.clone())
                    .collect(),
            },
            project_info: BaselineProjectInfo {
                name: first_scan.project_name.clone(),
                url: None,
                commit_hash: None,
                branch: None,
            },
            finding_count: baseline_findings.len() as u32,
        };

        // Convert summary to baseline format
        let summary = BaselineSummary {
            total: aggregated.summary.very_high + aggregated.summary.high + 
                   aggregated.summary.medium + aggregated.summary.low + 
                   aggregated.summary.very_low + aggregated.summary.informational,
            very_high: aggregated.summary.very_high,
            high: aggregated.summary.high,
            medium: aggregated.summary.medium,
            low: aggregated.summary.low,
            very_low: aggregated.summary.very_low,
            informational: aggregated.summary.informational,
            top_cwe_ids: aggregated.stats.top_cwe_ids.iter()
                .map(|cwe_stat| cwe_stat.cwe_id.clone())
                .collect(),
        };

        Ok(BaselineFile {
            metadata,
            findings: baseline_findings,
            summary,
        })
    }

    /// Convert FindingWithSource to BaselineFinding
    fn convert_to_baseline_finding(&self, finding_with_source: &FindingWithSource) -> crate::baseline::BaselineFinding {
        let finding = &finding_with_source.finding;
        
        // Extract the full hash from the finding_id (finding_id contains hash prefix, we need full hash)
        let finding_hash = create_finding_hash(finding);

        crate::baseline::BaselineFinding {
            finding_id: finding_with_source.finding_id.clone(),
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

    /// Export aggregated findings to CSV file (simplified format)
    pub fn export_to_csv(&self, aggregated: &AggregatedFindings, output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if self.debug {
            println!("💾 Exporting aggregated findings to CSV: {}", output_path.display());
        }

        let mut csv_content = String::new();
        
        // CSV Header
        csv_content.push_str("Scan_ID,Project_Name,Source_File,CWE_ID,Issue_Type,Title,Severity,File_Path,Line_Number,Function_Name,Flaw_Details_Link\n");

        // CSV Data
        for finding_with_source in &aggregated.findings {
            let finding = &finding_with_source.finding;
            let source = &finding_with_source.source_scan;
            
            let severity_name = match finding.severity {
                5 => "Very High",
                4 => "High",
                3 => "Medium", 
                2 => "Low",
                1 => "Very Low",
                0 => "Informational",
                _ => "Unknown",
            };

            csv_content.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{}\n",
                source.scan_id,
                escape_csv(&source.project_name),
                escape_csv(&source.source_file),
                finding.cwe_id,
                escape_csv(&finding.issue_type),
                escape_csv(&finding.title),
                severity_name,
                escape_csv(&finding.files.source_file.file),
                finding.files.source_file.line,
                escape_csv(&finding.files.source_file.function_name.as_deref().unwrap_or("N/A")),
                escape_csv(&finding.flaw_details_link.as_deref().unwrap_or("N/A"))
            ));
        }

        std::fs::write(output_path, csv_content)?;
        println!("✅ Aggregated findings exported to CSV: {}", output_path.display());
        Ok(())
    }

    /// Display detailed findings in human-readable format
    pub fn display_detailed_findings(&self, aggregated: &AggregatedFindings, limit: u32) {
        let filtered_findings: Vec<&FindingWithSource> = aggregated.findings.iter().collect();

        if filtered_findings.is_empty() {
            println!("\n📝 No findings match the specified criteria");
            return;
        }

        println!("\n📝 Detailed Security Findings");
        println!("═══════════════════════════════════════════════════════════════");

        let display_count = if limit == 0 { filtered_findings.len() } else { 
            std::cmp::min(limit as usize, filtered_findings.len()) 
        };

        for (index, finding_with_source) in filtered_findings.iter().take(display_count).enumerate() {
            let finding = &finding_with_source.finding;
            let source = &finding_with_source.source_scan;

            println!("\n{}. 🚨 {}", index + 1, finding.title);
            println!("   ┌─ Severity: {} ({})", self.severity_to_emoji(finding.severity), self.severity_to_name(finding.severity));
            println!("   ├─ CWE-{}: {}", finding.cwe_id, finding.issue_type);
            println!("   ├─ File: {}", finding.files.source_file.file);
            println!("   ├─ Line: {}", finding.files.source_file.line);
            
            if let Some(ref function_name) = finding.files.source_file.function_name {
                if !function_name.is_empty() {
                    println!("   ├─ Function: {}", function_name);
                }
            }
            
            println!("   ├─ Source Scan: {} ({})", source.source_file, source.scan_id);
            println!("   └─ Description: {}", self.strip_html_tags(&finding.display_text));
        }

        if filtered_findings.len() > display_count {
            println!("\n... and {} more findings", filtered_findings.len() - display_count);
            println!("Use --findings-limit 0 to show all findings or increase the limit");
        }

        // Show severity summary for findings
        self.display_filtered_summary(&filtered_findings);
    }

    /// Display a summary of findings
    fn display_filtered_summary(&self, findings: &[&FindingWithSource]) {
        let mut severity_counts = [0u32; 6]; // Index 0-5 for severity levels
        
        for finding in findings {
            if finding.finding.severity <= 5 {
                severity_counts[finding.finding.severity as usize] += 1;
            }
        }

        println!("\n📊 Findings Summary:");
        let severity_names = ["Informational", "Very Low", "Low", "Medium", "High", "Very High"];
        let severity_emojis = ["ℹ️", "🟢", "🟡", "🟠", "🔴", "🔥"];
        
        for (severity_level, &count) in severity_counts.iter().enumerate() {
            if count > 0 {
                println!("   {} {}: {}", 
                    severity_emojis[severity_level], 
                    severity_names[severity_level], 
                    count
                );
            }
        }
    }

    /// Convert severity level to emoji
    fn severity_to_emoji(&self, severity: u32) -> &'static str {
        match severity {
            0 => "ℹ️",
            1 => "🟢",
            2 => "🟡", 
            3 => "🟠",
            4 => "🔴",
            5 => "🔥",
            _ => "❓",
        }
    }

    /// Convert severity level to name
    fn severity_to_name(&self, severity: u32) -> &'static str {
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

    /// Strip HTML tags from text for better CLI display
    fn strip_html_tags(&self, html: &str) -> String {
        // Simple HTML tag removal - in production you might want a proper HTML parser
        let tag_regex = regex::Regex::new(r"<[^>]*>").unwrap_or_else(|_| regex::Regex::new(r"").unwrap());
        let without_tags = tag_regex.replace_all(html, "");
        
        // Clean up extra whitespace and decode common HTML entities
        without_tags
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ")
    }

    /// Parse severity string to numeric value
    pub fn parse_severity_level(severity_str: &str) -> u32 {
        match severity_str.to_lowercase().as_str() {
            "informational" | "info" => 0,
            "very-low" | "verylow" | "very_low" => 1,
            "low" => 2,
            "medium" | "med" => 3,
            "high" => 4,
            "very-high" | "veryhigh" | "very_high" | "critical" => 5,
            _ => 0, // Default to showing all
        }
    }

    /// Convert severity level to name (public method)
    pub fn severity_level_to_name(severity: u32) -> &'static str {
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

    /// Display aggregated findings summary
    pub fn display_summary(&self, aggregated: &AggregatedFindings) {
        println!("\n📊 Aggregated Findings Summary");
        println!("═══════════════════════════════════════");
        
        // Overall statistics
        println!("📈 Overall Statistics:");
        println!("   Total Scans Processed: {}", aggregated.stats.total_scans);
        println!("   Total Findings: {}", aggregated.stats.total_findings);
        println!("   Unique CWE Types: {}", aggregated.stats.unique_cwe_count);
        println!("   Files with Findings: {}", aggregated.stats.unique_files_count);

        // Severity breakdown
        println!("\n🎯 Severity Breakdown:");
        if aggregated.summary.very_high > 0 {
            println!("   Very High: {}", aggregated.summary.very_high);
        }
        if aggregated.summary.high > 0 {
            println!("   High: {}", aggregated.summary.high);
        }
        if aggregated.summary.medium > 0 {
            println!("   Medium: {}", aggregated.summary.medium);
        }
        if aggregated.summary.low > 0 {
            println!("   Low: {}", aggregated.summary.low);
        }
        if aggregated.summary.very_low > 0 {
            println!("   Very Low: {}", aggregated.summary.very_low);
        }
        if aggregated.summary.informational > 0 {
            println!("   Informational: {}", aggregated.summary.informational);
        }

        // Top CWE IDs
        if !aggregated.stats.top_cwe_ids.is_empty() {
            println!("\n🔍 Top Security Issues (CWE):");
            for (index, cwe_stat) in aggregated.stats.top_cwe_ids.iter().enumerate() {
                println!("   {}. CWE-{}: {} occurrences ({:.1}%)", 
                    index + 1, cwe_stat.cwe_id, cwe_stat.count, cwe_stat.percentage);
            }
        }

        // Scan details
        println!("\n📋 Individual Scan Details:");
        for (index, metadata) in aggregated.scan_metadata.iter().enumerate() {
            println!("   Scan {}: {} ({} findings)", 
                index + 1, metadata.source_file, metadata.finding_count);
            if self.debug {
                println!("      ID: {}, Status: {}", metadata.scan_id, metadata.scan_status);
                if let Some(ref uri) = metadata.project_uri {
                    println!("      URI: {}", uri);
                }
            }
        }
    }
}

fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_csv() {
        assert_eq!(escape_csv("simple"), "simple");
        assert_eq!(escape_csv("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv("with\"quote"), "\"with\"\"quote\"");
    }

    #[test]
    fn test_findings_aggregator_new() {
        let aggregator = FindingsAggregator::new(true);
        assert!(aggregator.debug);
    }

    #[test]
    fn test_parse_severity_level() {
        assert_eq!(FindingsAggregator::parse_severity_level("informational"), 0);
        assert_eq!(FindingsAggregator::parse_severity_level("low"), 2);
        assert_eq!(FindingsAggregator::parse_severity_level("medium"), 3);
        assert_eq!(FindingsAggregator::parse_severity_level("high"), 4);
        assert_eq!(FindingsAggregator::parse_severity_level("very-high"), 5);
        assert_eq!(FindingsAggregator::parse_severity_level("critical"), 5);
        assert_eq!(FindingsAggregator::parse_severity_level("invalid"), 0);
    }

    #[test]
    fn test_strip_html_tags() {
        let aggregator = FindingsAggregator::new(false);
        
        let html = "<p>This is a <strong>test</strong> with &amp; entities</p>";
        let expected = "This is a test with & entities";
        assert_eq!(aggregator.strip_html_tags(html), expected);
        
        let simple = "No HTML here";
        assert_eq!(aggregator.strip_html_tags(simple), simple);
    }

    #[test]
    fn test_severity_to_name() {
        let aggregator = FindingsAggregator::new(false);
        
        assert_eq!(aggregator.severity_to_name(0), "Informational");
        assert_eq!(aggregator.severity_to_name(1), "Very Low");
        assert_eq!(aggregator.severity_to_name(2), "Low");
        assert_eq!(aggregator.severity_to_name(3), "Medium");
        assert_eq!(aggregator.severity_to_name(4), "High");
        assert_eq!(aggregator.severity_to_name(5), "Very High");
        assert_eq!(aggregator.severity_to_name(99), "Unknown");
    }

    #[test]
    fn test_severity_level_to_name() {
        assert_eq!(FindingsAggregator::severity_level_to_name(0), "Informational");
        assert_eq!(FindingsAggregator::severity_level_to_name(1), "Very Low");
        assert_eq!(FindingsAggregator::severity_level_to_name(2), "Low");
        assert_eq!(FindingsAggregator::severity_level_to_name(3), "Medium");
        assert_eq!(FindingsAggregator::severity_level_to_name(4), "High");
        assert_eq!(FindingsAggregator::severity_level_to_name(5), "Very High");
        assert_eq!(FindingsAggregator::severity_level_to_name(99), "Unknown");
    }

    #[test]
    fn test_severity_filtering() {
        // This test would need mock data to fully test the filtering functionality
        // For now, we'll test the parse function which is the core logic
        assert_eq!(FindingsAggregator::parse_severity_level("medium"), 3);
        assert_eq!(FindingsAggregator::parse_severity_level("high"), 4);
        assert_eq!(FindingsAggregator::parse_severity_level("very-high"), 5);
    }
}
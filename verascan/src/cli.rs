use clap::{Parser, Subcommand};
use log::{error, info};
use serde_json;

#[derive(Parser)]
#[command(name = "verascan")]
#[command(
    about = "A comprehensive Rust client application for the Veracode platform to support pipeline, sandbox and policy scan submission and reporting."
)]
#[command(version = "0.5.2")]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable debug mode for detailed output
    #[arg(
        long = "debug",
        short = 'd',
        help = "Enable debug mode for detailed diagnostic output",
        global = true
    )]
    pub debug: bool,

    /// Veracode region (commercial, european, federal)
    #[arg(long = "region", help = "Veracode regions (commercial, european, federal)", default_value = "commercial", value_parser = validate_region, global = true)]
    pub region: String,

    /// Veracode API ID (set VERACODE_API_ID env var)
    #[arg(skip)]
    pub api_id: Option<String>,

    /// Veracode API Key (set VERACODE_API_KEY env var)
    #[arg(skip)]
    pub api_key: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Submit files for Veracode Pipeline Scan
    Pipeline {
        /// Directory path to search in
        #[arg(
            long = "filepath",
            short = 'f',
            help = "Path to the directory to search",
            default_value = "."
        )]
        filepath: String,

        /// File filter patterns (comma-separated)
        #[arg(
            long = "filefilter",
            help = "File patterns to match (e.g., '*.jar,*.war,*.zip')",
            default_value = "*"
        )]
        filefilter: String,

        /// Enable recursive search
        #[arg(
            long = "recursive",
            short = 'r',
            help = "Search recursively through subdirectories",
            default_value = "true"
        )]
        recursive: bool,

        /// Validate file types by checking file headers
        #[arg(
            long = "validate",
            short = 'v',
            help = "Validate file types using header signatures",
            default_value = "true"
        )]
        validate: bool,

        /// Project name for pipeline scan
        #[arg(short = 'p', long = "project-name", help = "Project name for pipeline scan", value_parser = validate_name_field)]
        project_name: Option<String>,

        /// Project URL for pipeline scan
        #[arg(short = 's', long = "project-url", help = "Project URL for pipeline scan (https:// required, http:// allowed with VERASCAN_DISABLE_CERT_VALIDATION)", value_parser = validate_project_url)]
        project_url: Option<String>,

        /// Timeout in minutes to wait for scan completion
        #[arg(
            short = 't',
            long = "timeout",
            help = "Timeout in minutes to wait for scan completion",
            default_value = "30"
        )]
        timeout: u32,

        /// Number of concurrent threads for file uploads
        #[arg(long = "threads", help = "Number of concurrent threads for file uploads (2-10)", default_value = "4", value_parser = validate_threads)]
        threads: usize,

        /// Export aggregated findings to a file
        #[arg(
            long = "export-findings",
            help = "Export aggregated findings to specified file path (supports .json and .csv)",
            default_value = "results.json"
        )]
        export_findings: String,

        /// Export format for findings
        #[arg(long = "export-format", help = "Export format for findings (json, csv, gitlab, all)", default_value = "json", value_parser = validate_export_format)]
        export_format: String,

        /// Show detailed findings in human-readable format
        #[arg(
            long = "show-findings",
            help = "Display detailed findings in human-readable format to CLI"
        )]
        show_findings: bool,

        /// Limit number of findings to display
        #[arg(long = "findings-limit", help = "Limit number of findings to display (1-100, 0 = show all)", default_value = "20", value_parser = validate_findings_limit)]
        findings_limit: u32,

        /// Filter findings by minimum severity level across all findings processing
        #[arg(long = "min-severity", help = "Filter out findings below this severity level from all processing (informational, very-low, low, medium, high, very-high)", value_parser = validate_severity_level)]
        min_severity: Option<String>,

        /// Project directory root for resolving relative file paths in GitLab permalinks
        #[arg(
            long = "project-dir",
            help = "Project directory root for resolving file paths in GitLab permalinks",
            default_value = "."
        )]
        project_dir: String,

        /// Create GitLab issues from findings
        #[arg(
            long = "create-gitlab-issues",
            help = "Create GitLab issues from scan findings using CI environment variables"
        )]
        create_gitlab_issues: bool,

        /// Baseline file for comparison with current scan results
        #[arg(long = "baseline-file", short = 'b', help = "Provide the baseline file.", value_parser = validate_baseline_file)]
        baseline_file: Option<String>,

        /// Policy file for results assessment
        #[arg(long = "policy-file", help = "Name of the local policy file to be applied to the scan results.", conflicts_with = "policy_name", value_parser = validate_policy_file)]
        policy_file: Option<String>,

        /// Policy name for results assessment
        #[arg(long = "policy-name", help = "Name of the Veracode Platform Policy to be applied to the scan results.", conflicts_with = "policy_file", value_parser = validate_policy_name)]
        policy_name: Option<String>,

        /// Filtered JSON output file for policy violations
        #[arg(
            long = "filtered-json-output-file",
            help = "Filename (in the current directory) to save results that violate pass-fail criteria."
        )]
        filtered_json_output_file: Option<String>,

        /// Development stage for pipeline scan
        #[arg(long = "development-stage", help = "Development stage (development, testing, release)", default_value = "development", value_parser = validate_development_stage)]
        development_stage: String,

        /// Fail on specific severity levels (comma-separated)
        #[arg(long = "fail-on-severity", help = "Set analysis to fail for issues of the given severities. Comma-separated list (e.g., 'Very High,High')", value_parser = validate_fail_on_severity)]
        fail_on_severity: Option<String>,

        /// Fail on specific CWE IDs (comma-separated)
        #[arg(long = "fail-on-cwe", help = "Set analysis to fail for the given CWEs. Comma-separated list (e.g., '89,79,22')", value_parser = validate_fail_on_cwe)]
        fail_on_cwe: Option<String>,
    },

    /// Submit files for Veracode Assessment Scan (sandbox or policy)
    Assessment {
        /// Directory path to search in
        #[arg(
            long = "filepath",
            short = 'f',
            help = "Path to the directory to search",
            default_value = "."
        )]
        filepath: String,

        /// File filter patterns (comma-separated)
        #[arg(
            long = "filefilter",
            help = "File patterns to match (e.g., '*.jar,*.war,*.zip')",
            default_value = "*"
        )]
        filefilter: String,

        /// Enable recursive search
        #[arg(
            long = "recursive",
            short = 'r',
            help = "Search recursively through subdirectories",
            default_value = "true"
        )]
        recursive: bool,

        /// Validate file types by checking file headers
        #[arg(
            long = "validate",
            short = 'v',
            help = "Validate file types using header signatures",
            default_value = "true"
        )]
        validate: bool,

        /// Veracode application profile name to link the scan to an existing application
        #[arg(short = 'n', long = "app-profile-name", help = "Veracode application profile name for automatic app_id lookup (required)", value_parser = validate_name_field, required = true)]
        app_profile_name: String,

        /// Timeout in minutes to wait for scan completion
        #[arg(
            short = 't',
            long = "timeout",
            help = "Timeout in minutes to wait for scan completion",
            default_value = "60"
        )]
        timeout: u32,

        /// Number of concurrent threads for file uploads
        #[arg(long = "threads", help = "Number of concurrent threads for file uploads (2-10)", default_value = "4", value_parser = validate_threads)]
        threads: usize,

        /// Export assessment scan results to a file
        #[arg(
            long = "export-results",
            help = "Export assessment scan results to specified file path (JSON format)",
            default_value = "assessment-results.json"
        )]
        export_results: String,

        /// Sandbox name for sandbox assessment scans
        #[arg(long = "sandbox-name", help = "Sandbox name for sandbox assessment scans (enables sandbox mode). Forward slashes (/) will be replaced with underscores (_)", value_parser = validate_sandbox_name)]
        sandbox_name: Option<String>,

        /// Selected modules for scanning (comma-separated)
        #[arg(long = "modules", help = "Specific modules to scan (comma-separated, e.g., 'module1,module2'). If not specified, scans all nonfatal top-level modules", value_parser = validate_modules_list)]
        modules: Option<String>,

        /// Team to assign to App-Profile-Name when App-Profile-Name does not exist
        #[arg(long = "teamname", help = "Specify the team name to ensure the teamname is added to the app-profile-name on creation", value_parser = validate_name_field)]
        teamname: Option<String>,

        /// Business criticality level for application creation
        #[arg(long = "bus-cri", help = "Business criticality level for application creation (very-high, high, medium, low, very-low)", default_value = "very-high", value_parser = validate_business_criticality)]
        bus_cri: String,

        /// Submit scan and exit without waiting for completion
        #[arg(
            long = "no-wait",
            help = "Submit scan and exit without waiting for completion",
            default_value = "false",
            conflicts_with = "break_build"
        )]
        no_wait: bool,

        /// Delete incomplete scan policy for assessment scans
        #[arg(long = "deleteincompletescan", help = "Build deletion policy for assessment scans: 0=Never delete, 1=Delete safe builds only (default), 2=Delete any build except Results Ready", default_value = "1", value_parser = validate_delete_incomplete_scan)]
        deleteincompletescan: u8,

        /// Break build on Veracode platform policy compliance
        #[arg(
            long = "break",
            help = "Break build based on Veracode platform policy compliance",
            conflicts_with = "no_wait"
        )]
        break_build: bool,

        /// Force use of getbuildinfo.do API for policy compliance (skip summary report)
        #[arg(
            long = "force-buildinfo-api",
            help = "Skip summary report API and use getbuildinfo.do XML API for break build evaluation"
        )]
        force_buildinfo_api: bool,

        /// Break build on sandbox Conditional Pass
        #[arg(
            long = "strict-sandbox",
            help = "Exit with code 4 when sandbox scans return 'Conditional Pass'"
        )]
        strict_sandbox: bool,
    },

    /// Download Veracode security policy by name
    Policy {
        /// Policy name to download
        #[arg(help = "Name of the Veracode security policy to download", value_parser = validate_policy_name)]
        policy_name: String,
    },

    /// Export findings from completed policy or sandbox scans
    Export {
        /// Veracode application profile name to export findings from
        #[arg(long = "app-profile-name", short = 'n', help = "Veracode application profile name for automatic app lookup (required)", value_parser = validate_name_field, required = true)]
        app_profile_name: String,

        /// Sandbox name for sandbox scan findings (optional, if not specified exports policy scan findings)
        #[arg(long = "sandbox-name", help = "Sandbox name to retrieve findings from (optional, for sandbox scans)", value_parser = validate_sandbox_name)]
        sandbox_name: Option<String>,

        /// Export format
        #[arg(long = "format", help = "Export format (gitlab, json, csv, all)", default_value = "gitlab", value_parser = validate_export_format)]
        export_format: String,

        /// Output file path
        #[arg(
            long = "output",
            short = 'o',
            help = "Output file path for exported findings",
            default_value = "findings_export.json"
        )]
        output_path: String,

        /// Project directory for GitLab file path resolution
        #[arg(
            long = "project-dir",
            help = "Project directory for file path resolution in GitLab reports",
            default_value = "."
        )]
        project_dir: String,

        /// Minimum severity filter
        #[arg(long = "min-severity", help = "Minimum severity to include (informational, very-low, low, medium, high, very-high)", value_parser = validate_severity_filter)]
        min_severity: Option<String>,
    },

    /// Show all supported environment variables
    HelpEnv,
}

impl Args {
    /// Validate conditional requirements after parsing
    pub fn validate_conditional_requirements(&self) -> Result<(), String> {
        match &self.command {
            Commands::Pipeline {
                baseline_file,
                export_findings,
                filtered_json_output_file,
                ..
            } => {
                // Validate baseline file requirements for pipeline scans
                if baseline_file.is_some() && export_findings.is_empty() {
                    return Err(
                        "--baseline-file requires --export-findings to be specified".to_string()
                    );
                }
                if filtered_json_output_file.is_some() && baseline_file.is_none() {
                    return Err(
                        "--filtered-json-output-file requires --baseline-file to be specified"
                            .to_string(),
                    );
                }
            }
            Commands::Assessment { .. } => {
                // Assessment validation happens at the field level with required fields
            }
            Commands::Policy { .. } => {
                // Policy validation happens at the field level
            }
            Commands::Export { .. } => {
                // Export validation happens at the field level with required fields
            }
            Commands::HelpEnv => {
                // No validation needed for help-env subcommand
            }
        }

        Ok(())
    }
}

/// Validate severity level input
fn validate_severity_level(s: &str) -> Result<String, String> {
    const VALID_SEVERITIES: &[&str] = &[
        "informational",
        "info",
        "very-low",
        "verylow",
        "very_low",
        "low",
        "medium",
        "med",
        "high",
        "very-high",
        "veryhigh",
        "very_high",
        "critical",
    ];

    let lower_input = s.to_lowercase();
    if VALID_SEVERITIES.contains(&lower_input.as_str()) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "Invalid severity level '{s}'. Valid options are: informational, very-low, low, medium, high, very-high"
        ))
    }
}

/// Validate export format input
fn validate_export_format(s: &str) -> Result<String, String> {
    const VALID_FORMATS: &[&str] = &["json", "csv", "gitlab", "all"];

    let lower_input = s.to_lowercase();
    if VALID_FORMATS.contains(&lower_input.as_str()) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "Invalid export format '{s}'. Valid options are: json, csv, gitlab, all"
        ))
    }
}

/// Validate region input
fn validate_region(s: &str) -> Result<String, String> {
    const VALID_REGIONS: &[&str] = &["commercial", "european", "federal"];

    let lower_input = s.to_lowercase();
    if VALID_REGIONS.contains(&lower_input.as_str()) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "Invalid region '{s}'. Valid options are: commercial, european, federal"
        ))
    }
}

/// Validate findings limit input
fn validate_findings_limit(s: &str) -> Result<u32, String> {
    match s.parse::<u32>() {
        Ok(0) => Ok(0), // 0 means show all
        Ok(n) if (1..=100).contains(&n) => Ok(n),
        Ok(n) => Err(format!(
            "Findings limit must be between 1 and 100 (or 0 for all), got: {n}"
        )),
        Err(_) => Err(format!("Findings limit must be a valid number, got: '{s}'")),
    }
}

/// Validate threads input
fn validate_threads(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(n) if (2..=10).contains(&n) => Ok(n),
        Ok(n) => Err(format!(
            "Number of threads must be between 2 and 10, got: {n}"
        )),
        Err(_) => Err(format!(
            "Number of threads must be a valid number, got: '{s}'"
        )),
    }
}

/// Validate name fields (project name, app profile name)
fn validate_name_field(s: &str) -> Result<String, String> {
    // Check length
    if s.len() > 70 {
        return Err(format!(
            "Name must be 70 characters or less, got: {} characters",
            s.len()
        ));
    }

    // Check if empty
    if s.trim().is_empty() {
        return Err("Name cannot be empty".to_string());
    }

    // Check for valid characters (alphanumeric, dash, underscore, space)
    let is_valid = s
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ');

    if !is_valid {
        return Err(format!(
            "Name can only contain alphanumeric characters, dashes (-), underscores (_), and spaces. Got: '{s}'"
        ));
    }

    Ok(s.to_string())
}

/// Validate sandbox name with forward slash replacement
/// Replaces forward slashes (/) with underscores (_) and then validates using validate_name_field
fn validate_sandbox_name(s: &str) -> Result<String, String> {
    // Replace forward slashes with underscores
    let sanitized_name = s.replace('/', "_");

    // Show user the transformation if any forward slashes were replaced
    if s.contains('/') {
        info!("📝 Sandbox name transformed: '{s}' → '{sanitized_name}'");
    }

    // Use the existing validate_name_field function for standard validation
    validate_name_field(&sanitized_name).map(|_| sanitized_name)
}

/// Validate project URL
fn validate_project_url(s: &str) -> Result<String, String> {
    // Check length
    if s.len() > 100 {
        return Err(format!(
            "Project URL must be 100 characters or less, got: {} characters",
            s.len()
        ));
    }

    // Check if empty
    if s.trim().is_empty() {
        return Err("Project URL cannot be empty".to_string());
    }

    // Check if certificate validation is disabled (allow http:// in that case)
    let cert_validation_disabled = std::env::var("VERASCAN_DISABLE_CERT_VALIDATION").is_ok();

    // Basic URI validation
    let valid_https = s.starts_with("https://");
    let valid_http_dev = cert_validation_disabled && s.starts_with("http://");

    if !valid_https && !valid_http_dev {
        if cert_validation_disabled {
            return Err(format!(
                "Project URL must start with https:// or http:// (http allowed due to VERASCAN_DISABLE_CERT_VALIDATION), got: '{s}'"
            ));
        }
        return Err(format!("Project URL must start with https://, got: '{s}'"));
    }

    // Additional basic URI structure validation
    if !s.contains('.') && !s.contains(':') {
        return Err(format!(
            "Project URL does not appear to be a valid URI, got: '{s}'"
        ));
    }

    Ok(s.to_string())
}

/// Validate JSON file exists and is readable
fn validate_json_file(s: &str, file_type: &str) -> Result<String, String> {
    use std::fs;
    use std::path::Path;

    let path = Path::new(s);

    // Check if file exists
    if !path.exists() {
        return Err(format!("{file_type} file does not exist: '{s}'"));
    }

    // Check if it's a file (not directory)
    if !path.is_file() {
        return Err(format!("{file_type} file path is not a file: '{s}'"));
    }

    // Try to read the file
    let content = fs::read_to_string(path).map_err(|e| {
        format!(
            "Cannot read {} file '{}': {}",
            file_type.to_lowercase(),
            s,
            e
        )
    })?;

    // Try to parse as JSON to validate format
    if let Err(e) = serde_json::from_str::<serde_json::Value>(&content) {
        return Err(format!("{file_type} file '{s}' is not valid JSON: {e}"));
    }

    Ok(s.to_string())
}

/// Validate baseline file exists and is readable JSON
fn validate_baseline_file(s: &str) -> Result<String, String> {
    validate_json_file(s, "Baseline")
}

/// Validate policy file exists and is readable JSON
fn validate_policy_file(s: &str) -> Result<String, String> {
    validate_json_file(s, "Policy")
}

/// Validate policy name input
fn validate_policy_name(s: &str) -> Result<String, String> {
    // Check if empty
    if s.trim().is_empty() {
        return Err("Policy name cannot be empty".to_string());
    }

    // Check length (reasonable limit)
    if s.len() > 100 {
        return Err(format!(
            "Policy name must be 100 characters or less, got: {} characters",
            s.len()
        ));
    }

    // Check for valid characters (alphanumeric, dash, underscore, space, dot)
    let is_valid = s
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.');

    if !is_valid {
        return Err(format!(
            "Policy name can only contain alphanumeric characters, dashes (-), underscores (_), spaces, and dots (.). Got: '{s}'"
        ));
    }

    Ok(s.to_string())
}

/// Validate development stage input
fn validate_development_stage(s: &str) -> Result<String, String> {
    const VALID_STAGES: &[&str] = &[
        "development",
        "dev",
        "testing",
        "test",
        "release",
        "rel",
        "production",
        "prod",
    ];

    let lower_input = s.to_lowercase();
    if VALID_STAGES.contains(&lower_input.as_str()) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "Invalid development stage '{s}'. Valid options are: development, testing, release"
        ))
    }
}

/// Validate fail-on-severity input (comma-separated severity levels)
fn validate_fail_on_severity(s: &str) -> Result<String, String> {
    const VALID_SEVERITIES: &[&str] = &[
        "informational",
        "info",
        "very low",
        "very-low",
        "verylow",
        "very_low",
        "low",
        "medium",
        "med",
        "high",
        "very high",
        "very-high",
        "veryhigh",
        "very_high",
        "critical",
    ];

    if s.trim().is_empty() {
        return Err("Fail-on-severity list cannot be empty".to_string());
    }

    // Split by comma and validate each severity
    let severities: Vec<&str> = s.split(',').map(str::trim).collect();

    for severity in &severities {
        let lower_severity = severity.to_lowercase();
        if !VALID_SEVERITIES.contains(&lower_severity.as_str()) {
            return Err(format!(
                "Invalid severity '{severity}'. Valid options are: Informational, Very Low, Low, Medium, High, Very High"
            ));
        }
    }

    Ok(s.to_string())
}

/// Validate fail-on-cwe input (comma-separated CWE IDs)
fn validate_fail_on_cwe(s: &str) -> Result<String, String> {
    if s.trim().is_empty() {
        return Err("Fail-on-CWE list cannot be empty".to_string());
    }

    // Split by comma and validate each CWE ID
    let cwes: Vec<&str> = s.split(',').map(str::trim).collect();

    for cwe in &cwes {
        // CWE should be numeric (with or without "CWE-" prefix)
        let cwe_number = if cwe.to_lowercase().starts_with("cwe-") {
            &cwe[4..]
        } else {
            cwe
        };

        if cwe_number.parse::<u32>().is_err() {
            return Err(format!(
                "Invalid CWE ID '{cwe}'. CWE IDs should be numeric (e.g., '89' or 'CWE-89')"
            ));
        }
    }

    Ok(s.to_string())
}

/// Validate modules list input (comma-separated module names)
fn validate_modules_list(s: &str) -> Result<String, String> {
    if s.trim().is_empty() {
        return Err("Modules list cannot be empty".to_string());
    }

    // Split by comma and validate each module name
    let modules: Vec<&str> = s.split(',').map(str::trim).collect();

    for module in &modules {
        if module.is_empty() {
            return Err("Module names cannot be empty".to_string());
        }

        // Check for valid characters (alphanumeric, dash, underscore, space, dot)
        let is_valid = module
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.');

        if !is_valid {
            return Err(format!(
                "Invalid module name '{module}'. Module names can only contain alphanumeric characters, dashes (-), underscores (_), spaces, and dots (.)"
            ));
        }

        // Check length (reasonable limit)
        if module.len() > 100 {
            return Err(format!(
                "Module name '{module}' is too long. Maximum length is 100 characters"
            ));
        }
    }

    Ok(s.to_string())
}

/// Validate business criticality input
fn validate_business_criticality(s: &str) -> Result<String, String> {
    const VALID_CRITICALITIES: &[&str] = &[
        "very-high",
        "veryhigh",
        "very_high",
        "high",
        "medium",
        "med",
        "low",
        "very-low",
        "verylow",
        "very_low",
    ];

    let lower_input = s.to_lowercase();
    if VALID_CRITICALITIES.contains(&lower_input.as_str()) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "Invalid business criticality '{s}'. Valid options are: very-high, high, medium, low, very-low"
        ))
    }
}

/// Validate delete incomplete scan policy input
fn validate_delete_incomplete_scan(s: &str) -> Result<u8, String> {
    match s.parse::<u8>() {
        Ok(0) => Ok(0), // Never delete builds
        Ok(1) => Ok(1), // Delete safe builds only (default)
        Ok(2) => Ok(2), // Delete any build except Results Ready
        Ok(n) => Err(format!(
            "Delete incomplete scan policy must be 0, 1, or 2, got: {n}"
        )),
        Err(_) => Err(format!(
            "Delete incomplete scan policy must be a valid number (0, 1, or 2), got: '{s}'"
        )),
    }
}

/// Validate severity filter for export command
fn validate_severity_filter(s: &str) -> Result<String, String> {
    const VALID_SEVERITIES: &[&str] = &[
        "informational",
        "info",
        "very-low",
        "verylow",
        "very_low",
        "low",
        "medium",
        "med",
        "high",
        "very-high",
        "veryhigh",
        "very_high",
        "critical",
    ];

    let lower_input = s.to_lowercase();
    if VALID_SEVERITIES.contains(&lower_input.as_str()) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "Invalid severity filter '{s}'. Valid options are: informational, very-low, low, medium, high, very-high"
        ))
    }
}

/// Parse business criticality string to BusinessCriticality enum
#[must_use]
pub fn parse_business_criticality(
    criticality_str: &str,
) -> veracode_platform::app::BusinessCriticality {
    use veracode_platform::app::BusinessCriticality;

    match criticality_str.to_lowercase().as_str() {
        "very-high" | "veryhigh" | "very_high" => BusinessCriticality::VeryHigh,
        "high" => BusinessCriticality::High,
        "medium" | "med" => BusinessCriticality::Medium,
        "low" => BusinessCriticality::Low,
        "very-low" | "verylow" | "very_low" => BusinessCriticality::VeryLow,
        _ => {
            // This should not happen due to CLI validation, but provide a fallback
            error!(
                "⚠️  Warning: Invalid business criticality '{criticality_str}', defaulting to Medium"
            );
            BusinessCriticality::Medium
        }
    }
}

/// Print all supported environment variables documentation
pub fn print_environment_variables() {
    println!("Environment Variables");
    println!("====================");
    println!();

    println!("🔐 AUTHENTICATION");
    println!("  VERACODE_API_ID       - Veracode API ID for authentication");
    println!("  VERACODE_API_KEY      - Veracode API Key for authentication");
    println!();

    println!("🏦 HASHICORP VAULT INTEGRATION");
    println!("  VAULT_CLI_ADDR        - Vault server URL (HTTPS required)");
    println!("  VAULT_CLI_JWT         - JWT token for OIDC authentication");
    println!("  VAULT_CLI_ROLE        - Vault role name for authentication");
    println!("  VAULT_CLI_SECRET_PATH - Secret path containing Veracode credentials");
    println!("  VAULT_CLI_NAMESPACE   - Vault namespace (optional)");
    println!("  VAULT_CLI_AUTH_PATH   - Vault auth path (default: auth/jwt)");
    println!();

    println!("🔧 API CONFIGURATION");
    println!("  VERASCAN_FORCE_BUILDINFO_API - Force XML buildinfo API for break build evaluation");
    println!();

    println!("🌐 NETWORK CONFIGURATION");
    println!("  VERASCAN_DISABLE_CERT_VALIDATION - Disable TLS certificate validation (dev only)");
    println!(
        "  VERASCAN_CONNECT_TIMEOUT         - HTTP connection timeout in seconds (default: 10)"
    );
    println!("  VERASCAN_REQUEST_TIMEOUT         - HTTP request timeout in seconds (default: 30)");
    println!();

    println!("🔄 RETRY CONFIGURATION");
    println!("  VERASCAN_MAX_RETRIES             - Maximum retry attempts (default: 3)");
    println!(
        "  VERASCAN_INITIAL_RETRY_DELAY_MS  - Initial retry delay in milliseconds (default: 500)"
    );
    println!(
        "  VERASCAN_MAX_RETRY_DELAY_MS      - Maximum retry delay in milliseconds (default: 10000)"
    );
    println!("  VERASCAN_BACKOFF_MULTIPLIER      - Exponential backoff multiplier (default: 2.0)");
    println!("  VERASCAN_DISABLE_JITTER          - Disable randomized jitter in retry timing");
    println!();

    println!("🦊 GITLAB INTEGRATION");
    println!("  PRIVATE_TOKEN         - GitLab API token for issue creation and repository access");
    println!("  CI_TOKEN              - GitLab CI token (alternative to PRIVATE_TOKEN)");
    println!("  GITLAB_TOKEN          - GitLab API token (alternative to PRIVATE_TOKEN)");
    println!("  CI_PROJECT_ID         - GitLab project ID for issue creation");
    println!("  GITLAB_URL            - GitLab instance URL (default: https://gitlab.com)");
    println!();

    println!("📖 EXAMPLES");
    println!();
    println!("Basic authentication:");
    println!("  export VERACODE_API_ID=\"your-api-id\"");
    println!("  export VERACODE_API_KEY=\"your-api-key\"");
    println!();
    println!("Network optimization for slow connections:");
    println!("  export VERASCAN_CONNECT_TIMEOUT=\"60\"");
    println!("  export VERASCAN_REQUEST_TIMEOUT=\"120\"");
    println!("  export VERASCAN_MAX_RETRIES=\"5\"");
    println!();
    println!("Force XML API for restricted permissions:");
    println!("  export VERASCAN_FORCE_BUILDINFO_API=\"1\"");
    println!();
    println!("GitLab CI integration:");
    println!("  export PRIVATE_TOKEN=\"your-gitlab-token\"");
    println!("  export CI_PROJECT_ID=\"123456\"");
    println!();
    println!("Vault integration:");
    println!("  export VAULT_CLI_ADDR=\"https://vault.example.com\"");
    println!("  export VAULT_CLI_JWT=\"your-jwt-token\"");
    println!("  export VAULT_CLI_ROLE=\"veracode-role\"");
    println!("  export VAULT_CLI_SECRET_PATH=\"secret/veracode/api\"");
    println!("  export VAULT_CLI_AUTH_PATH=\"auth/jwt\"  # Optional, defaults to auth/jwt");
    println!();
    println!("  Vault secret must contain these exact key names:");
    println!("  {{");
    println!("    \"VERACODE_API_ID\": \"your-veracode-api-id\",");
    println!("    \"VERACODE_API_KEY\": \"your-veracode-api-key\"");
    println!("  }}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_conditional_requirements_pipeline_with_baseline_requires_export() {
        let args = Args {
            command: Commands::Pipeline {
                filepath: ".".to_string(),
                filefilter: "*".to_string(),
                recursive: true,
                validate: true,
                project_name: Some("TestProject".to_string()),
                project_url: None,
                timeout: 30,
                threads: 4,
                export_findings: "".to_string(), // empty export_findings
                export_format: "json".to_string(),
                show_findings: false,
                findings_limit: 20,
                min_severity: None,
                project_dir: ".".to_string(),
                create_gitlab_issues: false,
                baseline_file: Some("baseline.json".to_string()), // baseline specified
                policy_file: None,
                policy_name: None,
                filtered_json_output_file: None,
                development_stage: "development".to_string(),
                fail_on_severity: None,
                fail_on_cwe: None,
            },
            region: "commercial".to_string(),
            api_id: None,
            api_key: None,
            debug: false,
        };

        let result = args.validate_conditional_requirements();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("--baseline-file requires --export-findings")
        );
    }

    #[test]
    fn test_validate_conditional_requirements_pipeline_with_filtered_output_requires_baseline() {
        let args = Args {
            command: Commands::Pipeline {
                filepath: ".".to_string(),
                filefilter: "*".to_string(),
                recursive: true,
                validate: true,
                project_name: Some("TestProject".to_string()),
                project_url: None,
                timeout: 30,
                threads: 4,
                export_findings: "results.json".to_string(),
                export_format: "json".to_string(),
                show_findings: false,
                findings_limit: 20,
                min_severity: None,
                project_dir: ".".to_string(),
                create_gitlab_issues: false,
                baseline_file: None, // no baseline
                policy_file: None,
                policy_name: None,
                filtered_json_output_file: Some("filtered.json".to_string()), // but filtered output specified
                development_stage: "development".to_string(),
                fail_on_severity: None,
                fail_on_cwe: None,
            },
            region: "commercial".to_string(),
            api_id: None,
            api_key: None,
            debug: false,
        };

        let result = args.validate_conditional_requirements();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("--filtered-json-output-file requires --baseline-file")
        );
    }

    #[test]
    fn test_validate_conditional_requirements_assessment_scan_ok() {
        let args = Args {
            command: Commands::Assessment {
                filepath: ".".to_string(),
                filefilter: "*".to_string(),
                recursive: true,
                validate: true,
                app_profile_name: "TestApp".to_string(),
                timeout: 60,
                threads: 4,
                export_results: "assessment-results.json".to_string(),
                sandbox_name: None,
                modules: None,
                no_wait: false,
                teamname: None,
                bus_cri: "very-high".to_string(),
                deleteincompletescan: 1,
                break_build: false,
                force_buildinfo_api: false,
                strict_sandbox: false,
            },
            region: "commercial".to_string(),
            api_id: None,
            api_key: None,
            debug: false,
        };

        let result = args.validate_conditional_requirements();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_business_criticality_valid() {
        assert!(validate_business_criticality("very-high").is_ok());
        assert!(validate_business_criticality("high").is_ok());
        assert!(validate_business_criticality("medium").is_ok());
        assert!(validate_business_criticality("low").is_ok());
        assert!(validate_business_criticality("very-low").is_ok());
        assert!(validate_business_criticality("veryhigh").is_ok());
        assert!(validate_business_criticality("med").is_ok());
    }

    #[test]
    fn test_validate_business_criticality_invalid() {
        let result = validate_business_criticality("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid business criticality"));
    }

    #[test]
    fn test_parse_business_criticality() {
        use veracode_platform::app::BusinessCriticality;

        assert_eq!(
            parse_business_criticality("very-high"),
            BusinessCriticality::VeryHigh
        );
        assert_eq!(
            parse_business_criticality("high"),
            BusinessCriticality::High
        );
        assert_eq!(
            parse_business_criticality("medium"),
            BusinessCriticality::Medium
        );
        assert_eq!(parse_business_criticality("low"), BusinessCriticality::Low);
        assert_eq!(
            parse_business_criticality("very-low"),
            BusinessCriticality::VeryLow
        );
        assert_eq!(
            parse_business_criticality("invalid"),
            BusinessCriticality::Medium
        ); // fallback
    }

    #[test]
    fn test_validate_modules_list_valid() {
        let result = validate_modules_list("module1,module2,module3");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "module1,module2,module3");
    }

    #[test]
    fn test_validate_modules_list_with_spaces() {
        let result = validate_modules_list("module 1, module 2 , module 3");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_modules_list_empty() {
        let result = validate_modules_list("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_modules_list_invalid_characters() {
        let result = validate_modules_list("module1,module@2");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid module name"));
    }

    #[test]
    fn test_validate_modules_list_too_long() {
        let long_module = "a".repeat(101);
        let result = validate_modules_list(&long_module);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_validate_delete_incomplete_scan_valid() {
        assert_eq!(validate_delete_incomplete_scan("0").unwrap(), 0);
        assert_eq!(validate_delete_incomplete_scan("1").unwrap(), 1);
        assert_eq!(validate_delete_incomplete_scan("2").unwrap(), 2);
    }

    #[test]
    fn test_validate_delete_incomplete_scan_invalid() {
        let result = validate_delete_incomplete_scan("3");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be 0, 1, or 2"));

        let result = validate_delete_incomplete_scan("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be a valid number"));
    }
}

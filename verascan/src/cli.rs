use clap::Parser;
use serde_json;

#[derive(Parser)]
#[command(name = "verascan")]
#[command(about = "A comprehensive Rust client application for the Veracode platform to support pipeline, sandbox and policy scan submission and reporting.")]
#[command(version = "0.1.0")]
pub struct Args {
    /// Directory path to search in
    #[arg(long = "filepath", short = 'f', help = "Path to the directory to search", required_unless_present = "request_policy")]
    pub filepath: Option<String>,

    /// File filter patterns (comma-separated)
    #[arg(long = "filefilter", help = "File patterns to match (e.g., '*.jar,*.war,*.zip')", default_value = "*")]
    pub filefilter: String,

    /// Enable recursive search
    #[arg(long = "recursive", short = 'r', help = "Search recursively through subdirectories", default_value = "true")]
    pub recursive: bool,

    /// Validate file types by checking file headers
    #[arg(long = "validate", short = 'v', help = "Validate file types using header signatures", default_value = "true")]
    pub validate: bool,

    /// Enable debug mode for detailed output
    #[arg(long = "debug", short = 'd', help = "Enable debug mode for detailed diagnostic output")]
    pub debug: bool,

    /// Submit found files for Veracode Pipeline Scan
    #[arg(long = "pipeline-scan", help = "Submit valid files for Veracode Pipeline Scan")]
    pub pipeline_scan: bool,

    /// Download Veracode security policy by name
    #[arg(long = "request-policy", help = "Download Veracode security policy by name and save as JSON", value_parser = validate_policy_name)]
    pub request_policy: Option<String>,

    /// Veracode API ID (set VERACODE_API_ID env var)
    #[arg(skip)]
    pub api_id: Option<String>,

    /// Veracode API Key (set VERACODE_API_KEY env var)
    #[arg(skip)]
    pub api_key: Option<String>,

    /// Veracode application profile name to link the scan to an existing application
    #[arg(short = 'n', long = "app-profile-name", help = "Veracode application profile name for automatic app_id lookup", requires = "pipeline_scan", value_parser = validate_name_field)]
    pub app_profile_name: Option<String>,

    /// Project name for pipeline scan
    #[arg(short = 'p', long = "project-name", help = "Project name for pipeline scan", requires = "pipeline_scan", value_parser = validate_name_field)]
    pub project_name: Option<String>,

    /// Project URL for pipeline scan
    #[arg(short = 's', long = "project-url", help = "Project URL for pipeline scan (https:// required, http:// allowed with VERASCAN_DISABLE_CERT_VALIDATION)", requires = "pipeline_scan", value_parser = validate_project_url)]
    pub project_url: Option<String>,

    /// Veracode region (commercial, european, federal)
    #[arg(long = "region", help = "Veracode region", default_value = "commercial", requires = "pipeline_scan", value_parser = validate_region)]
    pub region: String,

    /// Timeout in minutes to wait for pipeline scan completion
    #[arg(short = 't', long = "timeout", help = "Timeout in minutes to wait for pipeline scan completion (default: 30)", default_value = "30", requires = "pipeline_scan")]
    pub timeout: u32,

    /// Number of concurrent threads for pipeline scans
    #[arg(long = "threads", help = "Number of concurrent threads for pipeline scans (2-10)", default_value = "4", requires = "pipeline_scan", value_parser = validate_threads)]
    pub threads: usize,

    /// Export aggregated findings to a file
    #[arg(long = "export-findings", help = "Export aggregated findings to specified file path (supports .json and .csv)", requires = "pipeline_scan")]
    pub export_findings: Option<String>,

    /// Export format for findings
    #[arg(long = "export-format", help = "Export format for findings (json, csv, gitlab, all)", default_value = "json", requires = "export_findings", value_parser = validate_export_format)]
    pub export_format: String,

    /// Show detailed findings in human-readable format
    #[arg(long = "show-findings", help = "Display detailed findings in human-readable format to CLI", requires = "pipeline_scan")]
    pub show_findings: bool,

    /// Limit number of findings to display
    #[arg(long = "findings-limit", help = "Limit number of findings to display (1-100, 0 = show all)", default_value = "20", requires = "show_findings", value_parser = validate_findings_limit)]
    pub findings_limit: u32,

    /// Filter findings by minimum severity level across all findings processing
    #[arg(long = "min-severity", help = "Filter out findings below this severity level from all processing (informational, very-low, low, medium, high, very-high)", requires = "pipeline_scan", value_parser = validate_severity_level)]
    pub min_severity: Option<String>,

    /// Project directory root for resolving relative file paths in GitLab permalinks
    #[arg(long = "project-dir", help = "Project directory root for resolving file paths in GitLab permalinks", default_value = ".")]
    pub project_dir: String,

    /// Create GitLab issues from findings
    #[arg(long = "create-gitlab-issues", help = "Create GitLab issues from scan findings using CI environment variables", requires = "pipeline_scan")]
    pub create_gitlab_issues: bool,

    /// Baseline file for comparison with current scan results
    #[arg(long = "baseline-file", short = 'b', help = "Provide the baseline file.", requires = "export_findings", value_parser = validate_baseline_file)]
    pub baseline_file: Option<String>,

    /// Policy file for results assessment
    #[arg(long = "policy-file", help = "Name of the local policy file to be applied to the scan results.", requires = "export_findings", conflicts_with = "policy_name", value_parser = validate_policy_file)]
    pub policy_file: Option<String>,

    /// Policy name for results assessment
    #[arg(long = "policy-name", help = "Name of the Veracode Platform Policy to be applied to the scan results.", requires = "export_findings", conflicts_with = "policy_file", value_parser = validate_policy_name)]
    pub policy_name: Option<String>,

    /// Filtered JSON output file for policy violations
    #[arg(long = "filtered-json-output-file", help = "Filename (in the current directory) to save results that violate pass-fail criteria.", requires = "baseline_file")]
    pub filtered_json_output_file: Option<String>,

    /// Development stage for pipeline scan
    #[arg(long = "development-stage", help = "Development stage (development, testing, release)", default_value = "development", requires = "pipeline_scan", value_parser = validate_development_stage)]
    pub development_stage: String,

    /// Fail on specific severity levels (comma-separated)
    #[arg(long = "fail-on-severity", help = "Set analysis to fail for issues of the given severities. Comma-separated list (e.g., 'Very High,High')", requires = "export_findings", value_parser = validate_fail_on_severity)]
    pub fail_on_severity: Option<String>,

    /// Fail on specific CWE IDs (comma-separated)
    #[arg(long = "fail-on-cwe", help = "Set analysis to fail for the given CWEs. Comma-separated list (e.g., '89,79,22')", requires = "export_findings", value_parser = validate_fail_on_cwe)]
    pub fail_on_cwe: Option<String>,
}

/// Validate severity level input
fn validate_severity_level(s: &str) -> Result<String, String> {
    const VALID_SEVERITIES: &[&str] = &[
        "informational", "info",
        "very-low", "verylow", "very_low", 
        "low",
        "medium", "med",
        "high",
        "very-high", "veryhigh", "very_high", "critical"
    ];
    
    let lower_input = s.to_lowercase();
    if VALID_SEVERITIES.contains(&lower_input.as_str()) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "Invalid severity level '{}'. Valid options are: informational, very-low, low, medium, high, very-high",
            s
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
            "Invalid export format '{}'. Valid options are: json, csv, gitlab, all",
            s
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
            "Invalid region '{}'. Valid options are: commercial, european, federal",
            s
        ))
    }
}

/// Validate findings limit input
fn validate_findings_limit(s: &str) -> Result<u32, String> {
    match s.parse::<u32>() {
        Ok(0) => Ok(0), // 0 means show all
        Ok(n) if n >= 1 && n <= 100 => Ok(n),
        Ok(n) => Err(format!(
            "Findings limit must be between 1 and 100 (or 0 for all), got: {}",
            n
        )),
        Err(_) => Err(format!(
            "Findings limit must be a valid number, got: '{}'",
            s
        )),
    }
}

/// Validate threads input
fn validate_threads(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(n) if n >= 2 && n <= 10 => Ok(n),
        Ok(n) => Err(format!(
            "Number of threads must be between 2 and 10, got: {}",
            n
        )),
        Err(_) => Err(format!(
            "Number of threads must be a valid number, got: '{}'",
            s
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
    let is_valid = s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ');
    
    if !is_valid {
        return Err(format!(
            "Name can only contain alphanumeric characters, dashes (-), underscores (_), and spaces. Got: '{}'",
            s
        ));
    }
    
    Ok(s.to_string())
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
                "Project URL must start with https:// or http:// (http allowed due to VERASCAN_DISABLE_CERT_VALIDATION), got: '{}'",
                s
            ));
        } else {
            return Err(format!(
                "Project URL must start with https://, got: '{}'",
                s
            ));
        }
    }
    
    // Additional basic URI structure validation
    if !s.contains('.') && !s.contains(':') {
        return Err(format!(
            "Project URL does not appear to be a valid URI, got: '{}'",
            s
        ));
    }
    
    Ok(s.to_string())
}

/// Validate JSON file exists and is readable
fn validate_json_file(s: &str, file_type: &str) -> Result<String, String> {
    use std::path::Path;
    use std::fs;
    
    let path = Path::new(s);
    
    // Check if file exists
    if !path.exists() {
        return Err(format!("{} file does not exist: '{}'", file_type, s));
    }
    
    // Check if it's a file (not directory)
    if !path.is_file() {
        return Err(format!("{} file path is not a file: '{}'", file_type, s));
    }
    
    // Try to read the file
    let content = fs::read_to_string(path).map_err(|e| {
        format!("Cannot read {} file '{}': {}", file_type.to_lowercase(), s, e)
    })?;
    
    // Try to parse as JSON to validate format
    if let Err(e) = serde_json::from_str::<serde_json::Value>(&content) {
        return Err(format!("{} file '{}' is not valid JSON: {}", file_type, s, e));
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
    let is_valid = s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.');
    
    if !is_valid {
        return Err(format!(
            "Policy name can only contain alphanumeric characters, dashes (-), underscores (_), spaces, and dots (.). Got: '{}'",
            s
        ));
    }
    
    Ok(s.to_string())
}

/// Validate development stage input
fn validate_development_stage(s: &str) -> Result<String, String> {
    const VALID_STAGES: &[&str] = &[
        "development", "dev",
        "testing", "test", 
        "release", "rel", "production", "prod"
    ];
    
    let lower_input = s.to_lowercase();
    if VALID_STAGES.contains(&lower_input.as_str()) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "Invalid development stage '{}'. Valid options are: development, testing, release",
            s
        ))
    }
}

/// Validate fail-on-severity input (comma-separated severity levels)
fn validate_fail_on_severity(s: &str) -> Result<String, String> {
    const VALID_SEVERITIES: &[&str] = &[
        "informational", "info",
        "very low", "very-low", "verylow", "very_low",
        "low",
        "medium", "med",
        "high",
        "very high", "very-high", "veryhigh", "very_high", "critical"
    ];
    
    if s.trim().is_empty() {
        return Err("Fail-on-severity list cannot be empty".to_string());
    }
    
    // Split by comma and validate each severity
    let severities: Vec<&str> = s.split(',').map(|s| s.trim()).collect();
    
    for severity in &severities {
        let lower_severity = severity.to_lowercase();
        if !VALID_SEVERITIES.contains(&lower_severity.as_str()) {
            return Err(format!(
                "Invalid severity '{}'. Valid options are: Informational, Very Low, Low, Medium, High, Very High",
                severity
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
    let cwes: Vec<&str> = s.split(',').map(|s| s.trim()).collect();
    
    for cwe in &cwes {
        // CWE should be numeric (with or without "CWE-" prefix)
        let cwe_number = if cwe.to_lowercase().starts_with("cwe-") {
            &cwe[4..]
        } else {
            cwe
        };
        
        if cwe_number.parse::<u32>().is_err() {
            return Err(format!(
                "Invalid CWE ID '{}'. CWE IDs should be numeric (e.g., '89' or 'CWE-89')",
                cwe
            ));
        }
    }
    
    Ok(s.to_string())
}
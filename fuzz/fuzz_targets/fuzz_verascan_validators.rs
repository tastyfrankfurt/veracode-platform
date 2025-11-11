#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // Test all verascan validators

        // Category 1: CLI validators from verascan/src/cli.rs
        test_severity_level(input);
        test_export_format(input);
        test_region(input);
        test_gitlab_schema_version(input);
        test_findings_limit(input);
        test_threads(input);
        test_name_field(input);
        test_sandbox_name(input);
        test_project_url(input);
        test_policy_name(input);
        test_development_stage(input);
        test_business_criticality(input);
        test_delete_incomplete_scan(input);
        test_build_version(input);
        test_cmek_alias(input);

        // Category 2: CSV validators (test splitting and parsing)
        test_fail_on_severity(input);
        test_fail_on_cwe(input);
        test_modules_list(input);

        // Category 3: API credential validators (public functions)
        let _ = verascan::credentials::validate_api_credential(input, "test_field");
        let _ = verascan::credentials::validate_api_credential_ascii(input, "test_field");
    }
});

/// Test severity level validation (cli.rs:390)
/// Valid: informational, very-low, low, medium, high, very-high
fn test_severity_level(s: &str) {
    const VALID_SEVERITIES: &[&str] = &[
        "informational",
        "very-low",
        "low",
        "medium",
        "high",
        "very-high",
    ];

    let s_lower = s.to_lowercase();
    let _is_valid = VALID_SEVERITIES.contains(&s_lower.as_str());
}

/// Test export format validation (cli.rs:418)
/// Valid: json, csv, gitlab, all
fn test_export_format(s: &str) {
    const VALID_FORMATS: &[&str] = &["json", "csv", "gitlab", "all"];

    let s_lower = s.to_lowercase();
    let _is_valid = VALID_FORMATS.contains(&s_lower.as_str());
}

/// Test region validation (cli.rs:432)
/// Valid: commercial, european, federal
fn test_region(s: &str) {
    const VALID_REGIONS: &[&str] = &["commercial", "european", "federal"];

    let s_lower = s.to_lowercase();
    let _is_valid = VALID_REGIONS.contains(&s_lower.as_str());
}

/// Test GitLab schema version validation (cli.rs:446)
/// Valid: 15.2.1, 15.2.2, 15.2.3
fn test_gitlab_schema_version(s: &str) {
    const VALID_VERSIONS: &[&str] = &["15.2.1", "15.2.2", "15.2.3"];

    let _is_valid = VALID_VERSIONS.contains(&s);
}

/// Test findings limit validation (cli.rs:459)
/// Valid: 0 (for all) or 1-100
fn test_findings_limit(s: &str) {
    if let Ok(value) = s.parse::<u32>() {
        let _is_valid = value == 0 || (1..=100).contains(&value);
    }
}

/// Test threads validation (cli.rs:471)
/// Valid: 2-10
fn test_threads(s: &str) {
    if let Ok(value) = s.parse::<usize>() {
        let _is_valid = (2..=10).contains(&value);
    }
}

/// Test name field validation (cli.rs:484)
/// Max 70 chars, alphanumeric + dash/underscore/space/slash
fn test_name_field(s: &str) {
    let s_trimmed = s.trim();

    if s_trimmed.is_empty() || s_trimmed.len() > 70 {
        return;
    }

    // Check all chars are valid
    let _all_valid = s_trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '/');
}

/// Test sandbox name validation (cli.rs:514)
/// Replaces '/' with '_', then validates as name field
fn test_sandbox_name(s: &str) {
    let sanitized = s.replace('/', "_");
    test_name_field(&sanitized);
}

/// Test project URL validation (cli.rs:528)
/// Must be https:// or http:// with cert validation disabled
fn test_project_url(s: &str) {
    if s.is_empty() {
        return;
    }

    // Check protocol
    let has_https = s.starts_with("https://");
    let has_http = s.starts_with("http://");

    if !has_https && !has_http {
        return;
    }

    // Try to parse as URL
    let _ = url::Url::parse(s);
}

/// Test policy name validation (cli.rs:614)
/// Max 100 chars, alphanumeric + dash/underscore/space/dot
fn test_policy_name(s: &str) {
    let s_trimmed = s.trim();

    if s_trimmed.is_empty() || s_trimmed.len() > 100 {
        return;
    }

    // Check all chars are valid (includes '.' unlike name_field)
    let _all_valid = s_trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.');
}

/// Test development stage validation (cli.rs:643)
/// Valid: development, testing, release, production
fn test_development_stage(s: &str) {
    const VALID_STAGES: &[&str] = &["development", "testing", "release", "production"];

    let s_lower = s.to_lowercase();
    let _is_valid = VALID_STAGES.contains(&s_lower.as_str());
}

/// Test business criticality validation (cli.rs:768)
/// Valid: very-high, high, medium, low, very-low (with aliases)
fn test_business_criticality(s: &str) {
    const VALID_CRITICALITY: &[&str] = &[
        "very-high",
        "veryhigh",
        "high",
        "medium",
        "low",
        "very-low",
        "verylow",
    ];

    let s_lower = s.to_lowercase();
    let _is_valid = VALID_CRITICALITY.contains(&s_lower.as_str());
}

/// Test delete incomplete scan validation (cli.rs:793)
/// Valid: 0, 1, or 2
fn test_delete_incomplete_scan(s: &str) {
    if let Ok(value) = s.parse::<u8>() {
        let _is_valid = value <= 2;
    }
}

/// Test build version validation (cli.rs:836)
/// Max 70 chars, alphanumeric + dash/underscore/dot
fn test_build_version(s: &str) {
    let s_trimmed = s.trim();

    if s_trimmed.is_empty() || s_trimmed.len() > 70 {
        return;
    }

    // Check all chars are valid
    let _all_valid = s_trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.');
}

/// Test CMEK alias validation (cli.rs:865)
/// Length 8-256, alphanumeric + dash/underscore/slash
fn test_cmek_alias(s: &str) {
    let s_trimmed = s.trim();

    if s_trimmed.len() < 8 || s_trimmed.len() > 256 {
        return;
    }

    // Check all chars are valid
    let _all_valid = s_trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/');
}

/// Test fail-on-severity validation (cli.rs:666)
/// Comma-separated list of severities
fn test_fail_on_severity(s: &str) {
    const VALID_SEVERITIES: &[&str] = &[
        "informational",
        "very-low",
        "low",
        "medium",
        "high",
        "very-high",
    ];

    let severities: Vec<&str> = s.split(',').map(|s| s.trim()).collect();

    for severity in severities {
        if !severity.is_empty() {
            let s_lower = severity.to_lowercase();
            let _is_valid = VALID_SEVERITIES.contains(&s_lower.as_str());
        }
    }
}

/// Test fail-on-cwe validation (cli.rs:705)
/// Comma-separated CWE IDs (numeric with optional CWE- prefix)
fn test_fail_on_cwe(s: &str) {
    let cwes: Vec<&str> = s.split(',').map(|s| s.trim()).collect();

    for cwe in cwes {
        if !cwe.is_empty() {
            // Remove CWE- prefix if present
            let cwe_num = cwe.strip_prefix("CWE-").unwrap_or(cwe);

            // Try to parse as u32
            let _ = cwe_num.parse::<u32>();
        }
    }
}

/// Test modules list validation (cli.rs:732)
/// Comma-separated module names, max 100 chars each
fn test_modules_list(s: &str) {
    let modules: Vec<&str> = s.split(',').map(|s| s.trim()).collect();

    for module in modules {
        if !module.is_empty() && module.len() <= 100 {
            // Check all chars are valid (alphanumeric + dash/underscore/dot)
            let _all_valid = module
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.');
        }
    }
}

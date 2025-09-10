use crate::baseline::OwnedBaselineFile;
use crate::cli::{Args, Commands};
use crate::findings::FindingWithSource;
use crate::{
    AggregatedFindings, AssessmentScanConfig, AssessmentSubmitter, FindingsAggregator,
    GitLabExportConfig, GitLabExporter, GitLabIssuesClient, PipelineScanConfig, PipelineSubmitter,
    PolicyAssessment, ScanType, execute_baseline_compare, execute_policy_file_assessment,
    execute_policy_name_assessment,
};
use log::{debug, error, info, warn};
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use veracode_platform::identity::IdentityApi;
use veracode_platform::{RetryConfig, VeracodeConfig, VeracodeRegion};

/// Configure VeracodeConfig with VERASCAN environment variables
///
/// This function applies the same environment variables used by GitLab HTTP client
/// to the VeracodeConfig for consistent configuration across the application.
#[must_use]
pub fn configure_veracode_with_env_vars(mut config: VeracodeConfig) -> VeracodeConfig {
    use std::env;

    // Certificate validation
    if env::var("VERASCAN_DISABLE_CERT_VALIDATION").is_ok() {
        config = config.with_certificate_validation_disabled();
        warn!(
            "⚠️  WARNING: Certificate validation disabled for Veracode API via VERASCAN_DISABLE_CERT_VALIDATION"
        );
        warn!("   This should only be used in development environments!");
    }

    // Connection timeout
    if let Ok(timeout_str) = env::var("VERASCAN_CONNECT_TIMEOUT") {
        if let Ok(timeout) = timeout_str.parse::<u64>() {
            config = config.with_connect_timeout(timeout);
            debug!("🔧 Using VERASCAN_CONNECT_TIMEOUT: {timeout} seconds");
        } else {
            debug!("⚠️  Invalid VERASCAN_CONNECT_TIMEOUT value: {timeout_str}");
        }
    }

    // Request timeout
    if let Ok(timeout_str) = env::var("VERASCAN_REQUEST_TIMEOUT") {
        if let Ok(timeout) = timeout_str.parse::<u64>() {
            config = config.with_request_timeout(timeout);
            debug!("🔧 Using VERASCAN_REQUEST_TIMEOUT: {timeout} seconds");
        } else {
            debug!("⚠️  Invalid VERASCAN_REQUEST_TIMEOUT value: {timeout_str}");
        }
    }

    // Retry configuration
    let mut retry_config = RetryConfig::default();
    let mut retry_modified = false;

    if let Ok(retries_str) = env::var("VERASCAN_MAX_RETRIES") {
        if let Ok(retries) = retries_str.parse::<u32>() {
            retry_config = retry_config.with_max_attempts(retries);
            retry_modified = true;
            debug!("🔧 Using VERASCAN_MAX_RETRIES: {retries}");
        } else {
            debug!("⚠️  Invalid VERASCAN_MAX_RETRIES value: {retries_str}");
        }
    }

    if let Ok(delay_str) = env::var("VERASCAN_INITIAL_RETRY_DELAY_MS") {
        if let Ok(delay) = delay_str.parse::<u64>() {
            retry_config = retry_config.with_initial_delay_millis(delay);
            retry_modified = true;
            debug!("🔧 Using VERASCAN_INITIAL_RETRY_DELAY_MS: {delay}ms");
        } else {
            debug!("⚠️  Invalid VERASCAN_INITIAL_RETRY_DELAY_MS value: {delay_str}");
        }
    }

    if let Ok(delay_str) = env::var("VERASCAN_MAX_RETRY_DELAY_MS") {
        if let Ok(delay) = delay_str.parse::<u64>() {
            retry_config = retry_config.with_max_delay_millis(delay);
            retry_modified = true;
            debug!("🔧 Using VERASCAN_MAX_RETRY_DELAY_MS: {delay}ms");
        } else {
            debug!("⚠️  Invalid VERASCAN_MAX_RETRY_DELAY_MS value: {delay_str}");
        }
    }

    if let Ok(multiplier_str) = env::var("VERASCAN_BACKOFF_MULTIPLIER") {
        if let Ok(multiplier) = multiplier_str.parse::<f64>() {
            retry_config = retry_config.with_exponential_backoff(multiplier);
            retry_modified = true;
            debug!("🔧 Using VERASCAN_BACKOFF_MULTIPLIER: {multiplier}");
        } else {
            debug!("⚠️  Invalid VERASCAN_BACKOFF_MULTIPLIER value: {multiplier_str}");
        }
    }

    if env::var("VERASCAN_DISABLE_JITTER").is_ok() {
        retry_config = retry_config.with_jitter_disabled();
        retry_modified = true;
        debug!("🔧 Jitter disabled via VERASCAN_DISABLE_JITTER");
    }

    if retry_modified {
        config = config.with_retry_config(retry_config);
    }

    config
}

/// Validate baseline file early before starting the scan
pub fn validate_baseline_file_early(baseline_path: &str) -> Result<(), i32> {
    debug!("🔍 Validating baseline file: {baseline_path}");

    let path = Path::new(baseline_path);

    // Check if file exists (already done by CLI parser, but being thorough)
    if !path.exists() {
        error!("❌ Baseline file does not exist: '{baseline_path}'");
        return Err(1);
    }

    // Check if it's a file (not directory)
    if !path.is_file() {
        error!("❌ Baseline path is not a file: '{baseline_path}'");
        return Err(1);
    }

    // Check file size (baseline files shouldn't be too large or too small)
    let metadata = fs::metadata(path).map_err(|e| {
        error!("❌ Cannot read baseline file metadata '{baseline_path}': {e}");
        1
    })?;

    let file_size = metadata.len();
    if file_size == 0 {
        error!("❌ Baseline file is empty: '{baseline_path}'");
        return Err(1);
    }

    // Reasonable size limits for baseline files (1MB should be more than enough)
    const MAX_BASELINE_SIZE: u64 = 1024 * 1024; // 1MB
    if file_size > MAX_BASELINE_SIZE {
        error!(
            "❌ Baseline file is too large ({file_size} bytes): '{baseline_path}'. Maximum allowed: {MAX_BASELINE_SIZE} bytes"
        );
        return Err(1);
    }

    // Try to read and parse the baseline file
    let content = fs::read_to_string(path).map_err(|e| {
        error!("❌ Cannot read baseline file '{baseline_path}': {e}");
        1
    })?;

    // Parse as JSON first
    let json_value: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        error!("❌ Baseline file '{baseline_path}' is not valid JSON: {e}");
        1
    })?;

    // Try to parse as BaselineFile structure
    let baseline: OwnedBaselineFile = serde_json::from_value(json_value.clone()).map_err(|e| {
        error!("❌ Baseline file '{baseline_path}' does not match expected baseline format: {e}");
        error!("   Expected fields: metadata, findings, summary");
        1
    })?;

    // Validate baseline structure
    if baseline.metadata.version.is_empty() {
        error!("❌ Baseline file '{baseline_path}' has empty version in metadata");
        return Err(1);
    }

    if baseline.metadata.finding_count != baseline.findings.len() as u32 {
        error!(
            "⚠️  Warning: Baseline file '{}' metadata.finding_count ({}) does not match actual findings count ({})",
            baseline_path,
            baseline.metadata.finding_count,
            baseline.findings.len()
        );
    }

    // Check for minimal required fields in findings
    if !baseline.findings.is_empty() {
        let first_finding = &baseline.findings[0];
        if first_finding.finding_id.is_empty() || first_finding.cwe_id.is_empty() {
            error!(
                "❌ Baseline file '{baseline_path}' contains findings with empty required fields (finding_id, cwe_id)"
            );
            return Err(1);
        }
    }

    debug!("   ✅ Baseline file validation passed");
    debug!("      - Version: {}", baseline.metadata.version);
    debug!("      - Findings count: {}", baseline.findings.len());
    debug!(
        "      - Source project: {}",
        baseline.metadata.source_scan.project_name
    );
    debug!("      - Created at: {}", baseline.metadata.created_at);
    info!(
        "✅ Baseline file validated successfully ({} findings)",
        baseline.findings.len()
    );

    Ok(())
}

pub fn execute_pipeline_scan(
    matched_files: &[PathBuf],
    veracode_config: &VeracodeConfig,
    args: &Args,
) -> Result<(), i32> {
    if let Commands::Pipeline {
        baseline_file,
        export_findings,
        ..
    } = &args.command
    {
        info!("\n🚀 Pipeline Scan requested");

        // Validate baseline file early, before running scans
        if let Some(baseline_path) = baseline_file {
            validate_baseline_file_early(baseline_path)?;
        }

        // Validate export paths early, before running scans
        validate_export_paths_early(export_findings, args)?;

        // Note: GitLab validation moved to async context in execute_scan_with_runtime

        let region = parse_region(&args.region)?;
        let pipeline_config = create_pipeline_config(args, region);

        let submitter =
            PipelineSubmitter::new(veracode_config.clone(), pipeline_config).map_err(|e| {
                error!("❌ Failed to create pipeline submitter: {e}");
                1
            })?;

        execute_scan_with_runtime(submitter, matched_files, args, veracode_config)
    } else {
        error!("❌ execute_pipeline_scan called with non-pipeline command");
        Err(1)
    }
}

fn parse_region(region_str: &str) -> Result<VeracodeRegion, i32> {
    match region_str.to_lowercase().as_str() {
        "commercial" => Ok(VeracodeRegion::Commercial),
        "european" => Ok(VeracodeRegion::European),
        "federal" => Ok(VeracodeRegion::Federal),
        _ => {
            error!("❌ Invalid region '{region_str}'. Use: commercial, european, or federal");
            Err(1)
        }
    }
}

/// Parse development stage string to DevStage enum
fn parse_dev_stage(stage_str: &str) -> veracode_platform::pipeline::DevStage {
    use veracode_platform::pipeline::DevStage;

    match stage_str.to_lowercase().as_str() {
        "development" | "dev" => DevStage::Development,
        "testing" | "test" => DevStage::Testing,
        "release" | "rel" | "production" | "prod" => DevStage::Release,
        _ => {
            // This should not happen due to CLI validation, but provide a fallback
            error!(
                "⚠️  Warning: Invalid development stage '{stage_str}', defaulting to Development"
            );
            DevStage::Development
        }
    }
}

/// Attempt to resolve project URL from .git/config file
fn resolve_git_project_url() -> Option<String> {
    debug!("🔍 Attempting to resolve project URL from .git/config...");

    // Look for .git/config file in current directory or parent directories
    let Some(git_config_path) = find_git_config_file() else {
        debug!("   ⚠️  No .git/config file found in current directory or parent directories");
        return None;
    };

    debug!("   📁 Found git config: {}", git_config_path.display());

    // Read and parse the git config file
    let config_content = fs::read_to_string(&git_config_path).ok()?;
    let remote_url = parse_git_config_for_origin_url(&config_content)?;

    debug!(
        "   📡 Found remote origin URL: {}",
        redact_url_password(&remote_url)
    );

    // Convert git URL to web URL
    let web_url = convert_git_url_to_web_url(&remote_url)?;

    debug!("   🌐 Converted to web URL: {web_url}");

    Some(web_url)
}

/// Find .git/config file by walking up directory tree
fn find_git_config_file() -> Option<PathBuf> {
    let mut current_dir = std::env::current_dir().ok()?;

    loop {
        let git_config = current_dir.join(".git").join("config");
        if git_config.exists() {
            return Some(git_config);
        }

        // Move to parent directory
        if !current_dir.pop() {
            break;
        }
    }

    None
}

/// Parse git config file to extract remote origin URL
fn parse_git_config_for_origin_url(config_content: &str) -> Option<String> {
    let mut in_remote_origin = false;

    for line in config_content.lines() {
        let line = line.trim();

        // Check for [remote "origin"] section
        if line == "[remote \"origin\"]" {
            in_remote_origin = true;
            continue;
        }

        // Check for start of new section
        if line.starts_with('[') {
            in_remote_origin = false;
            continue;
        }

        // If we're in the remote origin section, look for url field
        if in_remote_origin && line.starts_with("url = ") {
            return Some(line.strip_prefix("url = ")?.trim().to_string());
        }
    }

    None
}

/// Strip username and password from HTTP/HTTPS URLs
fn strip_credentials_from_http_url(url: &str) -> String {
    // URLs with credentials have format: http://username:password@host/path
    // We want to convert to: http://host/path

    if let Some(at_pos) = url.find('@') {
        // Find the protocol part (http:// or https://)
        if let Some(protocol_end) = url.find("://") {
            let protocol = &url[..protocol_end + 3]; // Include ://
            let after_at = &url[at_pos + 1..]; // Everything after @
            return format!("{protocol}{after_at}");
        }
    }

    // No credentials found, return as is
    url.to_string()
}

/// Redact password from URLs for safe logging
fn redact_url_password(url: &str) -> String {
    // URLs with credentials have format: http://username:password@host/path
    // We want to convert to: http://username:[REDACTED]@host/path

    if let Some(at_pos) = url.find('@') {
        // Find the protocol part (http:// or https://)
        if let Some(protocol_end) = url.find("://") {
            let protocol = &url[..protocol_end + 3]; // Include ://
            let credentials_and_host = &url[protocol_end + 3..]; // Everything after protocol

            if let Some(colon_pos) = credentials_and_host.find(':')
                && colon_pos < at_pos - protocol_end - 3
            {
                // Colon is in credentials part
                let username = &credentials_and_host[..colon_pos];
                let after_at = &credentials_and_host[at_pos - protocol_end - 3 + 1..]; // Everything after @
                return format!("{protocol}{username}:[REDACTED]@{after_at}");
            }
        }
    }

    // No credentials found, return as is
    url.to_string()
}

/// Convert various git URL formats to web URLs
fn convert_git_url_to_web_url(git_url: &str) -> Option<String> {
    let url = git_url.trim();

    // Handle HTTPS URLs (remove credentials and .git suffix)
    if url.starts_with("https://") {
        let clean_url = strip_credentials_from_http_url(url);
        let final_url = clean_url.strip_suffix(".git").unwrap_or(&clean_url);
        return Some(final_url.to_string());
    }

    // Handle HTTP URLs (remove credentials and .git suffix)
    if url.starts_with("http://") {
        let clean_url = strip_credentials_from_http_url(url);
        let final_url = clean_url.strip_suffix(".git").unwrap_or(&clean_url);
        return Some(final_url.to_string());
    }

    // Handle SSH URLs (git@host:owner/repo.git)
    if url.starts_with("git@")
        && let Some((host, path)) = extract_ssh_url_parts(url)
    {
        let clean_path = path.strip_suffix(".git").unwrap_or(&path);
        return Some(format!("https://{host}/{clean_path}"));
    }

    // Handle git:// URLs
    if url.starts_with("git://") {
        let https_url = url.replacen("git://", "https://", 1);
        let clean_url = https_url.strip_suffix(".git").unwrap_or(&https_url);
        return Some(clean_url.to_string());
    }

    None
}

/// Extract host and path from SSH URL format (git@host:path)
fn extract_ssh_url_parts(ssh_url: &str) -> Option<(String, String)> {
    // Format: git@host:owner/repo.git
    let without_prefix = ssh_url.strip_prefix("git@")?;
    let parts: Vec<&str> = without_prefix.splitn(2, ':').collect();

    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

fn create_pipeline_config(args: &Args, region: VeracodeRegion) -> PipelineScanConfig {
    if let Commands::Pipeline {
        project_url,
        project_name,
        development_stage,
        timeout,
        threads,
        ..
    } = &args.command
    {
        // Auto-resolve project URL from git if not provided
        let project_uri = project_url
            .as_deref()
            .map(ToOwned::to_owned)
            .or_else(resolve_git_project_url);

        // Use Cow to avoid allocating default project name unless needed
        let project_name_cow: Cow<str> = project_name
            .as_ref()
            .map(|s| Cow::Borrowed(s.as_str()))
            .unwrap_or(Cow::Borrowed("Verascan Pipeline Scan"));

        PipelineScanConfig {
            project_name: project_name_cow.into_owned(),
            project_uri,
            dev_stage: parse_dev_stage(development_stage),
            region,
            timeout: Some(*timeout),
            include_low_severity: Some(true),
            max_findings: None,
            selected_modules: None, // Pipeline doesn't use modules
            app_profile_name: None, // Pipeline doesn't use app profile name
            threads: *threads,
        }
    } else {
        panic!("create_pipeline_config called with non-pipeline command");
    }
}

fn execute_scan_with_runtime(
    submitter: PipelineSubmitter,
    matched_files: &[PathBuf],
    args: &Args,
    veracode_config: &VeracodeConfig,
) -> Result<(), i32> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        error!("❌ Failed to create async runtime: {e}");
        1
    })?;

    rt.block_on(async {
        if let Commands::Pipeline {
            create_gitlab_issues,
            ..
        } = &args.command
        {
            // Validate GitLab connectivity early, before running scans (in async context)
            if *create_gitlab_issues {
                info!(
                    "Requires 'Developer' role and 'api' scope Access token for GitLab integration"
                );
                validate_gitlab_connectivity_early().await?;
            }
        }

        if matched_files.len() == 1 {
            execute_single_scan(&submitter, matched_files, args, veracode_config).await
        } else {
            execute_concurrent_scans(&submitter, matched_files, args, veracode_config).await
        }
    })
}

async fn execute_single_scan(
    submitter: &PipelineSubmitter,
    matched_files: &[PathBuf],
    args: &Args,
    veracode_config: &VeracodeConfig,
) -> Result<(), i32> {
    match submitter.submit_and_wait(matched_files).await {
        Ok(results) => {
            submitter.display_results_summary(&results);

            let results_vec = vec![results];

            // Handle findings aggregation and export
            handle_findings_export(&results_vec, matched_files, args, veracode_config).await;

            // Handle GitLab issues creation if requested (independent of export)
            if let Commands::Pipeline {
                create_gitlab_issues,
                ..
            } = &args.command
                && *create_gitlab_issues
            {
                handle_gitlab_issues_creation_from_results_async(
                    &results_vec,
                    matched_files,
                    args,
                    veracode_config,
                )
                .await;
            }

            Ok(())
        }
        Err(e) => {
            error!("❌ Pipeline scan failed: {e}");
            Err(1)
        }
    }
}

async fn execute_concurrent_scans(
    submitter: &PipelineSubmitter,
    matched_files: &[PathBuf],
    args: &Args,
    veracode_config: &VeracodeConfig,
) -> Result<(), i32> {
    match submitter
        .submit_files_concurrent_and_wait(matched_files)
        .await
    {
        Ok(results_vec) => {
            display_concurrent_results(&results_vec, submitter);

            // Handle findings aggregation and export
            handle_findings_export(&results_vec, matched_files, args, veracode_config).await;

            // Handle GitLab issues creation if requested (independent of export)
            if let Commands::Pipeline {
                create_gitlab_issues,
                ..
            } = &args.command
                && *create_gitlab_issues
            {
                handle_gitlab_issues_creation_from_results_async(
                    &results_vec,
                    matched_files,
                    args,
                    veracode_config,
                )
                .await;
            }

            Ok(())
        }
        Err(e) => {
            error!("❌ Concurrent pipeline scans failed: {e}");
            Err(1)
        }
    }
}

fn display_concurrent_results(
    results_vec: &[veracode_platform::pipeline::ScanResults],
    submitter: &PipelineSubmitter,
) {
    info!("\n📊 All Pipeline Scans Completed!");
    info!("   Total scans: {}", results_vec.len());

    for (index, results) in results_vec.iter().enumerate() {
        info!(
            "\n--- Scan {} of {} ({}) ---",
            index + 1,
            results_vec.len(),
            results.scan.binary_name
        );
        submitter.display_results_summary(results);
    }

    let total_findings: u32 = results_vec.iter().map(|r| r.summary.total).sum();
    let total_high_critical: u32 = results_vec
        .iter()
        .map(|r| r.summary.very_high + r.summary.high)
        .sum();

    info!("\n🎯 Overall Summary:");
    info!("   Total findings across all scans: {total_findings}");
    info!("   High/Critical findings: {total_high_critical}");
}

async fn handle_findings_export(
    results_vec: &[veracode_platform::pipeline::ScanResults],
    matched_files: &[PathBuf],
    args: &Args,
    veracode_config: &VeracodeConfig,
) {
    if let Commands::Pipeline {
        export_findings, ..
    } = &args.command
    {
        let export_path = export_findings;
        info!("\n📄 Aggregating findings for export...");

        // Create source file names from the matched files (avoid unnecessary string allocations)
        let source_file_names: Vec<&str> = matched_files
            .iter()
            .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
            .collect();

        // Only create owned strings when needed for the aggregator
        let source_files: Vec<String> = source_file_names
            .iter()
            .map(|&name| name.to_string())
            .collect();

        // Create findings aggregator
        let aggregator = FindingsAggregator::new();

        // Parse severity filter if provided
        let severity_filter = if let Commands::Pipeline { min_severity, .. } = &args.command {
            min_severity
                .as_ref()
                .map(|s| crate::findings::FindingsAggregator::parse_severity_level(s))
        } else {
            None
        };

        // Aggregate all findings with optional severity filtering
        let aggregated = if let Some(min_severity) = severity_filter {
            debug!(
                "🔽 Applying severity filter: {} and above",
                crate::findings::FindingsAggregator::severity_level_to_name(min_severity)
            );
            aggregator.aggregate_findings_with_filter(
                results_vec,
                &source_files,
                Some(min_severity),
            )
        } else {
            aggregator.aggregate_findings(results_vec, &source_files)
        };

        // Display aggregated summary
        aggregator.display_summary(&aggregated);

        // Handle baseline operations and get filtered findings
        let baseline_filtered = handle_baseline_operations(&aggregated, args);

        // Handle policy assessment and get violations (if policy is specified)
        let (policy_assessment, final_filtered) =
            handle_policy_assessment(&baseline_filtered, args, veracode_config).await;

        // Export filtered JSON based on pass-fail criteria
        if let Commands::Pipeline {
            filtered_json_output_file: Some(output_path),
            ..
        } = &args.command
        {
            export_pass_fail_violations(
                &final_filtered,
                &baseline_filtered,
                &aggregated,
                args,
                output_path,
                &policy_assessment,
            )
            .await;
        }

        // Display detailed findings if requested
        if let Commands::Pipeline {
            show_findings,
            findings_limit,
            ..
        } = &args.command
            && *show_findings
        {
            aggregator.display_detailed_findings(&final_filtered, *findings_limit);
        }

        // Export based on format
        if let Commands::Pipeline { export_format, .. } = &args.command {
            let export_format_lower = export_format.to_lowercase();
            match export_format_lower.as_str() {
                "json" => match ensure_extension(export_path, "json") {
                    Ok(json_path) => {
                        if let Err(e) = aggregator
                            .export_to_baseline_format(&final_filtered, &json_path)
                            .await
                        {
                            error!("❌ Failed to export JSON in baseline format: {e}");
                        }
                    }
                    Err(e) => {
                        error!("❌ Invalid export path: {e}");
                    }
                },
                "csv" => match ensure_extension(export_path, "csv") {
                    Ok(csv_path) => {
                        if let Err(e) = aggregator.export_to_csv(&final_filtered, &csv_path).await {
                            error!("❌ Failed to export CSV: {e}");
                        }
                    }
                    Err(e) => {
                        error!("❌ Invalid export path: {e}");
                    }
                },
                "gitlab" => match ensure_extension(export_path, "json") {
                    Ok(gitlab_path) => {
                        if let Commands::Pipeline { project_dir, .. } = &args.command {
                            let gitlab_config = GitLabExportConfig::default();
                            let gitlab_exporter =
                                GitLabExporter::new(gitlab_config).with_project_dir(project_dir);
                            if let Err(e) = gitlab_exporter
                                .export_to_gitlab_sast(&final_filtered, &gitlab_path)
                                .await
                            {
                                error!("❌ Failed to export GitLab SAST report: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        error!("❌ Invalid export path: {e}");
                    }
                },
                "all" => {
                    let json_result = ensure_extension(export_path, "json");
                    let csv_result = ensure_extension(export_path, "csv");
                    let gitlab_result = ensure_extension(export_path, "json");

                    match (json_result, csv_result, gitlab_result) {
                        (Ok(json_path), Ok(csv_path), Ok(gitlab_path)) => {
                            // Export JSON
                            if let Err(e) = aggregator
                                .export_to_baseline_format(&final_filtered, &json_path)
                                .await
                            {
                                error!("❌ Failed to export JSON in baseline format: {e}");
                            }
                            // Export CSV
                            if let Err(e) =
                                aggregator.export_to_csv(&final_filtered, &csv_path).await
                            {
                                error!("❌ Failed to export CSV: {e}");
                            }
                            // Export GitLab SAST report (use different filename to avoid conflict)
                            let gitlab_sast_path = {
                                let mut path = gitlab_path;
                                if let Some(file_stem) = path.file_stem() {
                                    let mut new_name = file_stem.to_os_string();
                                    new_name.push("_gitlab_sast.json");
                                    path.set_file_name(new_name);
                                } else {
                                    path.set_file_name("export_gitlab_sast.json");
                                }
                                path
                            };
                            if let Commands::Pipeline { project_dir, .. } = &args.command {
                                let gitlab_config = GitLabExportConfig::default();
                                let gitlab_exporter = GitLabExporter::new(gitlab_config)
                                    .with_project_dir(project_dir);
                                if let Err(e) = gitlab_exporter
                                    .export_to_gitlab_sast(&final_filtered, &gitlab_sast_path)
                                    .await
                                {
                                    error!("❌ Failed to export GitLab SAST report: {e}");
                                }
                            }
                        }
                        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                            error!("❌ Invalid export path: {e}");
                        }
                    }
                }
                _ => {
                    error!(
                        "❌ Unsupported export format: {export_format_lower}. Use 'json', 'csv', 'gitlab', or 'all'"
                    );
                }
            }
        }

        // Check policy assessment result for exit code
        if let Some(assessment) = policy_assessment {
            if !assessment.passed {
                info!("\n❌ Policy assessment FAILED - exiting with error code");
                info!("   Policy: {}", assessment.metadata.policy_info.name);
                info!("   Violations: {}", assessment.summary.total_violations);
                std::process::exit(1);
            } else {
                info!("✅ Policy assessment PASSED");
                info!("   Policy: {}", assessment.metadata.policy_info.name);
            }
        }

        // Note: GitLab issues creation is handled in the main scan workflows
    }
}

async fn validate_gitlab_connectivity_early() -> Result<(), i32> {
    info!("🔍 Validating GitLab integration...");

    match GitLabIssuesClient::validate_gitlab_connection().await {
        Ok(()) => {
            info!("✅ GitLab integration validated successfully");
            Ok(())
        }
        Err(e) => {
            error!("❌ GitLab validation failed: {e}");
            error!("   Please check your GitLab configuration and try again");
            Err(1)
        }
    }
}

fn validate_export_paths_early(export_path: &str, args: &Args) -> Result<(), i32> {
    if let Commands::Pipeline { export_format, .. } = &args.command {
        info!("🔍 Validating export paths...");

        let export_format_lower = export_format.to_lowercase();
        match export_format_lower.as_str() {
            "json" => {
                ensure_extension(export_path, "json").map_err(|e| {
                    error!("❌ Invalid JSON export path: {e}");
                    1
                })?;
            }
            "csv" => {
                ensure_extension(export_path, "csv").map_err(|e| {
                    error!("❌ Invalid CSV export path: {e}");
                    1
                })?;
            }
            "gitlab" => {
                ensure_extension(export_path, "json").map_err(|e| {
                    error!("❌ Invalid GitLab SAST export path: {e}");
                    1
                })?;
            }
            "all" => {
                ensure_extension(export_path, "json").map_err(|e| {
                    error!("❌ Invalid JSON export path: {e}");
                    1
                })?;
                ensure_extension(export_path, "csv").map_err(|e| {
                    error!("❌ Invalid CSV export path: {e}");
                    1
                })?;
                ensure_extension(export_path, "json").map_err(|e| {
                    error!("❌ Invalid GitLab SAST export path: {e}");
                    1
                })?;
            }
            _ => {
                error!(
                    "❌ Unsupported export format: {export_format_lower}. Use 'json', 'csv', 'gitlab', or 'all'"
                );
                return Err(1);
            }
        }

        info!("✅ Export paths validated successfully");
        Ok(())
    } else {
        error!("❌ validate_export_paths_early called with non-pipeline command");
        Err(1)
    }
}

fn ensure_extension(path: &str, extension: &str) -> Result<PathBuf, String> {
    let path_buf = PathBuf::from(path);

    // Check if the path already exists and is a directory
    if path_buf.exists() && path_buf.is_dir() {
        return Err(format!(
            "Export path '{path}' is a directory. Please specify a file path."
        ));
    }

    // Check if parent directory exists (if there is one)
    if let Some(parent) = path_buf.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        return Err(format!(
            "Parent directory '{}' does not exist. Please create it first.",
            parent.display()
        ));
    }

    // Ensure the file has the correct extension (optimized OsStr comparison)
    let final_path = if path_buf.extension() == Some(extension.as_ref()) {
        path_buf
    } else {
        path_buf.with_extension(extension)
    };

    // Check if file already exists and warn user
    if final_path.exists() {
        info!(
            "⚠️  Warning: File '{}' already exists and will be overwritten.",
            final_path.display()
        );
    }

    Ok(final_path)
}

/// Handle GitLab issues creation from scan results (independent of export) - async version
async fn handle_gitlab_issues_creation_from_results_async(
    results_vec: &[veracode_platform::pipeline::ScanResults],
    matched_files: &[PathBuf],
    args: &Args,
    veracode_config: &VeracodeConfig,
) {
    if let Commands::Pipeline { min_severity, .. } = &args.command {
        info!("\n🔗 Creating GitLab issues from scan findings...");

        // Create source file names from the matched files (avoid unnecessary string allocations)
        let source_file_names: Vec<&str> = matched_files
            .iter()
            .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
            .collect();

        // Only create owned strings when needed for the aggregator
        let source_files: Vec<String> = source_file_names
            .iter()
            .map(|&name| name.to_string())
            .collect();

        // Create findings aggregator
        let aggregator = FindingsAggregator::new();

        // Parse severity filter if provided
        let severity_filter = min_severity
            .as_ref()
            .map(|s| crate::findings::FindingsAggregator::parse_severity_level(s));

        // Aggregate all findings with optional severity filtering
        let aggregated = if let Some(min_severity) = severity_filter {
            aggregator.aggregate_findings_with_filter(
                results_vec,
                &source_files,
                Some(min_severity),
            )
        } else {
            aggregator.aggregate_findings(results_vec, &source_files)
        };

        // Handle baseline operations and get filtered findings
        let baseline_filtered = handle_baseline_operations(&aggregated, args);

        // Handle policy assessment and get violations (if policy is specified)
        let (_policy_assessment, final_filtered) =
            handle_policy_assessment(&baseline_filtered, args, veracode_config).await;

        // Create GitLab issues asynchronously
        handle_gitlab_issues_creation_async(&final_filtered, args).await;
    }
}

/// Handle GitLab issues creation from aggregated findings - async version
async fn handle_gitlab_issues_creation_async(
    aggregated: &crate::findings::AggregatedFindings,
    args: &Args,
) {
    if let Commands::Pipeline { project_dir, .. } = &args.command {
        match GitLabIssuesClient::from_env() {
            Ok(mut client) => {
                // Set project directory (always available with default ".")
                client = client.with_project_dir(project_dir);
                debug!("📁 Using project directory for file path resolution: {project_dir}");
                match client.create_issues_from_findings(aggregated).await {
                    Ok(issues) => {
                        info!("✅ Successfully created {} GitLab issues", issues.len());
                        for issue in issues {
                            debug!("   Issue #{}: {}", issue.iid, issue.web_url);
                        }
                    }
                    Err(e) => {
                        error!("❌ Failed to create GitLab issues: {e}");
                    }
                }
            }
            Err(e) => {
                error!("❌ Failed to initialize GitLab client: {e}");
                error!("   Make sure the following environment variables are set:");
                error!("   - PRIVATE_TOKEN or CI_TOKEN (GitLab API token)");
                error!("   - CI_PROJECT_ID (GitLab project ID)");
                error!("   Optional: CI_PIPELINE_ID, CI_PIPELINE_URL, CI_COMMIT_SHA");
            }
        }
    }
}

/// Handle baseline operations: filter findings against baseline (optimized to avoid clones)
fn handle_baseline_operations<'a>(
    aggregated: &'a AggregatedFindings,
    args: &Args,
) -> Cow<'a, AggregatedFindings> {
    // If baseline file is provided, filter the findings to show only new ones
    if let Commands::Pipeline {
        baseline_file: Some(baseline_path),
        ..
    } = &args.command
    {
        debug!("\n🔍 Translating baseline file");

        let baseline_path = Path::new(baseline_path);

        match execute_baseline_compare(aggregated, baseline_path, None) {
            Ok(comparison) => {
                debug!(
                    "Total flaws found: {}, New flaws found: {} as compared to baseline ({} baseline flaws ignored)",
                    aggregated.findings.len(),
                    comparison.summary.new_count,
                    comparison.summary.unchanged_count
                );

                // Check if policy assessment is enabled to determine precedence
                let policy_enabled = if let Commands::Pipeline {
                    policy_file,
                    policy_name,
                    fail_on_severity,
                    fail_on_cwe,
                    ..
                } = &args.command
                {
                    policy_file.is_some()
                        || policy_name.is_some()
                        || fail_on_severity.is_some()
                        || fail_on_cwe.is_some()
                } else {
                    false
                };
                let baseline_failed = comparison.summary.new_count > 0;

                if baseline_failed {
                    if policy_enabled {
                        // When policy criteria are present, defer the final pass/fail message
                        debug!(
                            "\n🔍 {} new findings detected vs baseline - applying policy criteria",
                            comparison.summary.new_count
                        );
                    } else {
                        // Standalone baseline comparison
                        info!(
                            "\n❌ Baseline comparison FAILED - {} new findings detected",
                            comparison.summary.new_count
                        );
                        info!(
                            "   Baseline created: {}",
                            comparison.metadata.baseline_info.created_at
                        );
                        info!("   New findings: {}", comparison.summary.new_count);
                        std::process::exit(1);
                    }
                } else {
                    info!("\n✅ Baseline comparison PASSED - no new findings");
                }

                // Only clone when we actually need to modify the findings
                if comparison.new_findings.len() != aggregated.findings.len() {
                    // Create a new aggregated findings with only the new findings
                    let mut filtered_aggregated = aggregated.clone();
                    filtered_aggregated.findings = comparison.new_findings;

                    // Recalculate summary for filtered findings
                    let aggregator = FindingsAggregator::new();
                    let updated_summary =
                        aggregator.calculate_summary_from_findings(&filtered_aggregated.findings);
                    filtered_aggregated.summary = updated_summary;

                    // Update stats
                    filtered_aggregated.stats.total_findings =
                        filtered_aggregated.findings.len() as u32;

                    return Cow::Owned(filtered_aggregated);
                }
                // No filtering needed, return borrowed reference
                return Cow::Borrowed(aggregated);
            }
            Err(_) => {
                error!(
                    "❌ The \"baseline_file\" does not contain JSON formatting. Correct the file and try again."
                );
                // Return original aggregated findings if baseline filtering fails
                return Cow::Borrowed(aggregated);
            }
        }
    }

    // Return original aggregated findings if no baseline file specified
    Cow::Borrowed(aggregated)
}

/// Handle policy assessment operations: assess findings against policy and export violations
async fn handle_policy_assessment<'a>(
    aggregated: &'a AggregatedFindings,
    args: &Args,
    veracode_config: &VeracodeConfig,
) -> (Option<PolicyAssessment>, Cow<'a, AggregatedFindings>) {
    // Check if policy assessment is requested
    if let Commands::Pipeline {
        policy_file,
        policy_name,
        ..
    } = &args.command
    {
        if policy_file.is_some() || policy_name.is_some() {
            debug!("\n🔍 Policy assessment requested");

            let assessment_result = if let Some(policy_file_path) = policy_file {
                // Use policy file
                let policy_path = Path::new(policy_file_path);
                execute_policy_file_assessment(aggregated, policy_path, None)
            } else if let Some(policy_name_str) = policy_name {
                // Use policy name (requires async)
                execute_policy_name_assessment(aggregated, policy_name_str, None, veracode_config)
                    .await
            } else {
                return (None, Cow::Borrowed(aggregated));
            };

            match assessment_result {
                Ok(assessment) => {
                    // Note: Filtered JSON export is now handled centrally in export_pass_fail_violations

                    // Return violations as filtered findings for subsequent processing
                    if !assessment.violations.is_empty() {
                        let mut filtered_aggregated = aggregated.clone();
                        filtered_aggregated.findings = assessment.violations.clone();

                        // Recalculate summary for violations only
                        let aggregator = FindingsAggregator::new();
                        let updated_summary = aggregator
                            .calculate_summary_from_findings(&filtered_aggregated.findings);
                        filtered_aggregated.summary = updated_summary;

                        // Update stats
                        filtered_aggregated.stats.total_findings =
                            filtered_aggregated.findings.len() as u32;

                        return (Some(assessment), Cow::Owned(filtered_aggregated));
                    }

                    (Some(assessment), Cow::Borrowed(aggregated))
                }
                Err(exit_code) => {
                    error!("❌ Policy assessment failed with exit code: {exit_code}");
                    (None, Cow::Borrowed(aggregated))
                }
            }
        } else {
            // No policy assessment requested
            (None, Cow::Borrowed(aggregated))
        }
    } else {
        // No policy assessment requested
        (None, Cow::Borrowed(aggregated))
    }
}

/// Export policy violations to filtered JSON output file
async fn export_policy_violations(assessment: &PolicyAssessment, output_path: &str) {
    debug!("💾 Exporting policy violations to: {output_path}");

    // Create a simplified structure for the filtered JSON output
    let violations_export = serde_json::json!({
        "policy": {
            "name": assessment.metadata.policy_info.name,
            "version": assessment.metadata.policy_info.version,
            "guid": assessment.metadata.policy_info.guid,
        },
        "assessment": {
            "assessed_at": assessment.metadata.assessed_at,
            "passed": assessment.passed,
            "total_violations": assessment.summary.total_violations,
        },
        "violations": assessment.violations,
        "summary": assessment.summary
    });

    match serde_json::to_string_pretty(&violations_export) {
        Ok(json_content) => {
            if let Err(e) = tokio::fs::write(output_path, json_content).await {
                error!("❌ Failed to write filtered JSON output file: {e}");
            } else {
                info!("✅ Policy violations exported to: {output_path}");
                info!(
                    "   Total violations: {}",
                    assessment.summary.total_violations
                );
            }
        }
        Err(e) => {
            error!("❌ Failed to serialize policy violations: {e}");
        }
    }
}

/// Export findings that violate pass-fail criteria to filtered JSON output file
async fn export_pass_fail_violations(
    final_filtered: &AggregatedFindings,
    baseline_filtered: &AggregatedFindings,
    _original_aggregated: &AggregatedFindings,
    args: &Args,
    output_path: &str,
    policy_assessment: &Option<PolicyAssessment>,
) {
    debug!("🔍 Evaluating pass-fail criteria for filtered JSON export");

    // Determine which findings violate pass-fail criteria
    let mut violating_findings = Vec::with_capacity(final_filtered.findings.len());
    let mut criteria_description = Vec::with_capacity(4); // Max 4 criteria types

    // 1. Policy violations (highest priority)
    if let Some(assessment) = policy_assessment
        && !assessment.violations.is_empty()
    {
        violating_findings.extend(assessment.violations.clone());
        criteria_description.push(format!(
            "Policy '{}' violations",
            assessment.metadata.policy_info.name
        ));

        export_policy_violations(assessment, output_path).await;
        return; // Policy takes precedence, export and return
    }

    // 2. Baseline violations (only if no severity/CWE criteria specified)
    if let Commands::Pipeline {
        baseline_file,
        fail_on_severity,
        fail_on_cwe,
        ..
    } = &args.command
    {
        if baseline_file.is_some()
            && fail_on_severity.is_none()
            && fail_on_cwe.is_none()
            && !baseline_filtered.findings.is_empty()
        {
            violating_findings.extend(baseline_filtered.findings.clone());
            criteria_description.push("New findings vs baseline".to_string());
        }

        // 3. Fail-on-severity violations (takes precedence over baseline)
        if let Some(severity_list) = fail_on_severity {
            let target_findings = if baseline_file.is_some() {
                &baseline_filtered.findings // Apply to new baseline findings only
            } else {
                &final_filtered.findings // Apply to all findings
            };

            let severity_violations = evaluate_fail_on_severity(target_findings, severity_list);
            if !severity_violations.is_empty() {
                violating_findings.extend(severity_violations);
                if baseline_file.is_some() {
                    criteria_description.push("New findings vs baseline".to_string());
                }
                criteria_description.push(format!("Severity criteria: {severity_list}"));
            }
        }

        // 4. Fail-on-CWE violations (takes precedence over baseline)
        if let Some(cwe_list) = fail_on_cwe {
            let target_findings = if baseline_file.is_some() {
                &baseline_filtered.findings // Apply to new baseline findings only
            } else {
                &final_filtered.findings // Apply to all findings
            };

            let cwe_violations = evaluate_fail_on_cwe(target_findings, cwe_list);
            if !cwe_violations.is_empty() {
                violating_findings.extend(cwe_violations);
                if baseline_file.is_some()
                    && !criteria_description.contains(&"New findings vs baseline".to_string())
                {
                    criteria_description.push("New findings vs baseline".to_string());
                }
                criteria_description.push(format!("CWE criteria: {cwe_list}"));
            }
        }
    }

    // Remove duplicates using HashSet for better performance
    let mut seen = HashSet::new();
    let mut unique_findings = Vec::with_capacity(violating_findings.len());

    for finding in violating_findings {
        let key = (
            finding.finding.title.clone(),
            finding.finding.files.source_file.file.clone(),
            finding.finding.files.source_file.line,
        );
        if seen.insert(key) {
            unique_findings.push(finding);
        }
    }

    violating_findings = unique_findings;

    // Export violations if any criteria were violated
    if !violating_findings.is_empty() {
        export_pass_fail_filtered_findings(&violating_findings, &criteria_description, output_path)
            .await;
        // Exit with non-zero code when pass-fail criteria are violated
        info!(
            "\n❌ Pass-fail criteria FAILED - {} violations detected",
            violating_findings.len()
        );
        std::process::exit(1);
    } else {
        // When policy criteria are specified and pass, show success message
        if let Commands::Pipeline {
            fail_on_severity,
            fail_on_cwe,
            baseline_file,
            ..
        } = &args.command
        {
            if fail_on_severity.is_some() || fail_on_cwe.is_some() {
                if baseline_file.is_some() {
                    info!("\n✅ Baseline comparison PASSED - no policy violations in new findings");
                } else {
                    info!("\n✅ Pass-fail criteria PASSED - no violations detected");
                }
            } else {
                debug!("ℹ️  No pass-fail criteria violations found - filtered JSON not created");
            }
        }
    }
}

/// Export pass-fail criteria violations to filtered JSON output file
async fn export_pass_fail_filtered_findings(
    violating_findings: &[FindingWithSource],
    criteria_description: &[String],
    output_path: &str,
) {
    debug!("💾 Exporting pass-fail violations to: {output_path}");

    // Create a structure for the pass-fail filtered JSON output
    let filtered_export = serde_json::json!({
        "pass_fail_criteria": {
            "filtered_at": chrono::Utc::now().to_rfc3339(),
            "description": "Findings that violate pass-fail criteria",
            "criteria_applied": criteria_description,
            "total_violations": violating_findings.len(),
        },
        "findings": violating_findings,
        "summary": {
            "total": violating_findings.len(),
            "by_severity": calculate_severity_breakdown(violating_findings),
            "by_cwe": calculate_cwe_breakdown(violating_findings)
        }
    });

    match serde_json::to_string_pretty(&filtered_export) {
        Ok(json_content) => {
            if let Err(e) = tokio::fs::write(output_path, json_content).await {
                error!("❌ Failed to write filtered JSON output file: {e}");
            } else {
                info!("✅ Pass-fail violations exported to: {output_path}");
                info!("   Total violations: {}", violating_findings.len());
                info!("   Criteria: {}", criteria_description.join(", "));
            }
        }
        Err(e) => {
            error!("❌ Failed to serialize pass-fail violations: {e}");
        }
    }
}

/// Evaluate fail-on-severity criteria and return violating findings
fn evaluate_fail_on_severity(
    findings: &[FindingWithSource],
    severity_list: &str,
) -> Vec<FindingWithSource> {
    // Parse severity list (pre-size for common case)
    let severity_parts: Vec<&str> = severity_list.split(',').collect();
    let mut target_severities = Vec::with_capacity(severity_parts.len());
    for s in severity_parts {
        if let Some(level) = parse_severity_name_to_level(s.trim()) {
            target_severities.push(level);
        }
    }

    if target_severities.is_empty() {
        return Vec::new();
    }

    // Filter findings that match target severities
    findings
        .iter()
        .filter(|finding| target_severities.contains(&finding.finding.severity))
        .cloned()
        .collect()
}

/// Evaluate fail-on-cwe criteria and return violating findings
fn evaluate_fail_on_cwe(findings: &[FindingWithSource], cwe_list: &str) -> Vec<FindingWithSource> {
    // Parse CWE list (pre-size and optimize string operations)
    let cwe_parts: Vec<&str> = cwe_list.split(',').collect();
    let mut target_cwes = Vec::with_capacity(cwe_parts.len());
    for s in cwe_parts {
        let cwe = s.trim();
        if let Some(stripped) = cwe
            .strip_prefix("cwe-")
            .or_else(|| cwe.strip_prefix("CWE-"))
        {
            target_cwes.push(stripped.to_string());
        } else {
            target_cwes.push(cwe.to_string());
        }
    }

    if target_cwes.is_empty() {
        return Vec::new();
    }

    // Filter findings that match target CWEs
    findings
        .iter()
        .filter(|finding| target_cwes.contains(&finding.finding.cwe_id))
        .cloned()
        .collect()
}

/// Parse severity name to numeric level
fn parse_severity_name_to_level(severity_name: &str) -> Option<u32> {
    match severity_name.to_lowercase().as_str() {
        "informational" | "info" => Some(0),
        "very low" | "very-low" | "verylow" | "very_low" => Some(1),
        "low" => Some(2),
        "medium" | "med" => Some(3),
        "high" => Some(4),
        "very high" | "very-high" | "veryhigh" | "very_high" | "critical" => Some(5),
        _ => None,
    }
}

/// Calculate severity breakdown for findings
fn calculate_severity_breakdown(findings: &[FindingWithSource]) -> serde_json::Value {
    let mut breakdown = std::collections::HashMap::new();

    for finding in findings {
        let severity_name = match finding.finding.severity {
            0 => "Informational",
            1 => "Very Low",
            2 => "Low",
            3 => "Medium",
            4 => "High",
            5 => "Very High",
            _ => "Unknown",
        };
        *breakdown.entry(severity_name.to_string()).or_insert(0u32) += 1;
    }

    serde_json::to_value(breakdown).unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
}

/// Calculate CWE breakdown for findings
fn calculate_cwe_breakdown(findings: &[FindingWithSource]) -> serde_json::Value {
    let mut breakdown = std::collections::HashMap::new();

    for finding in findings {
        *breakdown
            .entry(finding.finding.cwe_id.clone())
            .or_insert(0u32) += 1;
    }

    // Get top 10 CWEs by count
    let mut cwe_vec: Vec<(String, u32)> = breakdown.into_iter().collect();
    cwe_vec.sort_by(|a, b| b.1.cmp(&a.1));
    let top_cwes: std::collections::HashMap<String, u32> = cwe_vec.into_iter().take(10).collect();

    serde_json::to_value(top_cwes).unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
}

/// Validate that all specified teams exist in Veracode
async fn validate_teams_exist(
    client: &veracode_platform::VeracodeClient,
    team_names: &[String],
) -> Result<(), String> {
    if team_names.is_empty() {
        return Ok(());
    }

    debug!("🔍 Validating team existence...");

    // Get all available teams from Veracode
    let identity_api = IdentityApi::new(client);
    let all_teams = match identity_api.list_teams().await {
        Ok(teams) => teams,
        Err(e) => {
            warn!("⚠️  Could not validate teams due to API error: {e}");
            warn!(
                "   Skipping team validation - will let Veracode handle team assignment during application creation"
            );
            return Ok(());
        }
    };

    debug!("   Found {} teams in Veracode", all_teams.len());

    // Create a set of existing team names for fast lookup
    let existing_team_names: std::collections::HashSet<String> = all_teams
        .iter()
        .map(|team| team.team_name.clone())
        .collect();

    // Check if all requested teams exist
    let mut missing_teams = Vec::new();
    for team_name in team_names {
        if !existing_team_names.contains(team_name) {
            missing_teams.push(team_name.clone());
        }
    }

    if !missing_teams.is_empty() {
        return Err(format!(
            "The following teams do not exist in Veracode: {}. Available teams: {}",
            missing_teams.join(", "),
            existing_team_names
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
                + if existing_team_names.len() > 10 {
                    " ..."
                } else {
                    ""
                }
        ));
    }

    debug!("✅ All teams validated successfully");
    for team_name in team_names {
        debug!("   ✓ {team_name}");
    }

    Ok(())
}

/// Execute assessment scan workflow
pub fn execute_assessment_scan(
    matched_files: &[PathBuf],
    veracode_config: &VeracodeConfig,
    args: &Args,
) -> Result<(), i32> {
    if let Commands::Assessment {
        app_profile_name,
        sandbox_name,
        timeout,
        threads,
        modules,
        export_results,
        deleteincompletescan,
        no_wait,
        break_build,
        force_buildinfo_api,
        strict_sandbox,
        ..
    } = &args.command
    {
        info!("🚀 Assessment Scan requested");

        // App profile name is required field, no need to check

        // Determine scan type based on sandbox_name
        let scan_type = if sandbox_name.is_some() {
            ScanType::Sandbox
        } else {
            ScanType::Policy
        };

        // Use assessment timeout default if not overridden
        let timeout_value = if *timeout == 60 {
            // Assessment default, not overridden
            60 // Use assessment default
        } else {
            *timeout
        };

        let region = parse_region(&args.region)?;

        // Parse modules if provided
        let selected_modules = modules.as_ref().map(|modules_str| {
            modules_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<String>>()
        });

        let assessment_config = AssessmentScanConfig {
            app_profile_name: app_profile_name.clone(),
            scan_type,
            sandbox_name: sandbox_name.clone(),
            selected_modules,
            region,
            timeout: timeout_value,
            threads: *threads,
            autoscan: true, // Always true for now; required when no-wait is specified
            monitor_completion: !no_wait, // Inverse of no_wait
            export_results_path: export_results.clone(),
            deleteincompletescan: *deleteincompletescan,
            break_build: *break_build,
            policy_wait_max_retries: 30, // Default: 30 retries (5 minutes)
            policy_wait_retry_delay_seconds: 10, // Default: 10 seconds between retries
            force_buildinfo_api: *force_buildinfo_api, // CLI flag for forcing buildinfo API
            strict_sandbox: *strict_sandbox, // CLI flag for treating Conditional Pass as failure for sandbox scans
        };

        let submitter = AssessmentSubmitter::new(veracode_config.clone(), assessment_config)
            .map_err(|e| {
                error!("❌ Failed to create assessment submitter: {e}");
                1
            })?;

        execute_assessment_scan_with_runtime(submitter, matched_files, args)
    } else {
        error!("❌ execute_assessment_scan called with non-assessment command");
        Err(1)
    }
}

/// Execute assessment scan with async runtime
fn execute_assessment_scan_with_runtime(
    submitter: AssessmentSubmitter,
    matched_files: &[PathBuf],
    args: &Args,
) -> Result<(), i32> {
    submitter.display_config();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(
            async move { execute_assessment_scan_async(submitter, matched_files, args).await },
        )
}

/// Async execution of assessment scan
async fn execute_assessment_scan_async(
    submitter: AssessmentSubmitter,
    matched_files: &[PathBuf],
    args: &Args,
) -> Result<(), i32> {
    if let Commands::Assessment {
        app_profile_name,
        teamname,
        bus_cri,
        ..
    } = &args.command
    {
        debug!("🔍 Looking up or creating application profile: {app_profile_name}");

        // Parse team names from CLI if provided
        let team_names = teamname.as_ref().map(|team_str| {
            team_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<String>>()
        });

        if let Some(ref teams) = team_names {
            debug!("   Teams to assign: {}", teams.join(", "));

            // Validate team existence before creating application
            if let Err(e) = validate_teams_exist(&submitter.client, teams).await {
                error!("❌ Team validation failed: {e}");
                return Err(1);
            }
        }

        let app_id = match submitter
            .client
            .create_application_if_not_exists(
                app_profile_name,
                crate::cli::parse_business_criticality(bus_cri),
                Some("Application created by Verascan for assessment scanning".to_string()),
                team_names,
            )
            .await
        {
            Ok(app) => {
                debug!(
                    "✅ Application ready: {} (ID: {}, GUID: {})",
                    app.profile
                        .as_ref()
                        .map(|p| p.name.as_str())
                        .unwrap_or("Unknown"),
                    app.id,
                    app.guid
                );
                if let Some(profile) = &app.profile
                    && let Some(teams) = &profile.teams
                    && !teams.is_empty()
                {
                    let team_names: Vec<String> = teams
                        .iter()
                        .filter_map(|t| t.team_name.as_ref())
                        .cloned()
                        .collect();
                    debug!("   Associated teams: {}", team_names.join(", "));
                }
                info!("✅ Application ready: {app_profile_name}");
                crate::assessment::ApplicationId::new(app.guid, app.id.to_string())
            }
            Err(e) => {
                error!("❌ Failed to lookup or create application '{app_profile_name}': {e}");
                return Err(1);
            }
        };

        // Upload files and start scan
        match submitter.upload_and_scan(matched_files, &app_id).await {
            Ok(build_id) => {
                info!("✅ Assessment scan workflow completed");
                info!("   Build ID: {build_id}");
                info!("   App Profile: {app_profile_name}");
                match &submitter.config.scan_type {
                    ScanType::Sandbox => {
                        if let Some(sandbox_name) = &submitter.config.sandbox_name {
                            info!("   Sandbox: {sandbox_name}");
                        }
                    }
                    ScanType::Policy => {
                        info!("   Scan Type: Policy");
                    }
                }
                Ok(())
            }
            Err(e) => {
                error!("❌ Assessment scan failed: {e}");
                Err(1)
            }
        }
    } else {
        error!("❌ execute_assessment_scan_async called with non-assessment command");
        Err(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::TempDir;

    #[test]
    fn test_ensure_extension_adds_extension() {
        let result = ensure_extension("test-file", "json").unwrap();
        assert_eq!(result.extension().unwrap(), "json");
        assert_eq!(result.file_stem().unwrap(), "test-file");
    }

    #[test]
    fn test_ensure_extension_preserves_existing_extension() {
        let result = ensure_extension("test-file.json", "json").unwrap();
        assert_eq!(result.extension().unwrap(), "json");
        assert_eq!(result.file_stem().unwrap(), "test-file");
    }

    #[test]
    fn test_ensure_extension_replaces_wrong_extension() {
        let result = ensure_extension("test-file.txt", "json").unwrap();
        assert_eq!(result.extension().unwrap(), "json");
        assert_eq!(result.file_stem().unwrap(), "test-file");
    }

    #[test]
    fn test_ensure_extension_rejects_directory() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap();

        let result = ensure_extension(dir_path, "json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("is a directory"));
    }

    #[test]
    fn test_ensure_extension_rejects_nonexistent_parent() {
        let result = ensure_extension("/nonexistent/dir/file.json", "json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn test_ensure_extension_works_with_existing_parent() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test-file");
        let file_path_str = file_path.to_str().unwrap();

        let result = ensure_extension(file_path_str, "json").unwrap();
        assert_eq!(result.extension().unwrap(), "json");
    }

    #[test]
    fn test_validate_export_paths_early_success() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test-report");
        let file_path_str = file_path.to_str().unwrap();

        let args = Args {
            command: Commands::Pipeline {
                filepath: "/test".to_string(),
                filefilter: "*.jar".to_string(),
                recursive: true,
                validate: true,
                project_name: Some("Test".to_string()),
                project_url: None,
                timeout: 30,
                threads: 4,
                export_findings: file_path_str.to_string(),
                export_format: "json".to_string(),
                show_findings: false,
                findings_limit: 20,
                min_severity: None,
                project_dir: ".".to_string(),
                create_gitlab_issues: false,
                baseline_file: None,
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

        let result = validate_export_paths_early(file_path_str, &args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_export_paths_early_invalid_format() {
        let args = Args {
            command: Commands::Pipeline {
                filepath: "/test".to_string(),
                filefilter: "*.jar".to_string(),
                recursive: true,
                validate: true,
                project_name: Some("Test".to_string()),
                project_url: None,
                timeout: 30,
                threads: 4,
                export_findings: "test.txt".to_string(),
                export_format: "invalid".to_string(),
                show_findings: false,
                findings_limit: 20,
                min_severity: None,
                project_dir: ".".to_string(),
                create_gitlab_issues: false,
                baseline_file: None,
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

        let result = validate_export_paths_early("test.txt", &args);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_git_config_for_origin_url() {
        let config_content = r#"
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = https://gitlab.com:443/apptesting/vulnerable-java-app.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
        "#;

        let result = parse_git_config_for_origin_url(config_content);
        assert_eq!(
            result,
            Some("https://gitlab.com:443/apptesting/vulnerable-java-app.git".to_string())
        );
    }

    #[test]
    fn test_convert_git_url_to_web_url() {
        // Test HTTP URL
        assert_eq!(
            convert_git_url_to_web_url("https://gitlab.com:443/apptesting/vulnerable-java-app.git"),
            Some("https://gitlab.com:443/apptesting/vulnerable-java-app".to_string())
        );

        // Test HTTPS URL
        assert_eq!(
            convert_git_url_to_web_url("https://github.com/user/repo.git"),
            Some("https://github.com/user/repo".to_string())
        );

        // Test HTTP URL with credentials (exact example from user)
        assert_eq!(
            convert_git_url_to_web_url(
                "https://gitlab-ci-token:[MASKED]@gitlab.com:443/apptesting/vulnerable-python-app.git"
            ),
            Some("https://gitlab.com:443/apptesting/vulnerable-python-app".to_string())
        );

        // Test HTTPS URL with credentials
        assert_eq!(
            convert_git_url_to_web_url(
                "https://username:password@gitlab.example.com/project/repo.git"
            ),
            Some("https://gitlab.example.com/project/repo".to_string())
        );

        // Test SSH URL
        assert_eq!(
            convert_git_url_to_web_url("git@github.com:user/repo.git"),
            Some("https://github.com/user/repo".to_string())
        );

        // Test git:// URL
        assert_eq!(
            convert_git_url_to_web_url("git://github.com/user/repo.git"),
            Some("https://github.com/user/repo".to_string())
        );
    }

    #[test]
    fn test_extract_ssh_url_parts() {
        let result = extract_ssh_url_parts("git@github.com:user/repo.git");
        assert_eq!(
            result,
            Some(("github.com".to_string(), "user/repo.git".to_string()))
        );

        let result = extract_ssh_url_parts("invalid-format");
        assert_eq!(result, None);
    }

    #[test]
    fn test_redact_url_password() {
        // Test URL with credentials
        let url_with_creds =
            "http://gitlab-ci-token:secret123@gitlab.com:8929/apptesting/vulnerable-python-app.git";
        let redacted = redact_url_password(url_with_creds);
        assert_eq!(
            redacted,
            "http://gitlab-ci-token:[REDACTED]@gitlab.com:8929/apptesting/vulnerable-python-app.git"
        );

        // Test HTTPS URL with credentials
        let https_url = "https://user:password@example.com/repo.git";
        let redacted_https = redact_url_password(https_url);
        assert_eq!(
            redacted_https,
            "https://user:[REDACTED]@example.com/repo.git"
        );

        // Test URL without credentials (should remain unchanged)
        let url_no_creds = "https://github.com/user/repo.git";
        let redacted_no_creds = redact_url_password(url_no_creds);
        assert_eq!(redacted_no_creds, "https://github.com/user/repo.git");

        // Test URL with @ but no credentials (should remain unchanged)
        let url_with_at = "https://example.com/user@domain/repo.git";
        let redacted_with_at = redact_url_password(url_with_at);
        assert_eq!(redacted_with_at, "https://example.com/user@domain/repo.git");

        // Test edge case - URL with colon in path but no credentials
        let url_colon_path = "https://example.com:8080/repo.git";
        let redacted_colon_path = redact_url_password(url_colon_path);
        assert_eq!(redacted_colon_path, "https://example.com:8080/repo.git");
    }

    #[test]
    fn test_strip_credentials_from_http_url() {
        // Test HTTP URL with credentials
        assert_eq!(
            strip_credentials_from_http_url(
                "https://gitlab-ci-token:[MASKED]@gitlab.com:443/apptesting/vulnerable-python-app.git"
            ),
            "https://gitlab.com:443/apptesting/vulnerable-python-app.git"
        );

        // Test HTTPS URL with credentials
        assert_eq!(
            strip_credentials_from_http_url(
                "https://username:password@gitlab.example.com/project/repo.git"
            ),
            "https://gitlab.example.com/project/repo.git"
        );

        // Test URL without credentials (should remain unchanged)
        assert_eq!(
            strip_credentials_from_http_url("https://github.com/user/repo.git"),
            "https://github.com/user/repo.git"
        );

        // Test HTTP URL without credentials
        assert_eq!(
            strip_credentials_from_http_url(
                "https://gitlab.com:443/apptesting/vulnerable-python-app.git"
            ),
            "https://gitlab.com:443/apptesting/vulnerable-python-app.git"
        );
    }

    #[test]
    fn test_team_validation_logic() {
        // Test the core logic of team validation without needing actual API calls
        let existing_teams = vec![
            "Security Team".to_string(),
            "Development Team".to_string(),
            "QA Team".to_string(),
        ];
        let existing_team_names: HashSet<String> = existing_teams.into_iter().collect();

        // Test valid teams
        let requested_teams = vec!["Security Team".to_string(), "Development Team".to_string()];
        let mut missing_teams = Vec::new();
        for team_name in &requested_teams {
            if !existing_team_names.contains(team_name) {
                missing_teams.push(team_name.clone());
            }
        }
        assert!(missing_teams.is_empty(), "All teams should exist");

        // Test missing teams
        let requested_teams_with_missing =
            vec!["Security Team".to_string(), "NonExistent Team".to_string()];
        let mut missing_teams = Vec::new();
        for team_name in &requested_teams_with_missing {
            if !existing_team_names.contains(team_name) {
                missing_teams.push(team_name.clone());
            }
        }
        assert_eq!(
            missing_teams,
            vec!["NonExistent Team"],
            "Should detect missing team"
        );
    }
}

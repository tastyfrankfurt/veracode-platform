pub mod assessment;
pub mod baseline;
pub mod cli;
pub mod credentials;
pub mod export;
pub mod filefinder;
pub mod filevalidator;
pub mod findings;
pub mod gitlab_client;
pub mod gitlab_common;
pub mod gitlab_issues;
pub mod gitlab_mapping;
pub mod gitlab_report;
pub mod gitlab_utils;
pub mod graphql_client;
pub mod http_client;
pub mod path_resolver;
pub mod pipeline;
pub mod policy;
pub mod scan;
pub mod search;

pub use assessment::{AssessmentError, AssessmentScanConfig, AssessmentSubmitter, ScanType};
pub use baseline::{
    BaselineComparison, PolicyAssessment, execute_baseline_compare, execute_baseline_create,
    execute_policy_file_assessment, execute_policy_name_assessment,
};
pub use cli::{Args, Commands};
pub use credentials::{
    SecureApiCredentials, SecureApiId, SecureApiKey, check_pipeline_credentials,
    check_secure_pipeline_credentials, load_api_credentials, load_secure_api_credentials,
    validate_api_credential,
};
pub use export::{ExportConfig, ExportError, ExportWorkflow};
pub use filefinder::FileFinder;
pub use filevalidator::{FileValidator, SupportedFileType, ValidationError};
pub use findings::{AggregatedFindings, FindingsAggregator};
pub use gitlab_client::{GitLabClient, GitLabClientConfig, GitLabClientError};
pub use gitlab_common::{
    GitLabIssuePayload, GitLabIssueResponse, SecureToken, create_file_link, get_project_web_url,
    get_severity_name, resolve_file_path, strip_html_tags,
};
pub use gitlab_issues::{GitLabConfig, GitLabError, GitLabIssuesClient};
pub use gitlab_mapping::{
    GitLabMapperFactory, MappingConfig, ScanType as GitLabScanType, ScanTypeDetector,
    UnifiedGitLabMapper, UrlFilter,
};
pub use gitlab_report::{GitLabExportConfig, GitLabExporter};
pub use gitlab_utils::{GitLabUrlConfig, create_pipeline_url, extract_gitlab_host};
pub use graphql_client::{
    GitHubGraphQLClient, GraphQLClient, GraphQLClientConfig, GraphQLClientError,
};
pub use http_client::{
    ApiClientError, AuthStrategy, HttpClientConfig, HttpClientConfigBuilder, HttpClientError,
    HttpTimeouts, RetryConfig, RobustHttpClient,
};
pub use path_resolver::{PathResolver, PathResolverConfig};
pub use pipeline::{PipelineError, PipelineScanConfig, PipelineSubmitter};
pub use policy::execute_policy_download;
pub use scan::{execute_assessment_scan, execute_pipeline_scan};

/// Execute findings export workflow from completed scans using existing credentials
pub async fn execute_findings_export(args: &Args) -> Result<(), i32> {
    use crate::scan::configure_veracode_with_env_vars;
    use std::borrow::Cow;
    use std::path::PathBuf;

    // Extract export parameters from args
    let (app_profile_name, sandbox_name, export_format, output_path, project_dir, min_severity) =
        match &args.command {
            Commands::Export {
                app_profile_name,
                sandbox_name,
                export_format,
                output_path,
                project_dir,
                min_severity,
            } => (
                app_profile_name,
                sandbox_name,
                export_format,
                output_path,
                project_dir,
                min_severity,
            ),
            _ => return Err(1),
        };

    // Reuse existing credential loading pattern from policy.rs
    let secure_creds = load_secure_api_credentials().map_err(|_| 1)?;
    let (api_id, api_key) = check_secure_pipeline_credentials(&secure_creds).map_err(|_| 1)?;

    let region = match args.region.as_str() {
        s if s.eq_ignore_ascii_case("commercial") => veracode_platform::VeracodeRegion::Commercial,
        s if s.eq_ignore_ascii_case("european") => veracode_platform::VeracodeRegion::European,
        s if s.eq_ignore_ascii_case("federal") => veracode_platform::VeracodeRegion::Federal,
        _ => veracode_platform::VeracodeRegion::Commercial,
    };

    let base_config = veracode_platform::VeracodeConfig::new(&api_id, &api_key).with_region(region);
    let veracode_config = configure_veracode_with_env_vars(base_config, args.debug);
    let client = veracode_platform::VeracodeClient::new(veracode_config).map_err(|_| 1)?;

    // Convert severity string to numeric value if provided
    let min_severity_numeric = min_severity
        .as_ref()
        .map(|s| match s.to_lowercase().as_str() {
            "informational" | "info" => 0,
            "very-low" | "verylow" | "very_low" => 1,
            "low" => 2,
            "medium" | "med" => 3,
            "high" => 4,
            "very-high" | "veryhigh" | "very_high" | "critical" => 5,
            _ => 3, // Default to medium if unrecognized
        });

    // Create export configuration
    let config = ExportConfig {
        app_profile_name: Cow::Borrowed(app_profile_name),
        sandbox_name: sandbox_name.as_ref().map(|s| Cow::Borrowed(s.as_str())),
        sandbox_guid: None, // Will be resolved from sandbox_name internally
        export_format: Cow::Borrowed(export_format),
        output_path: Cow::Borrowed(output_path),
        project_dir: Some(PathBuf::from(project_dir)),
        debug: args.debug,
        min_severity: min_severity_numeric,
    };

    // Convert to 'static lifetime for ExportWorkflow
    let static_config = ExportConfig {
        app_profile_name: Cow::Owned(config.app_profile_name.into_owned()),
        sandbox_name: config.sandbox_name.map(|c| Cow::Owned(c.into_owned())),
        sandbox_guid: config.sandbox_guid.map(|c| Cow::Owned(c.into_owned())),
        export_format: Cow::Owned(config.export_format.into_owned()),
        output_path: Cow::Owned(config.output_path.into_owned()),
        project_dir: config.project_dir,
        debug: config.debug,
        min_severity: config.min_severity,
    };

    // Execute export workflow
    let export_workflow = ExportWorkflow::new(client, static_config);
    export_workflow.execute().await.map_err(|e| {
        eprintln!("❌ Export failed: {e}");
        1
    })?;

    Ok(())
}
pub use search::execute_file_search;

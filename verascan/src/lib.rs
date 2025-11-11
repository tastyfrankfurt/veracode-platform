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
pub mod vault_client;

#[cfg(test)]
pub mod test_utils;

pub use assessment::{AssessmentError, AssessmentScanConfig, AssessmentSubmitter, ScanType};
pub use baseline::{
    BaselineComparison, PolicyAssessment, execute_baseline_compare, execute_baseline_create,
    execute_policy_file_assessment, execute_policy_name_assessment,
};
pub use cli::{Args, Commands};
pub use credentials::{
    CredentialError, CredentialSource, SecureApiCredentials, VaultConfig,
    check_pipeline_credentials, create_veracode_config_from_args,
    create_veracode_config_from_credentials, create_veracode_config_with_proxy,
    load_api_credentials, load_veracode_credentials_from_args, validate_api_credential,
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
pub use vault_client::{
    VaultCredentialClient, load_credentials_and_proxy_from_vault, load_vault_config_from_env,
    load_veracode_credentials_with_vault,
};

use log::error;
use veracode_platform::VeracodeConfig;

/// Execute findings export workflow from completed scans using existing credentials
pub async fn execute_findings_export(
    veracode_config: &VeracodeConfig,
    args: &Args,
) -> Result<(), i32> {
    use std::borrow::Cow;
    use std::path::PathBuf;

    // Extract export parameters from args
    let Commands::Export {
        app_profile_name,
        sandbox_name,
        export_format,
        output_path,
        project_dir,
        min_severity,
        ..
    } = &args.command
    else {
        return Err(1);
    };

    let client = veracode_platform::VeracodeClient::new(veracode_config.clone()).map_err(|_| 1)?;

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
        min_severity: min_severity_numeric,
        schema_version: Cow::Borrowed(&args.gitlab_schema_version),
    };

    // Convert to 'static lifetime for ExportWorkflow
    let static_config = ExportConfig {
        app_profile_name: Cow::Owned(config.app_profile_name.into_owned()),
        sandbox_name: config.sandbox_name.map(|c| Cow::Owned(c.into_owned())),
        sandbox_guid: config.sandbox_guid.map(|c| Cow::Owned(c.into_owned())),
        export_format: Cow::Owned(config.export_format.into_owned()),
        output_path: Cow::Owned(config.output_path.into_owned()),
        project_dir: config.project_dir,
        min_severity: config.min_severity,
        schema_version: Cow::Owned(config.schema_version.into_owned()),
    };

    // Execute export workflow
    let export_workflow = ExportWorkflow::new(client, static_config);
    export_workflow.execute().await.map_err(|e| {
        error!("❌ Export failed: {e}");
        1
    })?;

    Ok(())
}
pub use search::execute_file_search;

//! GitLab Utilities
//!
//! Shared utilities for GitLab integrations to avoid code duplication across
//! different GitLab client implementations.

use url::Url;

/// GitLab URL configuration for generating web URLs
#[derive(Debug, Clone)]
pub struct GitLabUrlConfig {
    /// GitLab API base URL (e.g., "<https://gitlab.com/api/v4/projects/>")
    pub api_url: String,
    /// Project ID (numeric)
    pub project_id: String,
    /// Project web URL if available (e.g., "<https://gitlab.com/group/project>")
    pub project_web_url: Option<String>,
    /// Project path with namespace (e.g., "group/project")
    pub project_path_with_namespace: Option<String>,
}

impl GitLabUrlConfig {
    /// Create a new GitLab URL configuration
    #[must_use]
    pub fn new(
        api_url: String,
        project_id: String,
        project_web_url: Option<String>,
        project_path_with_namespace: Option<String>,
    ) -> Self {
        Self {
            api_url,
            project_id,
            project_web_url,
            project_path_with_namespace,
        }
    }
}

/// Generate a GitLab pipeline URL using the correct web URL format
///
/// This function implements a 3-tier fallback strategy:
/// 1. Use `project_web_url` if available (most reliable)
/// 2. Use `project_path_with_namespace` + host extraction
/// 3. Fallback to `project_id` based URLs
#[must_use]
pub fn create_pipeline_url(config: &GitLabUrlConfig, pipeline_id: &str) -> String {
    // First try using CI_PROJECT_URL if available (most reliable)
    if let Some(ref project_url) = config.project_web_url {
        return format!("{project_url}/-/pipelines/{pipeline_id}");
    }

    // If we have project path with namespace, construct the web URL properly
    if let Some(ref project_path) = config.project_path_with_namespace {
        // Extract the GitLab host from the API URL
        if let Some(gitlab_host) = extract_gitlab_host(&config.api_url) {
            return format!("https://{gitlab_host}/{project_path}/-/pipelines/{pipeline_id}");
        }
    }

    // Fallback: try to construct from api_url by replacing API path with web path
    // This handles cases where we don't have full project info yet
    let web_base = if config.api_url.contains("/api/v4/projects/") {
        config.api_url.replace("/api/v4/projects/", "/")
    } else {
        // Handle case where api_url might not contain the expected path
        config.api_url.trim_end_matches('/').to_string()
    };

    // Use project_id as fallback (less ideal but functional)
    format!(
        "{web_base}/-/projects/{}/pipelines/{pipeline_id}",
        config.project_id
    )
}

/// Extract GitLab host from API URL
///
/// Examples:
/// - "<https://gitlab.com/api/v4/projects/>" -> Some("gitlab.com")
/// - "<https://git.company.com/api/v4/projects/>" -> Some("git.company.com")
/// - "invalid-url" -> None
#[must_use]
pub fn extract_gitlab_host(api_url: &str) -> Option<String> {
    // Try parsing as proper URL first
    if let Ok(url) = Url::parse(api_url) {
        return Some(url.host_str()?.to_string());
    }

    // Fallback: extract host from URL string manually
    if let Some(start) = api_url.find("://") {
        let after_protocol = api_url.get(start.saturating_add(3)..)?;
        if let Some(end) = after_protocol.find('/') {
            return after_protocol.get(..end).map(String::from);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pipeline_url_with_project_web_url() {
        let config = GitLabUrlConfig::new(
            "https://gitlab.example.com/api/v4/projects/".to_string(),
            "123".to_string(),
            Some("https://gitlab.example.com/group/project".to_string()),
            None,
        );

        let pipeline_url = create_pipeline_url(&config, "456");
        assert_eq!(
            pipeline_url,
            "https://gitlab.example.com/group/project/-/pipelines/456"
        );
    }

    #[test]
    fn test_create_pipeline_url_with_project_path_namespace() {
        let config = GitLabUrlConfig::new(
            "https://gitlab.example.com/api/v4/projects/".to_string(),
            "123".to_string(),
            None,
            Some("group/project".to_string()),
        );

        let pipeline_url = create_pipeline_url(&config, "456");
        assert_eq!(
            pipeline_url,
            "https://gitlab.example.com/group/project/-/pipelines/456"
        );
    }

    #[test]
    fn test_create_pipeline_url_fallback() {
        let config = GitLabUrlConfig::new(
            "https://gitlab.example.com/api/v4/projects/".to_string(),
            "123".to_string(),
            None,
            None,
        );

        let pipeline_url = create_pipeline_url(&config, "456");
        assert_eq!(
            pipeline_url,
            "https://gitlab.example.com//-/projects/123/pipelines/456"
        );
    }

    #[test]
    fn test_extract_gitlab_host() {
        // Test valid URLs
        assert_eq!(
            extract_gitlab_host("https://gitlab.example.com/api/v4/projects/"),
            Some("gitlab.example.com".to_string())
        );

        assert_eq!(
            extract_gitlab_host("https://gitlab.com/api/v4/projects/"),
            Some("gitlab.com".to_string())
        );

        assert_eq!(
            extract_gitlab_host("https://git.company.com/api/v4/projects/"),
            Some("git.company.com".to_string())
        );

        // Test invalid URL
        assert_eq!(extract_gitlab_host("not-a-url"), None);
    }

    #[test]
    fn test_gitlab_url_config_creation() {
        let config = GitLabUrlConfig::new(
            "https://gitlab.com/api/v4/projects/".to_string(),
            "123".to_string(),
            Some("https://gitlab.com/group/project".to_string()),
            Some("group/project".to_string()),
        );

        assert_eq!(config.api_url, "https://gitlab.com/api/v4/projects/");
        assert_eq!(config.project_id, "123");
        assert_eq!(
            config.project_web_url,
            Some("https://gitlab.com/group/project".to_string())
        );
        assert_eq!(
            config.project_path_with_namespace,
            Some("group/project".to_string())
        );
    }
}

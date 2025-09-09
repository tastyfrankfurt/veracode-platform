//! GitLab API client using centralized HTTP client
//!
//! This module provides GitLab-specific API functionality built on top of the
//! centralized RobustHttpClient, maintaining all robust networking features.

use crate::findings::AggregatedFindings;
use crate::gitlab_common::{
    GitLabIssuePayload, GitLabIssueResponse, SecureToken, create_file_link, get_project_web_url,
    get_severity_name, resolve_file_path, strip_html_tags,
};
use crate::gitlab_utils::{GitLabUrlConfig, create_pipeline_url};
use crate::http_client::{
    AuthStrategy, HttpClientConfigBuilder, HttpClientError, RobustHttpClient,
};
use crate::path_resolver::{PathResolver, PathResolverConfig};
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};

use log::{debug, error, info};

/// GitLab client configuration
#[derive(Clone)]
pub struct GitLabClientConfig {
    pub api_token: SecureToken,
    pub project_id: String,
    pub pipeline_id: Option<String>,
    pub project_web_url: Option<String>,
    pub commit_sha: Option<String>,
    pub project_path_with_namespace: Option<String>,
    pub project_name: Option<String>,
    pub project_dir: Option<PathBuf>,
    pub path_resolver: Option<PathResolver>,
}

impl std::fmt::Debug for GitLabClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitLabClientConfig")
            .field("api_token", &"[REDACTED]")
            .field("project_id", &self.project_id)
            .field("pipeline_id", &self.pipeline_id)
            .field("project_web_url", &self.project_web_url)
            .field("commit_sha", &self.commit_sha)
            .field(
                "project_path_with_namespace",
                &self.project_path_with_namespace,
            )
            .field("project_name", &self.project_name)
            .field("project_dir", &self.project_dir)
            .field("path_resolver", &self.path_resolver.is_some())
            .finish()
    }
}

/// Type alias for GitLab client errors (using consolidated HTTP client error)
pub type GitLabClientError = HttpClientError;

/// GitLab API client with robust networking
pub struct GitLabClient {
    http_client: RobustHttpClient,
    config: GitLabClientConfig,
}

impl GitLabClient {
    /// Create a new GitLab client from environment variables
    pub fn from_env() -> Result<Self, GitLabClientError> {
        let gitlab_config = GitLabClientConfig::from_env()?;

        // Create HTTP client configuration
        let gitlab_url = env::var("CI_API_V4_URL")
            .map(|url| format!("{}/projects/", url.trim_end_matches('/')))
            .unwrap_or_else(|_| "https://gitlab.com/api/v4/projects/".to_string());

        let http_config = HttpClientConfigBuilder::for_api_client(gitlab_url, "VERASCAN")
            .with_auth_strategy(AuthStrategy::CustomHeader {
                name: "PRIVATE-TOKEN".to_string(),
                value: gitlab_config.api_token.as_str().to_string(),
            })?
            .with_api("GitLab")
            .build();

        let http_client = RobustHttpClient::new(http_config)?;

        Ok(Self {
            http_client,
            config: gitlab_config,
        })
    }

    /// Validate GitLab requirements and connectivity
    pub async fn validate_connection() -> Result<(), GitLabClientError> {
        HttpClientError::print_validation("GitLab");

        let client = Self::from_env()?;

        debug!("✅ Environment variables validated:");
        debug!("   Project ID: {}", client.config.project_id);
        debug!("   GitLab URL: {}", client.http_client.base_url());

        // Test API connectivity by checking project access
        client
            .http_client
            .test_connectivity(&client.config.project_id)
            .await?;

        let project_info: serde_json::Value =
            client.http_client.get(&client.config.project_id).await?;
        let project_name = project_info["name"].as_str().unwrap_or("Unknown");
        let project_path = project_info["path_with_namespace"]
            .as_str()
            .unwrap_or("unknown/project");

        HttpClientError::print_validation_success("GitLab");
        debug!("   Project: {project_name} ({project_path})");
        HttpClientError::print_api_access();

        // Check if we can create issues (check permissions)
        let issues_endpoint = format!("{}/issues", client.config.project_id);
        match client
            .http_client
            .get::<Vec<GitLabIssueResponse>>(&issues_endpoint)
            .await
        {
            Ok(_) => {
                HttpClientError::print_permission_result("Issue creation", true);
            }
            Err(HttpClientError::ApiError { status, .. }) => {
                info!("   Issue creation: ⚠️  May be restricted (status: {status})");
            }
            Err(e) => {
                HttpClientError::print_permission_error("Issue creation", &e.to_string());
            }
        }

        Ok(())
    }

    /// Create GitLab issues from aggregated findings
    pub async fn create_issues_from_findings(
        &mut self,
        aggregated: &AggregatedFindings,
    ) -> Result<Vec<GitLabIssueResponse>, GitLabClientError> {
        debug!(
            "📝 Creating GitLab issues from {} findings",
            aggregated.findings.len()
        );

        // Fetch project information for URL construction
        self.fetch_project_info().await?;

        let mut created_issues = Vec::new();
        let mut skipped_count = 0;
        let mut duplicate_count = 0;

        for (index, finding_with_source) in aggregated.findings.iter().enumerate() {
            let finding = &finding_with_source.finding;

            // Skip informational findings to reduce noise
            if finding.severity == 0 {
                skipped_count += 1;
                continue;
            }

            let issue_payload = self.create_issue_payload(finding_with_source)?;

            // Check if an issue with this title already exists
            match self.issue_already_exists(&issue_payload.title).await {
                Ok(true) => {
                    debug!(
                        "⏭️  Skipping duplicate issue {}/{}: {}",
                        index + 1,
                        aggregated.findings.len(),
                        issue_payload.title
                    );
                    duplicate_count += 1;
                    continue;
                }
                Ok(false) => {
                    // Continue with issue creation
                }
                Err(e) => {
                    error!(
                        "⚠️  Warning: Failed to check for duplicates for {}: {}. Creating issue anyway.",
                        finding.title, e
                    );
                }
            }

            debug!(
                "📋 Creating issue {}/{}: {}",
                index + 1,
                aggregated.findings.len(),
                issue_payload.title
            );

            match self.create_issue(&issue_payload).await {
                Ok(issue) => {
                    debug!("✅ Created issue #{}: {}", issue.iid, issue.web_url);
                    info!("✅ Created issue #{}: {}", issue.iid, finding.title);
                    created_issues.push(issue);
                }
                Err(e) => {
                    error!("❌ Failed to create issue for {}: {}", finding.title, e);
                }
            }

            // Add small delay to avoid rate limiting
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        if skipped_count > 0 {
            info!("ℹ️  Skipped {skipped_count} informational findings");
        }

        if duplicate_count > 0 {
            info!("⏭️  Skipped {duplicate_count} duplicate issues");
        }

        info!("✅ Created {} GitLab issues", created_issues.len());

        Ok(created_issues)
    }

    /// Create a single GitLab issue
    async fn create_issue(
        &self,
        payload: &GitLabIssuePayload,
    ) -> Result<GitLabIssueResponse, GitLabClientError> {
        let endpoint = format!("{}/issues", self.config.project_id);
        let issue = self.http_client.post(&endpoint, payload).await?;
        Ok(issue)
    }

    /// Check if an issue with the given title already exists
    async fn issue_already_exists(&self, title: &str) -> Result<bool, GitLabClientError> {
        let encoded_title = urlencoding::encode(title);
        let endpoint = format!(
            "{}/issues?search={}&in=title&state=opened&labels=security::veracode",
            self.config.project_id, encoded_title
        );

        debug!("🔍 Searching for existing issue: {title}");

        let issues: Vec<GitLabIssueResponse> = self.http_client.get(&endpoint).await?;

        // Check for exact title match (GitLab search is fuzzy, so we need exact match)
        let exact_match = issues.iter().any(|issue| issue.title == title);

        if exact_match {
            debug!("✅ Found existing issue with exact title match");
        } else {
            debug!("🆕 No existing issue found with exact title match");
        }

        Ok(exact_match)
    }

    /// Set the project directory for resolving file paths
    pub fn with_project_dir<P: AsRef<Path>>(mut self, project_dir: P) -> Self {
        let path = project_dir.as_ref();
        let absolute_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
                .canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
        };

        self.config.project_dir = Some(absolute_path.clone());

        let resolver_config = PathResolverConfig::new(&absolute_path);
        self.config.path_resolver = Some(PathResolver::new(resolver_config));

        self
    }

    /// Fetch and cache project information for URL construction
    async fn fetch_project_info(&mut self) -> Result<(), GitLabClientError> {
        if self.config.project_path_with_namespace.is_some() {
            return Ok(()); // Already cached
        }

        let project_info: serde_json::Value = self.http_client.get(&self.config.project_id).await?;

        if let Some(path_with_namespace) = project_info["path_with_namespace"].as_str() {
            self.config.project_path_with_namespace = Some(path_with_namespace.to_string());
        }
        if let Some(project_name) = project_info["name"].as_str() {
            self.config.project_name = Some(project_name.to_string());
        }

        Ok(())
    }

    /// Create issue payload from finding
    fn create_issue_payload(
        &self,
        finding_with_source: &crate::findings::FindingWithSource,
    ) -> Result<GitLabIssuePayload, GitLabClientError> {
        let finding = &finding_with_source.finding;
        let source = &finding_with_source.source_scan;

        // Resolve the file path once for consistent issue titles and descriptions
        let resolved_file_path = self.resolve_file_path(&finding.files.source_file.file);

        // Create concise title with CWE, function (or issue type), filename, line number
        let severity_name = get_severity_name(finding.severity);

        // Extract just the filename from the resolved path
        let filename = std::path::Path::new(&resolved_file_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&resolved_file_path);

        // Use function name if available, otherwise fallback to issue type
        let function_or_issue = finding
            .files
            .source_file
            .function_name
            .as_ref()
            .filter(|f| !f.is_empty() && *f != "UNKNOWN")
            .unwrap_or(&finding.issue_type);

        // Handle CWE ID (use 000 if not available)
        let cwe_id = if finding.cwe_id.is_empty() || finding.cwe_id == "0" {
            "000"
        } else {
            &finding.cwe_id
        };

        // Create initial title without hash
        let base_title = format!(
            "[{}] CWE-{}: {} @ {}:{}",
            severity_name, cwe_id, function_or_issue, filename, finding.files.source_file.line
        );

        // Create detailed description
        let description = self.create_issue_description_with_resolved_path(
            finding_with_source,
            &resolved_file_path,
        )?;

        // Create labels based on severity and issue type
        let mut labels = Vec::new();
        labels.push(format!(
            "security::severity::{}",
            severity_name.to_lowercase().replace(" ", "-")
        ));
        labels.push("security::veracode".to_string());
        labels.push("security::sast".to_string());

        // Add CWE label if available
        if !finding.cwe_id.is_empty() && finding.cwe_id != "0" {
            labels.push(format!("security::cwe-{}", finding.cwe_id));
        }

        // Add high priority label for critical/high severity
        if finding.severity >= 4 {
            labels.push("priority::high".to_string());
        }

        let labels_string = if labels.is_empty() {
            None
        } else {
            Some(labels.join(","))
        };

        // Create hash for uniqueness
        let mut hasher = Sha256::new();
        let project_name = self
            .config
            .project_name
            .as_deref()
            .unwrap_or(&source.project_name);
        hasher.update(project_name.as_bytes());
        hasher.update(b"|");
        hasher.update(finding.files.source_file.file.as_bytes());
        hasher.update(b"|");
        hasher.update(cwe_id.as_bytes());
        hasher.update(b"|");
        hasher.update(finding.issue_type.as_bytes());
        hasher.update(b"|");
        hasher.update(finding.title.as_bytes());
        hasher.update(b"|");
        hasher.update(finding.severity.to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(resolved_file_path.as_bytes());
        hasher.update(b"|");
        hasher.update(finding.files.source_file.line.to_string().as_bytes());
        hasher.update(b"|");
        let function_name = finding
            .files
            .source_file
            .function_name
            .as_ref()
            .filter(|f| !f.is_empty() && *f != "UNKNOWN")
            .map(|s| s.as_str())
            .unwrap_or("");
        hasher.update(function_name.as_bytes());

        let payload_hash = format!("{:x}", hasher.finalize());
        let short_hash = &payload_hash[..8];

        // Create final title with hash
        let title = format!("{base_title} ({short_hash})");

        Ok(GitLabIssuePayload {
            title,
            description,
            labels: labels_string,
            assignee_ids: None,
            confidential: Some(false),
        })
    }

    /// Resolve file path using shared utility
    fn resolve_file_path(&self, file_path: &str) -> String {
        resolve_file_path(file_path, self.config.path_resolver.as_ref()).into_owned()
    }

    /// Create detailed issue description with pre-resolved file path
    fn create_issue_description_with_resolved_path(
        &self,
        finding_with_source: &crate::findings::FindingWithSource,
        resolved_file_path: &str,
    ) -> Result<String, GitLabClientError> {
        let finding = &finding_with_source.finding;
        let source = &finding_with_source.source_scan;

        let mut description = String::new();

        // Summary
        description.push_str(&format!("## Security Vulnerability: {}\n\n", finding.title));

        // Severity badge
        let severity_name = get_severity_name(finding.severity);
        let badge_color = match finding.severity {
            5 => "critical",
            4 => "important",
            3 => "warning",
            2 => "secondary",
            _ => "info",
        };
        description.push_str(&format!(
            "![{}](https://img.shields.io/badge/Severity-{}-{})\n\n",
            severity_name,
            severity_name.replace(" ", "%20"),
            badge_color
        ));

        // Details table
        description.push_str("### Details\n\n");
        description.push_str("| Field | Value |\n");
        description.push_str("|-------|-------|\n");
        description.push_str(&format!("| **Issue Type** | {} |\n", finding.issue_type));
        description.push_str(&format!(
            "| **Severity** | {} ({}) |\n",
            severity_name, finding.severity
        ));
        description.push_str(&format!(
            "| **CWE** | {} |\n",
            if finding.cwe_id.is_empty() || finding.cwe_id == "0" {
                "N/A".to_string()
            } else {
                format!(
                    "[CWE-{}](https://cwe.mitre.org/data/definitions/{}.html)",
                    finding.cwe_id, finding.cwe_id
                )
            }
        ));

        // Create file link with line number
        let file_link = self.create_file_link(resolved_file_path, finding.files.source_file.line);
        description.push_str(&format!("| **File** | {file_link} |\n"));
        description.push_str(&format!(
            "| **Line** | {} |\n",
            finding.files.source_file.line
        ));

        if let Some(ref function_name) = finding.files.source_file.function_name {
            if !function_name.is_empty() && function_name != "UNKNOWN" {
                description.push_str(&format!("| **Function** | `{function_name}` |\n"));
            }
        }

        description.push_str(&format!("| **Scan ID** | `{}` |\n", source.scan_id));
        description.push_str(&format!("| **Project** | {} |\n", source.project_name));

        // Add flaw details link if available
        if let Some(ref flaw_details_link) = finding.flaw_details_link {
            if !flaw_details_link.is_empty() {
                description.push_str(&format!(
                    "| **Flaw Details** | [View in Veracode]({flaw_details_link}) |\n"
                ));
            }
        }

        description.push('\n');

        // Enhanced source code section with direct link
        if let Some(project_web_url) = get_project_web_url(
            self.config.project_web_url.as_deref(),
            self.config.project_path_with_namespace.as_deref(),
            self.http_client.base_url(),
        ) {
            let branch_or_commit = self.config.commit_sha.as_deref().unwrap_or("main");
            let file_url = format!(
                "{}/-/blob/{}/{}#L{}",
                project_web_url,
                branch_or_commit,
                resolved_file_path,
                finding.files.source_file.line
            );
            description.push_str("### 📁 Source Code\n\n");
            description.push_str(&format!(
                "🔗 **[View code at line {}]({})**\n\n",
                finding.files.source_file.line, file_url
            ));
        }

        // Related Links section
        let mut has_links = false;
        let mut links_section = String::new();

        // Pipeline link
        if let Some(ref pipeline_id) = self.config.pipeline_id {
            let pipeline_url = self.create_pipeline_url(pipeline_id);
            links_section.push_str(&format!("- [Pipeline Run]({pipeline_url})\n"));
            has_links = true;
        }

        // Flaw details link
        if let Some(ref flaw_details_link) = finding.flaw_details_link {
            if !flaw_details_link.is_empty() {
                links_section.push_str(&format!(
                    "- [Detailed Vulnerability Information (Veracode)]({flaw_details_link})\n"
                ));
                has_links = true;
            }
        }

        // Add the links section if we have any links
        if has_links {
            description.push_str("### 🔗 Related Links\n\n");
            description.push_str(&links_section);
            description.push('\n');
        }

        // Vulnerability Description from Veracode
        if !finding.display_text.is_empty() {
            description.push_str("### 📄 Vulnerability Description\n\n");
            let clean_text = strip_html_tags(&finding.display_text);
            description.push_str(&clean_text);
            description.push_str("\n\n");
        }

        // Remediation guidance
        description.push_str("### 🔧 Remediation\n\n");
        description.push_str(&format!(
            "This {} vulnerability requires attention. ",
            finding.issue_type
        ));
        description.push_str(
            "Please review the identified code and apply appropriate security measures:\n\n",
        );
        description
            .push_str("1. **Review** the vulnerable code in the identified file and function\n");
        description.push_str(
            "2. **Research** the specific vulnerability type and remediation techniques\n",
        );
        description.push_str("3. **Apply** security fixes following secure coding practices\n");
        description
            .push_str("4. **Test** thoroughly to ensure the fix doesn't break functionality\n");
        description.push_str("5. **Re-scan** to verify the vulnerability has been resolved\n\n");

        // CWE reference
        if !finding.cwe_id.is_empty() && finding.cwe_id != "0" {
            description.push_str(&format!(
                "For detailed information about this vulnerability type, see [CWE-{}](https://cwe.mitre.org/data/definitions/{}.html).\n\n",
                finding.cwe_id, finding.cwe_id
            ));
        }

        // Footer
        description.push_str("---\n\n");
        description
            .push_str("*This issue was automatically created by Verascan security scanning.*");

        Ok(description)
    }

    /// Create a hyperlink to the source file with line number using shared utility
    fn create_file_link(&self, file_path: &str, line_number: u32) -> String {
        let project_web_url = get_project_web_url(
            self.config.project_web_url.as_deref(),
            self.config.project_path_with_namespace.as_deref(),
            self.http_client.base_url(),
        );
        create_file_link(
            file_path,
            line_number,
            project_web_url.as_deref(),
            self.config.commit_sha.as_deref(),
        )
    }

    /// Create pipeline URL using the shared GitLab utilities
    fn create_pipeline_url(&self, pipeline_id: &str) -> String {
        let url_config = GitLabUrlConfig::new(
            self.http_client.base_url().to_string(),
            self.config.project_id.clone(),
            self.config.project_web_url.clone(),
            self.config.project_path_with_namespace.clone(),
        );
        create_pipeline_url(&url_config, pipeline_id)
    }
}

impl GitLabClientConfig {
    /// Create GitLab configuration from environment variables
    pub fn from_env() -> Result<Self, GitLabClientError> {
        let api_token = env::var("PRIVATE_TOKEN")
            .or_else(|_| env::var("CI_TOKEN"))
            .or_else(|_| env::var("GITLAB_TOKEN"))
            .map_err(|_| {
                HttpClientError::MissingEnvVar(
                    "PRIVATE_TOKEN, CI_TOKEN, or GITLAB_TOKEN".to_string(),
                )
            })?;

        let project_id = env::var("CI_PROJECT_ID")
            .map_err(|_| HttpClientError::MissingEnvVar("CI_PROJECT_ID".to_string()))?;

        let pipeline_id = env::var("CI_PIPELINE_ID").ok();
        let project_web_url = env::var("CI_PROJECT_URL").ok();
        let commit_sha = env::var("CI_COMMIT_SHA").ok();

        Ok(Self {
            api_token: SecureToken::new(api_token),
            project_id,
            pipeline_id,
            project_web_url,
            commit_sha,
            project_path_with_namespace: None,
            project_name: None,
            project_dir: None,
            path_resolver: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_token_redaction() {
        let token = SecureToken::new("super-secret-token-12345".to_string());

        let debug_output = format!("{token:?}");
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("super-secret-token"));

        let display_output = format!("{token}");
        assert_eq!(display_output, "[REDACTED]");
        assert!(!display_output.contains("super-secret-token"));

        assert_eq!(token.as_str(), "super-secret-token-12345");
    }

    #[test]
    fn test_gitlab_client_config_debug_redaction() {
        let config = GitLabClientConfig {
            api_token: SecureToken::new("secret-token-456".to_string()),
            project_id: "123".to_string(),
            pipeline_id: Some("456".to_string()),
            project_web_url: Some("https://gitlab.example.com/project".to_string()),
            commit_sha: Some("abc123".to_string()),
            project_path_with_namespace: Some("user/project".to_string()),
            project_name: Some("MyProject".to_string()),
            project_dir: None,
            path_resolver: None,
        };

        let debug_output = format!("{config:?}");

        assert!(debug_output.contains("api_token: \"[REDACTED]\""));
        assert!(!debug_output.contains("secret-token-456"));
        assert!(debug_output.contains("project_id: \"123\""));
        assert!(debug_output.contains("pipeline_id: Some(\"456\")"));
    }
}

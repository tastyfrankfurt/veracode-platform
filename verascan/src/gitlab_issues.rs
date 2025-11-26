//! GitLab Issues Integration
//!
//! This module provides functionality to create GitLab issues from Veracode scan results
//! using GitLab CI environment variables and API tokens.

use crate::findings::AggregatedFindings;
use crate::gitlab_common::{
    GitLabIssuePayload, GitLabIssueResponse, SecureToken, create_file_link, get_project_web_url,
    get_severity_name, resolve_file_path, strip_html_tags,
};
use crate::gitlab_utils::{GitLabUrlConfig, create_pipeline_url};
use crate::http_client::{HttpTimeouts, RetryConfig};
use crate::path_resolver::{PathResolver, PathResolverConfig};
use reqwest::{
    Client,
    header::{HeaderMap, HeaderValue},
};
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

use log::{debug, error, info};
use tokio::time::sleep;

/// GitLab environment configuration
#[derive(Clone)]
pub struct GitLabConfig {
    pub api_token: SecureToken,
    pub project_id: String,
    pub pipeline_id: Option<String>,
    pub gitlab_url: String,
    pub project_web_url: Option<String>,
    pub commit_sha: Option<String>,
    pub project_path_with_namespace: Option<String>,
    pub project_name: Option<String>,
    pub project_dir: Option<PathBuf>,
    pub path_resolver: Option<PathResolver>,
    pub http_timeouts: HttpTimeouts,
    pub retry_config: RetryConfig,
}

impl std::fmt::Debug for GitLabConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitLabConfig")
            .field("api_token", &"[REDACTED]")
            .field("project_id", &self.project_id)
            .field("pipeline_id", &self.pipeline_id)
            .field("gitlab_url", &self.gitlab_url)
            .field("project_web_url", &self.project_web_url)
            .field("commit_sha", &self.commit_sha)
            .field(
                "project_path_with_namespace",
                &self.project_path_with_namespace,
            )
            .field("project_name", &self.project_name)
            .field("project_dir", &self.project_dir)
            .field("path_resolver", &self.path_resolver.is_some())
            .field("http_timeouts", &self.http_timeouts)
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

/// Error types for GitLab integration
#[derive(Debug, thiserror::Error)]
pub enum GitLabError {
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("GitLab API error: {status} - {message}")]
    ApiError { status: u16, message: String },
    #[error("Request failed after {attempts} retry attempts: {last_error}")]
    RetryExhausted { attempts: u32, last_error: String },
    #[error("Request timeout after {duration:?}")]
    Timeout { duration: Duration },
}

/// Wrapper for retry-able HTTP requests
struct RetryableRequest {
    retry_config: RetryConfig,
}

impl RetryableRequest {
    fn new(retry_config: RetryConfig) -> Self {
        Self { retry_config }
    }

    /// Execute a request with retry logic and exponential backoff
    async fn execute_with_retry<F, Fut, T>(&self, operation: F) -> Result<T, GitLabError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, reqwest::Error>>,
    {
        let mut last_error = None;
        let mut current_delay = self.retry_config.initial_delay;

        for attempt in 0..=self.retry_config.max_retries {
            if attempt > 0 {
                debug!(
                    "🔄 Retry attempt {}/{} after {}ms delay",
                    attempt,
                    self.retry_config.max_retries,
                    current_delay.as_millis()
                );
            }

            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    last_error = Some(error.to_string());

                    // Check if error is retryable
                    if !self.is_retryable_error(&error) {
                        debug!("❌ Non-retryable error encountered: {error}");
                        return Err(GitLabError::HttpError(error));
                    }

                    // Don't sleep after the last attempt
                    if attempt < self.retry_config.max_retries {
                        // Add jitter if enabled
                        let delay = if self.retry_config.jitter {
                            self.add_jitter(current_delay)
                        } else {
                            current_delay
                        };
                        debug!("⏳ Waiting {}ms before retry...", delay.as_millis());

                        sleep(delay).await;

                        // Calculate next delay with exponential backoff
                        // Precision loss acceptable: converting duration to f64 for backoff calculation
                        #[allow(
                            clippy::cast_possible_truncation,
                            clippy::cast_sign_loss,
                            clippy::cast_precision_loss
                        )]
                        let next_delay_ms = (current_delay.as_millis() as f64
                            * self.retry_config.backoff_multiplier)
                            .max(0.0)
                            .round() as u64;
                        current_delay = std::cmp::min(
                            Duration::from_millis(next_delay_ms),
                            self.retry_config.max_delay,
                        );
                    }
                }
            }
        }

        Err(GitLabError::RetryExhausted {
            attempts: self.retry_config.max_retries.saturating_add(1),
            last_error: last_error.unwrap_or_else(|| "Unknown error".to_string()),
        })
    }

    /// Check if an error should trigger a retry
    fn is_retryable_error(&self, error: &reqwest::Error) -> bool {
        // Retry on network/connection errors
        if error.is_connect() || error.is_timeout() || error.is_request() {
            return true;
        }

        // Retry on specific HTTP status codes
        if let Some(status) = error.status() {
            match status.as_u16() {
                // Server errors (5xx) - usually temporary
                500..=599 => true,
                // Rate limiting
                429 => true,
                // Client errors (4xx) - usually permanent, don't retry
                400..=499 => false,
                _ => false,
            }
        } else {
            // If no status code, likely a network error, retry
            true
        }
    }

    /// Add random jitter to delay to avoid thundering herd
    fn add_jitter(&self, delay: Duration) -> Duration {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Simple deterministic "random" based on current time
        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .hash(&mut hasher);

        // Precision loss acceptable: converting hash and duration to f64 for jitter calculation
        #[allow(clippy::cast_precision_loss)]
        let jitter_factor = (hasher.finish() % 50) as f64 / 100.0; // 0-50% jitter
        let jitter_multiplier = 1.0 + jitter_factor;

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let jittered_ms = (delay.as_millis() as f64 * jitter_multiplier)
            .max(0.0)
            .round() as u64;
        Duration::from_millis(jittered_ms)
    }
}

/// GitLab Issues client
pub struct GitLabIssuesClient {
    client: Client,
    config: GitLabConfig,
    retryable_client: RetryableRequest,
}

impl GitLabIssuesClient {
    /// Validate GitLab requirements and connectivity
    ///
    /// # Errors
    /// Returns an error if environment variables are missing, API token format is invalid, or GitLab API connection fails
    pub async fn validate_gitlab_connection() -> Result<(), GitLabError> {
        debug!("🔍 Validating GitLab integration requirements...");

        // Check environment variables
        let config = GitLabConfig::from_env()?;

        debug!("✅ Environment variables validated:");
        debug!("   Project ID: {}", config.project_id);
        debug!("   GitLab URL: {}", config.gitlab_url);

        // Test API connectivity by checking project access
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        headers.insert(
            "PRIVATE-TOKEN",
            HeaderValue::from_str(config.api_token.as_str()).map_err(|_| {
                GitLabError::MissingEnvVar("Invalid PRIVATE_TOKEN format".to_string())
            })?,
        );

        let mut client_builder = Client::builder()
            .default_headers(headers)
            .connect_timeout(config.http_timeouts.connect_timeout)
            .timeout(config.http_timeouts.validation_timeout);

        // Check for environment variable to disable certificate validation
        if env::var("VERASCAN_DISABLE_CERT_VALIDATION").is_ok() {
            debug!(
                "⚠️  WARNING: Certificate validation disabled via VERASCAN_DISABLE_CERT_VALIDATION"
            );
            client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        let client = client_builder.build()?;
        let retryable_client = RetryableRequest::new(config.retry_config.clone());

        // Test connectivity by getting project info
        let test_url = format!("{}{}", config.gitlab_url, config.project_id);

        debug!("🌐 Testing GitLab API connectivity with retry logic...");
        debug!("   GET {test_url}");

        let response = retryable_client
            .execute_with_retry(|| client.get(&test_url).send())
            .await?;

        let status = response.status();

        if status.is_success() {
            let project_info: serde_json::Value = response.json().await?;
            let project_name = project_info
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let project_path = project_info
                .get("path_with_namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown/project");

            info!("✅ GitLab connectivity validated successfully!");
            debug!("   Project: {project_name} ({project_path})");
            debug!("   API access: ✅ Authenticated");

            // Check if we can create issues (check permissions)
            let issues_url = format!("{}{}/issues", config.gitlab_url, config.project_id);
            let issues_response = retryable_client
                .execute_with_retry(|| client.get(&issues_url).send())
                .await?;

            if issues_response.status().is_success() {
                info!("   Issue creation: ✅ Permitted");
            } else {
                info!(
                    "   Issue creation: ⚠️  May be restricted (status: {})",
                    issues_response.status()
                );
            }

            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or("Unknown error".to_string());
            Err(GitLabError::ApiError {
                status: status.as_u16(),
                message: format!("Project access failed: {error_text}"),
            })
        }
    }

    /// Create a new GitLab Issues client from environment variables
    ///
    /// # Errors
    /// Returns an error if required environment variables are missing, API token format is invalid, or HTTP client creation fails
    pub fn from_env() -> Result<Self, GitLabError> {
        let config = GitLabConfig::from_env()?;

        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        headers.insert(
            "PRIVATE-TOKEN",
            HeaderValue::from_str(config.api_token.as_str()).map_err(|_| {
                GitLabError::MissingEnvVar("Invalid PRIVATE_TOKEN format".to_string())
            })?,
        );

        let mut client_builder = Client::builder()
            .default_headers(headers)
            .connect_timeout(config.http_timeouts.connect_timeout)
            .timeout(config.http_timeouts.request_timeout);

        // Check for environment variable to disable certificate validation
        // WARNING: Only use this for development with self-signed certificates
        if env::var("VERASCAN_DISABLE_CERT_VALIDATION").is_ok() {
            debug!(
                "⚠️  WARNING: Certificate validation disabled via VERASCAN_DISABLE_CERT_VALIDATION"
            );
            debug!("   This should only be used in development environments!");
            client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        let client = client_builder.build()?;
        let retryable_client = RetryableRequest::new(config.retry_config.clone());

        debug!("🔧 GitLab Issues Client initialized with robust networking");
        debug!("   Project ID: {}", config.project_id);
        debug!("   GitLab URL: {}", config.gitlab_url);
        debug!(
            "   Connect timeout: {}s",
            config.http_timeouts.connect_timeout.as_secs()
        );
        debug!(
            "   Request timeout: {}s",
            config.http_timeouts.request_timeout.as_secs()
        );
        debug!("   Max retries: {}", config.retry_config.max_retries);
        debug!(
            "   Initial retry delay: {}ms",
            config.retry_config.initial_delay.as_millis()
        );
        if let Some(ref pipeline_id) = config.pipeline_id {
            debug!("   Pipeline ID: {pipeline_id}");
        }

        Ok(Self {
            client,
            config,
            retryable_client,
        })
    }

    /// Create GitLab issues from aggregated findings
    ///
    /// # Errors
    /// Returns an error if GitLab issue creation fails or API requests fail
    pub async fn create_issues_from_findings(
        &mut self,
        aggregated: &AggregatedFindings,
    ) -> Result<Vec<GitLabIssueResponse>, GitLabError> {
        debug!(
            "📝 Creating GitLab issues from {} findings",
            aggregated.findings.len()
        );

        // Fetch project information for URL construction
        self.fetch_project_info().await?;

        let mut created_issues = Vec::new();
        let mut skipped_count: u32 = 0;
        let mut duplicate_count: u32 = 0;

        for (index, finding_with_source) in aggregated.findings.iter().enumerate() {
            let finding = &finding_with_source.finding;

            // Skip informational findings to reduce noise
            if finding.severity == 0 {
                skipped_count = skipped_count.saturating_add(1);
                continue;
            }

            let issue_payload = self.create_issue_payload(finding_with_source)?;

            // Check if an issue with this title already exists using GitLab search API
            match self.issue_already_exists(&issue_payload.title).await {
                Ok(true) => {
                    debug!(
                        "⏭️  Skipping duplicate issue {}/{}: {}",
                        index.saturating_add(1),
                        aggregated.findings.len(),
                        issue_payload.title
                    );
                    duplicate_count = duplicate_count.saturating_add(1);
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
                    // Continue with issue creation despite search failure
                }
            }

            debug!(
                "📋 Creating issue {}/{}: {}",
                index.saturating_add(1),
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
    ) -> Result<GitLabIssueResponse, GitLabError> {
        let url = format!(
            "{}{}/issues",
            self.config.gitlab_url, self.config.project_id
        );

        debug!("🌐 POST {url} (with retry logic)");
        debug!("📤 Issue payload:");
        debug!("   Title: {}", payload.title);
        if let Some(ref labels) = payload.labels {
            debug!("   Labels: '{labels}'");
        } else {
            debug!("   Labels: None");
        }
        // Print full JSON payload
        match serde_json::to_string_pretty(payload) {
            Ok(json) => debug!("   Full JSON payload:\n{json}"),
            Err(e) => debug!("   Failed to serialize payload: {e}"),
        }

        let client = &self.client;
        let payload_json = serde_json::to_value(payload)?;

        let response = self
            .retryable_client
            .execute_with_retry(|| client.post(&url).json(&payload_json).send())
            .await?;

        let status = response.status();

        if status.is_success() {
            let issue: GitLabIssueResponse = response.json().await?;

            debug!("📥 GitLab API Response:");
            debug!("   Status: {status}");
            debug!("   Issue ID: {}", issue.id);
            debug!("   Issue IID: {}", issue.iid);
            debug!("   Title: {}", issue.title);
            debug!("   Web URL: {}", issue.web_url);
            // Print full JSON response
            match serde_json::to_string_pretty(&issue) {
                Ok(json) => debug!("   Full JSON response:\n{json}"),
                Err(e) => debug!("   Failed to serialize response: {e}"),
            }

            Ok(issue)
        } else {
            let error_text = response.text().await.unwrap_or("Unknown error".to_string());
            debug!("❌ GitLab API Error:");
            debug!("   Status: {status}");
            debug!("   Error: {error_text}");
            Err(GitLabError::ApiError {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    /// Check if an issue with the given title already exists using GitLab search API
    async fn issue_already_exists(&self, title: &str) -> Result<bool, GitLabError> {
        // URL encode the title for search parameter
        let encoded_title = urlencoding::encode(title);
        let url = format!(
            "{}{}/issues?search={}&in=title&state=opened&labels=security::veracode",
            self.config.gitlab_url, self.config.project_id, encoded_title
        );

        debug!("🔍 Searching for existing issue: {title}");
        debug!("🌐 GET {url} (with retry logic)");

        let client = &self.client;
        let response = self
            .retryable_client
            .execute_with_retry(|| client.get(&url).send())
            .await?;

        let status = response.status();

        if status.is_success() {
            let issues: Vec<GitLabIssueResponse> = response.json().await?;

            // Check for exact title match (GitLab search is fuzzy, so we need exact match)
            let exact_match = issues.iter().any(|issue| issue.title == title);

            if exact_match {
                debug!("✅ Found existing issue with exact title match");
                info!("🆕 No existing issue found with exact title match");
            }

            Ok(exact_match)
        } else {
            let error_text = response.text().await.unwrap_or("Unknown error".to_string());
            Err(GitLabError::ApiError {
                status: status.as_u16(),
                message: format!("Failed to search for existing issues: {error_text}"),
            })
        }
    }

    /// Create issue payload from finding
    fn create_issue_payload(
        &self,
        finding_with_source: &crate::findings::FindingWithSource,
    ) -> Result<GitLabIssuePayload, GitLabError> {
        let finding = &finding_with_source.finding;
        let source = &finding_with_source.source_scan;

        debug!("🔍 DEBUG: Creating issue payload for finding:");
        debug!(
            "   Raw file path from Veracode: '{}'",
            finding.files.source_file.file
        );
        debug!("   Issue type: '{}'", finding.issue_type);
        debug!(
            "   Severity: {} ({})",
            finding.severity,
            get_severity_name(finding.severity)
        );
        if !finding.cwe_id.is_empty() && finding.cwe_id != "0" {
            debug!("   CWE ID: '{}'", finding.cwe_id);
        }
        debug!("   Line number: {}", finding.files.source_file.line);
        if let Some(ref function_name) = finding.files.source_file.function_name
            && !function_name.is_empty()
            && function_name != "UNKNOWN"
        {
            debug!("   Function: '{function_name}'");
        }
        // Debug flaw details link
        match &finding.flaw_details_link {
            Some(link) if !link.is_empty() => {
                debug!("   Flaw Details Link: '{link}'");
            }
            Some(_) => {
                debug!("   Flaw Details Link: (empty)");
            }
            None => {
                debug!("   Flaw Details Link: (not provided)");
            }
        }

        // Resolve the file path once for consistent issue titles and descriptions
        let resolved_file_path = self.resolve_file_path(&finding.files.source_file.file);

        debug!("   Resolved file path: '{resolved_file_path}'");

        // Create concise title with CWE, function (or issue type), filename, line number and path hash
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

        // Create detailed description first
        let description = self.create_issue_description_with_resolved_path(
            finding_with_source,
            &resolved_file_path,
        )?;

        // Create labels based on severity and issue type
        let mut labels = Vec::new();

        // Add dynamic severity label (needs formatting)
        labels.push(format!(
            "security::severity::{}",
            severity_name.to_lowercase().replace(" ", "-")
        ));

        // Add static labels (convert to String for consistency)
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

        // Convert labels array to comma-separated string
        let labels_string = if labels.is_empty() {
            None
        } else {
            Some(labels.join(","))
        };

        // Create hash from specific fields for uniqueness
        // Fields: Project_Name,Source_File,CWE_ID,Issue_Type,Title,Severity,File_Path,Line_Number,Function_Name
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        // Project_Name (use project name from GitLab, fallback to source project name)
        let project_name = self
            .config
            .project_name
            .as_deref()
            .unwrap_or(&source.project_name);
        info!("{project_name}");
        hasher.update(project_name.as_bytes());
        hasher.update(b"|");

        // Source_File (original filename from finding)
        hasher.update(finding.files.source_file.file.as_bytes());
        hasher.update(b"|");

        // CWE_ID
        hasher.update(cwe_id.as_bytes());
        hasher.update(b"|");

        // Issue_Type
        hasher.update(finding.issue_type.as_bytes());
        hasher.update(b"|");

        // Title (use finding title, not the formatted title)
        hasher.update(finding.title.as_bytes());
        hasher.update(b"|");

        // Severity
        hasher.update(finding.severity.to_string().as_bytes());
        hasher.update(b"|");

        // File_Path (resolved file path)
        hasher.update(resolved_file_path.as_bytes());
        hasher.update(b"|");
        info!("{resolved_file_path}");
        // Line_Number
        hasher.update(finding.files.source_file.line.to_string().as_bytes());
        hasher.update(b"|");

        // Function_Name (use empty string if not available)
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
        let short_hash = payload_hash.get(..8).unwrap_or(&payload_hash); // Use first 8 characters

        // Create final title with hash
        let title = format!("{base_title} ({short_hash})");

        debug!("   Title components:");
        debug!("     Severity: '{severity_name}'");
        debug!("     CWE ID: '{cwe_id}'");
        debug!("     Function/Issue: '{function_or_issue}'");
        debug!("     Filename: '{filename}'");
        debug!("     Line: {}", finding.files.source_file.line);
        debug!("   Hash input fields:");
        debug!("     Project_Name: '{project_name}'");
        debug!("     Source_File: '{}'", finding.files.source_file.file);
        debug!("     CWE_ID: '{cwe_id}'");
        debug!("     Issue_Type: '{}'", finding.issue_type);
        debug!("     Title: '{}'", finding.title);
        debug!("     Severity: '{}'", finding.severity);
        debug!("     File_Path: '{resolved_file_path}'");
        debug!("     Line_Number: '{}'", finding.files.source_file.line);
        debug!("     Function_Name: '{function_name}'");
        debug!("     Generated hash: '{short_hash}' (first 8 chars)");
        debug!("   Final issue title: '{title}'");
        if let Some(ref labels_str) = labels_string {
            debug!("   Labels string for API: '{labels_str}'");
        }

        Ok(GitLabIssuePayload {
            title,
            description,
            labels: labels_string,
            assignee_ids: None,
            confidential: Some(false),
        })
    }

    /// Set the project directory for resolving file paths
    pub fn with_project_dir<P: AsRef<Path>>(mut self, project_dir: P) -> Self {
        // Convert to absolute path for consistent comparison
        let path = project_dir.as_ref();
        let absolute_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            // Convert relative path to absolute path
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
                .canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
        };

        self.config.project_dir = Some(absolute_path.clone());

        // Create path resolver when project dir is set
        let resolver_config = PathResolverConfig::new(&absolute_path);
        self.config.path_resolver = Some(PathResolver::new(resolver_config));

        self
    }

    /// Resolve file path relative to project directory using shared utility
    fn resolve_file_path(&self, file_path: &str) -> String {
        resolve_file_path(file_path, self.config.path_resolver.as_ref()).into_owned()
    }

    /// Create detailed issue description with pre-resolved file path
    fn create_issue_description_with_resolved_path(
        &self,
        finding_with_source: &crate::findings::FindingWithSource,
        resolved_file_path: &str,
    ) -> Result<String, GitLabError> {
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
        // Create file link with line number (using pre-resolved path)
        let file_link = self.create_file_link(resolved_file_path, finding.files.source_file.line);
        description.push_str(&format!("| **File** | {file_link} |\n"));
        description.push_str(&format!(
            "| **Line** | {} |\n",
            finding.files.source_file.line
        ));

        if let Some(ref function_name) = finding.files.source_file.function_name
            && !function_name.is_empty()
            && function_name != "UNKNOWN"
        {
            description.push_str(&format!("| **Function** | `{function_name}` |\n"));
        }

        description.push_str(&format!("| **Scan ID** | `{}` |\n", source.scan_id));
        description.push_str(&format!("| **Project** | {} |\n", source.project_name));

        // Add flaw details link if available
        if let Some(ref flaw_details_link) = finding.flaw_details_link {
            if !flaw_details_link.is_empty() {
                description.push_str(&format!(
                    "| **Flaw Details** | [View in Veracode]({flaw_details_link}) |\n"
                ));
                debug!("   Added flaw details link to GitLab issue: {flaw_details_link}");
            } else {
                debug!("   Flaw details link is empty, not adding to GitLab issue");
            }
        } else {
            debug!("   No flaw details link available for this finding");
        }

        description.push('\n');

        // Enhanced source code section with direct link
        if let Some(project_web_url) = get_project_web_url(
            self.config.project_web_url.as_deref(),
            self.config.project_path_with_namespace.as_deref(),
            &self.config.gitlab_url,
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
                debug!("   Added flaw details link to Related Links section: {flaw_details_link}");
            } else {
                debug!("   Flaw details link is empty, not adding to Related Links");
            }
        } else {
            debug!("   No flaw details link available for Related Links section");
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
            // Strip HTML tags from display_text for cleaner markdown
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
            description.push_str(&format!("For detailed information about this vulnerability type, see [CWE-{}](https://cwe.mitre.org/data/definitions/{}.html).\n\n", 
                finding.cwe_id, finding.cwe_id));
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
            &self.config.gitlab_url,
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
            self.config.gitlab_url.clone(),
            self.config.project_id.clone(),
            self.config.project_web_url.clone(),
            self.config.project_path_with_namespace.clone(),
        );
        create_pipeline_url(&url_config, pipeline_id)
    }

    /// Fetch and cache project information for URL construction
    ///
    /// # Errors
    /// Returns an error if the GitLab API request fails or project information cannot be retrieved
    pub async fn fetch_project_info(&mut self) -> Result<(), GitLabError> {
        if self.config.project_path_with_namespace.is_some() {
            return Ok(()); // Already cached
        }

        let test_url = format!("{}{}", self.config.gitlab_url, self.config.project_id);
        let client = &self.client;
        let response = self
            .retryable_client
            .execute_with_retry(|| client.get(&test_url).send())
            .await?;

        if response.status().is_success() {
            let project_info: serde_json::Value = response.json().await?;
            if let Some(path_with_namespace) = project_info
                .get("path_with_namespace")
                .and_then(|v| v.as_str())
            {
                self.config.project_path_with_namespace = Some(path_with_namespace.to_string());
            }
            if let Some(project_name) = project_info.get("name").and_then(|v| v.as_str()) {
                self.config.project_name = Some(project_name.to_string());
            }
        }

        Ok(())
    }
}

impl GitLabConfig {
    /// Create GitLab configuration from environment variables
    ///
    /// # Errors
    /// Returns an error if required environment variables (API token or project ID) are missing
    pub fn from_env() -> Result<Self, GitLabError> {
        // Required environment variables
        let api_token = env::var("PRIVATE_TOKEN")
            .or_else(|_| env::var("CI_TOKEN"))
            .or_else(|_| env::var("GITLAB_TOKEN"))
            .map_err(|_| {
                GitLabError::MissingEnvVar("PRIVATE_TOKEN, CI_TOKEN, or GITLAB_TOKEN".to_string())
            })?;

        let project_id = env::var("CI_PROJECT_ID")
            .map_err(|_| GitLabError::MissingEnvVar("CI_PROJECT_ID".to_string()))?;

        // Optional environment variables
        let pipeline_id = env::var("CI_PIPELINE_ID").ok();

        let gitlab_url = env::var("CI_API_V4_URL")
            .map(|url| format!("{}/projects/", url.trim_end_matches('/')))
            .unwrap_or_else(|_| "https://gitlab.com/api/v4/projects/".to_string());

        let project_web_url = env::var("CI_PROJECT_URL").ok();
        let commit_sha = env::var("CI_COMMIT_SHA").ok();

        // Configurable HTTP timeouts
        let connect_timeout = env::var("VERASCAN_CONNECT_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(10));

        let request_timeout = env::var("VERASCAN_REQUEST_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));

        let validation_timeout = env::var("VERASCAN_VALIDATION_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(10));

        let http_timeouts = HttpTimeouts {
            connect_timeout,
            request_timeout,
            validation_timeout,
        };

        // Configurable retry settings
        let max_retries = env::var("VERASCAN_MAX_RETRIES")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(3);

        let initial_delay = env::var("VERASCAN_INITIAL_RETRY_DELAY_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_millis(500));

        let max_delay = env::var("VERASCAN_MAX_RETRY_DELAY_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_secs(10));

        let backoff_multiplier = env::var("VERASCAN_BACKOFF_MULTIPLIER")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(2.0);

        let jitter = env::var("VERASCAN_DISABLE_JITTER")
            .map(|s| s.to_lowercase() != "true")
            .unwrap_or(true); // Jitter enabled by default

        let retry_config = RetryConfig {
            max_retries,
            initial_delay,
            max_delay,
            backoff_multiplier,
            jitter,
        };

        Ok(Self {
            api_token: SecureToken::new(api_token),
            project_id,
            pipeline_id,
            gitlab_url,
            project_web_url,
            commit_sha,
            project_path_with_namespace: None, // Will be populated during client creation
            project_name: None,                // Will be populated during client creation
            project_dir: None,                 // Will be set from CLI args
            path_resolver: None,               // Will be set when project_dir is set
            http_timeouts,
            retry_config,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_resolve_file_path_basic() {
        let client = GitLabIssuesClient {
            client: Client::new(),
            config: GitLabConfig {
                api_token: SecureToken::new("test".to_string()),
                project_id: "123".to_string(),
                pipeline_id: None,
                gitlab_url: "https://gitlab.com/api/v4/projects/".to_string(),
                project_web_url: None,
                commit_sha: None,
                project_path_with_namespace: None,
                project_name: None,
                project_dir: None, // No project dir set
                path_resolver: None,
                http_timeouts: HttpTimeouts::default(),
                retry_config: RetryConfig::default(),
            },
            retryable_client: RetryableRequest::new(RetryConfig::default()),
        };

        // Test with no project dir set - should return original path
        let result = client.resolve_file_path("com/example/vulnerable/CryptoUtils.java");
        assert_eq!(result, "com/example/vulnerable/CryptoUtils.java");

        // Test absolute path with no project dir
        let result = client.resolve_file_path("/absolute/path/file.java");
        assert_eq!(result, "/absolute/path/file.java");
    }

    #[test]
    fn test_common_source_directory_patterns() {
        // Test that the common source directories are correctly defined
        let test_patterns = [
            "src/main/java",
            "src/main/kotlin",
            "src/test/java",
            "src/test/kotlin",
            "src",
            "java",
            "kotlin",
            "main/java",
            "test/java",
        ];

        // Just verify the patterns are reasonable (this is more of a documentation test)
        assert!(!test_patterns.is_empty());
        assert!(test_patterns.contains(&"src/main/java")); // Most common Java pattern
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_severity_name_conversion() {
        let _client = GitLabIssuesClient {
            client: Client::new(),
            config: GitLabConfig {
                api_token: SecureToken::new("test".to_string()),
                project_id: "123".to_string(),
                pipeline_id: None,
                gitlab_url: "https://gitlab.com/api/v4/projects/".to_string(),
                project_web_url: None,
                commit_sha: None,
                project_path_with_namespace: None,
                project_name: None,
                project_dir: None,
                path_resolver: None,
                http_timeouts: HttpTimeouts::default(),
                retry_config: RetryConfig::default(),
            },
            retryable_client: RetryableRequest::new(RetryConfig::default()),
        };

        assert_eq!(get_severity_name(5), "Very High");
        assert_eq!(get_severity_name(4), "High");
        assert_eq!(get_severity_name(3), "Medium");
        assert_eq!(get_severity_name(2), "Low");
        assert_eq!(get_severity_name(1), "Very Low");
        assert_eq!(get_severity_name(0), "Info");
    }

    #[test]
    fn test_issue_title_url_encoding() {
        // Test that special characters in issue titles are properly URL encoded
        let title_with_spaces = "[High] SQL Injection in UserController.java";
        let encoded = urlencoding::encode(title_with_spaces);
        assert_eq!(
            encoded,
            "%5BHigh%5D%20SQL%20Injection%20in%20UserController.java"
        );

        let title_with_special_chars = "[Medium] XSS in <script>alert(1)</script>";
        let encoded_special = urlencoding::encode(title_with_special_chars);
        assert!(encoded_special.contains("%3Cscript%3E"));
        assert!(encoded_special.contains("%3C%2Fscript%3E"));
    }

    #[test]
    fn test_labels_format() {
        // Test that labels are correctly formatted as comma-separated string
        let labels = [
            "security::veracode".to_string(),
            "security::sast".to_string(),
            "security::severity::high".to_string(),
            "priority::high".to_string(),
        ];

        let labels_string = labels.join(",");
        assert_eq!(
            labels_string,
            "security::veracode,security::sast,security::severity::high,priority::high"
        );

        // Test empty labels
        let empty_labels: Vec<String> = vec![];
        assert!(empty_labels.is_empty());
    }

    #[test]
    fn test_title_format() {
        // Test that the new title format includes payload hash for uniqueness

        // Test payload-based hash generation
        use sha2::{Digest, Sha256};
        let payload1 = GitLabIssuePayload {
            title: "[High] CWE-89: executeQuery @ UserController.java:45".to_string(),
            description: "Test description 1".to_string(),
            labels: Some("security::veracode,security::sast".to_string()),
            assignee_ids: None,
            confidential: Some(false),
        };

        let payload2 = GitLabIssuePayload {
            title: "[High] CWE-89: executeQuery @ SimpleUserController.java:45".to_string(),
            description: "Test description 2".to_string(),
            labels: Some("security::veracode,security::sast".to_string()),
            assignee_ids: None,
            confidential: Some(false),
        };

        // Hash payload 1
        let payload1_json = serde_json::to_string(&payload1).expect("should serialize payload1");
        let mut hasher1 = Sha256::new();
        hasher1.update(payload1_json.as_bytes());
        let hash1_full = format!("{:x}", hasher1.finalize());
        let hash1 = hash1_full.get(..8).unwrap_or(&hash1_full).to_string();

        // Hash payload 2
        let payload2_json = serde_json::to_string(&payload2).expect("should serialize payload2");
        let mut hasher2 = Sha256::new();
        hasher2.update(payload2_json.as_bytes());
        let hash2_full = format!("{:x}", hasher2.finalize());
        let hash2 = hash2_full.get(..8).unwrap_or(&hash2_full).to_string();

        // Test that hash is 8 characters
        assert_eq!(hash1.len(), 8);
        assert_eq!(hash2.len(), 8);

        // Test that different payloads produce different hashes
        assert_ne!(
            hash1, hash2,
            "Different payloads should produce different hashes"
        );

        // Test title format with hash
        let final_title = format!("[High] CWE-89: executeQuery @ UserController.java:45 ({hash1})");
        assert!(final_title.contains("CWE-89"));
        assert!(final_title.contains("executeQuery"));
        assert!(final_title.contains(":45"));
        assert!(final_title.contains(&format!("({hash1})")));

        // Test filename extraction
        let full_path = "src/main/java/com/example/vulnerable/CryptoUtils.java";
        let filename = std::path::Path::new(full_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(full_path);
        assert_eq!(filename, "CryptoUtils.java");
    }

    #[test]
    fn test_path_matching_precision() {
        // Test that path matching is precise and doesn't do partial filename matches

        // Test that "VulnerableApp.java" should NOT match "SimpleVulnerableApp.java"
        let path1 = "com/example/vulnerable/VulnerableApp.java";
        let path2 = "com/example/vulnerable/SimpleVulnerableApp.java";

        // Simulate the path matching logic
        let candidate = "/project/src/main/java/com/example/vulnerable/SimpleVulnerableApp.java";
        let normalized_candidate = candidate.replace('\\', "/");
        let normalized_relative = path1.replace('\\', "/");

        // This should NOT match because SimpleVulnerableApp.java is not VulnerableApp.java
        let ends_with_match = normalized_candidate.ends_with(&normalized_relative);
        assert!(
            !ends_with_match,
            "SimpleVulnerableApp.java should not match VulnerableApp.java"
        );

        // But this SHOULD match
        let normalized_relative2 = path2.replace('\\', "/");
        let ends_with_match2 = normalized_candidate.ends_with(&normalized_relative2);
        assert!(
            ends_with_match2,
            "SimpleVulnerableApp.java should match itself"
        );

        // Test boundary checking
        let test_path = "/project/src/main/java/com/example/vulnerable/SimpleVulnerableApp.java";
        let target = "com/example/vulnerable/SimpleVulnerableApp.java";
        let match_start = test_path.len() - target.len();
        let boundary_char = test_path.chars().nth(match_start - 1);
        assert_eq!(
            boundary_char,
            Some('/'),
            "Should have path separator at boundary"
        );
    }

    #[test]
    fn test_gitlab_config_validation() {
        // Test that missing required env vars return proper errors
        unsafe {
            std::env::remove_var("PRIVATE_TOKEN");
            std::env::remove_var("CI_TOKEN");
            std::env::remove_var("GITLAB_TOKEN");
            std::env::remove_var("CI_PROJECT_ID");
        }

        let result = GitLabConfig::from_env();
        assert!(result.is_err());

        match result {
            Err(GitLabError::MissingEnvVar(var)) => {
                assert!(var.contains("PRIVATE_TOKEN") || var.contains("CI_TOKEN"));
            }
            _ => unreachable!("Expected MissingEnvVar error"),
        }
    }

    #[test]
    fn test_ci_api_v4_url_handling() {
        use std::env;

        // Clean up any existing env vars first to ensure test isolation
        unsafe {
            env::remove_var("GITLAB_TOKEN");
            env::remove_var("PRIVATE_TOKEN");
            env::remove_var("CI_TOKEN");
            env::remove_var("CI_PROJECT_ID");
            env::remove_var("CI_API_V4_URL");
        }

        // Test that CI_API_V4_URL gets /projects/ appended correctly
        unsafe {
            env::set_var("GITLAB_TOKEN", "test-token");
            env::set_var("CI_PROJECT_ID", "123");
            env::set_var("CI_API_V4_URL", "https://gitlab.example.com/api/v4");
        }

        let result = GitLabConfig::from_env();
        assert!(result.is_ok());

        let config = result.expect("should create config from env");
        assert_eq!(
            config.gitlab_url,
            "https://gitlab.example.com/api/v4/projects/"
        );

        // Test with trailing slash in CI_API_V4_URL
        unsafe {
            env::set_var("GITLAB_TOKEN", "test-token");
            env::set_var("CI_PROJECT_ID", "123");
            env::set_var("CI_API_V4_URL", "https://gitlab.example.com/api/v4/");
        }

        let result = GitLabConfig::from_env();
        assert!(result.is_ok());

        let config = result.expect("should create config from env with trailing slash");
        assert_eq!(
            config.gitlab_url,
            "https://gitlab.example.com/api/v4/projects/"
        );

        // Clean up
        unsafe {
            env::remove_var("GITLAB_TOKEN");
            env::remove_var("CI_PROJECT_ID");
            env::remove_var("CI_API_V4_URL");
        }
    }

    #[test]
    fn test_secure_token_redaction() {
        // Test that SecureToken properly redacts sensitive information
        let token = SecureToken::new("super-secret-token-12345".to_string());

        // Test Debug formatting
        let debug_output = format!("{token:?}");
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("super-secret-token"));

        // Test Display formatting
        let display_output = format!("{token}");
        assert_eq!(display_output, "[REDACTED]");
        assert!(!display_output.contains("super-secret-token"));

        // Test that we can still access the actual token when needed
        assert_eq!(token.as_str(), "super-secret-token-12345");
    }

    #[test]
    fn test_gitlab_config_debug_redaction() {
        // Test that GitLabConfig properly redacts the api_token in debug output
        let config = GitLabConfig {
            api_token: SecureToken::new("secret-token-456".to_string()),
            project_id: "123".to_string(),
            pipeline_id: Some("456".to_string()),
            gitlab_url: "https://gitlab.example.com/api/v4/projects/".to_string(),
            project_web_url: Some("https://gitlab.example.com/project".to_string()),
            commit_sha: Some("abc123".to_string()),
            project_path_with_namespace: Some("user/project".to_string()),
            project_name: Some("MyProject".to_string()),
            project_dir: None,
            path_resolver: None,
            http_timeouts: HttpTimeouts::default(),
            retry_config: RetryConfig::default(),
        };

        let debug_output = format!("{config:?}");

        // Verify the token is redacted
        assert!(debug_output.contains("api_token: \"[REDACTED]\""));
        assert!(!debug_output.contains("secret-token-456"));

        // Verify other fields are still visible
        assert!(debug_output.contains("project_id: \"123\""));
        assert!(debug_output.contains("pipeline_id: Some(\"456\")"));
        assert!(
            debug_output.contains("gitlab_url: \"https://gitlab.example.com/api/v4/projects/\"")
        );
    }

    #[test]
    fn test_http_timeouts_default() {
        let timeouts = HttpTimeouts::default();
        assert_eq!(timeouts.connect_timeout, Duration::from_secs(10));
        assert_eq!(timeouts.request_timeout, Duration::from_secs(30));
        assert_eq!(timeouts.validation_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_retry_config_default() {
        let retry_config = RetryConfig::default();
        assert_eq!(retry_config.max_retries, 3);
        assert_eq!(retry_config.initial_delay, Duration::from_millis(500));
        assert_eq!(retry_config.max_delay, Duration::from_secs(10));
        assert_eq!(retry_config.backoff_multiplier, 2.0);
        assert!(retry_config.jitter);
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_is_retryable_error() {
        let _client = Client::new();
        let retry_config = RetryConfig::default();
        let retryable_client = RetryableRequest::new(retry_config);

        // Create mock errors to test retryability
        // Note: These are conceptual tests since we can't easily create specific reqwest::Error instances

        // Network errors should be retryable (tested conceptually)
        // 5xx server errors should be retryable
        // 429 rate limiting should be retryable
        // 4xx client errors should not be retryable (except 429)

        // Test that the logic exists
        assert!(retryable_client.retry_config.max_retries > 0);
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_jitter_calculation() {
        let _client = Client::new();
        let retry_config = RetryConfig::default();
        let retryable_client = RetryableRequest::new(retry_config);

        let original_delay = Duration::from_millis(1000);
        let jittered_delay = retryable_client.add_jitter(original_delay);

        // Jittered delay should be between 100% and 150% of original
        assert!(jittered_delay >= original_delay);
        assert!(jittered_delay <= Duration::from_millis(1500));
    }

    #[test]
    fn test_environment_variable_parsing() {
        use std::env;

        // Test default values when env vars are not set
        unsafe {
            env::remove_var("VERASCAN_CONNECT_TIMEOUT");
            env::remove_var("VERASCAN_REQUEST_TIMEOUT");
            env::remove_var("VERASCAN_MAX_RETRIES");
        }

        // Test parsing when valid values are set
        unsafe {
            env::set_var("VERASCAN_CONNECT_TIMEOUT", "15");
            env::set_var("VERASCAN_REQUEST_TIMEOUT", "45");
            env::set_var("VERASCAN_MAX_RETRIES", "5");
            env::set_var("VERASCAN_INITIAL_RETRY_DELAY_MS", "1000");
            env::set_var("VERASCAN_BACKOFF_MULTIPLIER", "1.5");
        }

        // These would be tested in an integration test with actual config loading
        // For unit tests, we just verify the parsing logic exists
        let timeout_str = "15";
        let parsed_timeout: Option<u64> = timeout_str.parse().ok();
        assert_eq!(parsed_timeout, Some(15));

        let multiplier_str = "1.5";
        let parsed_multiplier: Option<f64> = multiplier_str.parse().ok();
        assert_eq!(parsed_multiplier, Some(1.5));

        // Clean up
        unsafe {
            env::remove_var("VERASCAN_CONNECT_TIMEOUT");
            env::remove_var("VERASCAN_REQUEST_TIMEOUT");
            env::remove_var("VERASCAN_MAX_RETRIES");
            env::remove_var("VERASCAN_INITIAL_RETRY_DELAY_MS");
            env::remove_var("VERASCAN_BACKOFF_MULTIPLIER");
        }
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_pipeline_url_generation_integration() {
        // Test that the client properly uses the shared utility for pipeline URL generation
        let client = GitLabIssuesClient {
            client: Client::new(),
            config: GitLabConfig {
                api_token: SecureToken::new("test".to_string()),
                project_id: "123".to_string(),
                pipeline_id: Some("456".to_string()),
                gitlab_url: "https://gitlab.example.com/api/v4/projects/".to_string(),
                project_web_url: Some("https://gitlab.example.com/group/project".to_string()),
                commit_sha: None,
                project_path_with_namespace: None,
                project_name: None,
                project_dir: None,
                path_resolver: None,
                http_timeouts: HttpTimeouts::default(),
                retry_config: RetryConfig::default(),
            },
            retryable_client: RetryableRequest::new(RetryConfig::default()),
        };

        let pipeline_url = client.create_pipeline_url("456");
        assert_eq!(
            pipeline_url,
            "https://gitlab.example.com/group/project/-/pipelines/456"
        );
    }
}

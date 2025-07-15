//! GitLab Issues Integration
//!
//! This module provides functionality to create GitLab issues from Veracode scan results
//! using GitLab CI environment variables and API tokens.

use crate::findings::AggregatedFindings;
use reqwest::{
    Client,
    header::{HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};

/// Secure token wrapper that prevents accidental exposure in logs
#[derive(Clone)]
pub struct SecureToken(String);

impl SecureToken {
    pub fn new(token: String) -> Self {
        SecureToken(token)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecureToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Display for SecureToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// GitLab issue creation payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabIssuePayload {
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<String>, // GitLab expects comma-separated string, not array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee_ids: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidential: Option<bool>,
}

/// GitLab issue response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabIssueResponse {
    pub id: u64,
    pub iid: u64,
    pub title: String,
    pub description: String,
    pub state: String,
    pub web_url: String,
    pub created_at: String,
    pub updated_at: String,
}

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
}

/// GitLab Issues client
pub struct GitLabIssuesClient {
    client: Client,
    config: GitLabConfig,
    debug: bool,
}

impl GitLabIssuesClient {
    /// Validate GitLab requirements and connectivity
    pub async fn validate_gitlab_connection(debug: bool) -> Result<(), GitLabError> {
        if debug {
            println!("🔍 Validating GitLab integration requirements...");
        }

        // Check environment variables
        let config = GitLabConfig::from_env()?;

        if debug {
            println!("✅ Environment variables validated:");
            println!("   Project ID: {}", config.project_id);
            println!("   GitLab URL: {}", config.gitlab_url);
        }

        // Test API connectivity by checking project access
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        headers.insert(
            "PRIVATE-TOKEN",
            HeaderValue::from_str(config.api_token.as_str()).map_err(|_| {
                GitLabError::MissingEnvVar("Invalid PRIVATE_TOKEN format".to_string())
            })?,
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        // Test connectivity by getting project info
        let test_url = format!("{}{}", config.gitlab_url, config.project_id);

        if debug {
            println!("🌐 Testing GitLab API connectivity...");
            println!("   GET {}", test_url);
        }

        let response = client.get(&test_url).send().await?;
        let status = response.status();

        if status.is_success() {
            let project_info: serde_json::Value = response.json().await?;
            let project_name = project_info["name"].as_str().unwrap_or("Unknown");
            let project_path = project_info["path_with_namespace"]
                .as_str()
                .unwrap_or("unknown/project");

            println!("✅ GitLab connectivity validated successfully!");
            if debug {
                println!("   Project: {} ({})", project_name, project_path);
                println!("   API access: ✅ Authenticated");
            }

            // Check if we can create issues (check permissions)
            let issues_url = format!("{}{}/issues", config.gitlab_url, config.project_id);
            let issues_response = client.get(&issues_url).send().await?;

            if issues_response.status().is_success() {
                println!("   Issue creation: ✅ Permitted");
            } else {
                println!(
                    "   Issue creation: ⚠️  May be restricted (status: {})",
                    issues_response.status()
                );
            }

            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(GitLabError::ApiError {
                status: status.as_u16(),
                message: format!("Project access failed: {}", error_text),
            })
        }
    }

    /// Create a new GitLab Issues client from environment variables
    pub fn from_env(debug: bool) -> Result<Self, GitLabError> {
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
            .timeout(std::time::Duration::from_secs(30));

        // Check for environment variable to disable certificate validation
        // WARNING: Only use this for development with self-signed certificates
        if env::var("VERASCAN_DISABLE_CERT_VALIDATION").is_ok() {
            if debug {
                println!(
                    "⚠️  WARNING: Certificate validation disabled via VERASCAN_DISABLE_CERT_VALIDATION"
                );
                println!("   This should only be used in development environments!");
            }
            client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        let client = client_builder.build()?;

        if debug {
            println!("🔧 GitLab Issues Client initialized");
            println!("   Project ID: {}", config.project_id);
            println!("   GitLab URL: {}", config.gitlab_url);
            if let Some(ref pipeline_id) = config.pipeline_id {
                println!("   Pipeline ID: {}", pipeline_id);
            }
        }

        Ok(Self {
            client,
            config,
            debug,
        })
    }

    /// Create GitLab issues from aggregated findings
    pub async fn create_issues_from_findings(
        &mut self,
        aggregated: &AggregatedFindings,
    ) -> Result<Vec<GitLabIssueResponse>, GitLabError> {
        if self.debug {
            println!(
                "📝 Creating GitLab issues from {} findings",
                aggregated.findings.len()
            );
        }

        // Fetch project information for URL construction
        self.fetch_project_info().await?;

        let mut created_issues = Vec::new();
        let mut skipped_count = 0;
        let mut duplicate_count = 0;

        for (index, finding_with_source) in aggregated.findings.iter().enumerate() {
            let finding = &finding_with_source.finding;
            let _source = &finding_with_source.source_scan;

            // Skip informational findings to reduce noise
            if finding.severity == 0 {
                skipped_count += 1;
                continue;
            }

            let issue_payload = self.create_issue_payload(finding_with_source)?;

            // Check if an issue with this title already exists using GitLab search API
            match self.issue_already_exists(&issue_payload.title).await {
                Ok(true) => {
                    if self.debug {
                        println!(
                            "⏭️  Skipping duplicate issue {}/{}: {}",
                            index + 1,
                            aggregated.findings.len(),
                            issue_payload.title
                        );
                    }
                    duplicate_count += 1;
                    continue;
                }
                Ok(false) => {
                    // Continue with issue creation
                }
                Err(e) => {
                    eprintln!(
                        "⚠️  Warning: Failed to check for duplicates for {}: {}. Creating issue anyway.",
                        finding.title, e
                    );
                    // Continue with issue creation despite search failure
                }
            }

            if self.debug {
                println!(
                    "📋 Creating issue {}/{}: {}",
                    index + 1,
                    aggregated.findings.len(),
                    issue_payload.title
                );
            }

            match self.create_issue(&issue_payload).await {
                Ok(issue) => {
                    if self.debug {
                        println!("✅ Created issue #{}: {}", issue.iid, issue.web_url);
                    } else {
                        println!("✅ Created issue #{}: {}", issue.iid, finding.title);
                    }
                    created_issues.push(issue);
                }
                Err(e) => {
                    eprintln!("❌ Failed to create issue for {}: {}", finding.title, e);
                }
            }

            // Add small delay to avoid rate limiting
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        if skipped_count > 0 {
            println!("ℹ️  Skipped {} informational findings", skipped_count);
        }

        if duplicate_count > 0 {
            println!("⏭️  Skipped {} duplicate issues", duplicate_count);
        }

        println!("✅ Created {} GitLab issues", created_issues.len());

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

        if self.debug {
            println!("🌐 POST {}", url);
            println!("📤 Issue payload:");
            println!("   Title: {}", payload.title);
            if let Some(ref labels) = payload.labels {
                println!("   Labels: '{}'", labels);
            } else {
                println!("   Labels: None");
            }

            // Print full JSON payload
            match serde_json::to_string_pretty(payload) {
                Ok(json) => println!("   Full JSON payload:\n{}", json),
                Err(e) => println!("   Failed to serialize payload: {}", e),
            }
        }

        let response = self.client.post(&url).json(payload).send().await?;

        let status = response.status();

        if status.is_success() {
            let issue: GitLabIssueResponse = response.json().await?;

            if self.debug {
                println!("📥 GitLab API Response:");
                println!("   Status: {}", status);
                println!("   Issue ID: {}", issue.id);
                println!("   Issue IID: {}", issue.iid);
                println!("   Title: {}", issue.title);
                println!("   Web URL: {}", issue.web_url);

                // Print full JSON response
                match serde_json::to_string_pretty(&issue) {
                    Ok(json) => println!("   Full JSON response:\n{}", json),
                    Err(e) => println!("   Failed to serialize response: {}", e),
                }
            }

            Ok(issue)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            if self.debug {
                println!("❌ GitLab API Error:");
                println!("   Status: {}", status);
                println!("   Error: {}", error_text);
            }
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

        if self.debug {
            println!("🔍 Searching for existing issue: {}", title);
            println!("🌐 GET {}", url);
        }

        let response = self.client.get(&url).send().await?;

        let status = response.status();

        if status.is_success() {
            let issues: Vec<GitLabIssueResponse> = response.json().await?;

            // Check for exact title match (GitLab search is fuzzy, so we need exact match)
            let exact_match = issues.iter().any(|issue| issue.title == title);

            if self.debug && exact_match {
                println!("✅ Found existing issue with exact title match");
            } else if self.debug {
                println!("🆕 No existing issue found with exact title match");
            }

            Ok(exact_match)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(GitLabError::ApiError {
                status: status.as_u16(),
                message: format!("Failed to search for existing issues: {}", error_text),
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

        if self.debug {
            println!("🔍 DEBUG: Creating issue payload for finding:");
            println!(
                "   Raw file path from Veracode: '{}'",
                finding.files.source_file.file
            );
            println!("   Issue type: '{}'", finding.issue_type);
            println!(
                "   Severity: {} ({})",
                finding.severity,
                self.get_severity_name(finding.severity)
            );
            if !finding.cwe_id.is_empty() && finding.cwe_id != "0" {
                println!("   CWE ID: '{}'", finding.cwe_id);
            }
            println!("   Line number: {}", finding.files.source_file.line);
            if let Some(ref function_name) = finding.files.source_file.function_name {
                if !function_name.is_empty() && function_name != "UNKNOWN" {
                    println!("   Function: '{}'", function_name);
                }
            }
            // Debug flaw details link
            match &finding.flaw_details_link {
                Some(link) if !link.is_empty() => {
                    println!("   Flaw Details Link: '{}'", link);
                }
                Some(_) => {
                    println!("   Flaw Details Link: (empty)");
                }
                None => {
                    println!("   Flaw Details Link: (not provided)");
                }
            }
        }

        // Resolve the file path once for consistent issue titles and descriptions
        let resolved_file_path = self.resolve_file_path(&finding.files.source_file.file);

        if self.debug {
            println!("   Resolved file path: '{}'", resolved_file_path);
        }

        // Create concise title with CWE, function (or issue type), filename, line number and path hash
        let severity_name = self.get_severity_name(finding.severity);

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
            "000".to_string()
        } else {
            finding.cwe_id.clone()
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
        let mut labels = vec![
            format!(
                "security::severity::{}",
                severity_name.to_lowercase().replace(" ", "-")
            ),
            "security::veracode".to_string(),
            "security::sast".to_string(),
        ];

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
        println!("{}", project_name);
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
        println!("{}", resolved_file_path);
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
        let short_hash = &payload_hash[..8]; // Use first 8 characters

        // Create final title with hash
        let title = format!("{} ({})", base_title, short_hash);

        if self.debug {
            println!("   Title components:");
            println!("     Severity: '{}'", severity_name);
            println!("     CWE ID: '{}'", cwe_id);
            println!("     Function/Issue: '{}'", function_or_issue);
            println!("     Filename: '{}'", filename);
            println!("     Line: {}", finding.files.source_file.line);
            println!("   Hash input fields:");
            println!("     Project_Name: '{}'", project_name);
            println!("     Source_File: '{}'", finding.files.source_file.file);
            println!("     CWE_ID: '{}'", cwe_id);
            println!("     Issue_Type: '{}'", finding.issue_type);
            println!("     Title: '{}'", finding.title);
            println!("     Severity: '{}'", finding.severity);
            println!("     File_Path: '{}'", resolved_file_path);
            println!("     Line_Number: '{}'", finding.files.source_file.line);
            println!("     Function_Name: '{}'", function_name);
            println!("     Generated hash: '{}' (first 8 chars)", short_hash);
            println!("   Final issue title: '{}'", title);
            if let Some(ref labels_str) = labels_string {
                println!("   Labels string for API: '{}'", labels_str);
            }
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

        self.config.project_dir = Some(absolute_path);
        self
    }

    /// Resolve file path relative to project directory
    fn resolve_file_path(&self, file_path: &str) -> String {
        if self.debug {
            println!("🔍 DEBUG: Resolving file path: '{}'", file_path);
        }

        // If no project directory is set, return the original path
        let project_dir = match &self.config.project_dir {
            Some(dir) => {
                if self.debug {
                    println!("   Project directory: '{}'", dir.display());
                }
                dir
            }
            None => {
                if self.debug {
                    println!("   No project directory set, returning original path");
                }
                return file_path.to_string();
            }
        };

        // Convert file_path to a Path
        let file_path_buf = Path::new(file_path);

        if self.debug {
            println!(
                "   Path is_absolute: {}, is_relative: {}",
                file_path_buf.is_absolute(),
                file_path_buf.is_relative()
            );
        }

        // Handle absolute paths - try to strip project directory prefix
        if file_path_buf.is_absolute() {
            if let Ok(relative_path) = file_path_buf.strip_prefix(project_dir) {
                let result = relative_path.to_string_lossy().to_string();
                if self.debug {
                    println!("   ✅ Stripped project prefix, result: '{}'", result);
                }
                return result;
            } else {
                if self.debug {
                    println!("   ⚠️  Cannot strip project prefix from absolute path");
                }
            }
        }

        // Handle relative paths - this is the main case for Veracode findings
        // Veracode often provides paths like: com/example/vulnerable/CryptoUtils.java
        // We need to find where this actually exists in the repository structure

        if self.debug {
            println!("   🔍 Searching for file in project structure...");
        }

        // Try to find the file by its full relative path first
        if let Some(found_path) = self.find_file_by_relative_path(project_dir, file_path) {
            if self.debug {
                println!("   ✅ Found by relative path search: '{}'", found_path);
            }
            return found_path;
        }

        // If that fails, try to find by filename only
        if let Some(filename) = file_path_buf.file_name().and_then(|n| n.to_str()) {
            if self.debug {
                println!("   🔍 Searching by filename only: '{}'", filename);
            }
            if let Some(found_path) = self.find_file_in_project(project_dir, filename) {
                if self.debug {
                    println!("   ✅ Found by filename search: '{}'", found_path);
                }
                return found_path;
            }
        }

        // Last resort: return the original path
        if self.debug {
            println!(
                "   ❌ Could not resolve path, returning original: '{}'",
                file_path
            );
        }
        file_path.to_string()
    }

    /// Find a file by its relative path structure within the project
    /// This handles cases like: com/example/vulnerable/CryptoUtils.java
    /// Should be found at: src/main/java/com/example/vulnerable/CryptoUtils.java
    fn find_file_by_relative_path(
        &self,
        project_dir: &Path,
        relative_path: &str,
    ) -> Option<String> {
        if self.debug {
            println!("   🔍 Searching for relative path: '{}'", relative_path);
        }

        // Common Java source directory patterns to search
        let common_source_dirs = [
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

        for source_dir in &common_source_dirs {
            let candidate_path = project_dir.join(source_dir).join(relative_path);
            if self.debug {
                println!("     Checking exact path: {}", candidate_path.display());
            }

            // Must check that the EXACT file exists (not just a partial match)
            if candidate_path.exists() && candidate_path.is_file() {
                // Verify this is an exact match by checking that the constructed path
                // ends with the exact relative path we're looking for
                if let Some(candidate_str) = candidate_path.to_str() {
                    // Use path separator normalization to ensure exact matching
                    let normalized_relative = relative_path.replace('\\', "/");
                    let normalized_candidate = candidate_str.replace('\\', "/");

                    if normalized_candidate.ends_with(&normalized_relative) {
                        // Additional check: ensure we're not matching a substring
                        // The character before our match should be a path separator or start of string
                        let match_start = normalized_candidate.len() - normalized_relative.len();
                        if match_start == 0
                            || normalized_candidate.chars().nth(match_start - 1) == Some('/')
                        {
                            // Return path relative to project root
                            if let Ok(result) = candidate_path.strip_prefix(project_dir) {
                                let result_str = result.to_string_lossy().to_string();
                                if self.debug {
                                    println!("     ✅ Found exact path match at: {}", result_str);
                                }
                                return Some(result_str);
                            }
                        } else if self.debug {
                            println!(
                                "     ⚠️  Path ends with target but not at boundary: {}",
                                normalized_candidate
                            );
                        }
                    }
                } else if self.debug {
                    println!(
                        "     ⚠️  Could not convert path to string: {}",
                        candidate_path.display()
                    );
                }
            }
        }

        // Also try the relative path directly in case it's already correct
        let direct_path = project_dir.join(relative_path);
        if self.debug {
            println!("     Checking direct path: {}", direct_path.display());
        }

        if direct_path.exists() && direct_path.is_file() {
            if let Ok(result) = direct_path.strip_prefix(project_dir) {
                let result_str = result.to_string_lossy().to_string();
                if self.debug {
                    println!("     ✅ Found exact direct match: {}", result_str);
                }
                return Some(result_str);
            }
        }

        if self.debug {
            println!("     ❌ No exact path match found in any source directories");
        }
        None
    }

    /// Find a file by name within the project directory tree
    fn find_file_in_project(&self, project_dir: &Path, filename: &str) -> Option<String> {
        if self.debug {
            println!("   🔍 Recursive search for filename: '{}'", filename);
        }
        self.search_for_file(project_dir, filename, project_dir)
    }

    /// Recursively search for a file by name and return its path relative to project root
    fn search_for_file(
        &self,
        current_dir: &Path,
        filename: &str,
        project_root: &Path,
    ) -> Option<String> {
        if let Ok(entries) = std::fs::read_dir(current_dir) {
            for entry in entries.flatten() {
                let entry_path = entry.path();

                if entry_path.is_file() {
                    if let Some(entry_filename) = entry_path.file_name().and_then(|n| n.to_str()) {
                        if entry_filename == filename {
                            // Found the file! Return its path relative to project root
                            if let Ok(relative_path) = entry_path.strip_prefix(project_root) {
                                return Some(relative_path.to_string_lossy().to_string());
                            }
                        }
                    }
                } else if entry_path.is_dir() {
                    // Recursively search subdirectories
                    if let Some(found) = self.search_for_file(&entry_path, filename, project_root) {
                        return Some(found);
                    }
                }
            }
        }
        None
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
        let severity_name = self.get_severity_name(finding.severity);
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
        description.push_str(&format!("| **File** | {} |\n", file_link));
        description.push_str(&format!(
            "| **Line** | {} |\n",
            finding.files.source_file.line
        ));

        if let Some(ref function_name) = finding.files.source_file.function_name {
            if !function_name.is_empty() && function_name != "UNKNOWN" {
                description.push_str(&format!("| **Function** | `{}` |\n", function_name));
            }
        }

        description.push_str(&format!("| **Scan ID** | `{}` |\n", source.scan_id));
        description.push_str(&format!("| **Project** | {} |\n", source.project_name));

        // Add flaw details link if available
        if let Some(ref flaw_details_link) = finding.flaw_details_link {
            if !flaw_details_link.is_empty() {
                description.push_str(&format!(
                    "| **Flaw Details** | [View in Veracode]({}) |\n",
                    flaw_details_link
                ));
                if self.debug {
                    println!(
                        "   Added flaw details link to GitLab issue: {}",
                        flaw_details_link
                    );
                }
            } else {
                if self.debug {
                    println!("   Flaw details link is empty, not adding to GitLab issue");
                }
            }
        } else {
            if self.debug {
                println!("   No flaw details link available for this finding");
            }
        }

        description.push('\n');

        // Enhanced source code section with direct link
        if let Some(project_web_url) = self.get_project_web_url() {
            let branch_or_commit = self.config.commit_sha.as_deref().unwrap_or("main");
            let file_url = format!(
                "{}/-/blob/{}/{}#L{}",
                project_web_url,
                branch_or_commit,
                resolved_file_path,
                finding.files.source_file.line
            );
            description.push_str(&format!("### 📁 Source Code\n\n"));
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
            let pipeline_url = format!(
                "{}{}/pipelines/{}",
                self.config.gitlab_url.replace("/api/v4/projects/", "/-/"),
                self.config.project_id,
                pipeline_id
            );
            links_section.push_str(&format!("- [Pipeline Run]({})\n", pipeline_url));
            has_links = true;
        }

        // Flaw details link
        if let Some(ref flaw_details_link) = finding.flaw_details_link {
            if !flaw_details_link.is_empty() {
                links_section.push_str(&format!(
                    "- [Detailed Vulnerability Information (Veracode)]({})\n",
                    flaw_details_link
                ));
                has_links = true;
                if self.debug {
                    println!(
                        "   Added flaw details link to Related Links section: {}",
                        flaw_details_link
                    );
                }
            } else {
                if self.debug {
                    println!("   Flaw details link is empty, not adding to Related Links");
                }
            }
        } else {
            if self.debug {
                println!("   No flaw details link available for Related Links section");
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
            // Strip HTML tags from display_text for cleaner markdown
            let clean_text = self.strip_html_tags(&finding.display_text);
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

    /// Create a hyperlink to the source file with line number
    fn create_file_link(&self, file_path: &str, line_number: u32) -> String {
        // Try to construct project web URL from available information
        let project_web_url = self.get_project_web_url();

        if let Some(base_url) = project_web_url {
            // Get commit SHA or use 'main' as default branch
            let branch_or_commit = self.config.commit_sha.as_deref().unwrap_or("main");

            // Create permalink format: /project/-/blob/branch/file#Lnumber
            let file_url = format!(
                "{}/-/blob/{}/{}#L{}",
                base_url, branch_or_commit, file_path, line_number
            );

            // Return as markdown link with both filename and line number
            format!("[`{}`]({})", file_path, file_url)
        } else {
            // Fallback to just the filename in code format if no URL available
            format!("`{}`", file_path)
        }
    }

    /// Get project web URL from available configuration
    fn get_project_web_url(&self) -> Option<String> {
        // First try CI_PROJECT_URL if available (most reliable)
        if let Some(ref project_url) = self.config.project_web_url {
            return Some(project_url.clone());
        }

        // If we have project path with namespace, construct URL
        if let Some(ref project_path) = self.config.project_path_with_namespace {
            if self.config.gitlab_url.contains("/api/v4/projects/") {
                let web_base = self.config.gitlab_url.replace("/api/v4/projects/", "/");
                return Some(format!("{}{}", web_base, project_path));
            }
        }

        None
    }

    /// Fetch and cache project information for URL construction
    pub async fn fetch_project_info(&mut self) -> Result<(), GitLabError> {
        if self.config.project_path_with_namespace.is_some() {
            return Ok(()); // Already cached
        }

        let test_url = format!("{}{}", self.config.gitlab_url, self.config.project_id);
        let response = self.client.get(&test_url).send().await?;

        if response.status().is_success() {
            let project_info: serde_json::Value = response.json().await?;
            if let Some(path_with_namespace) = project_info["path_with_namespace"].as_str() {
                self.config.project_path_with_namespace = Some(path_with_namespace.to_string());
            }
            if let Some(project_name) = project_info["name"].as_str() {
                self.config.project_name = Some(project_name.to_string());
            }
        }

        Ok(())
    }

    /// Convert Veracode severity to human-readable name
    fn get_severity_name(&self, severity: u32) -> &'static str {
        match severity {
            5 => "Very High",
            4 => "High",
            3 => "Medium",
            2 => "Low",
            1 => "Very Low",
            0 => "Info",
            _ => "Unknown",
        }
    }

    /// Strip HTML tags from display text to get plain text message
    fn strip_html_tags(&self, html: &str) -> String {
        // Simple HTML tag removal
        let mut result = String::new();
        let mut in_tag = false;

        for ch in html.chars() {
            match ch {
                '<' => in_tag = true,
                '>' => in_tag = false,
                _ if !in_tag => result.push(ch),
                _ => {}
            }
        }

        // Clean up extra whitespace and decode common HTML entities
        result
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
    }
}

impl GitLabConfig {
    /// Create GitLab configuration from environment variables
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
            },
            debug: false,
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
        assert!(test_patterns.len() > 0);
        assert!(test_patterns.contains(&"src/main/java")); // Most common Java pattern
    }

    #[test]
    fn test_severity_name_conversion() {
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
                project_dir: None,
            },
            debug: false,
        };

        assert_eq!(client.get_severity_name(5), "Very High");
        assert_eq!(client.get_severity_name(4), "High");
        assert_eq!(client.get_severity_name(3), "Medium");
        assert_eq!(client.get_severity_name(2), "Low");
        assert_eq!(client.get_severity_name(1), "Very Low");
        assert_eq!(client.get_severity_name(0), "Info");
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
        let labels = vec![
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
        let payload1_json = serde_json::to_string(&payload1).unwrap();
        let mut hasher1 = Sha256::new();
        hasher1.update(payload1_json.as_bytes());
        let hash1 = format!("{:x}", hasher1.finalize())[..8].to_string();

        // Hash payload 2
        let payload2_json = serde_json::to_string(&payload2).unwrap();
        let mut hasher2 = Sha256::new();
        hasher2.update(payload2_json.as_bytes());
        let hash2 = format!("{:x}", hasher2.finalize())[..8].to_string();

        // Test that hash is 8 characters
        assert_eq!(hash1.len(), 8);
        assert_eq!(hash2.len(), 8);

        // Test that different payloads produce different hashes
        assert_ne!(
            hash1, hash2,
            "Different payloads should produce different hashes"
        );

        // Test title format with hash
        let final_title = format!(
            "[High] CWE-89: executeQuery @ UserController.java:45 ({})",
            hash1
        );
        assert!(final_title.contains("CWE-89"));
        assert!(final_title.contains("executeQuery"));
        assert!(final_title.contains(":45"));
        assert!(final_title.contains(&format!("({})", hash1)));

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
            _ => panic!("Expected MissingEnvVar error"),
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

        let config = result.unwrap();
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

        let config = result.unwrap();
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
        let debug_output = format!("{:?}", token);
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("super-secret-token"));

        // Test Display formatting
        let display_output = format!("{}", token);
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
        };

        let debug_output = format!("{:?}", config);

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
}

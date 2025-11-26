//! GitLab Common Types and Utilities
//!
//! This module contains shared types and utilities used across different GitLab integrations
//! to eliminate code duplication and ensure consistency.

use crate::path_resolver::PathResolver;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use log::debug;

/// Secure token wrapper that prevents accidental exposure in logs
#[derive(Clone)]
pub struct SecureToken(String);

impl SecureToken {
    #[must_use]
    pub fn new(token: String) -> Self {
        SecureToken(token)
    }

    #[must_use]
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

/// Convert Veracode severity to human-readable name
#[must_use]
pub fn get_severity_name(severity: u32) -> &'static str {
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
#[must_use]
pub fn strip_html_tags(html: &str) -> String {
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

/// Create a hyperlink to the source file with line number
#[must_use]
pub fn create_file_link(
    file_path: &str,
    line_number: u32,
    project_web_url: Option<&str>,
    commit_sha: Option<&str>,
) -> String {
    if let Some(base_url) = project_web_url {
        // Get commit SHA or use 'main' as default branch
        let branch_or_commit = commit_sha.unwrap_or("main");

        // Create permalink format: /project/-/blob/branch/file#Lnumber
        let file_url = format!("{base_url}/-/blob/{branch_or_commit}/{file_path}#L{line_number}");

        // Return as markdown link with both filename and line number
        format!("[`{file_path}`]({file_url})")
    } else {
        // Fallback to just the filename in code format if no URL available
        format!("`{file_path}`")
    }
}

/// Get project web URL from available configuration
#[must_use]
pub fn get_project_web_url(
    project_web_url: Option<&str>,
    project_path_with_namespace: Option<&str>,
    gitlab_url: &str,
) -> Option<String> {
    // First try CI_PROJECT_URL if available (most reliable)
    if let Some(project_url) = project_web_url {
        return Some(project_url.to_string());
    }

    // If we have project path with namespace, construct URL
    if let Some(project_path) = project_path_with_namespace
        && gitlab_url.contains("/api/v4/projects/")
    {
        let web_base = gitlab_url.replace("/api/v4/projects/", "/");
        return Some(format!("{web_base}{project_path}"));
    }

    None
}

/// Resolve file path using path resolver or return original path
#[must_use]
pub fn resolve_file_path<'a>(
    file_path: &'a str,
    path_resolver: Option<&PathResolver>,
) -> Cow<'a, str> {
    match path_resolver {
        Some(resolver) => resolver.resolve_file_path(file_path),
        None => {
            debug!("   No path resolver configured, returning original path: '{file_path}'");
            Cow::Borrowed(file_path)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_token_redaction() {
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
    fn test_severity_name_conversion() {
        assert_eq!(get_severity_name(5), "Very High");
        assert_eq!(get_severity_name(4), "High");
        assert_eq!(get_severity_name(3), "Medium");
        assert_eq!(get_severity_name(2), "Low");
        assert_eq!(get_severity_name(1), "Very Low");
        assert_eq!(get_severity_name(0), "Info");
        assert_eq!(get_severity_name(999), "Unknown");
    }

    #[test]
    fn test_strip_html_tags() {
        // Test basic HTML tag removal
        let html = "<p>This is <b>bold</b> text</p>";
        let result = strip_html_tags(html);
        assert_eq!(result, "This is bold text");

        // Test HTML entities
        let html_entities = "Less than &lt; and greater than &gt; and &amp; ampersand";
        let result = strip_html_tags(html_entities);
        assert_eq!(result, "Less than < and greater than > and & ampersand");

        // Test nested tags
        let nested = "<div><p>Nested <span>content</span></p></div>";
        let result = strip_html_tags(nested);
        assert_eq!(result, "Nested content");

        // Test empty string
        assert_eq!(strip_html_tags(""), "");

        // Test no HTML
        assert_eq!(strip_html_tags("Plain text"), "Plain text");
    }

    #[test]
    fn test_create_file_link() {
        // Test with project web URL
        let link = create_file_link(
            "src/main.rs",
            42,
            Some("https://gitlab.com/user/project"),
            Some("abc123"),
        );
        assert_eq!(
            link,
            "[`src/main.rs`](https://gitlab.com/user/project/-/blob/abc123/src/main.rs#L42)"
        );

        // Test with default branch
        let link_default = create_file_link(
            "src/main.rs",
            42,
            Some("https://gitlab.com/user/project"),
            None,
        );
        assert_eq!(
            link_default,
            "[`src/main.rs`](https://gitlab.com/user/project/-/blob/main/src/main.rs#L42)"
        );

        // Test without project URL (fallback)
        let link_fallback = create_file_link("src/main.rs", 42, None, None);
        assert_eq!(link_fallback, "`src/main.rs`");
    }

    #[test]
    fn test_get_project_web_url() {
        // Test with direct project URL
        let result = get_project_web_url(
            Some("https://gitlab.com/user/project"),
            None,
            "https://gitlab.com/api/v4/projects/",
        );
        assert_eq!(result, Some("https://gitlab.com/user/project".to_string()));

        // Test with project path and namespace
        let result = get_project_web_url(
            None,
            Some("user/project"),
            "https://gitlab.com/api/v4/projects/",
        );
        assert_eq!(result, Some("https://gitlab.com/user/project".to_string()));

        // Test with no available info
        let result = get_project_web_url(None, None, "https://gitlab.com/api/v4/projects/");
        assert_eq!(result, None);
    }

    #[test]
    fn test_gitlab_issue_payload_serialization() {
        let payload = GitLabIssuePayload {
            title: "Test Issue".to_string(),
            description: "Test Description".to_string(),
            labels: Some("bug,security".to_string()),
            assignee_ids: Some(vec![123, 456]),
            confidential: Some(true),
        };

        // Test that it can be serialized
        let json = serde_json::to_string(&payload).expect("should serialize payload");
        assert!(json.contains("Test Issue"));
        assert!(json.contains("bug,security"));

        // Test deserialization
        let deserialized: GitLabIssuePayload =
            serde_json::from_str(&json).expect("should deserialize payload");
        assert_eq!(deserialized.title, "Test Issue");
        assert_eq!(deserialized.labels, Some("bug,security".to_string()));
    }

    #[test]
    fn test_gitlab_issue_response_deserialization() {
        let json = r#"{
            "id": 123,
            "iid": 1,
            "title": "Test Issue",
            "description": "Test Description",
            "state": "opened",
            "web_url": "https://gitlab.com/user/project/-/issues/1",
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T00:00:00Z"
        }"#;

        let response: GitLabIssueResponse =
            serde_json::from_str(json).expect("should deserialize response");
        assert_eq!(response.id, 123);
        assert_eq!(response.iid, 1);
        assert_eq!(response.title, "Test Issue");
        assert_eq!(response.state, "opened");
    }
}

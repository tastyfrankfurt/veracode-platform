use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{VeracodeClient, VeracodeError};

/// API error response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(rename = "_embedded")]
    pub embedded: Option<ApiErrorEmbedded>,
    pub fallback_type: Option<String>,
    pub full_type: Option<String>,
}

/// Embedded API errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorEmbedded {
    pub api_errors: Vec<ApiError>,
}

/// Individual API error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub id: String,
    pub code: String,
    pub title: String,
    pub status: String,
    pub source: Option<ApiErrorSource>,
}

/// API error source information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorSource {
    pub pointer: String,
    pub parameter: String,
}

/// Represents a Veracode development sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sandbox {
    pub id: Option<u64>,
    pub guid: String,
    pub name: String,
    pub description: Option<String>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub auto_recreate: bool,
    pub custom_fields: Option<HashMap<String, String>>,
    pub owner: Option<String>,
    pub owner_username: Option<String>,
    pub organization_id: Option<u64>,
    pub application_guid: Option<String>,
    pub team_identifiers: Option<Vec<String>>,
    pub scan_url: Option<String>,
    pub last_scan_date: Option<DateTime<Utc>>,
    pub status: Option<String>,
    #[serde(rename = "_links")]
    pub links: Option<serde_json::Value>,
}

/// Request payload for creating a new sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSandboxRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_recreate: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_identifiers: Option<Vec<String>>,
}

/// Request payload for updating an existing sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSandboxRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub auto_recreate: Option<bool>,
    pub custom_fields: Option<HashMap<String, String>>,
    pub team_identifiers: Option<Vec<String>>,
}

/// Response wrapper for sandbox list operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxListResponse {
    #[serde(rename = "_embedded")]
    pub embedded: Option<SandboxEmbedded>,
    pub page: Option<PageInfo>,
    pub total: Option<u64>,
}

/// Embedded sandboxes in the list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEmbedded {
    pub sandboxes: Vec<Sandbox>,
}

/// Page information for paginated responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    pub size: u64,
    pub number: u64,
    pub total_elements: u64,
    pub total_pages: u64,
}

/// Represents a scan within a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxScan {
    pub scan_id: u64,
    pub scan_type: String,
    pub status: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub scan_url: Option<String>,
    pub results_ready: bool,
    pub engine_version: Option<String>,
}

/// Query parameters for listing sandboxes
#[derive(Debug, Clone, Default)]
pub struct SandboxListParams {
    pub name: Option<String>,
    pub owner: Option<String>,
    pub team: Option<String>,
    pub page: Option<u64>,
    pub size: Option<u64>,
    pub modified_after: Option<DateTime<Utc>>,
    pub modified_before: Option<DateTime<Utc>>,
}

impl SandboxListParams {
    /// Convert to query parameters for HTTP requests
    #[must_use]
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        Vec::from(self) // Delegate to trait
    }
}

// Trait implementations for memory optimization
impl From<&SandboxListParams> for Vec<(String, String)> {
    fn from(query: &SandboxListParams) -> Self {
        let mut params = Vec::new();

        if let Some(ref name) = query.name {
            params.push(("name".to_string(), name.clone())); // Still clone for borrowing
        }
        if let Some(ref owner) = query.owner {
            params.push(("owner".to_string(), owner.clone()));
        }
        if let Some(ref team) = query.team {
            params.push(("team".to_string(), team.clone()));
        }
        if let Some(page) = query.page {
            params.push(("page".to_string(), page.to_string()));
        }
        if let Some(size) = query.size {
            params.push(("size".to_string(), size.to_string()));
        }
        if let Some(modified_after) = query.modified_after {
            params.push(("modified_after".to_string(), modified_after.to_rfc3339()));
        }
        if let Some(modified_before) = query.modified_before {
            params.push(("modified_before".to_string(), modified_before.to_rfc3339()));
        }

        params
    }
}

impl From<SandboxListParams> for Vec<(String, String)> {
    fn from(query: SandboxListParams) -> Self {
        let mut params = Vec::new();

        if let Some(name) = query.name {
            params.push(("name".to_string(), name)); // MOVE - no clone!
        }
        if let Some(owner) = query.owner {
            params.push(("owner".to_string(), owner)); // MOVE - no clone!
        }
        if let Some(team) = query.team {
            params.push(("team".to_string(), team)); // MOVE - no clone!
        }
        if let Some(page) = query.page {
            params.push(("page".to_string(), page.to_string()));
        }
        if let Some(size) = query.size {
            params.push(("size".to_string(), size.to_string()));
        }
        if let Some(modified_after) = query.modified_after {
            params.push(("modified_after".to_string(), modified_after.to_rfc3339()));
        }
        if let Some(modified_before) = query.modified_before {
            params.push(("modified_before".to_string(), modified_before.to_rfc3339()));
        }

        params
    }
}

/// Sandbox-specific error types that extend the base VeracodeError
#[derive(Debug)]
#[must_use = "Need to handle all error enum types."]
pub enum SandboxError {
    /// Veracode API error
    Api(VeracodeError),
    /// Sandbox not found
    NotFound,
    /// Invalid sandbox name or configuration
    InvalidInput(String),
    /// Maximum number of sandboxes reached
    LimitExceeded,
    /// Sandbox operation not allowed
    OperationNotAllowed(String),
    /// Sandbox already exists
    AlreadyExists(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Api(err) => write!(f, "API error: {err}"),
            SandboxError::NotFound => write!(f, "Sandbox not found"),
            SandboxError::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
            SandboxError::LimitExceeded => write!(f, "Maximum number of sandboxes reached"),
            SandboxError::OperationNotAllowed(msg) => write!(f, "Operation not allowed: {msg}"),
            SandboxError::AlreadyExists(msg) => write!(f, "Sandbox already exists: {msg}"),
        }
    }
}

impl std::error::Error for SandboxError {}

impl From<VeracodeError> for SandboxError {
    fn from(err: VeracodeError) -> Self {
        SandboxError::Api(err)
    }
}

impl From<reqwest::Error> for SandboxError {
    fn from(err: reqwest::Error) -> Self {
        SandboxError::Api(VeracodeError::Http(err))
    }
}

impl From<serde_json::Error> for SandboxError {
    fn from(err: serde_json::Error) -> Self {
        SandboxError::Api(VeracodeError::Serialization(err))
    }
}

/// Veracode Sandbox API operations
pub struct SandboxApi<'a> {
    client: &'a VeracodeClient,
}

impl<'a> SandboxApi<'a> {
    /// Create a new SandboxApi instance
    #[must_use]
    pub fn new(client: &'a VeracodeClient) -> Self {
        Self { client }
    }

    /// List all sandboxes for a given application
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `params` - Optional query parameters for filtering
    ///
    /// # Returns
    ///
    /// A `Result` containing a list of sandboxes or an error.
    pub async fn list_sandboxes(
        &self,
        application_guid: &str,
        params: Option<SandboxListParams>,
    ) -> Result<Vec<Sandbox>, SandboxError> {
        let endpoint = format!("/appsec/v1/applications/{application_guid}/sandboxes");

        let query_params = params.as_ref().map(Vec::from);

        let response = self.client.get(&endpoint, query_params.as_deref()).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let sandbox_response: SandboxListResponse = response.json().await?;
                Ok(sandbox_response
                    .embedded
                    .map(|e| e.sandboxes)
                    .unwrap_or_default())
            }
            404 => Err(SandboxError::NotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Get a specific sandbox by GUID
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `sandbox_guid` - The GUID of the sandbox
    ///
    /// # Returns
    ///
    /// A `Result` containing the sandbox or an error.
    pub async fn get_sandbox(
        &self,
        application_guid: &str,
        sandbox_guid: &str,
    ) -> Result<Sandbox, SandboxError> {
        let endpoint =
            format!("/appsec/v1/applications/{application_guid}/sandboxes/{sandbox_guid}");

        let response = self.client.get(&endpoint, None).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let sandbox: Sandbox = response.json().await?;
                Ok(sandbox)
            }
            404 => Err(SandboxError::NotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Create a new sandbox
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `request` - The sandbox creation request
    ///
    /// # Returns
    ///
    /// A `Result` containing the created sandbox or an error.
    pub async fn create_sandbox(
        &self,
        application_guid: &str,
        request: CreateSandboxRequest,
    ) -> Result<Sandbox, SandboxError> {
        // Validate the request
        Self::validate_create_request(&request)?;

        let endpoint = format!("/appsec/v1/applications/{application_guid}/sandboxes");

        let response = self.client.post(&endpoint, Some(&request)).await?;

        let status = response.status().as_u16();
        match status {
            200 | 201 => {
                let sandbox: Sandbox = response.json().await?;
                Ok(sandbox)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();

                // Try to parse the structured error response
                if let Ok(error_response) = serde_json::from_str::<ApiErrorResponse>(&error_text)
                    && let Some(embedded) = error_response.embedded
                {
                    for api_error in embedded.api_errors {
                        if api_error.title.contains("already exists") {
                            return Err(SandboxError::AlreadyExists(api_error.title));
                        }
                        if api_error.title.contains("limit") || api_error.title.contains("maximum")
                        {
                            return Err(SandboxError::LimitExceeded);
                        }
                        if api_error.title.contains("Json Parse Error")
                            || api_error.title.contains("Cannot deserialize")
                        {
                            return Err(SandboxError::InvalidInput(format!(
                                "JSON parsing error: {}",
                                api_error.title
                            )));
                        }
                    }
                }

                // Fallback to string matching for backwards compatibility
                if error_text.contains("limit") || error_text.contains("maximum") {
                    Err(SandboxError::LimitExceeded)
                } else if error_text.contains("already exists") {
                    Err(SandboxError::AlreadyExists(error_text))
                } else {
                    Err(SandboxError::InvalidInput(error_text))
                }
            }
            404 => Err(SandboxError::NotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Update an existing sandbox
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `sandbox_guid` - The GUID of the sandbox to update
    /// * `request` - The sandbox update request
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated sandbox or an error.
    pub async fn update_sandbox(
        &self,
        application_guid: &str,
        sandbox_guid: &str,
        request: UpdateSandboxRequest,
    ) -> Result<Sandbox, SandboxError> {
        // Validate the request
        Self::validate_update_request(&request)?;

        let endpoint =
            format!("/appsec/v1/applications/{application_guid}/sandboxes/{sandbox_guid}");

        let response = self.client.put(&endpoint, Some(&request)).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let sandbox: Sandbox = response.json().await?;
                Ok(sandbox)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::InvalidInput(error_text))
            }
            404 => Err(SandboxError::NotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Delete a sandbox
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `sandbox_guid` - The GUID of the sandbox to delete
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure.
    pub async fn delete_sandbox(
        &self,
        application_guid: &str,
        sandbox_guid: &str,
    ) -> Result<(), SandboxError> {
        let endpoint =
            format!("/appsec/v1/applications/{application_guid}/sandboxes/{sandbox_guid}");

        let response = self.client.delete(&endpoint).await?;

        let status = response.status().as_u16();
        match status {
            204 => Ok(()),
            404 => Err(SandboxError::NotFound),
            409 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::OperationNotAllowed(error_text))
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Promote a sandbox scan to the policy sandbox
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `sandbox_guid` - The GUID of the sandbox to promote
    /// * `delete_on_promote` - Whether to delete the sandbox after promotion
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure.
    pub async fn promote_sandbox_scan(
        &self,
        application_guid: &str,
        sandbox_guid: &str,
        delete_on_promote: bool,
    ) -> Result<(), SandboxError> {
        let endpoint = if delete_on_promote {
            format!(
                "/appsec/v1/applications/{application_guid}/sandboxes/{sandbox_guid}/promote?delete_on_promote=true"
            )
        } else {
            format!("/appsec/v1/applications/{application_guid}/sandboxes/{sandbox_guid}/promote")
        };

        let response = self.client.post(&endpoint, None::<&()>).await?;

        let status = response.status().as_u16();
        match status {
            200 | 204 => Ok(()),
            404 => Err(SandboxError::NotFound),
            409 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::OperationNotAllowed(error_text))
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Get sandbox scan information
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `sandbox_guid` - The GUID of the sandbox
    ///
    /// # Returns
    ///
    /// A `Result` containing a list of scans or an error.
    pub async fn get_sandbox_scans(
        &self,
        application_guid: &str,
        sandbox_guid: &str,
    ) -> Result<Vec<SandboxScan>, SandboxError> {
        let endpoint =
            format!("/appsec/v1/applications/{application_guid}/sandboxes/{sandbox_guid}/scans");

        let response = self.client.get(&endpoint, None).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let scans: Vec<SandboxScan> = response.json().await?;
                Ok(scans)
            }
            404 => Err(SandboxError::NotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Check if a sandbox exists
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `sandbox_guid` - The GUID of the sandbox
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean indicating if the sandbox exists.
    pub async fn sandbox_exists(
        &self,
        application_guid: &str,
        sandbox_guid: &str,
    ) -> Result<bool, SandboxError> {
        match self.get_sandbox(application_guid, sandbox_guid).await {
            Ok(_) => Ok(true),
            Err(SandboxError::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Get sandbox by name
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `name` - The name of the sandbox to find
    ///
    /// # Returns
    ///
    /// A `Result` containing the sandbox if found, or None if not found.
    pub async fn get_sandbox_by_name(
        &self,
        application_guid: &str,
        name: &str,
    ) -> Result<Option<Sandbox>, SandboxError> {
        let params = SandboxListParams {
            name: Some(name.to_string()),
            ..Default::default()
        };

        let sandboxes = self.list_sandboxes(application_guid, Some(params)).await?;
        Ok(sandboxes.into_iter().find(|s| s.name == name))
    }

    /// Validate sandbox creation request
    fn validate_create_request(request: &CreateSandboxRequest) -> Result<(), SandboxError> {
        if request.name.is_empty() {
            return Err(SandboxError::InvalidInput(
                "Sandbox name cannot be empty".to_string(),
            ));
        }
        if request.name.len() > 256 {
            return Err(SandboxError::InvalidInput(
                "Sandbox name too long (max 256 characters)".to_string(),
            ));
        }

        // Check for invalid characters in name
        if request.name.contains(['<', '>', '"', '&', '\'']) {
            return Err(SandboxError::InvalidInput(
                "Sandbox name contains invalid characters".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate sandbox update request
    fn validate_update_request(request: &UpdateSandboxRequest) -> Result<(), SandboxError> {
        if let Some(name) = &request.name {
            if name.is_empty() {
                return Err(SandboxError::InvalidInput(
                    "Sandbox name cannot be empty".to_string(),
                ));
            }
            if name.len() > 256 {
                return Err(SandboxError::InvalidInput(
                    "Sandbox name too long (max 256 characters)".to_string(),
                ));
            }

            // Check for invalid characters in name
            if name.contains(['<', '>', '"', '&', '\'']) {
                return Err(SandboxError::InvalidInput(
                    "Sandbox name contains invalid characters".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Convenience methods for common sandbox operations
impl<'a> SandboxApi<'a> {
    /// Create a simple sandbox with just a name
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `name` - The name of the sandbox
    ///
    /// # Returns
    ///
    /// A `Result` containing the created sandbox or an error.
    pub async fn create_simple_sandbox(
        &self,
        application_guid: &str,
        name: &str,
    ) -> Result<Sandbox, SandboxError> {
        let request = CreateSandboxRequest {
            name: name.to_string(),
            description: None,
            auto_recreate: None,
            custom_fields: None,
            team_identifiers: None,
        };

        self.create_sandbox(application_guid, request).await
    }

    /// Create a sandbox with auto-recreate enabled
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `name` - The name of the sandbox
    /// * `description` - Optional description
    ///
    /// # Returns
    ///
    /// A `Result` containing the created sandbox or an error.
    pub async fn create_auto_recreate_sandbox(
        &self,
        application_guid: &str,
        name: &str,
        description: Option<String>,
    ) -> Result<Sandbox, SandboxError> {
        let request = CreateSandboxRequest {
            name: name.to_string(),
            description,
            auto_recreate: Some(true),
            custom_fields: None,
            team_identifiers: None,
        };

        self.create_sandbox(application_guid, request).await
    }

    /// Update sandbox name
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `sandbox_guid` - The GUID of the sandbox
    /// * `new_name` - The new name for the sandbox
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated sandbox or an error.
    pub async fn update_sandbox_name(
        &self,
        application_guid: &str,
        sandbox_guid: &str,
        new_name: &str,
    ) -> Result<Sandbox, SandboxError> {
        let request = UpdateSandboxRequest {
            name: Some(new_name.to_string()),
            description: None,
            auto_recreate: None,
            custom_fields: None,
            team_identifiers: None,
        };

        self.update_sandbox(application_guid, sandbox_guid, request)
            .await
    }

    /// Count sandboxes for an application
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    ///
    /// # Returns
    ///
    /// A `Result` containing the count of sandboxes or an error.
    pub async fn count_sandboxes(&self, application_guid: &str) -> Result<usize, SandboxError> {
        let sandboxes = self.list_sandboxes(application_guid, None).await?;
        Ok(sandboxes.len())
    }

    /// Get numeric sandbox_id from sandbox GUID.
    ///
    /// This is needed for XML API operations that require numeric IDs.
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `sandbox_guid` - The sandbox GUID
    ///
    /// # Returns
    ///
    /// A `Result` containing the numeric sandbox_id as a string.
    pub async fn get_sandbox_id_from_guid(
        &self,
        application_guid: &str,
        sandbox_guid: &str,
    ) -> Result<String, SandboxError> {
        let sandbox = self.get_sandbox(application_guid, sandbox_guid).await?;
        match sandbox.id {
            Some(id) => Ok(id.to_string()),
            None => Err(SandboxError::InvalidInput(
                "Sandbox has no numeric ID".to_string(),
            )),
        }
    }

    /// Create sandbox if it doesn't exist, or return existing sandbox.
    ///
    /// This method implements the "check and create" pattern commonly needed
    /// for automated workflows.
    ///
    /// # Arguments
    ///
    /// * `application_guid` - The GUID of the application
    /// * `name` - The name of the sandbox
    /// * `description` - Optional description for new sandboxes
    ///
    /// # Returns
    ///
    /// A `Result` containing the sandbox (existing or newly created).
    pub async fn create_sandbox_if_not_exists(
        &self,
        application_guid: &str,
        name: &str,
        description: Option<String>,
    ) -> Result<Sandbox, SandboxError> {
        // First, check if sandbox already exists
        if let Some(existing_sandbox) = self.get_sandbox_by_name(application_guid, name).await? {
            return Ok(existing_sandbox);
        }

        // Sandbox doesn't exist, create it
        let create_request = CreateSandboxRequest {
            name: name.to_string(),
            description,
            auto_recreate: Some(true), // Enable auto-recreate by default for CI/CD
            custom_fields: None,
            team_identifiers: None,
        };

        self.create_sandbox(application_guid, create_request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_create_request() {
        // Valid request
        let valid_request = CreateSandboxRequest {
            name: "valid-sandbox".to_string(),
            description: None,
            auto_recreate: None,
            custom_fields: None,
            team_identifiers: None,
        };
        assert!(SandboxApi::validate_create_request(&valid_request).is_ok());

        // Empty name
        let empty_name_request = CreateSandboxRequest {
            name: String::new(),
            description: None,
            auto_recreate: None,
            custom_fields: None,
            team_identifiers: None,
        };
        assert!(SandboxApi::validate_create_request(&empty_name_request).is_err());

        // Long name
        let long_name_request = CreateSandboxRequest {
            name: "x".repeat(300),
            description: None,
            auto_recreate: None,
            custom_fields: None,
            team_identifiers: None,
        };
        assert!(SandboxApi::validate_create_request(&long_name_request).is_err());

        // Invalid characters
        let invalid_char_request = CreateSandboxRequest {
            name: "invalid<name>".to_string(),
            description: None,
            auto_recreate: None,
            custom_fields: None,
            team_identifiers: None,
        };
        assert!(SandboxApi::validate_create_request(&invalid_char_request).is_err());
    }

    #[test]
    fn test_sandbox_list_params_to_query() {
        let params = SandboxListParams {
            name: Some("test".to_string()),
            page: Some(1),
            size: Some(10),
            ..Default::default()
        };

        let query_params: Vec<_> = params.into();
        assert_eq!(query_params.len(), 3);
        assert!(query_params.contains(&("name".to_string(), "test".to_string())));
        assert!(query_params.contains(&("page".to_string(), "1".to_string())));
        assert!(query_params.contains(&("size".to_string(), "10".to_string())));
    }

    #[test]
    fn test_sandbox_error_display() {
        let error = SandboxError::NotFound;
        assert_eq!(error.to_string(), "Sandbox not found");

        let error = SandboxError::InvalidInput("test".to_string());
        assert_eq!(error.to_string(), "Invalid input: test");

        let error = SandboxError::LimitExceeded;
        assert_eq!(error.to_string(), "Maximum number of sandboxes reached");
    }
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::json_validator::{MAX_JSON_DEPTH, validate_json_depth};
use crate::validation::validate_url_segment;
use crate::{VeracodeClient, VeracodeError};

/// Maximum page size for pagination to prevent memory exhaustion attacks
const MAX_PAGE_SIZE: u64 = 500;

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
            // Cap page size at MAX_PAGE_SIZE to prevent memory exhaustion
            let safe_size = size.min(MAX_PAGE_SIZE);
            params.push(("size".to_string(), safe_size.to_string()));
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
            // Cap page size at MAX_PAGE_SIZE to prevent memory exhaustion
            let safe_size = size.min(MAX_PAGE_SIZE);
            params.push(("size".to_string(), safe_size.to_string()));
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

///
/// # Errors
///
/// Returns an error if the API request fails, the resource is not found,
/// or authentication/authorization fails.
/// Sandbox-specific error types that extend the base `VeracodeError`
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// Create a new `SandboxApi` instance
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
                let response_text = response.text().await?;

                // Validate JSON depth before parsing to prevent DoS attacks
                if validate_json_depth(&response_text, MAX_JSON_DEPTH).is_err() {
                    return Err(SandboxError::Api(VeracodeError::InvalidResponse(
                        "JSON validation failed on response".to_string(),
                    )));
                }

                let sandbox_response: SandboxListResponse = serde_json::from_str(&response_text)?;
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
                let response_text = response.text().await?;

                // Validate JSON depth before parsing to prevent DoS attacks
                if validate_json_depth(&response_text, MAX_JSON_DEPTH).is_err() {
                    return Err(SandboxError::Api(VeracodeError::InvalidResponse(
                        "JSON validation failed on response".to_string(),
                    )));
                }

                let sandbox: Sandbox = serde_json::from_str(&response_text)?;
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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

                // Validate JSON depth before parsing to prevent DoS attacks
                if validate_json_depth(&error_text, MAX_JSON_DEPTH).is_err() {
                    return Err(SandboxError::Api(VeracodeError::InvalidResponse(
                        "JSON validation failed on error response".to_string(),
                    )));
                }

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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
                let response_text = response.text().await?;

                // Validate JSON depth before parsing to prevent DoS attacks
                if validate_json_depth(&response_text, MAX_JSON_DEPTH).is_err() {
                    return Err(SandboxError::Api(VeracodeError::InvalidResponse(
                        "JSON validation failed on response".to_string(),
                    )));
                }

                let sandbox: Sandbox = serde_json::from_str(&response_text)?;
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
                let response_text = response.text().await?;

                // Validate JSON depth before parsing to prevent DoS attacks
                if validate_json_depth(&response_text, MAX_JSON_DEPTH).is_err() {
                    return Err(SandboxError::Api(VeracodeError::InvalidResponse(
                        "JSON validation failed on response".to_string(),
                    )));
                }

                let scans: Vec<SandboxScan> = serde_json::from_str(&response_text)?;
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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

    /// Validate sandbox name
    fn validate_name(name: &str) -> Result<(), SandboxError> {
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

        // Use shared validation from validation.rs to prevent path traversal and control characters
        validate_url_segment(name, 256)
            .map_err(|e| SandboxError::InvalidInput(format!("Invalid sandbox name: {}", e)))?;

        Ok(())
    }

    /// Validate sandbox creation request
    fn validate_create_request(request: &CreateSandboxRequest) -> Result<(), SandboxError> {
        Self::validate_name(&request.name)?;

        // Validate custom fields if present
        if let Some(ref custom_fields) = request.custom_fields {
            Self::validate_custom_fields(custom_fields)?;
        }

        // Validate team identifiers if present
        if let Some(ref team_ids) = request.team_identifiers {
            Self::validate_team_identifiers(team_ids)?;
        }

        Ok(())
    }

    /// Validate sandbox update request
    fn validate_update_request(request: &UpdateSandboxRequest) -> Result<(), SandboxError> {
        if let Some(name) = &request.name {
            Self::validate_name(name)?;
        }

        // Validate custom fields if present
        if let Some(ref custom_fields) = request.custom_fields {
            Self::validate_custom_fields(custom_fields)?;
        }

        // Validate team identifiers if present
        if let Some(ref team_ids) = request.team_identifiers {
            Self::validate_team_identifiers(team_ids)?;
        }

        Ok(())
    }

    /// Validate custom fields
    fn validate_custom_fields(custom_fields: &HashMap<String, String>) -> Result<(), SandboxError> {
        const MAX_CUSTOM_FIELDS: usize = 50;
        const MAX_KEY_LENGTH: usize = 128;
        const MAX_VALUE_LENGTH: usize = 1024;

        if custom_fields.len() > MAX_CUSTOM_FIELDS {
            return Err(SandboxError::InvalidInput(format!(
                "Too many custom fields (max {MAX_CUSTOM_FIELDS})"
            )));
        }

        for (key, value) in custom_fields {
            // Validate key
            if key.is_empty() {
                return Err(SandboxError::InvalidInput(
                    "Custom field key cannot be empty".to_string(),
                ));
            }
            if key.len() > MAX_KEY_LENGTH {
                return Err(SandboxError::InvalidInput(format!(
                    "Custom field key too long (max {MAX_KEY_LENGTH} characters)"
                )));
            }
            if key.chars().any(|c| c.is_control()) {
                return Err(SandboxError::InvalidInput(
                    "Custom field key contains control characters".to_string(),
                ));
            }
            if key.contains(['<', '>', '"', '&', '\'', '/', '\\']) {
                return Err(SandboxError::InvalidInput(
                    "Custom field key contains invalid characters".to_string(),
                ));
            }

            // Validate value
            if value.len() > MAX_VALUE_LENGTH {
                return Err(SandboxError::InvalidInput(format!(
                    "Custom field value too long (max {MAX_VALUE_LENGTH} characters)"
                )));
            }
            if value
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
            {
                return Err(SandboxError::InvalidInput(
                    "Custom field value contains invalid control characters".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate team identifiers
    fn validate_team_identifiers(team_ids: &[String]) -> Result<(), SandboxError> {
        const MAX_TEAM_IDS: usize = 100;
        const MAX_TEAM_ID_LENGTH: usize = 128;

        if team_ids.len() > MAX_TEAM_IDS {
            return Err(SandboxError::InvalidInput(format!(
                "Too many team identifiers (max {MAX_TEAM_IDS})"
            )));
        }

        for team_id in team_ids {
            if team_id.is_empty() {
                return Err(SandboxError::InvalidInput(
                    "Team identifier cannot be empty".to_string(),
                ));
            }
            if team_id.len() > MAX_TEAM_ID_LENGTH {
                return Err(SandboxError::InvalidInput(format!(
                    "Team identifier too long (max {MAX_TEAM_ID_LENGTH} characters)"
                )));
            }
            if team_id.chars().any(|c| c.is_control()) {
                return Err(SandboxError::InvalidInput(
                    "Team identifier contains control characters".to_string(),
                ));
            }
            if team_id.contains(['<', '>', '"', '&', '\'', '/', '\\']) {
                return Err(SandboxError::InvalidInput(
                    "Team identifier contains invalid characters".to_string(),
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
    pub async fn count_sandboxes(&self, application_guid: &str) -> Result<u64, SandboxError> {
        let endpoint = format!("/appsec/v1/applications/{application_guid}/sandboxes");

        // Request with size=1 to minimize data transfer - we only need the count
        let query_params = vec![("size".to_string(), "1".to_string())];

        let response = self.client.get(&endpoint, Some(&query_params)).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;

                // Validate JSON depth before parsing to prevent DoS attacks
                if validate_json_depth(&response_text, MAX_JSON_DEPTH).is_err() {
                    return Err(SandboxError::Api(VeracodeError::InvalidResponse(
                        "JSON validation failed on response".to_string(),
                    )));
                }

                let sandbox_response: SandboxListResponse = serde_json::from_str(&response_text)?;
                // Use the total from page info if available, otherwise fall back to counting embedded items
                Ok(sandbox_response
                    .page
                    .map(|p| p.total_elements)
                    .or(sandbox_response.total)
                    .unwrap_or(0))
            }
            404 => Ok(0), // Application not found or has no sandboxes
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(SandboxError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
    /// Get numeric `sandbox_id` from sandbox GUID.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
    /// A `Result` containing the numeric `sandbox_id` as a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the sandbox is not found,
    /// or authentication/authorization fails.
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
    /// This method implements the "try-create-or-get" pattern which is safe
    /// against TOCTOU race conditions in concurrent environments.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or authentication/authorization fails.
    /// Does not return an error if the sandbox already exists.
    pub async fn create_sandbox_if_not_exists(
        &self,
        application_guid: &str,
        name: &str,
        description: Option<String>,
    ) -> Result<Sandbox, SandboxError> {
        // Try to create the sandbox first (optimistic approach)
        let create_request = CreateSandboxRequest {
            name: name.to_string(),
            description: description.clone(),
            auto_recreate: Some(true), // Enable auto-recreate by default for CI/CD
            custom_fields: None,
            team_identifiers: None,
        };

        match self.create_sandbox(application_guid, create_request).await {
            Ok(sandbox) => Ok(sandbox),
            Err(SandboxError::AlreadyExists(_)) => {
                // Sandbox was created concurrently, fetch and return it
                self.get_sandbox_by_name(application_guid, name)
                    .await?
                    .ok_or_else(|| {
                        SandboxError::Api(VeracodeError::InvalidResponse(
                            "Sandbox exists but cannot be retrieved".to_string(),
                        ))
                    })
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
    fn test_sandbox_list_params_page_size_limit() {
        // Test that excessive page sizes are capped at MAX_PAGE_SIZE
        let params = SandboxListParams {
            size: Some(999999999),
            ..Default::default()
        };

        let query_params: Vec<_> = params.into();
        assert_eq!(query_params.len(), 1);
        assert!(query_params.contains(&("size".to_string(), MAX_PAGE_SIZE.to_string())));

        // Test with u64::MAX
        let params = SandboxListParams {
            size: Some(u64::MAX),
            ..Default::default()
        };

        let query_params: Vec<_> = params.into();
        assert_eq!(query_params.len(), 1);
        assert!(query_params.contains(&("size".to_string(), MAX_PAGE_SIZE.to_string())));

        // Test that reasonable sizes are not modified
        let params = SandboxListParams {
            size: Some(100),
            ..Default::default()
        };

        let query_params: Vec<_> = params.into();
        assert_eq!(query_params.len(), 1);
        assert!(query_params.contains(&("size".to_string(), "100".to_string())));
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

    #[test]
    fn test_validate_name_control_characters() {
        // Test control characters
        assert!(SandboxApi::validate_name("test\x00name").is_err());
        assert!(SandboxApi::validate_name("test\nname").is_err());
        assert!(SandboxApi::validate_name("test\rname").is_err());
        assert!(SandboxApi::validate_name("test\x1Fname").is_err());
    }

    #[test]
    fn test_validate_name_path_traversal() {
        // Test path traversal sequences
        assert!(SandboxApi::validate_name("../etc/passwd").is_err());
        assert!(SandboxApi::validate_name("test/../name").is_err());
        assert!(SandboxApi::validate_name("test/name").is_err());
        assert!(SandboxApi::validate_name("test\\name").is_err());
    }

    #[test]
    fn test_validate_custom_fields() {
        use std::collections::HashMap;

        // Valid custom fields
        let mut valid_fields = HashMap::new();
        valid_fields.insert("key1".to_string(), "value1".to_string());
        assert!(SandboxApi::validate_custom_fields(&valid_fields).is_ok());

        // Empty key
        let mut empty_key = HashMap::new();
        empty_key.insert("".to_string(), "value".to_string());
        assert!(SandboxApi::validate_custom_fields(&empty_key).is_err());

        // Key too long
        let mut long_key = HashMap::new();
        long_key.insert("x".repeat(200), "value".to_string());
        assert!(SandboxApi::validate_custom_fields(&long_key).is_err());

        // Value too long
        let mut long_value = HashMap::new();
        long_value.insert("key".to_string(), "x".repeat(2000));
        assert!(SandboxApi::validate_custom_fields(&long_value).is_err());

        // Control characters in key
        let mut control_key = HashMap::new();
        control_key.insert("test\x00key".to_string(), "value".to_string());
        assert!(SandboxApi::validate_custom_fields(&control_key).is_err());

        // Invalid characters in key
        let mut invalid_key = HashMap::new();
        invalid_key.insert("test<key>".to_string(), "value".to_string());
        assert!(SandboxApi::validate_custom_fields(&invalid_key).is_err());

        // Too many fields
        let mut too_many = HashMap::new();
        for i in 0..100 {
            too_many.insert(format!("key{i}"), format!("value{i}"));
        }
        assert!(SandboxApi::validate_custom_fields(&too_many).is_err());
    }

    #[test]
    fn test_validate_team_identifiers() {
        // Valid team identifiers
        assert!(
            SandboxApi::validate_team_identifiers(&["team1".to_string(), "team2".to_string()])
                .is_ok()
        );

        // Empty team identifier
        assert!(SandboxApi::validate_team_identifiers(&["".to_string()]).is_err());

        // Team identifier too long
        assert!(SandboxApi::validate_team_identifiers(&["x".repeat(200)]).is_err());

        // Control characters
        assert!(SandboxApi::validate_team_identifiers(&["team\x00id".to_string()]).is_err());

        // Invalid characters
        assert!(SandboxApi::validate_team_identifiers(&["team<id>".to_string()]).is_err());

        // Too many team identifiers
        let too_many: Vec<String> = (0..150).map(|i| format!("team{i}")).collect();
        assert!(SandboxApi::validate_team_identifiers(&too_many).is_err());
    }

    // ========================================================================
    // PROPTEST SECURITY TESTS
    // ========================================================================
    //
    // These property-based tests verify security properties across all validation
    // functions using randomly generated inputs. They are Miri-optimized to run
    // 10 cases under Miri (for memory safety checking) and 1000 cases normally.
    //
    // SECURITY PROPERTIES TESTED:
    // 1. Input validation rejects control characters (prevents injection)
    // 2. Path traversal sequences are rejected (prevents directory traversal)
    // 3. Length bounds are enforced (prevents DoS via memory exhaustion)
    // 4. Dangerous characters are rejected (prevents XSS/injection)
    // 5. Empty/invalid inputs are rejected (prevents logic errors)
    // 6. Page size limits are enforced (prevents DoS via unbounded queries)
    //
    // TESTING STRATEGY:
    // - Tier 1: Property-based testing with proptest (all validation functions)
    // - No unsafe code → Miri verification not needed
    // - No cryptographic/concurrent code → Kani formal verification not needed
    //
    // WHY KANI IS NOT USED:
    // These are simple input validation functions with straightforward logic.
    // Kani would provide formal proofs but at high computational cost (minutes
    // to hours per proof). Proptest provides excellent coverage for validation
    // logic at much lower cost (seconds). Kani is reserved for cryptographic,
    // concurrent, or mission-critical state machines where formal proofs add
    // significant value.

    mod proptest_security_tests {
        use super::*;

        // Property: validate_name should reject any string with control characters
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_name_rejects_control_chars(
                prefix in "[a-zA-Z0-9_-]{0,10}",
                control_char in prop::char::range('\x00', '\x1F'),
                suffix in "[a-zA-Z0-9_-]{0,10}",
            ) {
                let name = format!("{}{}{}", prefix, control_char, suffix);
                let result = SandboxApi::validate_name(&name);
                prop_assert!(result.is_err(), "Should reject control character: {:?}", control_char);
            }
        }

        // Property: validate_name should reject path traversal sequences
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_name_rejects_path_traversal(
                prefix in "[a-zA-Z0-9_-]{0,20}",
                suffix in "[a-zA-Z0-9_-]{0,20}",
            ) {
                let test_cases = vec![
                    format!("{}/../{}", prefix, suffix),
                    format!("{}//{}", prefix, suffix),
                    format!("{}\\{}", prefix, suffix),
                    format!("{}..", suffix),
                ];

                for name in test_cases {
                    let result = SandboxApi::validate_name(&name);
                    prop_assert!(result.is_err(), "Should reject path traversal in: {}", name);
                }
            }
        }

        // Property: validate_name should reject names exceeding max length
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            #[allow(clippy::arithmetic_side_effects)]
            fn prop_validate_name_rejects_too_long(
                extra_len in 1usize..=100usize,
            ) {
                let name = "a".repeat(256 + extra_len);
                let result = SandboxApi::validate_name(&name);
                prop_assert!(result.is_err(), "Should reject name of length {}", name.len());
            }
        }

        // Property: validate_name should accept valid names
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_name_accepts_valid_names(
                name in "[a-zA-Z0-9_-]{1,256}",
            ) {
                // Filter out any accidentally generated invalid patterns
                prop_assume!(!name.contains(".."));
                prop_assume!(!name.contains('/'));
                prop_assume!(!name.contains('\\'));

                let result = SandboxApi::validate_name(&name);
                prop_assert!(result.is_ok(), "Should accept valid name: {}", name);
            }
        }

        // Property: validate_name should reject dangerous characters
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 500 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_name_rejects_dangerous_chars(
                prefix in "[a-zA-Z0-9]{0,20}",
                dangerous in prop::sample::select(vec!['<', '>', '"', '&', '\'']),
                suffix in "[a-zA-Z0-9]{0,20}",
            ) {
                let name = format!("{}{}{}", prefix, dangerous, suffix);
                let result = SandboxApi::validate_name(&name);
                prop_assert!(result.is_err(), "Should reject dangerous character: {}", dangerous);
            }
        }

        // Property: validate_custom_fields should reject empty keys
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_custom_fields_rejects_empty_key(
                value in "[a-zA-Z0-9]{1,100}",
            ) {
                let mut fields = HashMap::new();
                fields.insert("".to_string(), value);
                let result = SandboxApi::validate_custom_fields(&fields);
                prop_assert!(result.is_err(), "Should reject empty key");
            }
        }

        // Property: validate_custom_fields should reject keys exceeding max length
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_custom_fields_rejects_long_key(
                extra_len in 1usize..=50usize,
            ) {
                let mut fields = HashMap::new();
                let long_key = "a".repeat(128_usize.saturating_add(extra_len));
                fields.insert(long_key.clone(), "value".to_string());
                let result = SandboxApi::validate_custom_fields(&fields);
                prop_assert!(result.is_err(), "Should reject key of length {}", long_key.len());
            }
        }

        // Property: validate_custom_fields should reject values exceeding max length
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_custom_fields_rejects_long_value(
                extra_len in 1usize..=100usize,
            ) {
                let mut fields = HashMap::new();
                let long_value = "a".repeat(1024_usize.saturating_add(extra_len));
                fields.insert("key".to_string(), long_value.clone());
                let result = SandboxApi::validate_custom_fields(&fields);
                prop_assert!(result.is_err(), "Should reject value of length {}", long_value.len());
            }
        }

        // Property: validate_custom_fields should reject too many fields
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 100 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_custom_fields_rejects_too_many(
                extra_count in 1usize..=20usize,
            ) {
                let mut fields = HashMap::new();
                let total = 50_usize.saturating_add(extra_count);
                for i in 0..total {
                    fields.insert(format!("key{}", i), format!("value{}", i));
                }
                let result = SandboxApi::validate_custom_fields(&fields);
                prop_assert!(result.is_err(), "Should reject {} fields", total);
            }
        }

        // Property: validate_custom_fields should reject keys with control characters
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_custom_fields_rejects_control_in_key(
                prefix in "[a-zA-Z]{1,10}",
                control_char in prop::char::range('\x00', '\x1F'),
                suffix in "[a-zA-Z]{1,10}",
            ) {
                let mut fields = HashMap::new();
                let key = format!("{}{}{}", prefix, control_char, suffix);
                fields.insert(key.clone(), "value".to_string());
                let result = SandboxApi::validate_custom_fields(&fields);
                prop_assert!(result.is_err(), "Should reject key with control character: {:?}", control_char);
            }
        }

        // Property: validate_custom_fields should reject dangerous characters in keys
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 500 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_custom_fields_rejects_dangerous_in_key(
                prefix in "[a-zA-Z]{1,10}",
                dangerous in prop::sample::select(vec!['<', '>', '"', '&', '\'', '/', '\\']),
                suffix in "[a-zA-Z]{1,10}",
            ) {
                let mut fields = HashMap::new();
                let key = format!("{}{}{}", prefix, dangerous, suffix);
                fields.insert(key.clone(), "value".to_string());
                let result = SandboxApi::validate_custom_fields(&fields);
                prop_assert!(result.is_err(), "Should reject key with dangerous character: {}", dangerous);
            }
        }

        // Property: validate_team_identifiers should reject empty identifiers
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_team_identifiers_rejects_empty(
                prefix_count in 0usize..=5usize,
                suffix_count in 0usize..=5usize,
            ) {
                let mut team_ids = Vec::new();
                for i in 0..prefix_count {
                    team_ids.push(format!("team{}", i));
                }
                team_ids.push("".to_string());
                for i in 0..suffix_count {
                    team_ids.push(format!("team{}", i.saturating_add(prefix_count)));
                }
                let result = SandboxApi::validate_team_identifiers(&team_ids);
                prop_assert!(result.is_err(), "Should reject empty team identifier");
            }
        }

        // Property: validate_team_identifiers should reject identifiers exceeding max length
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_team_identifiers_rejects_too_long(
                extra_len in 1usize..=50usize,
            ) {
                let long_id = "a".repeat(128_usize.saturating_add(extra_len));
                let result = SandboxApi::validate_team_identifiers(std::slice::from_ref(&long_id));
                prop_assert!(result.is_err(), "Should reject identifier of length {}", long_id.len());
            }
        }

        // Property: validate_team_identifiers should reject too many identifiers
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 100 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_team_identifiers_rejects_too_many(
                extra_count in 1usize..=20usize,
            ) {
                let total = 100_usize.saturating_add(extra_count);
                let team_ids: Vec<String> = (0..total).map(|i| format!("team{}", i)).collect();
                let result = SandboxApi::validate_team_identifiers(&team_ids);
                prop_assert!(result.is_err(), "Should reject {} identifiers", total);
            }
        }

        // Property: validate_team_identifiers should reject control characters
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_team_identifiers_rejects_control(
                prefix in "[a-zA-Z]{1,10}",
                control_char in prop::char::range('\x00', '\x1F'),
                suffix in "[a-zA-Z]{1,10}",
            ) {
                let team_id = format!("{}{}{}", prefix, control_char, suffix);
                let result = SandboxApi::validate_team_identifiers(std::slice::from_ref(&team_id));
                prop_assert!(result.is_err(), "Should reject identifier with control character: {:?}", control_char);
            }
        }

        // Property: validate_team_identifiers should reject dangerous characters
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 500 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_team_identifiers_rejects_dangerous(
                prefix in "[a-zA-Z]{1,10}",
                dangerous in prop::sample::select(vec!['<', '>', '"', '&', '\'', '/', '\\']),
                suffix in "[a-zA-Z]{1,10}",
            ) {
                let team_id = format!("{}{}{}", prefix, dangerous, suffix);
                let result = SandboxApi::validate_team_identifiers(std::slice::from_ref(&team_id));
                prop_assert!(result.is_err(), "Should reject identifier with dangerous character: {}", dangerous);
            }
        }

        // Property: SandboxListParams page size capping
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_sandbox_list_params_caps_page_size(
                excessive_size in (MAX_PAGE_SIZE + 1)..=u64::MAX,
            ) {
                let params = SandboxListParams {
                    size: Some(excessive_size),
                    ..Default::default()
                };
                let query_params: Vec<_> = params.into();

                // Find the size parameter
                let size_param = query_params.iter().find(|(k, _)| k == "size");
                prop_assert!(size_param.is_some(), "Should have size parameter");

                let (_, size_value) = size_param.expect("Size parameter should exist");
                let parsed_size: u64 = size_value.parse().expect("Size value should be parseable");
                prop_assert_eq!(parsed_size, MAX_PAGE_SIZE, "Should cap size to MAX_PAGE_SIZE");
            }
        }

        // Property: SandboxListParams preserves reasonable page sizes
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_sandbox_list_params_preserves_reasonable_size(
                reasonable_size in 1u64..=MAX_PAGE_SIZE,
            ) {
                let params = SandboxListParams {
                    size: Some(reasonable_size),
                    ..Default::default()
                };
                let query_params: Vec<_> = params.into();

                let size_param = query_params.iter().find(|(k, _)| k == "size");
                prop_assert!(size_param.is_some(), "Should have size parameter");

                let (_, size_value) = size_param.expect("Size parameter should exist");
                let parsed_size: u64 = size_value.parse().expect("Size value should be parseable");
                prop_assert_eq!(parsed_size, reasonable_size, "Should preserve reasonable size");
            }
        }

        // Property: validate_create_request should accept valid requests
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 500 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_create_request_accepts_valid(
                name in "[a-zA-Z0-9_-]{1,256}",
            ) {
                prop_assume!(!name.contains(".."));
                prop_assume!(!name.contains('/'));
                prop_assume!(!name.contains('\\'));

                let request = CreateSandboxRequest {
                    name,
                    description: None,
                    auto_recreate: None,
                    custom_fields: None,
                    team_identifiers: None,
                };
                let result = SandboxApi::validate_create_request(&request);
                prop_assert!(result.is_ok(), "Should accept valid create request");
            }
        }

        // Property: validate_update_request should accept valid requests
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 500 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            #[test]
            fn prop_validate_update_request_accepts_valid(
                name in "[a-zA-Z0-9_-]{1,256}",
            ) {
                prop_assume!(!name.contains(".."));
                prop_assume!(!name.contains('/'));
                prop_assume!(!name.contains('\\'));

                let request = UpdateSandboxRequest {
                    name: Some(name),
                    description: None,
                    auto_recreate: None,
                    custom_fields: None,
                    team_identifiers: None,
                };
                let result = SandboxApi::validate_update_request(&request);
                prop_assert!(result.is_ok(), "Should accept valid update request");
            }
        }
    }
}

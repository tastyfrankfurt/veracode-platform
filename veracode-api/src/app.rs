//! Application-specific functionality built on top of the core client.
//!
//! This module contains application-specific methods and convenience functions
//! that use the core `VeracodeClient` to perform application-related operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::VeracodeError;
use crate::client::VeracodeClient;
use crate::validation::{
    AppGuid, AppName, Description, ValidationError, build_query_param, validate_page_number,
    validate_page_size,
};

/// Represents a Veracode application.
///
/// This struct contains all the information about a Veracode application,
/// including its profile, scans, and metadata.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Application {
    /// Globally unique identifier (GUID) for the application
    pub guid: String,
    /// Unique numeric identifier for id the application
    pub id: u64,
    /// Organization ID
    pub oid: Option<u64>,
    /// Organization ID
    pub alt_org_id: Option<u64>,
    /// Unique numeric identifier for `organization_id` the application
    pub organization_id: Option<u64>,
    /// ISO 8601 timestamp of the last completed scan
    pub created: String,
    /// ISO 8601 timestamp when the application was last modified
    pub modified: Option<String>,
    /// ISO 8601 timestamp of the last completed scan
    pub last_completed_scan_date: Option<String>,
    /// ISO 8601 timestamp of the last policy compliance check
    pub last_policy_compliance_check_date: Option<String>,
    /// URL to the application profile in the Veracode platform
    pub app_profile_url: Option<String>,
    /// Detailed application profile information
    pub profile: Option<Profile>,
    /// List of scans associated with this application
    pub scans: Option<Vec<Scan>>,
    /// URL to the application profile in the Veracode platform
    pub results_url: Option<String>,
}

/// Application profile information.
///
/// # Security
///
/// Uses validated types for `name` and `description` to prevent injection attacks
/// and ensure data meets business requirements.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Profile {
    /// Profile name (validated)
    pub name: AppName,
    /// Profile description (validated)
    pub description: Option<Description>,
    /// Profile tags
    pub tags: Option<String>,
    /// Business unit associated with the application
    pub business_unit: Option<BusinessUnit>,
    /// List of business owners
    pub business_owners: Option<Vec<BusinessOwner>>,
    /// List of policies applied to the application
    pub policies: Option<Vec<Policy>>,
    /// List of teams associated with the application
    pub teams: Option<Vec<Team>>,
    /// Archer application name
    pub archer_app_name: Option<String>,
    /// Custom fields
    pub custom_fields: Option<Vec<CustomField>>,
    /// Business criticality level (required)
    #[serde(serialize_with = "serialize_business_criticality")]
    pub business_criticality: BusinessCriticality,
    /// Application Profile Settings
    pub settings: Option<Settings>,
    /// Customer Managed Encryption Key (CMEK) alias for encrypting application data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_kms_alias: Option<String>,
    /// Repository URL for the application (e.g., Git repository URL)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    /// Profile name
    pub nextday_consultation_allowed: bool,
    /// Profile description
    pub static_scan_xpa_or_dpa: bool,
    /// Profile tags
    pub dynamic_scan_approval_not_required: bool,
    /// Business unit associated with the application
    pub sca_enabled: bool,
    /// List of business owners
    pub static_scan_xpp_enabled: bool,
}

/// Business unit information.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BusinessUnit {
    /// Business unit ID
    pub id: Option<u64>,
    /// Business unit name
    pub name: Option<String>,
    /// Business unit GUID
    pub guid: Option<String>,
}

/// Business owner information.
///
/// # Security
///
/// This struct contains PII (email, name). The `Debug` implementation
/// redacts sensitive fields to prevent accidental logging of personal information.
#[derive(Serialize, Deserialize, Clone)]
pub struct BusinessOwner {
    /// Owner's email address
    pub email: Option<String>,
    /// Owner's name
    pub name: Option<String>,
}

impl fmt::Debug for BusinessOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BusinessOwner")
            .field("email", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .finish()
    }
}

/// Policy information.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    /// Policy GUID
    pub guid: String,
    /// Policy name
    pub name: String,
    /// Whether this is the default policy
    pub is_default: bool,
    /// Policy compliance status
    pub policy_compliance_status: Option<String>,
}

/// Team information.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Team {
    /// Team GUID (primary identifier)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
    /// Team ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<u64>,
    /// Team name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_name: Option<String>,
    /// Legacy team ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_legacy_id: Option<u64>,
}

/// Custom field information.
///
/// # Security
///
/// This struct may contain sensitive data in the `value` field.
/// The `Debug` implementation redacts the value to prevent accidental
/// logging of potentially sensitive information.
#[derive(Serialize, Deserialize, Clone)]
pub struct CustomField {
    /// Field name
    pub name: Option<String>,
    /// Field value
    pub value: Option<String>,
}

impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Scan information.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Scan {
    /// Scan ID
    pub scan_id: Option<u64>,
    /// Type of scan (STATIC, DYNAMIC, etc.)
    pub scan_type: Option<String>,
    /// Scan status
    pub status: Option<String>,
    /// URL to the scan results
    pub scan_url: Option<String>,
    /// When the scan was last modified
    pub modified_date: Option<String>,
    /// Internal scan status
    pub internal_status: Option<String>,
    /// Related links
    pub links: Option<Vec<Link>>,
    /// Fallback scan type
    pub fallback_type: Option<String>,
    /// Full scan type
    pub full_type: Option<String>,
}

/// Link information.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Link {
    /// Link relationship
    pub rel: Option<String>,
    /// Link URL
    pub href: Option<String>,
}

/// Response from the Applications API.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApplicationsResponse {
    /// Embedded applications data
    #[serde(rename = "_embedded")]
    pub embedded: Option<EmbeddedApplications>,
    /// Pagination information
    pub page: Option<PageInfo>,
    /// Response links
    #[serde(rename = "_links")]
    pub links: Option<HashMap<String, Link>>,
}

/// Embedded applications in the response.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EmbeddedApplications {
    /// List of applications
    pub applications: Vec<Application>,
}

/// Pagination information.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PageInfo {
    /// Number of items per page
    pub size: Option<u32>,
    /// Current page number
    pub number: Option<u32>,
    /// Total number of elements
    pub total_elements: Option<u64>,
    /// Total number of pages
    pub total_pages: Option<u32>,
}

/// Request for creating a new application.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateApplicationRequest {
    /// Application profile information
    pub profile: CreateApplicationProfile,
}

/// Profile information for creating an application.
///
/// # Security
///
/// Uses validated types for `name` and `description` to ensure data meets
/// business requirements and prevent injection attacks.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateApplicationProfile {
    /// Application name (validated)
    pub name: AppName,
    /// Business criticality level (required)
    #[serde(serialize_with = "serialize_business_criticality")]
    pub business_criticality: BusinessCriticality,
    /// Application description (validated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Business unit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_unit: Option<BusinessUnit>,
    /// Business owners
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_owners: Option<Vec<BusinessOwner>>,
    /// Policies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<Policy>>,
    /// Teams
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<Vec<Team>>,
    /// Tags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    /// Custom fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    /// Customer Managed Encryption Key (CMEK) alias for encrypting application data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_kms_alias: Option<String>,
    /// Repository URL for the application (e.g., Git repository URL)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_url: Option<String>,
}

/// Business criticality levels for applications
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessCriticality {
    VeryHigh,
    High,
    Medium,
    Low,
    VeryLow,
}

impl BusinessCriticality {
    /// Convert to the string value expected by the API
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            BusinessCriticality::VeryHigh => "VERY_HIGH",
            BusinessCriticality::High => "HIGH",
            BusinessCriticality::Medium => "MEDIUM",
            BusinessCriticality::Low => "LOW",
            BusinessCriticality::VeryLow => "VERY_LOW",
        }
    }
}

impl From<BusinessCriticality> for String {
    fn from(criticality: BusinessCriticality) -> Self {
        criticality.as_str().to_string()
    }
}

impl std::fmt::Display for BusinessCriticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Custom serializer for `BusinessCriticality`
fn serialize_business_criticality<S>(
    criticality: &BusinessCriticality,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(criticality.as_str())
}

/// Parse `BusinessCriticality` from string
impl std::str::FromStr for BusinessCriticality {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "VERY_HIGH" => Ok(BusinessCriticality::VeryHigh),
            "HIGH" => Ok(BusinessCriticality::High),
            "MEDIUM" => Ok(BusinessCriticality::Medium),
            "LOW" => Ok(BusinessCriticality::Low),
            "VERY_LOW" => Ok(BusinessCriticality::VeryLow),
            _ => Err(format!(
                "Invalid business criticality: '{s}'. Must be one of: VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW"
            )),
        }
    }
}

/// Deserialize `BusinessCriticality` from string
impl<'de> serde::Deserialize<'de> for BusinessCriticality {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Request for updating an application.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateApplicationRequest {
    /// Application profile information
    pub profile: UpdateApplicationProfile,
}

/// Profile information for updating an application.
///
/// # Security
///
/// Uses validated types for `name` and `description` to ensure data meets
/// business requirements and prevent injection attacks.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateApplicationProfile {
    /// Application name (validated)
    pub name: Option<AppName>,
    /// Application description (validated)
    pub description: Option<Description>,
    /// Business unit
    pub business_unit: Option<BusinessUnit>,
    /// Business owners
    pub business_owners: Option<Vec<BusinessOwner>>,
    /// Business criticality level (required)
    #[serde(serialize_with = "serialize_business_criticality")]
    pub business_criticality: BusinessCriticality,
    /// Policies
    pub policies: Option<Vec<Policy>>,
    /// Teams
    pub teams: Option<Vec<Team>>,
    /// Tags
    pub tags: Option<String>,
    /// Custom fields
    pub custom_fields: Option<Vec<CustomField>>,
    /// Customer Managed Encryption Key (CMEK) alias for encrypting application data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_kms_alias: Option<String>,
    /// Repository URL for the application (e.g., Git repository URL)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_url: Option<String>,
}

/// Query parameters for filtering applications.
#[derive(Debug, Clone, Default)]
pub struct ApplicationQuery {
    /// Filter by application name (partial match)
    pub name: Option<String>,
    /// Filter by policy compliance status (PASSED, `DID_NOT_PASS`, etc.)
    pub policy_compliance: Option<String>,
    /// Filter applications modified after this date (ISO 8601 format)
    pub modified_after: Option<String>,
    /// Filter applications modified before this date (ISO 8601 format)
    pub modified_before: Option<String>,
    /// Filter applications created after this date (ISO 8601 format)
    pub created_after: Option<String>,
    /// Filter applications created before this date (ISO 8601 format)
    pub created_before: Option<String>,
    /// Filter by scan type (STATIC, DYNAMIC, MANUAL, SCA)
    pub scan_type: Option<String>,
    /// Filter by tags (comma-separated)
    pub tags: Option<String>,
    /// Filter by business unit name
    pub business_unit: Option<String>,
    /// Page number for pagination (0-based)
    pub page: Option<u32>,
    /// Number of items per page (default: 20, max: 500)
    pub size: Option<u32>,
}

impl ApplicationQuery {
    /// Create a new empty query.
    #[must_use = "builder methods consume self and return modified Self"]
    pub fn new() -> Self {
        ApplicationQuery::default()
    }

    /// Filter applications by name (partial match).
    #[must_use = "builder methods consume self and return modified Self"]
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Filter applications by policy compliance status.
    #[must_use = "builder methods consume self and return modified Self"]
    pub fn with_policy_compliance(mut self, compliance: &str) -> Self {
        self.policy_compliance = Some(compliance.to_string());
        self
    }

    /// Filter applications modified after the specified date.
    #[must_use = "builder methods consume self and return modified Self"]
    pub fn with_modified_after(mut self, date: &str) -> Self {
        self.modified_after = Some(date.to_string());
        self
    }

    /// Filter applications modified before the specified date.
    #[must_use = "builder methods consume self and return modified Self"]
    pub fn with_modified_before(mut self, date: &str) -> Self {
        self.modified_before = Some(date.to_string());
        self
    }

    /// Set the page number for pagination.
    #[must_use]
    pub fn with_page(mut self, page: u32) -> Self {
        self.page = Some(page);
        self
    }

    /// Set the number of items per page.
    #[must_use]
    pub fn with_size(mut self, size: u32) -> Self {
        self.size = Some(size);
        self
    }

    /// Normalize and validate pagination parameters.
    ///
    /// This method ensures that pagination parameters are within safe bounds
    /// to prevent resource exhaustion attacks. It uses the library-wide
    /// validation functions from the `validation` module.
    ///
    /// # Behavior
    ///
    /// - Sets default page size if not specified
    /// - Rejects page size of 0
    /// - Caps page size at maximum with warning
    /// - Caps page number at maximum with warning
    ///
    /// # Returns
    ///
    /// A `Result` containing the normalized query or a `ValidationError`.
    ///
    /// # Errors
    ///
    /// Returns an error if the page size is 0.
    ///
    /// # Security
    ///
    /// This method prevents `DoS` attacks from unbounded pagination requests.
    pub fn normalize(mut self) -> Result<Self, ValidationError> {
        // Validate and normalize using library-wide validation functions
        self.size = Some(validate_page_size(self.size)?);
        self.page = validate_page_number(self.page)?;

        Ok(self)
    }

    /// Convert the query to URL query parameters.
    #[must_use]
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        Vec::from(self)
    }
}

/// Convert `ApplicationQuery` to query parameters by borrowing (allows reuse)
///
/// # Security
///
/// All query parameter values are properly URL-encoded to prevent injection attacks.
impl From<&ApplicationQuery> for Vec<(String, String)> {
    fn from(query: &ApplicationQuery) -> Self {
        let mut params = Vec::new();

        if let Some(ref name) = query.name {
            params.push(build_query_param("name", name));
        }
        if let Some(ref compliance) = query.policy_compliance {
            params.push(build_query_param("policy_compliance", compliance));
        }
        if let Some(ref date) = query.modified_after {
            params.push(build_query_param("modified_after", date));
        }
        if let Some(ref date) = query.modified_before {
            params.push(build_query_param("modified_before", date));
        }
        if let Some(ref date) = query.created_after {
            params.push(build_query_param("created_after", date));
        }
        if let Some(ref date) = query.created_before {
            params.push(build_query_param("created_before", date));
        }
        if let Some(ref scan_type) = query.scan_type {
            params.push(build_query_param("scan_type", scan_type));
        }
        if let Some(ref tags) = query.tags {
            params.push(build_query_param("tags", tags));
        }
        if let Some(ref business_unit) = query.business_unit {
            params.push(build_query_param("business_unit", business_unit));
        }
        if let Some(page) = query.page {
            params.push(("page".to_string(), page.to_string()));
        }
        if let Some(size) = query.size {
            params.push(("size".to_string(), size.to_string()));
        }

        params
    }
}

/// Convert `ApplicationQuery` to query parameters by consuming (better performance)
///
/// # Security
///
/// All query parameter values are properly URL-encoded to prevent injection attacks.
impl From<ApplicationQuery> for Vec<(String, String)> {
    fn from(query: ApplicationQuery) -> Self {
        let mut params = Vec::new();

        if let Some(name) = query.name {
            params.push(build_query_param("name", &name));
        }
        if let Some(compliance) = query.policy_compliance {
            params.push(build_query_param("policy_compliance", &compliance));
        }
        if let Some(date) = query.modified_after {
            params.push(build_query_param("modified_after", &date));
        }
        if let Some(date) = query.modified_before {
            params.push(build_query_param("modified_before", &date));
        }
        if let Some(date) = query.created_after {
            params.push(build_query_param("created_after", &date));
        }
        if let Some(date) = query.created_before {
            params.push(build_query_param("created_before", &date));
        }
        if let Some(scan_type) = query.scan_type {
            params.push(build_query_param("scan_type", &scan_type));
        }
        if let Some(tags) = query.tags {
            params.push(build_query_param("tags", &tags));
        }
        if let Some(business_unit) = query.business_unit {
            params.push(build_query_param("business_unit", &business_unit));
        }
        if let Some(page) = query.page {
            params.push(("page".to_string(), page.to_string()));
        }
        if let Some(size) = query.size {
            params.push(("size".to_string(), size.to_string()));
        }

        params
    }
}

/// Application-specific methods that build on the core client.
impl VeracodeClient {
    /// Get all applications with optional filtering.
    ///
    /// # Arguments
    ///
    /// * `query` - Optional query parameters to filter the results
    ///
    /// # Returns
    ///
    /// A `Result` containing an `ApplicationsResponse` with the list of applications.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the response cannot be parsed,
    /// or validation of pagination parameters fails.
    ///
    /// # Security
    ///
    /// Pagination parameters are automatically validated and normalized to prevent
    /// resource exhaustion attacks.
    pub async fn get_applications(
        &self,
        query: Option<ApplicationQuery>,
    ) -> Result<ApplicationsResponse, VeracodeError> {
        let endpoint = "/appsec/v1/applications";

        // Normalize query parameters to enforce pagination bounds
        let normalized_query = if let Some(q) = query {
            Some(q.normalize()?)
        } else {
            None
        };

        let query_params = normalized_query.as_ref().map(Vec::from);

        let response = self.get(endpoint, query_params.as_deref()).await?;
        let response = Self::handle_response(response, "list applications").await?;

        let apps_response: ApplicationsResponse = response.json().await?;
        Ok(apps_response)
    }

    /// Get a specific application by its GUID.
    ///
    /// # Arguments
    ///
    /// * `guid` - The GUID of the application to retrieve
    ///
    /// # Returns
    ///
    /// A `Result` containing the `Application` details.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the response cannot be parsed,
    /// or the application is not found.
    ///
    /// # Security
    ///
    /// This method validates the GUID format to prevent URL path injection attacks.
    pub async fn get_application(&self, guid: &AppGuid) -> Result<Application, VeracodeError> {
        // AppGuid is already validated, safe to use in URL
        let endpoint = format!("/appsec/v1/applications/{}", guid.as_url_safe());

        let response = self.get(&endpoint, None).await?;
        let response = Self::handle_response(response, "get application details").await?;

        let app: Application = response.json().await?;
        Ok(app)
    }

    /// Create a new application.
    ///
    /// # Arguments
    ///
    /// * `request` - The application creation request containing profile information
    ///
    /// # Returns
    ///
    /// A `Result` containing the created `Application`.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the request cannot be serialized,
    /// or the response cannot be parsed.
    pub async fn create_application(
        &self,
        request: &CreateApplicationRequest,
    ) -> Result<Application, VeracodeError> {
        let endpoint = "/appsec/v1/applications";

        // Debug: Log the exact JSON being sent to the API
        if let Ok(json_payload) = serde_json::to_string_pretty(&request) {
            log::debug!(
                "🔍 Creating application with JSON payload: {}",
                json_payload
            );
        }

        let response = self.post(endpoint, Some(&request)).await?;
        let response = Self::handle_response(response, "create application").await?;

        let app: Application = response.json().await?;
        Ok(app)
    }

    /// Update an existing application.
    ///
    /// # Arguments
    ///
    /// * `guid` - The GUID of the application to update
    /// * `request` - The update request containing the new profile information
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated `Application`.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the request cannot be serialized,
    /// or the response cannot be parsed.
    ///
    /// # Security
    ///
    /// This method validates the GUID format to prevent URL path injection attacks.
    pub async fn update_application(
        &self,
        guid: &AppGuid,
        request: &UpdateApplicationRequest,
    ) -> Result<Application, VeracodeError> {
        // AppGuid is already validated, safe to use in URL
        let endpoint = format!("/appsec/v1/applications/{}", guid.as_url_safe());

        let response = self.put(&endpoint, Some(&request)).await?;
        let response = Self::handle_response(response, "update application").await?;

        let app: Application = response.json().await?;
        Ok(app)
    }

    /// Delete an application.
    ///
    /// # Arguments
    ///
    /// * `guid` - The GUID of the application to delete
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the application is not found.
    ///
    /// # Security
    ///
    /// This method validates the GUID format to prevent URL path injection attacks.
    pub async fn delete_application(&self, guid: &AppGuid) -> Result<(), VeracodeError> {
        // AppGuid is already validated, safe to use in URL
        let endpoint = format!("/appsec/v1/applications/{}", guid.as_url_safe());

        let response = self.delete(&endpoint).await?;
        let _response = Self::handle_response(response, "delete application").await?;

        Ok(())
    }

    /// Get applications that failed policy compliance.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec<Application>` of non-compliant applications.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response cannot be parsed.
    pub async fn get_non_compliant_applications(&self) -> Result<Vec<Application>, VeracodeError> {
        let query = ApplicationQuery::new().with_policy_compliance("DID_NOT_PASS");

        let response = self.get_applications(Some(query)).await?;

        if let Some(embedded) = response.embedded {
            Ok(embedded.applications)
        } else {
            Ok(Vec::new())
        }
    }

    /// Get applications modified after a specific date.
    ///
    /// # Arguments
    ///
    /// * `date` - ISO 8601 formatted date string
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec<Application>` of applications modified after the date.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response cannot be parsed.
    pub async fn get_applications_modified_after(
        &self,
        date: &str,
    ) -> Result<Vec<Application>, VeracodeError> {
        let query = ApplicationQuery::new().with_modified_after(date);

        let response = self.get_applications(Some(query)).await?;

        if let Some(embedded) = response.embedded {
            Ok(embedded.applications)
        } else {
            Ok(Vec::new())
        }
    }

    /// Search applications by name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to search for (partial matches are supported)
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec<Application>` of applications matching the name.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response cannot be parsed.
    pub async fn search_applications_by_name(
        &self,
        name: &str,
    ) -> Result<Vec<Application>, VeracodeError> {
        let query = ApplicationQuery::new().with_name(name);

        let response = self.get_applications(Some(query)).await?;

        if let Some(embedded) = response.embedded {
            Ok(embedded.applications)
        } else {
            Ok(Vec::new())
        }
    }

    /// Get all applications with automatic pagination.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec<Application>` of all applications.
    ///
    /// # Errors
    ///
    /// Returns an error if any API request fails or responses cannot be parsed.
    pub async fn get_all_applications(&self) -> Result<Vec<Application>, VeracodeError> {
        let mut all_applications = Vec::new();
        let mut page = 0;

        loop {
            let query = ApplicationQuery::new().with_page(page).with_size(100);

            let response = self.get_applications(Some(query)).await?;

            if let Some(embedded) = response.embedded {
                if embedded.applications.is_empty() {
                    break;
                }
                all_applications.extend(embedded.applications);
                page = page.saturating_add(1);
            } else {
                break;
            }
        }

        Ok(all_applications)
    }

    /// Get application by name (exact match).
    ///
    /// # Arguments
    ///
    /// * `name` - The exact name of the application to find
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Option<Application>` if found.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response cannot be parsed.
    pub async fn get_application_by_name(
        &self,
        name: &str,
    ) -> Result<Option<Application>, VeracodeError> {
        let applications = self.search_applications_by_name(name).await?;

        // Find exact match (search_applications_by_name does partial matching)
        Ok(applications.into_iter().find(|app| {
            if let Some(profile) = &app.profile {
                profile.name.as_str() == name
            } else {
                false
            }
        }))
    }

    /// Check if application exists by name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the application to check
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean indicating if the application exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails or the response cannot be parsed.
    pub async fn application_exists_by_name(&self, name: &str) -> Result<bool, VeracodeError> {
        match self.get_application_by_name(name).await? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// Get numeric `app_id` from application GUID.
    ///
    /// This is needed for XML API operations that require numeric IDs.
    ///
    /// # Arguments
    ///
    /// * `guid` - The application GUID
    ///
    /// # Returns
    ///
    /// A `Result` containing the numeric `app_id` as a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the application is not found,
    /// or the response cannot be parsed.
    pub async fn get_app_id_from_guid(&self, guid: &AppGuid) -> Result<String, VeracodeError> {
        let app = self.get_application(guid).await?;
        Ok(app.id.to_string())
    }

    /// Create application if it doesn't exist, or return existing application.
    ///
    /// This method implements the "check and create" pattern commonly needed
    /// for automated workflows. It intelligently updates missing fields on existing
    /// applications without overriding any existing values.
    ///
    /// # Behavior
    ///
    /// - **If application doesn't exist**: Creates it with all provided parameters
    /// - **If application exists**:
    ///   - Updates `repo_url` if current value is None/empty and parameter is provided
    ///   - Updates `description` if current value is None/empty and parameter is provided
    ///   - Never modifies `business_criticality` or `teams` on existing applications
    ///   - All other existing profile settings are preserved
    ///
    /// This "fill in blanks" strategy ensures safe automation without overriding
    /// intentional configuration changes made through other workflows.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the application
    /// * `business_criticality` - Business criticality level (required for creation, ignored for existing apps)
    /// * `description` - Optional description (sets on creation, updates if missing on existing apps)
    /// * `team_names` - Optional list of team names (sets on creation, ignored for existing apps)
    /// * `repo_url` - Optional repository URL (sets on creation, updates if missing on existing apps)
    /// * `custom_kms_alias` - Optional KMS alias for encryption
    ///
    /// # Returns
    ///
    /// A `Result` containing the application (existing, updated, or newly created).
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, validation fails, team lookup fails,
    /// or the response cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use veracode_platform::{VeracodeClient, VeracodeConfig, app::BusinessCriticality};
    /// # use std::sync::Arc;
    /// # use secrecy::SecretString;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = VeracodeConfig::from_arc_credentials(
    /// #     Arc::new(SecretString::from("api_id")),
    /// #     Arc::new(SecretString::from("api_key"))
    /// # );
    /// # let client = VeracodeClient::new(config)?;
    /// // First call: Creates application with repo_url
    /// let app = client.create_application_if_not_exists(
    ///     "My Application",
    ///     BusinessCriticality::High,
    ///     Some("My app description".to_string()),
    ///     None,
    ///     Some("https://github.com/user/repo".to_string()),
    ///     None,
    /// ).await?;
    ///
    /// // Second call: Returns existing app, no updates (all fields populated)
    /// let same_app = client.create_application_if_not_exists(
    ///     "My Application",
    ///     BusinessCriticality::Medium, // Ignored - won't change existing HIGH
    ///     Some("Different description".to_string()), // Ignored - existing has value
    ///     None,
    ///     Some("https://github.com/user/repo".to_string()), // Ignored - existing has value
    ///     None,
    /// ).await?;
    ///
    /// // Application created without repo_url, then updated later
    /// let app_v1 = client.create_application_if_not_exists(
    ///     "Another App",
    ///     BusinessCriticality::Medium,
    ///     None,
    ///     None,
    ///     None, // No repo_url initially
    ///     None,
    /// ).await?;
    ///
    /// // Later: Adds repo_url to existing application (because it was missing)
    /// let app_v2 = client.create_application_if_not_exists(
    ///     "Another App",
    ///     BusinessCriticality::High, // Ignored - won't change
    ///     Some("Adding description".to_string()), // Updates (was None)
    ///     None,
    ///     Some("https://github.com/user/another".to_string()), // Updates (was None)
    ///     None,
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_application_if_not_exists(
        &self,
        name: &str,
        business_criticality: BusinessCriticality,
        description: Option<String>,
        team_names: Option<Vec<String>>,
        repo_url: Option<String>,
        custom_kms_alias: Option<String>,
    ) -> Result<Application, VeracodeError> {
        // First, check if application already exists
        if let Some(existing_app) = self.get_application_by_name(name).await? {
            // Check if we need to update any missing fields
            let mut needs_update = false;
            let mut update_repo_url = false;
            let mut update_description = false;
            // CMEK update logic commented out - API limitation prevents reading CMEK status
            // Uncomment when API supports returning custom_kms_alias in profile responses
            // let mut update_custom_kms_alias = false;

            if let Some(ref profile) = existing_app.profile {
                // Check repo_url: update if we have one AND existing is None/empty
                if repo_url.is_some()
                    && (profile.repo_url.is_none()
                        || profile
                            .repo_url
                            .as_ref()
                            .is_some_and(|u| u.trim().is_empty()))
                {
                    update_repo_url = true;
                    needs_update = true;
                }

                // Check description: update if we have one AND existing is None/empty
                if description.is_some()
                    && (profile.description.is_none()
                        || profile
                            .description
                            .as_ref()
                            .is_some_and(|d| d.as_str().trim().is_empty()))
                {
                    update_description = true;
                    needs_update = true;
                }

                // CMEK update logic commented out - API limitation prevents reading CMEK status
                // The Veracode API does not return custom_kms_alias in profile responses,
                // so we cannot determine if CMEK is already configured or needs updating.
                // To restore: uncomment this block and the related sections below
                // // Check custom_kms_alias: update if we have one AND existing is None/empty
                // if custom_kms_alias.is_some()
                //     && (profile.custom_kms_alias.is_none()
                //         || profile
                //             .custom_kms_alias
                //             .as_ref()
                //             .is_some_and(|k| k.trim().is_empty()))
                // {
                //     update_custom_kms_alias = true;
                //     needs_update = true;
                // }
            }

            if needs_update {
                log::debug!("🔄 Updating fields for existing application '{}'", name);
                if update_repo_url {
                    log::debug!(
                        "   Setting repo_url: {}",
                        repo_url.as_deref().unwrap_or("None")
                    );
                }
                if update_description {
                    log::debug!(
                        "   Setting description: {}",
                        description.as_deref().unwrap_or("None")
                    );
                }
                // CMEK logging commented out - restore when API supports CMEK status retrieval
                // if update_custom_kms_alias {
                //     log::debug!(
                //         "   Setting custom_kms_alias: {}",
                //         custom_kms_alias.as_deref().unwrap_or("None")
                //     );
                // }

                // Build update request preserving all existing values
                let profile = existing_app.profile.as_ref().ok_or_else(|| {
                    VeracodeError::InvalidResponse(format!("Application '{}' has no profile", name))
                })?;
                let update_request = UpdateApplicationRequest {
                    profile: UpdateApplicationProfile {
                        name: Some(profile.name.clone()),
                        description: if update_description {
                            description.map(Description::new).transpose()?
                        } else {
                            profile.description.clone()
                        },
                        business_unit: profile.business_unit.clone(),
                        business_owners: profile.business_owners.clone(),
                        business_criticality: profile.business_criticality, // Keep existing
                        policies: profile.policies.clone(),
                        teams: profile.teams.clone(), // Keep existing
                        tags: profile.tags.clone(),
                        custom_fields: profile.custom_fields.clone(),
                        // CMEK update commented out - API limitation prevents reliable updates
                        // To restore: uncomment this block and the related sections above
                        // custom_kms_alias: if update_custom_kms_alias {
                        //     custom_kms_alias
                        // } else {
                        //     profile.custom_kms_alias.clone()
                        // },
                        custom_kms_alias: profile.custom_kms_alias.clone(), // Always preserve existing (or None)
                        repo_url: if update_repo_url {
                            repo_url
                        } else {
                            profile.repo_url.clone()
                        },
                    },
                };

                let guid = AppGuid::new(&existing_app.guid)?;
                return self.update_application(&guid, &update_request).await;
            }

            return Ok(existing_app);
        }

        // Application doesn't exist, create it

        // Convert team names to Team objects with GUIDs if provided
        let teams = if let Some(names) = team_names {
            let identity_api = self.identity_api();
            let mut resolved_teams = Vec::new();

            for team_name in names {
                match identity_api.get_team_guid_by_name(&team_name).await {
                    Ok(Some(team_guid)) => {
                        resolved_teams.push(Team {
                            guid: Some(team_guid),
                            team_id: None,
                            team_name: None, // Not needed when using GUID
                            team_legacy_id: None,
                        });
                    }
                    Ok(None) => {
                        return Err(VeracodeError::NotFound(format!(
                            "Team '{}' not found",
                            team_name
                        )));
                    }
                    Err(identity_err) => {
                        return Err(VeracodeError::InvalidResponse(format!(
                            "Failed to lookup team '{}': {}",
                            team_name, identity_err
                        )));
                    }
                }
            }

            Some(resolved_teams)
        } else {
            None
        };

        let create_request = CreateApplicationRequest {
            profile: CreateApplicationProfile {
                name: AppName::new(name)?,
                business_criticality,
                description: description.map(Description::new).transpose()?,
                business_unit: None,
                business_owners: None,
                policies: None,
                teams,
                tags: None,
                custom_fields: None,
                custom_kms_alias,
                repo_url,
            },
        };

        self.create_application(&create_request).await
    }

    /// Create application if it doesn't exist, or return existing application (with team GUIDs).
    ///
    /// This method allows specifying teams by their GUID, which is the preferred
    /// approach for programmatic application creation.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the application
    /// * `business_criticality` - Business criticality level (required for creation)
    /// * `description` - Optional description for new applications
    /// * `team_guids` - Optional list of team GUIDs to assign to the application
    ///
    /// # Returns
    ///
    /// A `Result` containing the application (existing or newly created).
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, validation fails,
    /// or the response cannot be parsed.
    pub async fn create_application_if_not_exists_with_team_guids(
        &self,
        name: &str,
        business_criticality: BusinessCriticality,
        description: Option<String>,
        team_guids: Option<Vec<String>>,
    ) -> Result<Application, VeracodeError> {
        // First, check if application already exists
        if let Some(existing_app) = self.get_application_by_name(name).await? {
            return Ok(existing_app);
        }

        // Application doesn't exist, create it

        // Convert team GUIDs to Team objects if provided
        let teams = team_guids.map(|guids| {
            guids
                .into_iter()
                .map(|team_guid| Team {
                    guid: Some(team_guid),
                    team_id: None,        // Will be assigned by Veracode
                    team_name: None,      // Not needed when using GUID
                    team_legacy_id: None, // Will be assigned by Veracode
                })
                .collect()
        });

        let create_request = CreateApplicationRequest {
            profile: CreateApplicationProfile {
                name: AppName::new(name)?,
                business_criticality,
                description: description.map(Description::new).transpose()?,
                business_unit: None,
                business_owners: None,
                policies: None,
                teams,
                tags: None,
                custom_fields: None,
                custom_kms_alias: None,
                repo_url: None,
            },
        };

        self.create_application(&create_request).await
    }

    /// Create application if it doesn't exist, or return existing application (without teams).
    ///
    /// This is a convenience method that maintains backward compatibility
    /// for callers that don't need to specify teams.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the application
    /// * `business_criticality` - Business criticality level (required for creation)
    /// * `description` - Optional description for new applications
    ///
    /// # Returns
    ///
    /// A `Result` containing the application (existing or newly created).
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, validation fails,
    /// or the response cannot be parsed.
    pub async fn create_application_if_not_exists_simple(
        &self,
        name: &str,
        business_criticality: BusinessCriticality,
        description: Option<String>,
    ) -> Result<Application, VeracodeError> {
        self.create_application_if_not_exists(
            name,
            business_criticality,
            description,
            None,
            None,
            None,
        )
        .await
    }

    /// Enable Customer Managed Encryption Key (CMEK) on an application
    ///
    /// This method updates an existing application to use a customer-managed encryption key.
    /// The KMS alias must be properly formatted and the key must be accessible to Veracode.
    ///
    /// # Arguments
    ///
    /// * `app_guid` - The GUID of the application to enable encryption on
    /// * `kms_alias` - The AWS KMS alias to use for encryption (must start with "alias/")
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated application or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the KMS alias format is invalid, the API request fails,
    /// the application is not found, or the response cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use veracode_platform::{VeracodeClient, VeracodeConfig, AppGuid};
    /// # use std::sync::Arc;
    /// # use secrecy::SecretString;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = VeracodeConfig::from_arc_credentials(
    ///     Arc::new(SecretString::from("api_id")),
    ///     Arc::new(SecretString::from("api_key"))
    /// );
    /// let client = VeracodeClient::new(config)?;
    /// let guid = AppGuid::new("550e8400-e29b-41d4-a716-446655440000")?;
    ///
    /// let app = client.enable_application_encryption(
    ///     &guid,
    ///     "alias/my-encryption-key"
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn enable_application_encryption(
        &self,
        app_guid: &AppGuid,
        kms_alias: &str,
    ) -> Result<Application, VeracodeError> {
        // Validate KMS alias format
        validate_kms_alias(kms_alias).map_err(VeracodeError::InvalidConfig)?;

        // Get current application to preserve existing settings
        let current_app = self.get_application(app_guid).await?;

        let profile = current_app
            .profile
            .ok_or_else(|| VeracodeError::NotFound("Application profile not found".to_string()))?;

        // Create update request with CMEK enabled
        let update_request = UpdateApplicationRequest {
            profile: UpdateApplicationProfile {
                name: Some(profile.name),
                description: profile.description,
                business_unit: profile.business_unit,
                business_owners: profile.business_owners,
                business_criticality: profile.business_criticality,
                policies: profile.policies,
                teams: profile.teams,
                tags: profile.tags,
                custom_fields: profile.custom_fields,
                custom_kms_alias: Some(kms_alias.to_string()),
                repo_url: profile.repo_url,
            },
        };

        self.update_application(app_guid, &update_request).await
    }

    /// Change the encryption key for an application with CMEK enabled
    ///
    /// This method updates the KMS alias used for encrypting an application's data.
    /// The application must already have CMEK enabled.
    ///
    /// # Arguments
    ///
    /// * `app_guid` - The GUID of the application to update
    /// * `new_kms_alias` - The new AWS KMS alias to use for encryption
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated application or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the KMS alias format is invalid, the API request fails,
    /// the application is not found, or the response cannot be parsed.
    pub async fn change_encryption_key(
        &self,
        app_guid: &AppGuid,
        new_kms_alias: &str,
    ) -> Result<Application, VeracodeError> {
        // Validate new KMS alias format
        validate_kms_alias(new_kms_alias).map_err(VeracodeError::InvalidConfig)?;

        // Get current application
        let current_app = self.get_application(app_guid).await?;

        let profile = current_app
            .profile
            .ok_or_else(|| VeracodeError::NotFound("Application profile not found".to_string()))?;

        // Create update request with new KMS alias
        let update_request = UpdateApplicationRequest {
            profile: UpdateApplicationProfile {
                name: Some(profile.name),
                description: profile.description,
                business_unit: profile.business_unit,
                business_owners: profile.business_owners,
                business_criticality: profile.business_criticality,
                policies: profile.policies,
                teams: profile.teams,
                tags: profile.tags,
                custom_fields: profile.custom_fields,
                custom_kms_alias: Some(new_kms_alias.to_string()),
                repo_url: profile.repo_url,
            },
        };

        self.update_application(app_guid, &update_request).await
    }

    /// Get the encryption status of an application
    ///
    /// This method retrieves the current CMEK configuration for an application.
    ///
    /// # Arguments
    ///
    /// * `app_guid` - The GUID of the application to check
    ///
    /// # Returns
    ///
    /// A `Result` containing the KMS alias if CMEK is enabled, None if disabled, or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the application is not found,
    /// or the response cannot be parsed.
    pub async fn get_application_encryption_status(
        &self,
        app_guid: &AppGuid,
    ) -> Result<Option<String>, VeracodeError> {
        let app = self.get_application(app_guid).await?;

        // CMEK is stored directly in the profile as custom_kms_alias, not in custom_fields
        Ok(app.profile.and_then(|profile| profile.custom_kms_alias))
    }
}

/// Validates an AWS KMS alias format
///
/// AWS KMS aliases must follow specific naming conventions:
/// - Must be prefixed with "alias/"
/// - Total length must be between 8-256 characters
/// - Can contain alphanumeric characters, hyphens, underscores, and forward slashes
/// - Cannot begin or end with "aws" (reserved by AWS)
///
/// # Examples
///
/// ```
/// use veracode_platform::app::validate_kms_alias;
///
/// assert!(validate_kms_alias("alias/my-app-key").is_ok());
/// assert!(validate_kms_alias("alias/my_app_key_2024").is_ok());
/// assert!(validate_kms_alias("invalid-alias").is_err());
/// assert!(validate_kms_alias("alias/aws-managed").is_err());
/// ```
///
/// # Errors
///
/// Returns an error if the alias doesn't meet AWS KMS naming requirements.
pub fn validate_kms_alias(alias: &str) -> Result<(), String> {
    // Check prefix
    if !alias.starts_with("alias/") {
        return Err("KMS alias must start with 'alias/'".to_string());
    }

    // Check length (including the "alias/" prefix) - minimum 8 characters for meaningful alias
    if alias.len() < 8 || alias.len() > 256 {
        return Err("KMS alias must be between 8 and 256 characters long".to_string());
    }

    // Extract the alias name part (after "alias/")
    let alias_name = alias
        .strip_prefix("alias/")
        .ok_or_else(|| "KMS alias must start with 'alias/'".to_string())?;

    // Check for AWS reserved prefixes
    if alias_name.starts_with("aws") || alias_name.ends_with("aws") {
        return Err("KMS alias cannot begin or end with 'aws' (reserved by AWS)".to_string());
    }

    // Check valid characters: alphanumeric, hyphens, underscores, forward slashes
    if !alias_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/')
    {
        return Err("KMS alias can only contain alphanumeric characters, hyphens, underscores, and forward slashes".to_string());
    }

    // Check that it's not empty after prefix
    if alias_name.is_empty() {
        return Err("KMS alias name cannot be empty after 'alias/' prefix".to_string());
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_query_params() {
        let query = ApplicationQuery::new()
            .with_name("test_app")
            .with_policy_compliance("PASSED")
            .with_page(1)
            .with_size(50);

        let params = query.to_query_params();
        assert!(params.contains(&("name".to_string(), "test_app".to_string())));
        assert!(params.contains(&("policy_compliance".to_string(), "PASSED".to_string())));
        assert!(params.contains(&("page".to_string(), "1".to_string())));
        assert!(params.contains(&("size".to_string(), "50".to_string())));
    }

    #[test]
    fn test_application_query_builder() {
        let query = ApplicationQuery::new()
            .with_name("MyApp")
            .with_policy_compliance("DID_NOT_PASS")
            .with_modified_after("2023-01-01T00:00:00.000Z")
            .with_page(2)
            .with_size(25);

        assert_eq!(query.name, Some("MyApp".to_string()));
        assert_eq!(query.policy_compliance, Some("DID_NOT_PASS".to_string()));
        assert_eq!(
            query.modified_after,
            Some("2023-01-01T00:00:00.000Z".to_string())
        );
        assert_eq!(query.page, Some(2));
        assert_eq!(query.size, Some(25));
    }

    #[test]
    fn test_application_query_normalize_defaults() {
        let query = ApplicationQuery::new();
        let normalized = query.normalize().expect("should normalize");

        // Should set default page size
        assert_eq!(normalized.size, Some(50)); // DEFAULT_PAGE_SIZE
        assert_eq!(normalized.page, None);
    }

    #[test]
    fn test_application_query_normalize_valid_values() {
        let query = ApplicationQuery::new().with_page(10).with_size(100);
        let normalized = query.normalize().expect("should normalize");

        assert_eq!(normalized.page, Some(10));
        assert_eq!(normalized.size, Some(100));
    }

    #[test]
    fn test_application_query_normalize_zero_size() {
        let query = ApplicationQuery::new().with_size(0);
        let result = query.normalize();

        assert!(result.is_err());
    }

    #[test]
    fn test_application_query_normalize_caps_large_size() {
        let query = ApplicationQuery::new().with_size(10000);
        let normalized = query.normalize().expect("should cap to max");

        // Should be capped to MAX_PAGE_SIZE (500)
        assert_eq!(normalized.size, Some(500));
    }

    #[test]
    fn test_application_query_normalize_caps_large_page() {
        let query = ApplicationQuery::new().with_page(50000);
        let normalized = query.normalize().expect("should cap to max");

        // Should be capped to MAX_PAGE_NUMBER (10,000)
        assert_eq!(normalized.page, Some(10000));
    }

    #[test]
    fn test_query_params_url_encoding_normal() {
        let query = ApplicationQuery::new()
            .with_name("MyApp")
            .with_policy_compliance("PASSED");

        let params = query.to_query_params();

        // Normal values should remain unchanged
        assert!(params.contains(&("name".to_string(), "MyApp".to_string())));
        assert!(params.contains(&("policy_compliance".to_string(), "PASSED".to_string())));
    }

    #[test]
    fn test_query_params_url_encoding_special_chars() {
        let query = ApplicationQuery::new()
            .with_name("My App & Co")
            .with_policy_compliance("DID_NOT_PASS");

        let params = query.to_query_params();

        // Spaces and ampersands should be encoded
        assert!(params.contains(&("name".to_string(), "My%20App%20%26%20Co".to_string())));
    }

    #[test]
    fn test_query_params_injection_attempt() {
        // Attempt to inject additional parameters via ampersand
        let query = ApplicationQuery::new().with_name("foo&admin=true");

        let params = query.to_query_params();

        // The ampersand should be encoded, preventing injection
        assert!(params.contains(&("name".to_string(), "foo%26admin%3Dtrue".to_string())));

        // Verify there's no "admin" parameter
        assert!(!params.iter().any(|(key, _)| key == "admin"));
    }

    #[test]
    fn test_query_params_equals_injection() {
        // Attempt to inject key=value pairs
        let query = ApplicationQuery::new().with_name("test=malicious");

        let params = query.to_query_params();

        // The equals sign should be encoded
        assert!(params.contains(&("name".to_string(), "test%3Dmalicious".to_string())));
    }

    #[test]
    fn test_query_params_semicolon_injection() {
        // Attempt command injection via semicolon
        let query = ApplicationQuery::new().with_name("test;rm -rf /");

        let params = query.to_query_params();

        // The semicolon and spaces should be encoded
        assert!(params.contains(&("name".to_string(), "test%3Brm%20-rf%20%2F".to_string())));
    }

    #[test]
    fn test_query_params_multiple_fields_with_encoding() {
        let mut query = ApplicationQuery::new()
            .with_name("App & Test")
            .with_policy_compliance("PASSED")
            .with_modified_after("2023-01-01T00:00:00.000Z");
        query.business_unit = Some("Test & Development".to_string());

        let params = query.to_query_params();

        // Check that all fields are present with proper encoding
        assert!(params.contains(&("name".to_string(), "App%20%26%20Test".to_string())));
        assert!(params.contains(&("policy_compliance".to_string(), "PASSED".to_string())));
        assert!(params.contains(&(
            "modified_after".to_string(),
            "2023-01-01T00%3A00%3A00.000Z".to_string()
        )));
        assert!(params.contains(&(
            "business_unit".to_string(),
            "Test%20%26%20Development".to_string()
        )));
    }

    #[test]
    fn test_create_application_request_with_teams() {
        let team_names = vec!["Security Team".to_string(), "Development Team".to_string()];
        let teams: Vec<Team> = team_names
            .into_iter()
            .map(|team_name| Team {
                guid: None,
                team_id: None,
                team_name: Some(team_name),
                team_legacy_id: None,
            })
            .collect();

        let request = CreateApplicationRequest {
            profile: CreateApplicationProfile {
                name: AppName::new("Test Application").expect("valid name"),
                business_criticality: BusinessCriticality::Medium,
                description: Some(Description::new("Test description").expect("valid description")),
                business_unit: None,
                business_owners: None,
                policies: None,
                teams: Some(teams.clone()),
                tags: None,
                custom_fields: None,
                custom_kms_alias: None,
                repo_url: None,
            },
        };

        assert_eq!(request.profile.name.as_str(), "Test Application");
        assert_eq!(
            request.profile.business_criticality,
            BusinessCriticality::Medium
        );
        assert!(request.profile.teams.is_some());

        let request_teams = request.profile.teams.expect("teams should be present");
        assert_eq!(request_teams.len(), 2);
        assert_eq!(
            request_teams
                .first()
                .expect("should have first team")
                .team_name,
            Some("Security Team".to_string())
        );
        assert_eq!(
            request_teams
                .get(1)
                .expect("should have second team")
                .team_name,
            Some("Development Team".to_string())
        );
    }

    #[test]
    fn test_create_application_request_with_team_guids() {
        let team_guids = vec!["team-guid-1".to_string(), "team-guid-2".to_string()];
        let teams: Vec<Team> = team_guids
            .into_iter()
            .map(|team_guid| Team {
                guid: Some(team_guid),
                team_id: None,
                team_name: None,
                team_legacy_id: None,
            })
            .collect();

        let request = CreateApplicationRequest {
            profile: CreateApplicationProfile {
                name: AppName::new("Test Application").expect("valid name"),
                business_criticality: BusinessCriticality::High,
                description: Some(Description::new("Test description").expect("valid description")),
                business_unit: None,
                business_owners: None,
                policies: None,
                teams: Some(teams.clone()),
                tags: None,
                custom_fields: None,
                custom_kms_alias: None,
                repo_url: None,
            },
        };

        assert_eq!(request.profile.name.as_str(), "Test Application");
        assert_eq!(
            request.profile.business_criticality,
            BusinessCriticality::High
        );
        assert!(request.profile.teams.is_some());

        let request_teams = request.profile.teams.expect("teams should be present");
        assert_eq!(request_teams.len(), 2);
        assert_eq!(
            request_teams.first().expect("should have first team").guid,
            Some("team-guid-1".to_string())
        );
        assert_eq!(
            request_teams.get(1).expect("should have second team").guid,
            Some("team-guid-2".to_string())
        );
        assert!(
            request_teams
                .first()
                .expect("should have first team")
                .team_name
                .is_none()
        );
        assert!(
            request_teams
                .get(1)
                .expect("should have second team")
                .team_name
                .is_none()
        );
    }

    #[test]
    fn test_create_application_profile_cmek_serialization() {
        // Test that custom_kms_alias is included when Some
        let profile_with_cmek = CreateApplicationProfile {
            name: AppName::new("Test Application").expect("valid name"),
            business_criticality: BusinessCriticality::High,
            description: None,
            business_unit: None,
            business_owners: None,
            policies: None,
            teams: None,
            tags: None,
            custom_fields: None,
            custom_kms_alias: Some("alias/my-app-key".to_string()),
            repo_url: None,
        };

        let json = serde_json::to_string(&profile_with_cmek).expect("should serialize to json");
        assert!(json.contains("custom_kms_alias"));
        assert!(json.contains("alias/my-app-key"));

        // Test that custom_kms_alias is excluded when None
        let profile_without_cmek = CreateApplicationProfile {
            name: AppName::new("Test Application").expect("valid name"),
            business_criticality: BusinessCriticality::High,
            description: None,
            business_unit: None,
            business_owners: None,
            policies: None,
            teams: None,
            tags: None,
            custom_fields: None,
            custom_kms_alias: None,
            repo_url: None,
        };

        let json = serde_json::to_string(&profile_without_cmek).expect("should serialize to json");
        assert!(!json.contains("custom_kms_alias"));
    }

    #[test]
    fn test_update_application_profile_cmek_serialization() {
        // Test that custom_kms_alias is included when Some
        let profile_with_cmek = UpdateApplicationProfile {
            name: Some(AppName::new("Updated Application").expect("valid name")),
            description: None,
            business_unit: None,
            business_owners: None,
            business_criticality: BusinessCriticality::Medium,
            policies: None,
            teams: None,
            tags: None,
            custom_fields: None,
            custom_kms_alias: Some("alias/updated-key".to_string()),
            repo_url: None,
        };

        let json = serde_json::to_string(&profile_with_cmek).expect("should serialize to json");
        assert!(json.contains("custom_kms_alias"));
        assert!(json.contains("alias/updated-key"));

        // Test that custom_kms_alias is excluded when None
        let profile_without_cmek = UpdateApplicationProfile {
            name: Some(AppName::new("Updated Application").expect("valid name")),
            description: None,
            business_unit: None,
            business_owners: None,
            business_criticality: BusinessCriticality::Medium,
            policies: None,
            teams: None,
            tags: None,
            custom_fields: None,
            custom_kms_alias: None,
            repo_url: None,
        };

        let json = serde_json::to_string(&profile_without_cmek).expect("should serialize to json");
        assert!(!json.contains("custom_kms_alias"));
    }

    #[test]
    fn test_validate_kms_alias_valid_cases() {
        // Valid aliases
        assert!(validate_kms_alias("alias/my-app-key").is_ok());
        assert!(validate_kms_alias("alias/my_app_key_2024").is_ok());
        assert!(validate_kms_alias("alias/app/environment/key").is_ok());
        assert!(validate_kms_alias("alias/123-test-key").is_ok());
    }

    #[test]
    fn test_validate_kms_alias_invalid_cases() {
        // Missing prefix
        assert!(validate_kms_alias("my-app-key").is_err());
        assert!(validate_kms_alias("invalid-alias").is_err());

        // Wrong prefix
        assert!(validate_kms_alias("arn:aws:kms:us-east-1:123456789:alias/my-key").is_err());

        // AWS reserved names
        assert!(validate_kms_alias("alias/aws-managed").is_err());
        assert!(validate_kms_alias("alias/my-key-aws").is_err());

        // Empty alias name
        assert!(validate_kms_alias("alias/").is_err());

        // Too short
        assert!(validate_kms_alias("alias/a").is_err());

        // Invalid characters
        assert!(validate_kms_alias("alias/my@key").is_err());
        assert!(validate_kms_alias("alias/my key").is_err());
        assert!(validate_kms_alias("alias/my.key").is_err());

        // Too long (over 256 characters)
        let long_alias = format!("alias/{}", "a".repeat(251));
        assert!(validate_kms_alias(&long_alias).is_err());
    }

    #[test]
    fn test_cmek_backward_compatibility() {
        // Test that existing application creation still works without CMEK field
        let legacy_profile = CreateApplicationProfile {
            name: AppName::new("Legacy Application").expect("valid name"),
            business_criticality: BusinessCriticality::High,
            description: Some(
                Description::new("Legacy app without CMEK").expect("valid description"),
            ),
            business_unit: None,
            business_owners: None,
            policies: None,
            teams: None,
            tags: None,
            custom_fields: None,
            custom_kms_alias: None,
            repo_url: None,
        };

        let request = CreateApplicationRequest {
            profile: legacy_profile,
        };

        // Should serialize successfully
        let json = serde_json::to_string(&request).expect("should serialize to json");

        // Should not contain CMEK field
        assert!(!json.contains("custom_kms_alias"));

        // Should still contain required fields
        assert!(json.contains("name"));
        assert!(json.contains("business_criticality"));
        assert!(json.contains("Legacy Application"));

        // Should be able to deserialize back
        let _deserialized: CreateApplicationRequest =
            serde_json::from_str(&json).expect("should deserialize json");
    }

    #[test]
    fn test_cmek_field_deserialization() {
        // Test deserializing JSON with CMEK field
        let json_with_cmek = r#"{
            "profile": {
                "name": "Test App",
                "business_criticality": "HIGH",
                "custom_kms_alias": "alias/test-key"
            }
        }"#;

        let request: CreateApplicationRequest =
            serde_json::from_str(json_with_cmek).expect("should deserialize json");
        assert_eq!(
            request.profile.custom_kms_alias,
            Some("alias/test-key".to_string())
        );

        // Test deserializing JSON without CMEK field (backward compatibility)
        let json_without_cmek = r#"{
            "profile": {
                "name": "Test App",
                "business_criticality": "HIGH"
            }
        }"#;

        let request: CreateApplicationRequest =
            serde_json::from_str(json_without_cmek).expect("should deserialize json");
        assert_eq!(request.profile.custom_kms_alias, None);
    }

    #[test]
    fn test_create_application_profile_with_cmek() {
        // Test that CreateApplicationProfile includes custom_kms_alias when Some
        let profile_with_cmek = CreateApplicationProfile {
            name: AppName::new("MyApplication").expect("valid name"),
            business_criticality: BusinessCriticality::High,
            description: Some(
                Description::new("Application created for assessment scanning")
                    .expect("valid description"),
            ),
            business_unit: None,
            business_owners: None,
            policies: None,
            teams: None,
            tags: None,
            custom_fields: None,
            custom_kms_alias: Some("alias/my-encryption-key".to_string()),
            repo_url: Some("https://github.com/user/repo".to_string()),
        };

        let request = CreateApplicationRequest {
            profile: profile_with_cmek,
        };

        let json = serde_json::to_string_pretty(&request).expect("should serialize to json");

        // Print the actual JSON payload that would be sent to Veracode
        println!("\n📦 Example JSON Payload sent to Veracode API:");
        println!("{}", json);
        println!();

        assert!(json.contains("custom_kms_alias"));
        assert!(json.contains("alias/my-encryption-key"));

        // Verify it deserializes correctly
        let deserialized: CreateApplicationRequest =
            serde_json::from_str(&json).expect("should deserialize json");
        assert_eq!(
            deserialized.profile.custom_kms_alias,
            Some("alias/my-encryption-key".to_string())
        );
    }

    #[test]
    fn test_create_application_profile_without_cmek() {
        // Test that CreateApplicationProfile excludes custom_kms_alias when None
        let profile_without_cmek = CreateApplicationProfile {
            name: AppName::new("MyApplication").expect("valid name"),
            business_criticality: BusinessCriticality::High,
            description: Some(
                Description::new("Application created for assessment scanning")
                    .expect("valid description"),
            ),
            business_unit: None,
            business_owners: None,
            policies: None,
            teams: None,
            tags: None,
            custom_fields: None,
            custom_kms_alias: None,
            repo_url: Some("https://github.com/user/repo".to_string()),
        };

        let request = CreateApplicationRequest {
            profile: profile_without_cmek,
        };

        let json = serde_json::to_string_pretty(&request).expect("should serialize to json");

        // Print the actual JSON payload WITHOUT CMEK
        println!("\n📦 Example JSON Payload sent to Veracode API (without --cmek):");
        println!("{}", json);
        println!("⚠️  Notice: 'custom_kms_alias' field is NOT included in the payload");
        println!();

        assert!(!json.contains("custom_kms_alias"));

        // Verify it deserializes correctly
        let deserialized: CreateApplicationRequest =
            serde_json::from_str(&json).expect("should deserialize json");
        assert_eq!(deserialized.profile.custom_kms_alias, None);
    }

    #[test]
    fn test_update_application_profile_with_cmek() {
        // Test that UpdateApplicationProfile handles custom_kms_alias correctly
        let profile_with_cmek = UpdateApplicationProfile {
            name: Some(AppName::new("Updated Application").expect("valid name")),
            description: Some(Description::new("Updated description").expect("valid description")),
            business_unit: None,
            business_owners: None,
            business_criticality: BusinessCriticality::Medium,
            policies: None,
            teams: None,
            tags: None,
            custom_fields: None,
            custom_kms_alias: Some("alias/updated-key".to_string()),
            repo_url: None,
        };

        let json = serde_json::to_string(&profile_with_cmek).expect("should serialize to json");
        assert!(json.contains("custom_kms_alias"));
        assert!(json.contains("alias/updated-key"));
    }

    /// Test case demonstrating exact JSON payload structure WITH CMEK
    /// This documents the API contract when creating applications with encryption enabled
    #[test]
    fn test_cmek_enabled_payload_structure() {
        let request = CreateApplicationRequest {
            profile: CreateApplicationProfile {
                name: AppName::new("MyApplication").expect("valid name"),
                business_criticality: BusinessCriticality::High,
                description: Some(
                    Description::new("Application created for assessment scanning")
                        .expect("valid description"),
                ),
                business_unit: None,
                business_owners: None,
                policies: None,
                teams: None,
                tags: None,
                custom_fields: None,
                custom_kms_alias: Some("alias/my-encryption-key".to_string()),
                repo_url: Some("https://github.com/user/repo".to_string()),
            },
        };

        let json = serde_json::to_string_pretty(&request).expect("should serialize to json");

        // Verify the exact structure matches expected API format
        let expected_keys = vec![
            "profile",
            "name",
            "business_criticality",
            "description",
            "custom_kms_alias",
            "repo_url",
        ];

        for key in expected_keys {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "Expected key '{}' not found in payload",
                key
            );
        }

        // Verify custom_kms_alias is present and has correct value
        assert!(json.contains("\"custom_kms_alias\": \"alias/my-encryption-key\""));
        assert!(json.contains("\"business_criticality\": \"HIGH\""));
        assert!(json.contains("\"name\": \"MyApplication\""));

        // Parse and verify structure
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("should deserialize json");
        assert_eq!(
            parsed
                .get("profile")
                .and_then(|p| p.get("custom_kms_alias"))
                .and_then(|v| v.as_str())
                .expect("should have custom_kms_alias"),
            "alias/my-encryption-key"
        );
        assert_eq!(
            parsed
                .get("profile")
                .and_then(|p| p.get("business_criticality"))
                .and_then(|v| v.as_str())
                .expect("should have business_criticality"),
            "HIGH"
        );
    }

    /// Test case demonstrating exact JSON payload structure WITHOUT CMEK
    /// This documents the API contract when creating applications without encryption
    #[test]
    fn test_cmek_disabled_payload_structure() {
        let request = CreateApplicationRequest {
            profile: CreateApplicationProfile {
                name: AppName::new("MyApplication").expect("valid name"),
                business_criticality: BusinessCriticality::High,
                description: Some(
                    Description::new("Application created for assessment scanning")
                        .expect("valid description"),
                ),
                business_unit: None,
                business_owners: None,
                policies: None,
                teams: None,
                tags: None,
                custom_fields: None,
                custom_kms_alias: None, // CMEK not specified
                repo_url: Some("https://github.com/user/repo".to_string()),
            },
        };

        let json = serde_json::to_string_pretty(&request).expect("should serialize to json");

        // Verify custom_kms_alias is NOT present in the payload
        assert!(
            !json.contains("custom_kms_alias"),
            "custom_kms_alias should not be present when None"
        );

        // Verify other expected fields are present
        assert!(json.contains("\"name\": \"MyApplication\""));
        assert!(json.contains("\"business_criticality\": \"HIGH\""));
        assert!(json.contains("\"repo_url\""));

        // Parse and verify structure
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("should deserialize json");
        assert_eq!(
            parsed
                .get("profile")
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .expect("should have name"),
            "MyApplication"
        );
        assert_eq!(
            parsed
                .get("profile")
                .and_then(|p| p.get("business_criticality"))
                .and_then(|v| v.as_str())
                .expect("should have business_criticality"),
            "HIGH"
        );

        // Verify custom_kms_alias key doesn't exist in JSON
        assert!(
            !parsed
                .get("profile")
                .and_then(|p| p.as_object())
                .expect("should have profile object")
                .contains_key("custom_kms_alias"),
            "custom_kms_alias key should not exist in JSON object"
        );
    }

    /// Test case for various valid CMEK alias formats
    #[test]
    fn test_cmek_alias_format_variations() {
        // Test different valid alias formats
        let test_cases = vec![
            "alias/production-key",
            "alias/dev_environment_key",
            "alias/app/prod/2024",
            "alias/KEY123",
            "alias/my-app-key-2024",
        ];

        for alias in test_cases {
            let request = CreateApplicationRequest {
                profile: CreateApplicationProfile {
                    name: AppName::new("TestApp").expect("valid name"),
                    business_criticality: BusinessCriticality::Medium,
                    description: None,
                    business_unit: None,
                    business_owners: None,
                    policies: None,
                    teams: None,
                    tags: None,
                    custom_fields: None,
                    custom_kms_alias: Some(alias.to_string()),
                    repo_url: None,
                },
            };

            let json = serde_json::to_string(&request).expect("should serialize to json");
            assert!(
                json.contains(alias),
                "Alias '{}' should be present in payload",
                alias
            );

            // Verify it can be deserialized
            let parsed: CreateApplicationRequest =
                serde_json::from_str(&json).expect("should deserialize json");
            assert_eq!(parsed.profile.custom_kms_alias, Some(alias.to_string()));
        }
    }

    /// Test case demonstrating full application profile with all optional fields
    #[test]
    fn test_complete_application_profile_with_cmek() {
        let request = CreateApplicationRequest {
            profile: CreateApplicationProfile {
                name: AppName::new("CompleteApplication").expect("valid name"),
                business_criticality: BusinessCriticality::VeryHigh,
                description: Some(
                    Description::new("Full featured application with CMEK")
                        .expect("valid description"),
                ),
                business_unit: Some(BusinessUnit {
                    id: Some(123),
                    name: Some("Engineering".to_string()),
                    guid: Some("bu-guid-123".to_string()),
                }),
                business_owners: Some(vec![BusinessOwner {
                    email: Some("owner@example.com".to_string()),
                    name: Some("App Owner".to_string()),
                }]),
                policies: None,
                teams: Some(vec![Team {
                    guid: Some("team-guid-456".to_string()),
                    team_id: None,
                    team_name: None,
                    team_legacy_id: None,
                }]),
                tags: Some("production,encrypted".to_string()),
                custom_fields: Some(vec![CustomField {
                    name: Some("Environment".to_string()),
                    value: Some("Production".to_string()),
                }]),
                custom_kms_alias: Some("alias/production-cmek-key".to_string()),
                repo_url: Some("https://github.com/company/secure-app".to_string()),
            },
        };

        let json = serde_json::to_string_pretty(&request).expect("should serialize to json");

        // Verify all major sections are present
        assert!(json.contains("\"custom_kms_alias\": \"alias/production-cmek-key\""));
        assert!(json.contains("\"business_unit\""));
        assert!(json.contains("\"business_owners\""));
        assert!(json.contains("\"teams\""));
        assert!(json.contains("\"tags\""));
        assert!(json.contains("\"custom_fields\""));

        // Verify deserialization works with full structure
        let parsed: CreateApplicationRequest =
            serde_json::from_str(&json).expect("should deserialize json");
        assert_eq!(
            parsed.profile.custom_kms_alias,
            Some("alias/production-cmek-key".to_string())
        );
        assert!(parsed.profile.business_unit.is_some());
        assert!(parsed.profile.business_owners.is_some());
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test-only hardcoded regexes are safe
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Strategy for valid KMS aliases
    fn valid_kms_alias_strategy() -> impl Strategy<Value = String> {
        // Valid characters: alphanumeric, hyphen, underscore, forward slash
        // Length: 8-256 chars including "alias/" prefix
        // Must not start/end with "aws"
        prop::string::string_regex("[a-zA-Z0-9_/-]{2,250}")
            .expect("valid regex pattern for KMS alias")
            .prop_map(|s| format!("alias/{}", s))
            .prop_filter("Cannot start with aws", |s| {
                !s.strip_prefix("alias/").unwrap_or("").starts_with("aws")
            })
            .prop_filter("Cannot end with aws", |s| {
                !s.strip_prefix("alias/").unwrap_or("").ends_with("aws")
            })
    }

    fn invalid_kms_alias_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // Missing prefix
            prop::string::string_regex("[a-zA-Z0-9_/-]{5,20}")
                .expect("valid regex for missing prefix test"),
            // Wrong prefix
            Just("arn:aws:kms:us-east-1:123456789:alias/test".to_string()),
            // AWS reserved
            Just("alias/aws-managed".to_string()),
            Just("alias/test-aws".to_string()),
            // Empty after prefix
            Just("alias/".to_string()),
            // Too short
            Just("alias/a".to_string()),
            // Invalid characters
            Just("alias/test@key".to_string()),
            Just("alias/test key".to_string()),
            Just("alias/test.key".to_string()),
            // Too long
            prop::string::string_regex("[a-z]{252}")
                .expect("valid regex for too long test")
                .prop_map(|s| format!("alias/{}", s)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None, // Required for Miri compatibility
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_valid_kms_aliases_accepted(alias in valid_kms_alias_strategy()) {
            prop_assert!(validate_kms_alias(&alias).is_ok(),
                "Valid alias rejected: {}", alias);
        }

        #[test]
        fn proptest_invalid_kms_aliases_rejected(alias in invalid_kms_alias_strategy()) {
            prop_assert!(validate_kms_alias(&alias).is_err(),
                "Invalid alias accepted: {}", alias);
        }

        #[test]
        fn proptest_kms_alias_length_bounds(
            prefix in prop::string::string_regex("[a-zA-Z0-9_/-]{1,7}").expect("valid regex for prefix"),
            suffix in prop::string::string_regex("[a-zA-Z0-9_/-]{251,300}").expect("valid regex for suffix")
        ) {
            let too_short = format!("alias/{}", prefix);
            let too_long = format!("alias/{}", suffix);

            prop_assert!(validate_kms_alias(&too_short).is_err() || too_short.len() >= 8,
                "Too short alias not rejected");
            prop_assert!(validate_kms_alias(&too_long).is_err(),
                "Too long alias not rejected");
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test-only hardcoded regexes are safe
mod query_proptests {
    use super::*;
    use crate::validation::encode_query_param;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None, // Required for Miri compatibility
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_query_param_no_injection(
            value in prop::string::string_regex(".{1,100}").expect("valid regex for query param")
        ) {
            let encoded = encode_query_param(&value);

            // Encoded value should not contain raw injection characters
            prop_assert!(!encoded.contains('&'), "Ampersand not encoded");
            prop_assert!(!encoded.contains('=') || value.contains('=') && encoded.contains("%3D"),
                "Equals not encoded");
            prop_assert!(!encoded.contains(';'), "Semicolon not encoded");
        }

        #[test]
        fn proptest_query_param_path_traversal_encoded(
            segments in prop::collection::vec(
                prop::string::string_regex("[a-zA-Z0-9]{1,10}").expect("valid regex for path segments"),
                1..5
            )
        ) {
            let path_traversal = segments.join("../");
            let encoded = encode_query_param(&path_traversal);

            // Path traversal is prevented by encoding the separators, not the dots
            // The sequence "../" becomes "..%2F" which won't be interpreted as traversal
            prop_assert!(!encoded.contains("../"), "Path traversal sequence '../' not broken by encoding");
            prop_assert!(!encoded.contains("..\\"), "Path traversal sequence '..\\' not broken by encoding");
            prop_assert!(encoded.contains("%2F") || !path_traversal.contains('/'),
                "Forward slash not encoded");
        }

        #[test]
        fn proptest_application_query_to_params_no_key_pollution(
            name in prop::option::of(prop::string::string_regex("[a-zA-Z0-9 &=;]{1,50}").expect("valid regex for app name")),
            compliance in prop::option::of(Just("PASSED".to_string())),
            page in prop::option::of(0u32..1000u32),
            size in prop::option::of(1u32..1000u32)
        ) {
            let mut query = ApplicationQuery::new();
            if let Some(n) = name {
                query = query.with_name(&n);
            }
            if let Some(c) = compliance {
                query = query.with_policy_compliance(&c);
            }
            query.page = page;
            query.size = size;

            let params = query.to_query_params();

            // Verify each key appears at most once
            let mut seen_keys = std::collections::HashSet::new();
            for (key, _) in params.iter() {
                prop_assert!(!seen_keys.contains(key),
                    "Duplicate parameter key: {}", key);
                seen_keys.insert(key.clone());
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test-only validation patterns are safe
mod pagination_proptests {
    use super::*;
    use crate::validation::{MAX_PAGE_NUMBER, MAX_PAGE_SIZE};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None, // Required for Miri compatibility
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_page_size_bounds_enforced(size in 0u32..u32::MAX) {
            match validate_page_size(Some(size)) {
                Ok(validated) => {
                    prop_assert!(validated >= 1, "Zero page size accepted");
                    prop_assert!(validated <= MAX_PAGE_SIZE,
                        "Page size {} exceeds maximum {}", validated, MAX_PAGE_SIZE);
                }
                Err(_) => {
                    prop_assert_eq!(size, 0, "Non-zero size rejected");
                }
            }
        }

        #[test]
        fn proptest_page_number_bounds_enforced(page in 0u32..u32::MAX) {
            let validated = validate_page_number(Some(page)).expect("page number validation should not fail");

            if let Some(p) = validated {
                prop_assert!(p <= MAX_PAGE_NUMBER,
                    "Page number {} exceeds maximum {}", p, MAX_PAGE_NUMBER);
            }
        }

        #[test]
        fn proptest_application_query_normalize_safety(
            page in prop::option::of(0u32..u32::MAX),
            size in prop::option::of(0u32..u32::MAX)
        ) {
            let mut query = ApplicationQuery::new();
            query.page = page;
            query.size = size;

            match query.normalize() {
                Ok(normalized) => {
                    // If normalization succeeds, bounds must be enforced
                    if let Some(s) = normalized.size {
                        prop_assert!((1..=MAX_PAGE_SIZE).contains(&s),
                            "Normalized size {} out of bounds", s);
                    }
                    if let Some(p) = normalized.page {
                        prop_assert!(p <= MAX_PAGE_NUMBER,
                            "Normalized page {} exceeds maximum", p);
                    }
                }
                Err(_) => {
                    // Errors only for zero size
                    prop_assert_eq!(size, Some(0), "Unexpected normalization error");
                }
            }
        }
    }
}
#[cfg(test)]
mod miri_tests {
    use super::*;

    #[test]
    fn miri_business_owner_debug_redaction() {
        let owner = BusinessOwner {
            email: Some("sensitive@example.com".to_string()),
            name: Some("Sensitive Name".to_string()),
        };

        let debug_str = format!("{:?}", owner);

        // Verify redaction occurred
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("sensitive@example.com"));
        assert!(!debug_str.contains("Sensitive Name"));
    }

    #[test]
    fn miri_business_owner_none_fields() {
        let owner = BusinessOwner {
            email: None,
            name: None,
        };

        // Should not panic or exhibit UB with None fields
        let debug_str = format!("{:?}", owner);
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn miri_custom_field_debug_redaction() {
        let field = CustomField {
            name: Some("API_KEY".to_string()),
            value: Some("super-secret-key".to_string()),
        };

        let debug_str = format!("{:?}", field);

        // Verify value is redacted but name is visible
        assert!(debug_str.contains("API_KEY"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super-secret-key"));
    }

    #[test]
    fn miri_custom_field_none_value() {
        let field = CustomField {
            name: Some("EMPTY_FIELD".to_string()),
            value: None,
        };

        // Should not panic with None value
        let debug_str = format!("{:?}", field);
        assert!(debug_str.contains("EMPTY_FIELD"));
        assert!(debug_str.contains("[REDACTED]"));
    }
}

#[cfg(test)]
mod miri_validation_tests {
    use super::*;

    #[test]
    fn miri_app_name_utf8_boundaries() {
        // Test with various UTF-8 characters
        let emoji_name = "MyApp 🚀 Test";
        let result = AppName::new(emoji_name);
        assert!(result.is_ok());

        // Test with combining characters
        let combining = "Café"; // é is a combining character
        let result = AppName::new(combining);
        assert!(result.is_ok());
    }

    #[test]
    fn miri_description_null_byte_handling() {
        // Ensure null byte check doesn't cause UB
        let with_null = "test\0value";
        let result = Description::new(with_null);
        assert!(result.is_err());

        // Verify error type
        if let Err(err) = result {
            assert!(matches!(err, ValidationError::NullByteInDescription));
        }
    }

    #[test]
    fn miri_kms_alias_character_iteration() {
        // Test character iteration doesn't violate memory safety
        let test_cases = vec![
            "alias/test-key",
            "alias/test_key_2024",
            "alias/app/prod/key",
            "alias/UPPERCASE_KEY",
        ];

        for alias in test_cases {
            let _ = validate_kms_alias(alias);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test-only hardcoded regexes are safe
mod miri_proptest {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None, // Required for Miri compatibility
            .. ProptestConfig::default()
        })]

        #[test]
        fn miri_proptest_app_name_utf8_safety(
            s in prop::string::string_regex("[\\p{L}\\p{N} ]{1,50}").expect("valid regex")
        ) {
            let _ = AppName::new(&s);
            // Miri will catch any UTF-8 boundary violations
        }
    }
}

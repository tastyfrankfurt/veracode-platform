//! Application-specific functionality built on top of the core client.
//!
//! This module contains application-specific methods and convenience functions
//! that use the core `VeracodeClient` to perform application-related operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::VeracodeError;
use crate::client::VeracodeClient;

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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Profile {
    /// Profile name
    pub name: String,
    /// Profile description
    pub description: Option<String>,
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BusinessOwner {
    /// Owner's email address
    pub email: Option<String>,
    /// Owner's name
    pub name: Option<String>,
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomField {
    /// Field name
    pub name: Option<String>,
    /// Field value
    pub value: Option<String>,
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateApplicationProfile {
    /// Application name
    pub name: String,
    /// Business criticality level (required)
    #[serde(serialize_with = "serialize_business_criticality")]
    pub business_criticality: BusinessCriticality,
    /// Application description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateApplicationProfile {
    /// Application name
    pub name: Option<String>,
    /// Application description
    pub description: Option<String>,
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
    #[must_use]
    pub fn new() -> Self {
        ApplicationQuery::default()
    }

    /// Filter applications by name (partial match).
    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Filter applications by policy compliance status.
    #[must_use]
    pub fn with_policy_compliance(mut self, compliance: &str) -> Self {
        self.policy_compliance = Some(compliance.to_string());
        self
    }

    /// Filter applications modified after the specified date.
    #[must_use]
    pub fn with_modified_after(mut self, date: &str) -> Self {
        self.modified_after = Some(date.to_string());
        self
    }

    /// Filter applications modified before the specified date.
    #[must_use]
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

    /// Convert the query to URL query parameters.
    #[must_use]
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        Vec::from(self)
    }
}

/// Convert `ApplicationQuery` to query parameters by borrowing (allows reuse)
impl From<&ApplicationQuery> for Vec<(String, String)> {
    fn from(query: &ApplicationQuery) -> Self {
        let mut params = Vec::new();

        if let Some(ref name) = query.name {
            params.push(("name".to_string(), name.clone()));
        }
        if let Some(ref compliance) = query.policy_compliance {
            params.push(("policy_compliance".to_string(), compliance.clone()));
        }
        if let Some(ref date) = query.modified_after {
            params.push(("modified_after".to_string(), date.clone()));
        }
        if let Some(ref date) = query.modified_before {
            params.push(("modified_before".to_string(), date.clone()));
        }
        if let Some(ref date) = query.created_after {
            params.push(("created_after".to_string(), date.clone()));
        }
        if let Some(ref date) = query.created_before {
            params.push(("created_before".to_string(), date.clone()));
        }
        if let Some(ref scan_type) = query.scan_type {
            params.push(("scan_type".to_string(), scan_type.clone()));
        }
        if let Some(ref tags) = query.tags {
            params.push(("tags".to_string(), tags.clone()));
        }
        if let Some(ref business_unit) = query.business_unit {
            params.push(("business_unit".to_string(), business_unit.clone()));
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
impl From<ApplicationQuery> for Vec<(String, String)> {
    fn from(query: ApplicationQuery) -> Self {
        let mut params = Vec::new();

        if let Some(name) = query.name {
            params.push(("name".to_string(), name));
        }
        if let Some(compliance) = query.policy_compliance {
            params.push(("policy_compliance".to_string(), compliance));
        }
        if let Some(date) = query.modified_after {
            params.push(("modified_after".to_string(), date));
        }
        if let Some(date) = query.modified_before {
            params.push(("modified_before".to_string(), date));
        }
        if let Some(date) = query.created_after {
            params.push(("created_after".to_string(), date));
        }
        if let Some(date) = query.created_before {
            params.push(("created_before".to_string(), date));
        }
        if let Some(scan_type) = query.scan_type {
            params.push(("scan_type".to_string(), scan_type));
        }
        if let Some(tags) = query.tags {
            params.push(("tags".to_string(), tags));
        }
        if let Some(business_unit) = query.business_unit {
            params.push(("business_unit".to_string(), business_unit));
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
    pub async fn get_applications(
        &self,
        query: Option<ApplicationQuery>,
    ) -> Result<ApplicationsResponse, VeracodeError> {
        let endpoint = "/appsec/v1/applications";
        let query_params = query.as_ref().map(Vec::from);

        let response = self.get(endpoint, query_params.as_deref()).await?;
        let response = Self::handle_response(response).await?;

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
    pub async fn get_application(&self, guid: &str) -> Result<Application, VeracodeError> {
        let endpoint = format!("/appsec/v1/applications/{guid}");

        let response = self.get(&endpoint, None).await?;
        let response = Self::handle_response(response).await?;

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
        let response = Self::handle_response(response).await?;

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
    pub async fn update_application(
        &self,
        guid: &str,
        request: &UpdateApplicationRequest,
    ) -> Result<Application, VeracodeError> {
        let endpoint = format!("/appsec/v1/applications/{guid}");

        let response = self.put(&endpoint, Some(&request)).await?;
        let response = Self::handle_response(response).await?;

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
    pub async fn delete_application(&self, guid: &str) -> Result<(), VeracodeError> {
        let endpoint = format!("/appsec/v1/applications/{guid}");

        let response = self.delete(&endpoint).await?;
        let _response = Self::handle_response(response).await?;

        Ok(())
    }

    /// Get applications that failed policy compliance.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec<Application>` of non-compliant applications.
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
                page += 1;
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
    pub async fn get_application_by_name(
        &self,
        name: &str,
    ) -> Result<Option<Application>, VeracodeError> {
        let applications = self.search_applications_by_name(name).await?;

        // Find exact match (search_applications_by_name does partial matching)
        Ok(applications.into_iter().find(|app| {
            if let Some(profile) = &app.profile {
                profile.name == name
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
    pub async fn get_app_id_from_guid(&self, guid: &str) -> Result<String, VeracodeError> {
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
    ///
    /// # Returns
    ///
    /// A `Result` containing the application (existing, updated, or newly created).
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
    /// ).await?;
    ///
    /// // Second call: Returns existing app, no updates (all fields populated)
    /// let same_app = client.create_application_if_not_exists(
    ///     "My Application",
    ///     BusinessCriticality::Medium, // Ignored - won't change existing HIGH
    ///     Some("Different description".to_string()), // Ignored - existing has value
    ///     None,
    ///     Some("https://github.com/user/repo".to_string()), // Ignored - existing has value
    /// ).await?;
    ///
    /// // Application created without repo_url, then updated later
    /// let app_v1 = client.create_application_if_not_exists(
    ///     "Another App",
    ///     BusinessCriticality::Medium,
    ///     None,
    ///     None,
    ///     None, // No repo_url initially
    /// ).await?;
    ///
    /// // Later: Adds repo_url to existing application (because it was missing)
    /// let app_v2 = client.create_application_if_not_exists(
    ///     "Another App",
    ///     BusinessCriticality::High, // Ignored - won't change
    ///     Some("Adding description".to_string()), // Updates (was None)
    ///     None,
    ///     Some("https://github.com/user/another".to_string()), // Updates (was None)
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
    ) -> Result<Application, VeracodeError> {
        // First, check if application already exists
        if let Some(existing_app) = self.get_application_by_name(name).await? {
            // Check if we need to update any missing fields
            let mut needs_update = false;
            let mut update_repo_url = false;
            let mut update_description = false;

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
                            .is_some_and(|d| d.trim().is_empty()))
                {
                    update_description = true;
                    needs_update = true;
                }
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

                // Build update request preserving all existing values
                let profile = existing_app.profile.as_ref().unwrap();
                let update_request = UpdateApplicationRequest {
                    profile: UpdateApplicationProfile {
                        name: Some(profile.name.clone()),
                        description: if update_description {
                            description
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
                        custom_kms_alias: profile.custom_kms_alias.clone(),
                        repo_url: if update_repo_url {
                            repo_url
                        } else {
                            profile.repo_url.clone()
                        },
                    },
                };

                return self
                    .update_application(&existing_app.guid, &update_request)
                    .await;
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
                name: name.to_string(),
                business_criticality,
                description,
                business_unit: None,
                business_owners: None,
                policies: None,
                teams,
                tags: None,
                custom_fields: None,
                custom_kms_alias: None,
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
                name: name.to_string(),
                business_criticality,
                description,
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
    pub async fn create_application_if_not_exists_simple(
        &self,
        name: &str,
        business_criticality: BusinessCriticality,
        description: Option<String>,
    ) -> Result<Application, VeracodeError> {
        self.create_application_if_not_exists(name, business_criticality, description, None, None)
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
    /// # Examples
    ///
    /// ```no_run
    /// # use veracode_platform::{VeracodeClient, VeracodeConfig};
    /// # use std::sync::Arc;
    /// # use secrecy::SecretString;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = VeracodeConfig::from_arc_credentials(
    ///     Arc::new(SecretString::from("api_id")),
    ///     Arc::new(SecretString::from("api_key"))
    /// );
    /// let client = VeracodeClient::new(config)?;
    ///
    /// let app = client.enable_application_encryption(
    ///     "app-guid-123",
    ///     "alias/my-encryption-key"
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn enable_application_encryption(
        &self,
        app_guid: &str,
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
    pub async fn change_encryption_key(
        &self,
        app_guid: &str,
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
    pub async fn get_application_encryption_status(
        &self,
        app_guid: &str,
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
    let alias_name = &alias[6..];

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
                name: "Test Application".to_string(),
                business_criticality: BusinessCriticality::Medium,
                description: Some("Test description".to_string()),
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

        assert_eq!(request.profile.name, "Test Application");
        assert_eq!(
            request.profile.business_criticality,
            BusinessCriticality::Medium
        );
        assert!(request.profile.teams.is_some());

        let request_teams = request.profile.teams.unwrap();
        assert_eq!(request_teams.len(), 2);
        assert_eq!(
            request_teams[0].team_name,
            Some("Security Team".to_string())
        );
        assert_eq!(
            request_teams[1].team_name,
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
                name: "Test Application".to_string(),
                business_criticality: BusinessCriticality::High,
                description: Some("Test description".to_string()),
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

        assert_eq!(request.profile.name, "Test Application");
        assert_eq!(
            request.profile.business_criticality,
            BusinessCriticality::High
        );
        assert!(request.profile.teams.is_some());

        let request_teams = request.profile.teams.unwrap();
        assert_eq!(request_teams.len(), 2);
        assert_eq!(request_teams[0].guid, Some("team-guid-1".to_string()));
        assert_eq!(request_teams[1].guid, Some("team-guid-2".to_string()));
        assert!(request_teams[0].team_name.is_none());
        assert!(request_teams[1].team_name.is_none());
    }

    #[test]
    fn test_create_application_profile_cmek_serialization() {
        // Test that custom_kms_alias is included when Some
        let profile_with_cmek = CreateApplicationProfile {
            name: "Test Application".to_string(),
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

        let json = serde_json::to_string(&profile_with_cmek).unwrap();
        assert!(json.contains("custom_kms_alias"));
        assert!(json.contains("alias/my-app-key"));

        // Test that custom_kms_alias is excluded when None
        let profile_without_cmek = CreateApplicationProfile {
            name: "Test Application".to_string(),
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

        let json = serde_json::to_string(&profile_without_cmek).unwrap();
        assert!(!json.contains("custom_kms_alias"));
    }

    #[test]
    fn test_update_application_profile_cmek_serialization() {
        // Test that custom_kms_alias is included when Some
        let profile_with_cmek = UpdateApplicationProfile {
            name: Some("Updated Application".to_string()),
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

        let json = serde_json::to_string(&profile_with_cmek).unwrap();
        assert!(json.contains("custom_kms_alias"));
        assert!(json.contains("alias/updated-key"));

        // Test that custom_kms_alias is excluded when None
        let profile_without_cmek = UpdateApplicationProfile {
            name: Some("Updated Application".to_string()),
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

        let json = serde_json::to_string(&profile_without_cmek).unwrap();
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
            name: "Legacy Application".to_string(),
            business_criticality: BusinessCriticality::High,
            description: Some("Legacy app without CMEK".to_string()),
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
        let json = serde_json::to_string(&request).unwrap();

        // Should not contain CMEK field
        assert!(!json.contains("custom_kms_alias"));

        // Should still contain required fields
        assert!(json.contains("name"));
        assert!(json.contains("business_criticality"));
        assert!(json.contains("Legacy Application"));

        // Should be able to deserialize back
        let _deserialized: CreateApplicationRequest = serde_json::from_str(&json).unwrap();
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

        let request: CreateApplicationRequest = serde_json::from_str(json_with_cmek).unwrap();
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

        let request: CreateApplicationRequest = serde_json::from_str(json_without_cmek).unwrap();
        assert_eq!(request.profile.custom_kms_alias, None);
    }
}

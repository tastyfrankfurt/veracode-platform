//! Application-specific functionality built on top of the core client.
//!
//! This module contains application-specific methods and convenience functions
//! that use the core VeracodeClient to perform application-related operations.

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
    /// Unique numeric identifier for organization_id the application
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
    /// Team ID
    pub team_id: Option<u64>,
    /// Team name
    pub team_name: Option<String>,
    /// Legacy team ID
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
    pub description: Option<String>,
    /// Business unit
    pub business_unit: Option<BusinessUnit>,
    /// Business owners
    pub business_owners: Option<Vec<BusinessOwner>>,
    /// Policies
    pub policies: Option<Vec<Policy>>,
    /// Teams
    pub teams: Option<Vec<Team>>,
    /// Tags
    pub tags: Option<String>,
    /// Custom fields
    pub custom_fields: Option<Vec<CustomField>>,
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

/// Custom serializer for BusinessCriticality
fn serialize_business_criticality<S>(
    criticality: &BusinessCriticality,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(criticality.as_str())
}

/// Parse BusinessCriticality from string
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

/// Deserialize BusinessCriticality from string
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
}

/// Query parameters for filtering applications.
#[derive(Debug, Clone, Default)]
pub struct ApplicationQuery {
    /// Filter by application name (partial match)
    pub name: Option<String>,
    /// Filter by policy compliance status (PASSED, DID_NOT_PASS, etc.)
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
    pub fn new() -> Self {
        Default::default()
    }

    /// Filter applications by name (partial match).
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Filter applications by policy compliance status.
    pub fn with_policy_compliance(mut self, compliance: String) -> Self {
        self.policy_compliance = Some(compliance);
        self
    }

    /// Filter applications modified after the specified date.
    pub fn with_modified_after(mut self, date: String) -> Self {
        self.modified_after = Some(date);
        self
    }

    /// Filter applications modified before the specified date.
    pub fn with_modified_before(mut self, date: String) -> Self {
        self.modified_before = Some(date);
        self
    }

    /// Set the page number for pagination.
    pub fn with_page(mut self, page: u32) -> Self {
        self.page = Some(page);
        self
    }

    /// Set the number of items per page.
    pub fn with_size(mut self, size: u32) -> Self {
        self.size = Some(size);
        self
    }

    /// Convert the query to URL query parameters.
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();

        if let Some(ref name) = self.name {
            params.push(("name".to_string(), name.clone()));
        }
        if let Some(ref compliance) = self.policy_compliance {
            params.push(("policy_compliance".to_string(), compliance.clone()));
        }
        if let Some(ref date) = self.modified_after {
            params.push(("modified_after".to_string(), date.clone()));
        }
        if let Some(ref date) = self.modified_before {
            params.push(("modified_before".to_string(), date.clone()));
        }
        if let Some(ref date) = self.created_after {
            params.push(("created_after".to_string(), date.clone()));
        }
        if let Some(ref date) = self.created_before {
            params.push(("created_before".to_string(), date.clone()));
        }
        if let Some(ref scan_type) = self.scan_type {
            params.push(("scan_type".to_string(), scan_type.clone()));
        }
        if let Some(ref tags) = self.tags {
            params.push(("tags".to_string(), tags.clone()));
        }
        if let Some(ref business_unit) = self.business_unit {
            params.push(("business_unit".to_string(), business_unit.clone()));
        }
        if let Some(page) = self.page {
            params.push(("page".to_string(), page.to_string()));
        }
        if let Some(size) = self.size {
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
        let query_params = query.as_ref().map(|q| q.to_query_params());

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
        request: CreateApplicationRequest,
    ) -> Result<Application, VeracodeError> {
        let endpoint = "/appsec/v1/applications";

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
        request: UpdateApplicationRequest,
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
        let query = ApplicationQuery::new().with_policy_compliance("DID_NOT_PASS".to_string());

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
        let query = ApplicationQuery::new().with_modified_after(date.to_string());

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
        let query = ApplicationQuery::new().with_name(name.to_string());

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

    /// Get numeric app_id from application GUID.
    ///
    /// This is needed for XML API operations that require numeric IDs.
    ///
    /// # Arguments
    ///
    /// * `guid` - The application GUID
    ///
    /// # Returns
    ///
    /// A `Result` containing the numeric app_id as a string.
    pub async fn get_app_id_from_guid(&self, guid: &str) -> Result<String, VeracodeError> {
        let app = self.get_application(guid).await?;
        Ok(app.id.to_string())
    }

    /// Create application if it doesn't exist, or return existing application.
    ///
    /// This method implements the "check and create" pattern commonly needed
    /// for automated workflows.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the application
    /// * `business_criticality` - Business criticality level (required for creation)
    /// * `description` - Optional description for new applications
    /// * `team_names` - Optional list of team names to assign to the application
    ///
    /// # Returns
    ///
    /// A `Result` containing the application (existing or newly created).
    pub async fn create_application_if_not_exists(
        &self,
        name: &str,
        business_criticality: BusinessCriticality,
        description: Option<String>,
        team_names: Option<Vec<String>>,
    ) -> Result<Application, VeracodeError> {
        // First, check if application already exists
        if let Some(existing_app) = self.get_application_by_name(name).await? {
            return Ok(existing_app);
        }

        // Application doesn't exist, create it

        // Convert team names to Team objects if provided
        let teams = team_names.map(|names| {
            names
                .into_iter()
                .map(|team_name| Team {
                    team_id: None, // Will be assigned by Veracode
                    team_name: Some(team_name),
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
            },
        };

        self.create_application(create_request).await
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
        self.create_application_if_not_exists(name, business_criticality, description, None)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_params() {
        let query = ApplicationQuery::new()
            .with_name("test_app".to_string())
            .with_policy_compliance("PASSED".to_string())
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
            .with_name("MyApp".to_string())
            .with_policy_compliance("DID_NOT_PASS".to_string())
            .with_modified_after("2023-01-01T00:00:00.000Z".to_string())
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
}

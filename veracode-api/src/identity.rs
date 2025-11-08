//! Identity API functionality for managing users, teams, roles, and API credentials.
//!
//! This module provides functionality to interact with the Veracode Identity API,
//! allowing you to manage users, teams, roles, and API credentials programmatically.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{VeracodeClient, VeracodeError};

/// Represents a Veracode user account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique user ID
    pub user_id: String,
    /// Legacy user ID
    pub user_legacy_id: Option<u32>,
    /// Username for the account
    pub user_name: String,
    /// User's email address
    pub email_address: String,
    /// User's first name
    pub first_name: String,
    /// User's last name
    pub last_name: String,
    /// User account type (optional in basic response)
    pub user_type: Option<UserType>,
    /// Whether the user account is active (optional in basic response)
    pub active: Option<bool>,
    /// Whether login is enabled
    pub login_enabled: Option<bool>,
    /// Whether this is a SAML user
    pub saml_user: Option<bool>,
    /// List of roles assigned to the user (only in detailed response)
    pub roles: Option<Vec<Role>>,
    /// List of teams the user belongs to (only in detailed response)
    pub teams: Option<Vec<Team>>,
    /// Login status information (only in detailed response)
    pub login_status: Option<LoginStatus>,
    /// Date when the user was created (only in detailed response)
    pub created_date: Option<DateTime<Utc>>,
    /// Date when the user was last modified (only in detailed response)
    pub modified_date: Option<DateTime<Utc>>,
    /// API credentials information (for API service accounts, only in detailed response)
    pub api_credentials: Option<Vec<ApiCredential>>,
    /// Links for navigation
    #[serde(rename = "_links")]
    pub links: Option<serde_json::Value>,
}

/// User account types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum UserType {
    /// Regular human user account
    Human,
    /// API service account
    #[serde(rename = "API")]
    ApiService,
    /// SAML user account
    Saml,
    /// VOSP user account
    #[serde(rename = "VOSP")]
    Vosp,
}

/// Represents a user role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique role ID
    pub role_id: String,
    /// Legacy role ID (optional)
    pub role_legacy_id: Option<i32>,
    /// Role name
    pub role_name: String,
    /// Role description
    pub role_description: Option<String>,
    /// Whether this is an internal Veracode role
    pub is_internal: Option<bool>,
    /// Whether the role requires a token
    pub requires_token: Option<bool>,
    /// Whether the role is assigned to proxy users
    pub assigned_to_proxy_users: Option<bool>,
    /// Whether team admins can manage this role
    pub team_admin_manageable: Option<bool>,
    /// Whether the role is JIT assignable
    pub jit_assignable: Option<bool>,
    /// Whether the role is JIT assignable by default
    pub jit_assignable_default: Option<bool>,
    /// Whether this is an API role
    pub is_api: Option<bool>,
    /// Whether this is a scan type role
    pub is_scan_type: Option<bool>,
    /// Whether the role ignores team restrictions
    pub ignore_team_restrictions: Option<bool>,
    /// Whether the role is HMAC only
    pub is_hmac_only: Option<bool>,
    /// Organization ID (for custom roles)
    pub org_id: Option<String>,
    /// Child roles (nested roles)
    pub child_roles: Option<Vec<serde_json::Value>>,
    /// Whether the role is disabled
    pub role_disabled: Option<bool>,
    /// List of permissions granted by this role
    pub permissions: Option<Vec<Permission>>,
    /// Links for navigation
    #[serde(rename = "_links")]
    pub links: Option<serde_json::Value>,
}

/// Represents a permission within a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Permission ID (returned from API)
    pub permission_id: Option<String>,
    /// Permission name
    pub permission_name: String,
    /// Permission description (optional)
    pub description: Option<String>,
    /// Whether this permission is API only
    pub api_only: Option<bool>,
    /// Whether this permission is UI only
    pub ui_only: Option<bool>,
}

/// Represents a team
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    /// Unique team ID
    pub team_id: String,
    /// Team name
    pub team_name: String,
    /// Team description
    pub team_description: Option<String>,
    /// List of users in the team
    pub users: Option<Vec<User>>,
    /// Business unit the team belongs to
    pub business_unit: Option<BusinessUnit>,
}

/// Represents a business unit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessUnit {
    /// Unique business unit ID
    pub bu_id: String,
    /// Business unit name
    pub bu_name: String,
    /// Business unit description
    pub bu_description: Option<String>,
    /// List of teams in the business unit
    pub teams: Option<Vec<Team>>,
}

/// Represents API credentials
#[derive(Clone, Serialize, Deserialize)]
pub struct ApiCredential {
    /// Unique API credential ID
    pub api_id: String,
    /// API key (only shown when first created) - automatically redacted in debug output
    pub api_key: Option<String>,
    /// Expiration date of the credentials
    pub expiration_ts: Option<DateTime<Utc>>,
    /// Whether the credentials are active
    pub active: Option<bool>,
    /// Creation date
    pub created_date: Option<DateTime<Utc>>,
}

    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
/// Custom Debug implementation for `ApiCredential` that redacts sensitive information
impl std::fmt::Debug for ApiCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiCredential")
            .field("api_id", &self.api_id)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("expiration_ts", &self.expiration_ts)
            .field("active", &self.active)
            .field("created_date", &self.created_date)
            .finish()
    }
}

/// Login status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStatus {
    /// Last login date
    pub last_login_date: Option<DateTime<Utc>>,
    /// Whether the user has ever logged in
    pub never_logged_in: Option<bool>,
    /// Number of failed login attempts
    pub failed_login_attempts: Option<u32>,
}

/// Request structure for creating a new user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    /// Email address (required)
    pub email_address: String,
    /// First name (required)
    pub first_name: String,
    /// Last name (required)
    pub last_name: String,
    /// Username (required)
    pub user_name: Option<String>,
    /// User type (defaults to HUMAN)
    pub user_type: Option<UserType>,
    /// Whether to send email invitation
    pub send_email_invitation: Option<bool>,
    /// List of role IDs to assign
    pub role_ids: Option<Vec<String>>,
    /// List of team IDs to assign (at least one required for human users)
    pub team_ids: Option<Vec<String>>,
    /// List of permissions to assign
    pub permissions: Option<Vec<Permission>>,
}

/// Request structure for updating a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    /// Email address (required)
    pub email_address: String,
    /// Username (required)
    pub user_name: String,
    /// First name
    pub first_name: Option<String>,
    /// Last name
    pub last_name: Option<String>,
    /// Whether the account is active
    pub active: Option<bool>,
    /// List of role IDs to assign (required)
    pub role_ids: Vec<String>,
    /// List of team IDs to assign (required)
    pub team_ids: Vec<String>,
}

/// Request structure for creating a team
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTeamRequest {
    /// Team name (required)
    pub team_name: String,
    /// Team description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_description: Option<String>,
    /// Business unit ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_unit_id: Option<String>,
    /// List of user IDs to add to the team
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_ids: Option<Vec<String>>,
}

/// Request structure for updating a team
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTeamRequest {
    /// Team name
    pub team_name: Option<String>,
    /// Team description
    pub team_description: Option<String>,
    /// Business unit ID
    pub business_unit_id: Option<String>,
    /// List of user IDs to add to the team (when using incremental=true)
    pub user_ids: Option<Vec<String>>,
}

/// Request structure for creating API credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiCredentialRequest {
    /// User ID to create credentials for (optional, defaults to current user)
    pub user_id: Option<String>,
    /// Expiration date (optional)
    pub expiration_ts: Option<DateTime<Utc>>,
}

/// Response wrapper for paginated user results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersResponse {
    /// List of users (direct array) or embedded
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<User>,
    /// Embedded users (alternative structure)
    #[serde(rename = "_embedded")]
    pub embedded: Option<EmbeddedUsers>,
    /// Pagination information
    pub page: Option<PageInfo>,
    /// Response links
    #[serde(rename = "_links")]
    pub links: Option<HashMap<String, Link>>,
}

/// Embedded users in the response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedUsers {
    /// List of users
    pub users: Vec<User>,
}

/// Response wrapper for paginated team results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsResponse {
    /// List of teams (direct array) or embedded
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub teams: Vec<Team>,
    /// Embedded teams (alternative structure)
    #[serde(rename = "_embedded")]
    pub embedded: Option<EmbeddedTeams>,
    /// Pagination information
    pub page: Option<PageInfo>,
}

/// Embedded teams in the response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedTeams {
    /// List of teams
    pub teams: Vec<Team>,
}

/// Response wrapper for paginated role results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolesResponse {
    /// List of roles (direct array) or embedded
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<Role>,
    /// Embedded roles (alternative structure)
    #[serde(rename = "_embedded")]
    pub embedded: Option<EmbeddedRoles>,
    /// Pagination information
    pub page: Option<PageInfo>,
}

/// Embedded roles in the response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedRoles {
    /// List of roles
    pub roles: Vec<Role>,
}

/// Pagination information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    /// Current page number
    pub number: Option<u32>,
    /// Number of items per page
    pub size: Option<u32>,
    /// Total number of elements
    pub total_elements: Option<u64>,
    /// Total number of pages
    pub total_pages: Option<u32>,
}

/// Link information for navigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    /// URL for the link
    pub href: String,
}

/// Query parameters for user search
#[derive(Debug, Clone, Default)]
pub struct UserQuery {
    /// Filter by username
    pub user_name: Option<String>,
    /// Filter by email address
    pub email_address: Option<String>,
    /// Filter by role ID
    pub role_id: Option<String>,
    /// Filter by user type
    pub user_type: Option<UserType>,
    /// Filter by login status
    pub login_status: Option<String>,
    /// Page number
    pub page: Option<u32>,
    /// Items per page
    pub size: Option<u32>,
}

impl UserQuery {
    /// Create a new empty user query
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by username
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.user_name = Some(username.into());
        self
    }

    /// Filter by email address
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email_address = Some(email.into());
        self
    }

    /// Filter by role ID
    pub fn with_role_id(mut self, role_id: impl Into<String>) -> Self {
        self.role_id = Some(role_id.into());
        self
    }

    /// Filter by user type
    #[must_use]
    pub fn with_user_type(mut self, user_type: UserType) -> Self {
        self.user_type = Some(user_type);
        self
    }

    /// Set pagination
    #[must_use]
    pub fn with_pagination(mut self, page: u32, size: u32) -> Self {
        self.page = Some(page);
        self.size = Some(size);
        self
    }

    /// Convert to query parameters
    #[must_use]
    pub fn to_query_params(&self) -> Vec<(String, String)> {
        Vec::from(self) // Delegate to trait
    }
}

// Trait implementations for memory optimization
impl From<&UserQuery> for Vec<(String, String)> {
    fn from(query: &UserQuery) -> Self {
        let mut params = Vec::new();

        if let Some(ref username) = query.user_name {
            params.push(("user_name".to_string(), username.clone())); // Still clone for borrowing
        }
        if let Some(ref email) = query.email_address {
            params.push(("email_address".to_string(), email.clone()));
        }
        if let Some(ref role_id) = query.role_id {
            params.push(("role_id".to_string(), role_id.clone()));
        }
        if let Some(ref user_type) = query.user_type {
            let type_str = match user_type {
                UserType::Human => "HUMAN",
                UserType::ApiService => "API",
                UserType::Saml => "SAML",
                UserType::Vosp => "VOSP",
            };
            params.push(("user_type".to_string(), type_str.to_string()));
        }
        if let Some(ref login_status) = query.login_status {
            params.push(("login_status".to_string(), login_status.clone()));
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

impl From<UserQuery> for Vec<(String, String)> {
    fn from(query: UserQuery) -> Self {
        let mut params = Vec::new();

        if let Some(username) = query.user_name {
            params.push(("user_name".to_string(), username)); // MOVE - no clone!
        }
        if let Some(email) = query.email_address {
            params.push(("email_address".to_string(), email)); // MOVE - no clone!
        }
        if let Some(role_id) = query.role_id {
            params.push(("role_id".to_string(), role_id)); // MOVE - no clone!
        }
        if let Some(user_type) = query.user_type {
            let type_str = match user_type {
                UserType::Human => "HUMAN",
                UserType::ApiService => "API",
                UserType::Saml => "SAML",
                UserType::Vosp => "VOSP",
            };
            params.push(("user_type".to_string(), type_str.to_string()));
        }
        if let Some(login_status) = query.login_status {
            params.push(("login_status".to_string(), login_status)); // MOVE - no clone!
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

/// Identity-specific error types
#[derive(Debug)]
#[must_use = "Need to handle all error enum types."]
pub enum IdentityError {
    /// General API error
    Api(VeracodeError),
    /// User not found
    UserNotFound,
    /// Team not found
    TeamNotFound,
    /// Role not found
    RoleNotFound,
    /// Invalid input data
    InvalidInput(String),
    /// Permission denied
    PermissionDenied(String),
    /// User already exists
    UserAlreadyExists(String),
    /// Team already exists
    TeamAlreadyExists(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::Api(err) => write!(f, "API error: {err}"),
            IdentityError::UserNotFound => write!(f, "User not found"),
            IdentityError::TeamNotFound => write!(f, "Team not found"),
            IdentityError::RoleNotFound => write!(f, "Role not found"),
            IdentityError::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
            IdentityError::PermissionDenied(msg) => write!(f, "Permission denied: {msg}"),
            IdentityError::UserAlreadyExists(msg) => write!(f, "User already exists: {msg}"),
            IdentityError::TeamAlreadyExists(msg) => write!(f, "Team already exists: {msg}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<VeracodeError> for IdentityError {
    fn from(err: VeracodeError) -> Self {
        IdentityError::Api(err)
    }
}

impl From<reqwest::Error> for IdentityError {
    fn from(err: reqwest::Error) -> Self {
        IdentityError::Api(VeracodeError::Http(err))
    }
}

impl From<serde_json::Error> for IdentityError {
    fn from(err: serde_json::Error) -> Self {
        IdentityError::Api(VeracodeError::Serialization(err))
    }
}

/// Identity API operations
pub struct IdentityApi<'a> {
    client: &'a VeracodeClient,
}

impl<'a> IdentityApi<'a> {
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// Create a new `IdentityApi` instance
    #[must_use]
    pub fn new(client: &'a VeracodeClient) -> Self {
        Self { client }
    }

    /// List users with optional filtering
    ///
    /// # Arguments
    ///
    /// * `query` - Optional query parameters for filtering users
    ///
    /// # Returns
    ///
    /// A `Result` containing a list of users or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn list_users(&self, query: Option<UserQuery>) -> Result<Vec<User>, IdentityError> {
        let endpoint = "/api/authn/v2/users";
        let query_params = query.as_ref().map(Vec::from);

        let response = self.client.get(endpoint, query_params.as_deref()).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;

                // Try embedded response format first
                if let Ok(users_response) = serde_json::from_str::<UsersResponse>(&response_text) {
                    let users = if !users_response.users.is_empty() {
                        users_response.users
                    } else if let Some(embedded) = users_response.embedded {
                        embedded.users
                    } else {
                        Vec::new()
                    };
                    return Ok(users);
                }

                // Try direct array as fallback
                if let Ok(users) = serde_json::from_str::<Vec<User>>(&response_text) {
                    return Ok(users);
                }

                Err(IdentityError::Api(VeracodeError::InvalidResponse(
                    "Unable to parse users response".to_string(),
                )))
            }
            404 => Err(IdentityError::UserNotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Get a specific user by ID
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user to retrieve
    ///
    /// # Returns
    ///
    /// A `Result` containing the user or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn get_user(&self, user_id: &str) -> Result<User, IdentityError> {
        let endpoint = format!("/api/authn/v2/users/{user_id}");

        let response = self.client.get(&endpoint, None).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let user: User = response.json().await?;
                Ok(user)
            }
            404 => Err(IdentityError::UserNotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Create a new user
    ///
    /// # Arguments
    ///
    /// * `request` - The user creation request
    ///
    /// # Returns
    ///
    /// A `Result` containing the created user or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, IdentityError> {
        let endpoint = "/api/authn/v2/users";

        let mut fixed_request = request.clone();

        // Both email_address and user_name are required by the API
        if fixed_request.user_name.is_none() {
            return Err(IdentityError::InvalidInput(
                "user_name is required".to_string(),
            ));
        }

        // Team membership validation: ALL users must either have team assignment OR "No Team Restrictions" role
        let has_teams = fixed_request
            .team_ids
            .as_ref()
            .is_some_and(|teams| !teams.is_empty());

        if !has_teams {
            // Check if user has "No Team Restrictions" role (works for both human and API users)
            let has_no_team_restriction_role = if let Some(ref role_ids) = fixed_request.role_ids {
                // Get available roles to check role descriptions
                let roles = self.list_roles().await?;
                role_ids.iter().any(|role_id| {
                    roles.iter().any(|r| {
                        &r.role_id == role_id
                            && (r
                                .role_description
                                .as_ref()
                                .is_some_and(|desc| desc == "No Team Restriction API")
                                || r.role_name.to_lowercase() == "noteamrestrictionapi")
                    })
                })
            } else {
                false
            };

            if !has_no_team_restriction_role {
                return Err(IdentityError::InvalidInput(
                    "You must select at least one team for this user, or select No Team Restrictions role".to_string()
                ));
            }
        }

        // Determine user type flags early
        let is_api_user = matches!(fixed_request.user_type, Some(UserType::ApiService));
        let is_saml_user = matches!(fixed_request.user_type, Some(UserType::Saml));

        // Validate role assignments for API users
        if is_api_user && let Some(ref provided_role_ids) = fixed_request.role_ids {
            let roles = self.list_roles().await?;

            // Define human-only role descriptions (from userrolesbydescription file)
            let human_role_descriptions = [
                "Creator",
                "Executive",
                "Mitigation Approver",
                "Reviewer",
                "Sandbox User",
                "Security Lead",
                "Team Admin",
                "Workspace Editor",
                "Analytics Creator",
                "Delete Scans",
                "Greenlight IDE User",
                "Policy Administrator",
                "Sandbox Administrator",
                "Security Insights",
                "Submitter",
                "Workspace Administrator",
            ];

            for role_id in provided_role_ids {
                if let Some(role) = roles.iter().find(|r| &r.role_id == role_id) {
                    // Check if this is a human-only role
                    if let Some(ref desc) = role.role_description
                        && human_role_descriptions.contains(&desc.as_str())
                    {
                        return Err(IdentityError::InvalidInput(format!(
                            "Role '{}' (description: '{}') is a human-only role and cannot be assigned to API users.",
                            role.role_name, desc
                        )));
                    }

                    // API users can only be assigned roles where is_api is true
                    if role.is_api != Some(true) {
                        return Err(IdentityError::InvalidInput(format!(
                            "Role '{}' (is_api: {}) cannot be assigned to API users. API users can only be assigned API roles.",
                            role.role_name,
                            role.is_api.map_or("None".to_string(), |b| b.to_string())
                        )));
                    }
                }
            }
        }

        // If no roles provided, assign default roles (any scan and submitter)
        if fixed_request
            .role_ids
            .as_ref()
            .is_none_or(|roles| roles.is_empty())
        {
            // Get available roles to find default ones
            let roles = self.list_roles().await?;
            let mut default_role_ids = Vec::new();

            // Based on Veracode documentation, assign appropriate default roles
            if is_api_user {
                // For API service accounts, assign apisubmitanyscan role
                if let Some(api_submit_role) = roles
                    .iter()
                    .find(|r| r.role_name.to_lowercase() == "apisubmitanyscan")
                {
                    default_role_ids.push(api_submit_role.role_id.clone());
                }

                // Always assign noteamrestrictionapi role for API users (required for team restrictions)
                if let Some(noteam_role) = roles
                    .iter()
                    .find(|r| r.role_name.to_lowercase() == "noteamrestrictionapi")
                {
                    default_role_ids.push(noteam_role.role_id.clone());
                }
            } else {
                // For human users (Human/SAML/VOSP), start with Submitter as it's the most basic role
                if let Some(submitter_role) = roles.iter().find(|r| {
                    r.role_description
                        .as_ref()
                        .is_some_and(|desc| desc == "Submitter")
                }) {
                    default_role_ids.push(submitter_role.role_id.clone());
                } else if let Some(creator_role) = roles.iter().find(|r| {
                    r.role_description
                        .as_ref()
                        .is_some_and(|desc| desc == "Creator")
                }) {
                    default_role_ids.push(creator_role.role_id.clone());
                } else if let Some(reviewer_role) = roles.iter().find(|r| {
                    r.role_description
                        .as_ref()
                        .is_some_and(|desc| desc == "Reviewer")
                }) {
                    default_role_ids.push(reviewer_role.role_id.clone());
                }

                // If user has no teams, also assign "No Team Restrictions" role
                if !has_teams
                    && let Some(no_team_role) = roles.iter().find(|r| {
                        r.role_description
                            .as_ref()
                            .is_some_and(|desc| desc == "No Team Restriction API")
                            || r.role_name.to_lowercase() == "noteamrestrictionapi"
                    })
                {
                    default_role_ids.push(no_team_role.role_id.clone());
                }
            }

            // If we found default roles, use them
            if !default_role_ids.is_empty() {
                fixed_request.role_ids = Some(default_role_ids);
            }
        }

        // If no permissions provided, assign default permissions based on user type
        if fixed_request
            .permissions
            .as_ref()
            .is_none_or(|p| p.is_empty())
        {
            if is_api_user {
                // For API users, assign "apiUser" permission (from defaultapiuserperm file)
                let api_user_permission = Permission {
                    permission_id: None,
                    permission_name: "apiUser".to_string(),
                    description: Some("API User".to_string()),
                    api_only: Some(false),
                    ui_only: Some(false),
                };
                fixed_request.permissions = Some(vec![api_user_permission]);
            } else {
                // For human users, assign "humanUser" permission
                let human_user_permission = Permission {
                    permission_id: None,
                    permission_name: "humanUser".to_string(),
                    description: Some("Human User".to_string()),
                    api_only: Some(false),
                    ui_only: Some(false),
                };
                fixed_request.permissions = Some(vec![human_user_permission]);
            }
        }

        // Create the payload with the correct role structure
        let roles_payload = if let Some(ref role_ids) = fixed_request.role_ids {
            role_ids
                .iter()
                .map(|id| serde_json::json!({"role_id": id}))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        // Create the payload with the correct team structure
        let teams_payload = if let Some(ref team_ids) = fixed_request.team_ids {
            team_ids
                .iter()
                .map(|id| serde_json::json!({"team_id": id}))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        // Create the payload with the correct permissions structure
        let permissions_payload = if let Some(ref permissions) = fixed_request.permissions {
            permissions
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "permission_name": p.permission_name,
                        "api_only": p.api_only.unwrap_or(false),
                        "ui_only": p.ui_only.unwrap_or(false)
                    })
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        // Build payload conditionally to exclude null fields and user_type for API users
        let mut payload = serde_json::json!({
            "email_address": fixed_request.email_address,
            "first_name": fixed_request.first_name,
            "last_name": fixed_request.last_name,
            "apiUser": is_api_user,
            "samlUser": is_saml_user,
            "active": true, // New users are active by default
            "send_email_invitation": fixed_request.send_email_invitation.unwrap_or(false)
        });

        // Add user_name only if it's not None
        if let Some(ref user_name) = fixed_request.user_name
            && let Some(obj) = payload.as_object_mut()
        {
            obj.insert("user_name".to_string(), serde_json::json!(user_name));
        }

        // Add roles only if not empty
        if !roles_payload.is_empty()
            && let Some(obj) = payload.as_object_mut()
        {
            obj.insert("roles".to_string(), serde_json::json!(roles_payload));
        }

        // Add teams only if not empty
        if !teams_payload.is_empty()
            && let Some(obj) = payload.as_object_mut()
        {
            obj.insert("teams".to_string(), serde_json::json!(teams_payload));
        }

        // Add permissions only if not empty
        if !permissions_payload.is_empty()
            && let Some(obj) = payload.as_object_mut()
        {
            obj.insert(
                "permissions".to_string(),
                serde_json::json!(permissions_payload),
            );
        }

        let response = self.client.post(endpoint, Some(&payload)).await?;

        let status = response.status().as_u16();
        match status {
            200 | 201 => {
                let user: User = response.json().await?;
                Ok(user)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                if error_text.contains("already exists") {
                    Err(IdentityError::UserAlreadyExists(error_text))
                } else {
                    Err(IdentityError::InvalidInput(error_text))
                }
            }
            403 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::PermissionDenied(error_text))
            }
            415 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP 415 Unsupported Media Type: {error_text}"
                ))))
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Update an existing user
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user to update
    /// * `request` - The user update request
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated user or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn update_user(
        &self,
        user_id: &str,
        request: UpdateUserRequest,
    ) -> Result<User, IdentityError> {
        let endpoint = format!("/api/authn/v2/users/{user_id}");

        // Create the payload with the correct role and team structure
        let roles_payload = request
            .role_ids
            .iter()
            .map(|id| serde_json::json!({"role_id": id}))
            .collect::<Vec<_>>();

        let teams_payload = request
            .team_ids
            .iter()
            .map(|id| serde_json::json!({"team_id": id}))
            .collect::<Vec<_>>();

        let payload = serde_json::json!({
            "email_address": request.email_address,
            "user_name": request.user_name,
            "first_name": request.first_name,
            "last_name": request.last_name,
            "active": request.active,
            "roles": roles_payload,
            "teams": teams_payload
        });

        let response = self.client.put(&endpoint, Some(&payload)).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let user: User = response.json().await?;
                Ok(user)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::InvalidInput(error_text))
            }
            403 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::PermissionDenied(error_text))
            }
            404 => Err(IdentityError::UserNotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Delete a user
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user to delete
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn delete_user(&self, user_id: &str) -> Result<(), IdentityError> {
        let endpoint = format!("/api/authn/v2/users/{user_id}");

        let response = self.client.delete(&endpoint).await?;

        let status = response.status().as_u16();
        match status {
            200 | 204 => Ok(()),
            403 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::PermissionDenied(error_text))
            }
            404 => Err(IdentityError::UserNotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// List all roles
    ///
    /// # Returns
    ///
    /// A `Result` containing a list of roles or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn list_roles(&self) -> Result<Vec<Role>, IdentityError> {
        let endpoint = "/api/authn/v2/roles";
        let mut all_roles = Vec::new();
        let mut page: u32 = 0;
        let page_size = 500;

        // Simple pagination loop - fetch pages until empty
        loop {
            let query_params = vec![
                ("page".to_string(), page.to_string()),
                ("size".to_string(), page_size.to_string()),
            ];

            let response = self.client.get(endpoint, Some(&query_params)).await?;
            let status = response.status().as_u16();

            match status {
                200 => {
                    let response_text = response.text().await?;

                    // Try embedded response format
                    if let Ok(roles_response) =
                        serde_json::from_str::<RolesResponse>(&response_text)
                    {
                        let page_roles = if !roles_response.roles.is_empty() {
                            roles_response.roles
                        } else if let Some(embedded) = roles_response.embedded {
                            embedded.roles
                        } else {
                            Vec::new()
                        };

                        if page_roles.is_empty() {
                            break; // No more roles to fetch
                        }

                        all_roles.extend(page_roles);
                        page = page.saturating_add(1);

                        // Check pagination info if available
                        if let Some(page_info) = roles_response.page
                            && let (Some(current_page), Some(total_pages)) =
                                (page_info.number, page_info.total_pages)
                            && current_page.saturating_add(1) >= total_pages
                        {
                            break;
                        }

                        continue;
                    }

                    // Try direct array as fallback
                    if let Ok(roles) = serde_json::from_str::<Vec<Role>>(&response_text) {
                        if roles.is_empty() {
                            break;
                        }
                        all_roles.extend(roles);
                        page = page.saturating_add(1);
                        continue;
                    }

                    // If we can't parse, maybe it's the first page without pagination
                    if page == 0 {
                        return Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                            "Unable to parse roles response: {response_text}"
                        ))));
                    }
                    break; // End of pages
                }
                _ => {
                    let error_text = response.text().await.unwrap_or_default();
                    return Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                        "HTTP {status}: {error_text}"
                    ))));
                }
            }
        }

        Ok(all_roles)
    }

    /// List all teams with pagination support
    ///
    /// # Returns
    ///
    /// A `Result` containing a list of all teams across all pages or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn list_teams(&self) -> Result<Vec<Team>, IdentityError> {
        let endpoint = "/api/authn/v2/teams";
        let mut all_teams = Vec::new();
        let mut page: u32 = 0;
        let page_size = 500;

        // Simple pagination loop - fetch pages until empty
        loop {
            // Safety check to prevent infinite loops
            if page > 100 {
                break;
            }

            let query_params = vec![
                ("page".to_string(), page.to_string()),
                ("size".to_string(), page_size.to_string()),
            ];

            let response = self.client.get(endpoint, Some(&query_params)).await?;
            let status = response.status().as_u16();

            match status {
                200 => {
                    let response_text = response.text().await?;

                    // Try embedded response format first
                    if let Ok(teams_response) =
                        serde_json::from_str::<TeamsResponse>(&response_text)
                    {
                        let page_teams = if !teams_response.teams.is_empty() {
                            teams_response.teams
                        } else if let Some(embedded) = teams_response.embedded {
                            embedded.teams
                        } else {
                            Vec::new()
                        };

                        if page_teams.is_empty() {
                            break; // No more teams to fetch
                        }

                        all_teams.extend(page_teams);
                        page = page.saturating_add(1);

                        // Check pagination info if available
                        if let Some(page_info) = teams_response.page
                            && let (Some(current_page), Some(total_pages)) =
                                (page_info.number, page_info.total_pages)
                            && current_page.saturating_add(1) >= total_pages
                        {
                            break; // Last page reached
                        }

                        continue;
                    }

                    // Try direct array as fallback
                    if let Ok(teams) = serde_json::from_str::<Vec<Team>>(&response_text) {
                        if teams.is_empty() {
                            break;
                        }
                        all_teams.extend(teams);
                        page = page.saturating_add(1);
                        continue;
                    }

                    // If we can't parse, maybe it's the first page without pagination
                    if page == 0 {
                        return Err(IdentityError::Api(VeracodeError::InvalidResponse(
                            "Unable to parse teams response".to_string(),
                        )));
                    }
                    // We've gotten some teams, but this page failed - break
                    break;
                }
                _ => {
                    let error_text = response.text().await.unwrap_or_default();
                    return Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                        "HTTP {status}: {error_text}"
                    ))));
                }
            }
        }

        Ok(all_teams)
    }

    /// Create a new team
    ///
    /// # Arguments
    ///
    /// * `request` - The team creation request
    ///
    /// # Returns
    ///
    /// A `Result` containing the created team or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn create_team(&self, request: CreateTeamRequest) -> Result<Team, IdentityError> {
        let endpoint = "/api/authn/v2/teams";

        let response = self.client.post(endpoint, Some(&request)).await?;

        let status = response.status().as_u16();
        match status {
            200 | 201 => {
                let team: Team = response.json().await?;
                Ok(team)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                if error_text.contains("already exists") {
                    Err(IdentityError::TeamAlreadyExists(error_text))
                } else {
                    Err(IdentityError::InvalidInput(error_text))
                }
            }
            403 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::PermissionDenied(error_text))
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Delete a team
    ///
    /// # Arguments
    ///
    /// * `team_id` - The ID of the team to delete
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn delete_team(&self, team_id: &str) -> Result<(), IdentityError> {
        let endpoint = format!("/api/authn/v2/teams/{team_id}");

        let response = self.client.delete(&endpoint).await?;

        let status = response.status().as_u16();
        match status {
            200 | 204 => Ok(()),
            403 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::PermissionDenied(error_text))
            }
            404 => Err(IdentityError::TeamNotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Get a team by its name
    ///
    /// Searches for a team by exact name match. The API may return multiple teams
    /// that match the search criteria, so this method performs an exact string
    /// comparison to find the specific team requested.
    ///
    /// # Arguments
    ///
    /// * `team_name` - The exact name of the team to find
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Option<Team>` if found, or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn get_team_by_name(&self, team_name: &str) -> Result<Option<Team>, IdentityError> {
        let endpoint = "/api/authn/v2/teams";

        let query_params = vec![
            ("page".to_string(), "0".to_string()),
            ("size".to_string(), "50".to_string()),
            ("team_name".to_string(), team_name.to_string()),
            ("ignore_self_teams".to_string(), "false".to_string()),
            ("only_manageable".to_string(), "false".to_string()),
            ("deleted".to_string(), "false".to_string()),
        ];

        log::debug!("🔍 Team lookup request - endpoint: {}", endpoint);
        log::debug!(
            "🔍 Team lookup request - query parameters: [{}]",
            query_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(", ")
        );
        log::debug!(
            "🔍 Team lookup request - searching for team: '{}'",
            team_name
        );

        let response = self.client.get(endpoint, Some(&query_params)).await?;
        let status = response.status().as_u16();

        log::debug!("🔍 Team lookup response - HTTP status: {}", status);

        match status {
            200 => {
                let response_text = response.text().await?;
                log::debug!("🔍 Team lookup response - body: {}", response_text);

                // Helper closure to process teams list and find exact case-insensitive match
                let process_teams = |teams: Vec<Team>, format_description: &str| -> Option<Team> {
                    let team_count = teams.len();
                    log::debug!(
                        "🔍 Team lookup response - found {} teams total ({})",
                        team_count,
                        format_description
                    );
                    for (i, team) in teams.iter().enumerate() {
                        log::debug!(
                            "🔍 Team lookup response - team {}: '{}' (GUID: {})",
                            i.saturating_add(1),
                            team.team_name,
                            team.team_id
                        );
                    }

                    // Find exact case-insensitive match by team name
                    // Note: API search is case-insensitive, so we match case-insensitively too
                    let found_team = teams
                        .into_iter()
                        .find(|team| team.team_name.to_lowercase() == team_name.to_lowercase());
                    if let Some(ref team) = found_team {
                        log::debug!(
                            "🔍 Team lookup result - found case-insensitive match: '{}' (searched for '{}') with GUID: {}",
                            team.team_name,
                            team_name,
                            team.team_id
                        );
                    } else {
                        log::debug!(
                            "🔍 Team lookup result - no case-insensitive match for '{}' among {} teams",
                            team_name,
                            team_count
                        );
                    }
                    found_team
                };

                // Parse response - prioritize embedded format as shown in your example
                if let Ok(teams_response) = serde_json::from_str::<TeamsResponse>(&response_text) {
                    let teams = if let Some(embedded) = teams_response.embedded {
                        embedded.teams
                    } else if !teams_response.teams.is_empty() {
                        teams_response.teams
                    } else {
                        Vec::new()
                    };
                    Ok(process_teams(teams, "embedded format"))
                } else if let Ok(teams) = serde_json::from_str::<Vec<Team>>(&response_text) {
                    // Fallback for direct array (less common based on your example)
                    Ok(process_teams(teams, "direct array"))
                } else {
                    Err(IdentityError::Api(VeracodeError::InvalidResponse(
                        "Unable to parse team response".to_string(),
                    )))
                }
            }
            404 => {
                log::debug!(
                    "🔍 Team lookup result - HTTP 404: team '{}' not found",
                    team_name
                );
                Ok(None) // Team not found
            }
            403 => {
                let error_text = response.text().await.unwrap_or_default();
                log::debug!(
                    "🔍 Team lookup error - HTTP 403: permission denied - {}",
                    error_text
                );
                Err(IdentityError::PermissionDenied(error_text))
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                log::debug!("🔍 Team lookup error - HTTP {}: {}", status, error_text);
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Get a team's GUID by its name
    ///
    /// This is a convenience method for application creation workflows where
    /// only the team GUID is needed.
    ///
    /// # Arguments
    ///
    /// * `team_name` - The exact name of the team to find
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Option<String>` with the team's GUID if found, or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn get_team_guid_by_name(
        &self,
        team_name: &str,
    ) -> Result<Option<String>, IdentityError> {
        match self.get_team_by_name(team_name).await? {
            Some(team) => Ok(Some(team.team_id)),
            None => Ok(None),
        }
    }

    /// Create API credentials
    ///
    /// # Arguments
    ///
    /// * `request` - The API credential creation request
    ///
    /// # Returns
    ///
    /// A `Result` containing the created API credentials or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn create_api_credentials(
        &self,
        request: CreateApiCredentialRequest,
    ) -> Result<ApiCredential, IdentityError> {
        let endpoint = "/api/authn/v2/api_credentials";

        let response = self.client.post(endpoint, Some(&request)).await?;

        let status = response.status().as_u16();
        match status {
            200 | 201 => {
                let credentials: ApiCredential = response.json().await?;
                Ok(credentials)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::InvalidInput(error_text))
            }
            403 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::PermissionDenied(error_text))
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Revoke API credentials
    ///
    /// # Arguments
    ///
    /// * `api_creds_id` - The ID of the API credentials to revoke
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn revoke_api_credentials(&self, api_creds_id: &str) -> Result<(), IdentityError> {
        let endpoint = format!("/api/authn/v2/api_credentials/{api_creds_id}");

        let response = self.client.delete(&endpoint).await?;

        let status = response.status().as_u16();
        match status {
            200 | 204 => Ok(()), // Accept both 200 OK and 204 No Content as success
            403 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::PermissionDenied(error_text))
            }
            404 => Err(IdentityError::UserNotFound), // API credentials not found
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(IdentityError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }
}

/// Convenience methods for common operations
impl<'a> IdentityApi<'a> {
    /// Find a user by email address
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to search for
    ///
    /// # Returns
    ///
    /// A `Result` containing the user if found, or None if not found
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, IdentityError> {
        let query = UserQuery::new().with_email(email);
        let users = self.list_users(Some(query)).await?;
        Ok(users.into_iter().find(|u| u.email_address == email))
    }

    /// Find a user by username
    ///
    /// # Arguments
    ///
    /// * `username` - The username to search for
    ///
    /// # Returns
    ///
    /// A `Result` containing the user if found, or None if not found
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<User>, IdentityError> {
        let query = UserQuery::new().with_username(username);
        let users = self.list_users(Some(query)).await?;
        Ok(users.into_iter().find(|u| u.user_name == username))
    }

    /// Create a simple user with basic information
    ///
    /// # Arguments
    ///
    /// * `email` - User's email address
    /// * `username` - User's username
    /// * `first_name` - User's first name
    /// * `last_name` - User's last name
    /// * `team_ids` - List of team IDs to assign (at least one required)
    ///
    /// # Returns
    ///
    /// A `Result` containing the created user or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn create_simple_user(
        &self,
        email: &str,
        username: &str,
        first_name: &str,
        last_name: &str,
        team_ids: Vec<String>,
    ) -> Result<User, IdentityError> {
        let request = CreateUserRequest {
            email_address: email.to_string(),
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            user_name: Some(username.to_string()),
            user_type: Some(UserType::Human),
            send_email_invitation: Some(true),
            role_ids: None, // Will be auto-assigned to "any scan" and "submitter" roles
            team_ids: Some(team_ids),
            permissions: None, // Will use default permissions for human users
        };

        self.create_user(request).await
    }

    /// Create an API service account
    ///
    /// # Arguments
    ///
    /// * `email` - Service account email address
    /// * `username` - Service account username
    /// * `first_name` - Service account first name
    /// * `last_name` - Service account last name
    /// * `role_ids` - List of role IDs to assign
    /// * `team_ids` - Optional list of team IDs to assign
    ///
    /// # Returns
    ///
    /// A `Result` containing the created user or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the identity resource is not found,
    /// or authentication/authorization fails.
    pub async fn create_api_service_account(
        &self,
        email: &str,
        username: &str,
        first_name: &str,
        last_name: &str,
        role_ids: Vec<String>,
        team_ids: Option<Vec<String>>,
    ) -> Result<User, IdentityError> {
        let request = CreateUserRequest {
            email_address: email.to_string(),
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            user_name: Some(username.to_string()),
            user_type: Some(UserType::ApiService), // Still needed for internal logic
            send_email_invitation: Some(false),
            role_ids: Some(role_ids),
            team_ids,          // Use the provided team IDs
            permissions: None, // Will auto-assign "apiUser" permission for API users
        };

        self.create_user(request).await
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_user_query_params() {
        let query = UserQuery::new()
            .with_username("testuser")
            .with_email("test@example.com")
            .with_user_type(UserType::Human)
            .with_pagination(1, 50);

        let params: Vec<_> = query.into();
        assert_eq!(params.len(), 5); // username, email, user_type, page, size
        assert!(params.contains(&("user_name".to_string(), "testuser".to_string())));
        assert!(params.contains(&("email_address".to_string(), "test@example.com".to_string())));
        assert!(params.contains(&("user_type".to_string(), "HUMAN".to_string())));
        assert!(params.contains(&("page".to_string(), "1".to_string())));
        assert!(params.contains(&("size".to_string(), "50".to_string())));
    }

    #[test]
    fn test_user_type_serialization() {
        assert_eq!(
            serde_json::to_string(&UserType::Human).expect("should serialize to json"),
            "\"HUMAN\""
        );
        assert_eq!(
            serde_json::to_string(&UserType::ApiService).expect("should serialize to json"),
            "\"API\""
        );
        assert_eq!(
            serde_json::to_string(&UserType::Saml).expect("should serialize to json"),
            "\"SAML\""
        );
        assert_eq!(
            serde_json::to_string(&UserType::Vosp).expect("should serialize to json"),
            "\"VOSP\""
        );
    }
}

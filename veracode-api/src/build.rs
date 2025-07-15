//! Build API functionality for Veracode platform.
//!
//! This module provides functionality to interact with the Veracode Build XML APIs,
//! allowing you to create, update, delete, and query builds for applications and sandboxes.
//! These operations use the XML API endpoints (analysiscenter.veracode.com).

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, NaiveDate};
use std::collections::HashMap;
use quick_xml::Reader;
use quick_xml::events::Event;

use crate::{VeracodeClient, VeracodeError};

/// Valid lifecycle stage values for Veracode builds
pub const LIFECYCLE_STAGES: &[&str] = &[
    "In Development (pre-Alpha)",
    "Internal or Alpha Testing", 
    "External or Beta Testing",
    "Deployed",
    "Maintenance",
    "Cannot Disclose",
    "Not Specified"
];

/// Validate if a lifecycle stage value is valid
pub fn is_valid_lifecycle_stage(stage: &str) -> bool {
    LIFECYCLE_STAGES.contains(&stage)
}

/// Get the default lifecycle stage for development builds
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
    pub fn from_str(status: &str) -> Self {
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
    pub fn is_safe_to_delete(&self, deletion_policy: u8) -> bool {
        match deletion_policy {
            0 => false, // Never delete
            1 => {
                // Delete only safe builds (incomplete, failed, cancelled states)
                matches!(self,
                    BuildStatus::Incomplete |
                    BuildStatus::NotSubmitted |
                    BuildStatus::PreScanFailed |
                    BuildStatus::PreScanCancelled |
                    BuildStatus::PrescanFailed |
                    BuildStatus::PrescanCancelled |
                    BuildStatus::ScanCancelled |
                    BuildStatus::Failed |
                    BuildStatus::Cancelled
                )
            },
            2 => {
                // Delete any build except Results Ready
                !matches!(self, BuildStatus::ResultsReady)
            },
            _ => false, // Invalid policy, default to never delete
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
    /// Create a new BuildApi instance
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
    pub async fn create_build(&self, request: CreateBuildRequest) -> Result<Build, BuildError> {
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

        let response = self.client.post_with_query_params(endpoint, &query_params).await?;
        
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
                Err(BuildError::CreationFailed(format!("HTTP {status}: {error_text}")))
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
    pub async fn update_build(&self, request: UpdateBuildRequest) -> Result<Build, BuildError> {
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

        let response = self.client.post_with_query_params(endpoint, &query_params).await?;
        
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
                Err(BuildError::UpdateFailed(format!("HTTP {status}: {error_text}")))
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
    pub async fn delete_build(&self, request: DeleteBuildRequest) -> Result<DeleteBuildResult, BuildError> {
        let endpoint = "/api/5.0/deletebuild.do";
        
        // Build query parameters
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));
        
        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        let response = self.client.post_with_query_params(endpoint, &query_params).await?;
        
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
                Err(BuildError::DeletionFailed(format!("HTTP {status}: {error_text}")))
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
    pub async fn get_build_info(&self, request: GetBuildInfoRequest) -> Result<Build, BuildError> {
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

        let response = self.client.get_with_query_params(endpoint, &query_params).await?;
        
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
                Err(BuildError::Api(VeracodeError::InvalidResponse(format!("HTTP {status}: {error_text}"))))
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
    pub async fn get_build_list(&self, request: GetBuildListRequest) -> Result<BuildList, BuildError> {
        let endpoint = "/api/5.0/getbuildlist.do";
        
        // Build query parameters
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));
        
        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        let response = self.client.get_with_query_params(endpoint, &query_params).await?;
        
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
                Err(BuildError::Api(VeracodeError::InvalidResponse(format!("HTTP {status}: {error_text}"))))
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
                            } else {
                                return Err(BuildError::Api(VeracodeError::InvalidResponse(error_msg.to_string())));
                            }
                        }
                    },
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
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    
                                    match key.as_ref() {
                                        "build_id" => build.build_id = value.to_string(),
                                        "app_id" => build.app_id = value.to_string(),
                                        "version" => build.version = Some(value.to_string()),
                                        "app_name" => build.app_name = Some(value.to_string()),
                                        "sandbox_id" => build.sandbox_id = Some(value.to_string()),
                                        "sandbox_name" => build.sandbox_name = Some(value.to_string()),
                                        "lifecycle_stage" => build.lifecycle_stage = Some(value.to_string()),
                                        "submitter" => build.submitter = Some(value.to_string()),
                                        "platform" => build.platform = Some(value.to_string()),
                                        "analysis_unit" => build.analysis_unit = Some(value.to_string()),
                                        "policy_name" => build.policy_name = Some(value.to_string()),
                                        "policy_version" => build.policy_version = Some(value.to_string()),
                                        "policy_compliance_status" => build.policy_compliance_status = Some(value.to_string()),
                                        "rules_status" => build.rules_status = Some(value.to_string()),
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
                                            build.attributes.insert(key.to_string(), value.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        b"analysis_unit" if inside_build => {
                            // Parse analysis_unit element nested inside build (primary source for build status)
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    
                                    // Store all analysis_unit attributes, especially status
                                    match key.as_ref() {
                                        "status" => {
                                            // Store the analysis_unit status as the primary status
                                            build.attributes.insert("status".to_string(), value.to_string());
                                        }
                                        _ => {
                                            // Store other analysis_unit attributes with prefix
                                            build.attributes.insert(format!("analysis_{}", key), value.to_string());
                                        }
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
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = String::from_utf8_lossy(attr.key.as_ref());
                                let value = String::from_utf8_lossy(&attr.value);
                                
                                match key.as_ref() {
                                    "status" => {
                                        build.attributes.insert("status".to_string(), value.to_string());
                                    }
                                    _ => {
                                        build.attributes.insert(format!("analysis_{}", key), value.to_string());
                                    }
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
            return Err(BuildError::XmlParsingError("No build information found in response".to_string()));
        }


        Ok(build)
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
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"buildlist" => {
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    
                                    match key.as_ref() {
                                        "account_id" => build_list.account_id = Some(value.to_string()),
                                        "app_id" => build_list.app_id = value.to_string(),
                                        "app_name" => build_list.app_name = Some(value.to_string()),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        b"build" => {
                            let mut build = Build {
                                build_id: String::new(),
                                app_id: build_list.app_id.clone(),
                                version: None,
                                app_name: build_list.app_name.clone(),
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

                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    
                                    match key.as_ref() {
                                        "build_id" => build.build_id = value.to_string(),
                                        "version" => build.version = Some(value.to_string()),
                                        "sandbox_id" => build.sandbox_id = Some(value.to_string()),
                                        "sandbox_name" => build.sandbox_name = Some(value.to_string()),
                                        "lifecycle_stage" => build.lifecycle_stage = Some(value.to_string()),
                                        "submitter" => build.submitter = Some(value.to_string()),
                                        "platform" => build.platform = Some(value.to_string()),
                                        "analysis_unit" => build.analysis_unit = Some(value.to_string()),
                                        "policy_name" => build.policy_name = Some(value.to_string()),
                                        "policy_version" => build.policy_version = Some(value.to_string()),
                                        "policy_compliance_status" => build.policy_compliance_status = Some(value.to_string()),
                                        "rules_status" => build.rules_status = Some(value.to_string()),
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
                                            build.attributes.insert(key.to_string(), value.to_string());
                                        }
                                    }
                                }
                            }
                            
                            if !build.build_id.is_empty() {
                                build_list.builds.push(build);
                            }
                        }
                        _ => {}
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
                        match reader.read_event_into(&mut buf) {
                            Ok(Event::Text(e)) => {
                                result = String::from_utf8_lossy(&e).to_string();
                            }
                            _ => {}
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
            return Err(BuildError::XmlParsingError("No result found in delete response".to_string()));
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
    pub async fn create_simple_build(&self, app_id: &str, version: Option<&str>) -> Result<Build, BuildError> {
        let request = CreateBuildRequest {
            app_id: app_id.to_string(),
            version: version.map(|s| s.to_string()),
            lifecycle_stage: None,
            launch_date: None,
            sandbox_id: None,
        };
        
        self.create_build(request).await
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
    pub async fn create_sandbox_build(&self, app_id: &str, sandbox_id: &str, version: Option<&str>) -> Result<Build, BuildError> {
        let request = CreateBuildRequest {
            app_id: app_id.to_string(),
            version: version.map(|s| s.to_string()),
            lifecycle_stage: None,
            launch_date: None,
            sandbox_id: Some(sandbox_id.to_string()),
        };
        
        self.create_build(request).await
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
    pub async fn delete_app_build(&self, app_id: &str) -> Result<DeleteBuildResult, BuildError> {
        let request = DeleteBuildRequest {
            app_id: app_id.to_string(),
            sandbox_id: None,
        };
        
        self.delete_build(request).await
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
    pub async fn delete_sandbox_build(&self, app_id: &str, sandbox_id: &str) -> Result<DeleteBuildResult, BuildError> {
        let request = DeleteBuildRequest {
            app_id: app_id.to_string(),
            sandbox_id: Some(sandbox_id.to_string()),
        };
        
        self.delete_build(request).await
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
    pub async fn get_app_build_info(&self, app_id: &str) -> Result<Build, BuildError> {
        let request = GetBuildInfoRequest {
            app_id: app_id.to_string(),
            build_id: None,
            sandbox_id: None,
        };
        
        self.get_build_info(request).await
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
    pub async fn get_sandbox_build_info(&self, app_id: &str, sandbox_id: &str) -> Result<Build, BuildError> {
        let request = GetBuildInfoRequest {
            app_id: app_id.to_string(),
            build_id: None,
            sandbox_id: Some(sandbox_id.to_string()),
        };
        
        self.get_build_info(request).await
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
    pub async fn get_app_builds(&self, app_id: &str) -> Result<BuildList, BuildError> {
        let request = GetBuildListRequest {
            app_id: app_id.to_string(),
            sandbox_id: None,
        };
        
        self.get_build_list(request).await
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
    pub async fn get_sandbox_builds(&self, app_id: &str, sandbox_id: &str) -> Result<BuildList, BuildError> {
        let request = GetBuildListRequest {
            app_id: app_id.to_string(),
            sandbox_id: Some(sandbox_id.to_string()),
        };
        
        self.get_build_list(request).await
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
        assert_eq!(request.lifecycle_stage, Some("In Development (pre-Alpha)".to_string()));
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
        assert_eq!(error.to_string(), "Build creation failed: Build creation failed");
    }

    #[tokio::test]
    async fn test_build_api_method_signatures() {
        async fn _test_build_methods() -> Result<(), Box<dyn std::error::Error>> {
            let config = VeracodeConfig::new("test".to_string(), "test".to_string());
            let client = VeracodeClient::new(config)?;
            let api = client.build_api();
            
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
            let _: Result<Build, _> = api.create_build(create_request).await;
            let _: Result<Build, _> = api.create_simple_build("123", None).await;
            let _: Result<Build, _> = api.create_sandbox_build("123", "456", None).await;
            let _: Result<DeleteBuildResult, _> = api.delete_app_build("123").await;
            let _: Result<Build, _> = api.get_app_build_info("123").await;
            let _: Result<BuildList, _> = api.get_app_builds("123").await;
            
            Ok(())
        }
        
        // If this compiles, the methods have correct signatures
        assert!(true);
    }

    #[test]
    fn test_build_status_from_str() {
        assert_eq!(BuildStatus::from_str("Incomplete"), BuildStatus::Incomplete);
        assert_eq!(BuildStatus::from_str("Results Ready"), BuildStatus::ResultsReady);
        assert_eq!(BuildStatus::from_str("Pre-Scan Failed"), BuildStatus::PreScanFailed);
        assert_eq!(BuildStatus::from_str("Unknown Status"), BuildStatus::Unknown("Unknown Status".to_string()));
    }

    #[test]
    fn test_build_status_to_str() {
        assert_eq!(BuildStatus::Incomplete.to_str(), "Incomplete");
        assert_eq!(BuildStatus::ResultsReady.to_str(), "Results Ready");
        assert_eq!(BuildStatus::PreScanFailed.to_str(), "Pre-Scan Failed");
        assert_eq!(BuildStatus::Unknown("Custom".to_string()).to_str(), "Custom");
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
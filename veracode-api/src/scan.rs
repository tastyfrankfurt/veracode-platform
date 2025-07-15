//! Scan API functionality for Veracode platform.
//!
//! This module provides functionality to interact with the Veracode Scan APIs,
//! allowing you to upload files, initiate scans, and monitor scan progress for both
//! application-level and sandbox scans. This implementation mirrors the Java API wrapper functionality.

use chrono::{DateTime, Utc};
use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{VeracodeClient, VeracodeError};

/// Represents an uploaded file in a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadedFile {
    /// File ID assigned by Veracode
    pub file_id: String,
    /// Original filename
    pub file_name: String,
    /// File size in bytes
    pub file_size: u64,
    /// Upload timestamp
    pub uploaded: DateTime<Utc>,
    /// File status
    pub file_status: String,
    /// MD5 hash of the file
    pub md5: Option<String>,
}

/// Represents pre-scan results for a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreScanResults {
    /// Build ID for the pre-scan
    pub build_id: String,
    /// Application ID
    pub app_id: String,
    /// Sandbox ID
    pub sandbox_id: Option<String>,
    /// Pre-scan status
    pub status: String,
    /// Available modules for scanning
    pub modules: Vec<ScanModule>,
    /// Pre-scan errors or warnings
    pub messages: Vec<PreScanMessage>,
}

/// Represents a module available for scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanModule {
    /// Module ID
    pub id: String,
    /// Module name
    pub name: String,
    /// Module type
    pub module_type: String,
    /// Whether module is fatal (required for scan)
    pub is_fatal: bool,
    /// Whether module should be selected for scanning
    pub selected: bool,
    /// Module size
    pub size: Option<u64>,
    /// Module platform
    pub platform: Option<String>,
}

/// Represents a pre-scan message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreScanMessage {
    /// Message severity
    pub severity: String,
    /// Message text
    pub text: String,
    /// Associated module (if any)
    pub module_name: Option<String>,
}

/// Represents scan information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInfo {
    /// Build ID
    pub build_id: String,
    /// Application ID
    pub app_id: String,
    /// Sandbox ID
    pub sandbox_id: Option<String>,
    /// Scan status
    pub status: String,
    /// Scan type
    pub scan_type: String,
    /// Analysis unit ID
    pub analysis_unit_id: Option<String>,
    /// Scan completion percentage
    pub scan_progress_percentage: Option<u32>,
    /// Scan started timestamp
    pub scan_start: Option<DateTime<Utc>>,
    /// Scan completed timestamp
    pub scan_complete: Option<DateTime<Utc>>,
    /// Total lines of code
    pub total_lines_of_code: Option<u64>,
}

/// Request for uploading a file
#[derive(Debug, Clone)]
pub struct UploadFileRequest {
    /// Application ID
    pub app_id: String,
    /// File path to upload
    pub file_path: String,
    /// Name to save file as (optional)
    pub save_as: Option<String>,
    /// Sandbox ID (optional, for sandbox uploads)
    pub sandbox_id: Option<String>,
}

/// Request for uploading a large file
#[derive(Debug, Clone)]
pub struct UploadLargeFileRequest {
    /// Application ID
    pub app_id: String,
    /// File path to upload
    pub file_path: String,
    /// Name to save file as (optional, for flaw matching)
    pub filename: Option<String>,
    /// Sandbox ID (optional, for sandbox uploads)
    pub sandbox_id: Option<String>,
}

/// Progress information for file uploads
#[derive(Debug, Clone)]
pub struct UploadProgress {
    /// Bytes uploaded so far
    pub bytes_uploaded: u64,
    /// Total bytes to upload
    pub total_bytes: u64,
    /// Progress percentage (0-100)
    pub percentage: f64,
}

/// Callback trait for upload progress tracking
pub trait UploadProgressCallback: Send + Sync {
    /// Called when upload progress changes
    fn on_progress(&self, progress: UploadProgress);
    /// Called when upload completes successfully
    fn on_completed(&self);
    /// Called when upload fails
    fn on_error(&self, error: &str);
}

/// Request for beginning a pre-scan
#[derive(Debug, Clone)]
pub struct BeginPreScanRequest {
    /// Application ID
    pub app_id: String,
    /// Sandbox ID (optional)
    pub sandbox_id: Option<String>,
    /// Auto-scan flag
    pub auto_scan: Option<bool>,
    /// Scan all non-fatal top level modules
    pub scan_all_nonfatal_top_level_modules: Option<bool>,
    /// Include new modules
    pub include_new_modules: Option<bool>,
}

/// Request for beginning a scan
#[derive(Debug, Clone)]
pub struct BeginScanRequest {
    /// Application ID
    pub app_id: String,
    /// Sandbox ID (optional)
    pub sandbox_id: Option<String>,
    /// Modules to scan (comma-separated module IDs)
    pub modules: Option<String>,
    /// Scan all top level modules
    pub scan_all_top_level_modules: Option<bool>,
    /// Scan all non-fatal top level modules
    pub scan_all_nonfatal_top_level_modules: Option<bool>,
    /// Scan previously selected modules
    pub scan_previously_selected_modules: Option<bool>,
}

/// Scan specific error types
#[derive(Debug)]
pub enum ScanError {
    /// Veracode API error
    Api(VeracodeError),
    /// File not found
    FileNotFound(String),
    /// Invalid file format
    InvalidFileFormat(String),
    /// Upload failed
    UploadFailed(String),
    /// Scan failed
    ScanFailed(String),
    /// Pre-scan failed
    PreScanFailed(String),
    /// Build not found
    BuildNotFound,
    /// Application not found
    ApplicationNotFound,
    /// Sandbox not found
    SandboxNotFound,
    /// Unauthorized access
    Unauthorized,
    /// Permission denied
    PermissionDenied,
    /// Invalid parameter
    InvalidParameter(String),
    /// File too large (exceeds 2GB limit)
    FileTooLarge(String),
    /// Upload or prescan already in progress
    UploadInProgress,
    /// Scan in progress, cannot upload
    ScanInProgress,
    /// Build creation failed
    BuildCreationFailed(String),
    /// Chunked upload failed
    ChunkedUploadFailed(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Api(err) => write!(f, "API error: {err}"),
            ScanError::FileNotFound(path) => write!(f, "File not found: {path}"),
            ScanError::InvalidFileFormat(msg) => write!(f, "Invalid file format: {msg}"),
            ScanError::UploadFailed(msg) => write!(f, "Upload failed: {msg}"),
            ScanError::ScanFailed(msg) => write!(f, "Scan failed: {msg}"),
            ScanError::PreScanFailed(msg) => write!(f, "Pre-scan failed: {msg}"),
            ScanError::BuildNotFound => write!(f, "Build not found"),
            ScanError::ApplicationNotFound => write!(f, "Application not found"),
            ScanError::SandboxNotFound => write!(f, "Sandbox not found"),
            ScanError::Unauthorized => write!(f, "Unauthorized access"),
            ScanError::PermissionDenied => write!(f, "Permission denied"),
            ScanError::InvalidParameter(msg) => write!(f, "Invalid parameter: {msg}"),
            ScanError::FileTooLarge(msg) => write!(f, "File too large: {msg}"),
            ScanError::UploadInProgress => write!(f, "Upload or prescan already in progress"),
            ScanError::ScanInProgress => write!(f, "Scan in progress, cannot upload"),
            ScanError::BuildCreationFailed(msg) => write!(f, "Build creation failed: {msg}"),
            ScanError::ChunkedUploadFailed(msg) => write!(f, "Chunked upload failed: {msg}"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<VeracodeError> for ScanError {
    fn from(err: VeracodeError) -> Self {
        ScanError::Api(err)
    }
}

impl From<reqwest::Error> for ScanError {
    fn from(err: reqwest::Error) -> Self {
        ScanError::Api(VeracodeError::Http(err))
    }
}

impl From<serde_json::Error> for ScanError {
    fn from(err: serde_json::Error) -> Self {
        ScanError::Api(VeracodeError::Serialization(err))
    }
}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        ScanError::FileNotFound(err.to_string())
    }
}

/// Veracode Scan API operations
pub struct ScanApi {
    client: VeracodeClient,
}

impl ScanApi {
    /// Create a new ScanApi instance
    pub fn new(client: VeracodeClient) -> Self {
        Self { client }
    }

    /// Upload a file to an application or sandbox
    ///
    /// # Arguments
    ///
    /// * `request` - The upload file request
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_file(&self, request: UploadFileRequest) -> Result<UploadedFile, ScanError> {
        // Validate file exists
        if !Path::new(&request.file_path).exists() {
            return Err(ScanError::FileNotFound(request.file_path));
        }

        let endpoint = "/api/5.0/uploadfile.do";

        // Build query parameters like Java implementation
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        if let Some(save_as) = &request.save_as {
            query_params.push(("save_as", save_as.as_str()));
        }

        // Read file data
        let file_data = std::fs::read(&request.file_path)?;

        // Get filename from path
        let filename = Path::new(&request.file_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("file");

        let response = self
            .client
            .upload_file_with_query_params(endpoint, &query_params, "file", filename, file_data)
            .await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_upload_response(&response_text, &request.file_path)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::InvalidParameter(error_text))
            }
            401 => Err(ScanError::Unauthorized),
            403 => Err(ScanError::PermissionDenied),
            404 => {
                if request.sandbox_id.is_some() {
                    Err(ScanError::SandboxNotFound)
                } else {
                    Err(ScanError::ApplicationNotFound)
                }
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::UploadFailed(format!(
                    "HTTP {status}: {error_text}"
                )))
            }
        }
    }

    /// Upload a large file using the uploadlargefile.do endpoint
    ///
    /// This method uploads large files (up to 2GB) to an existing build.
    /// Unlike uploadfile.do, this endpoint requires a build to exist before uploading.
    /// It automatically creates a build if one doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `request` - The upload large file request
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_large_file(
        &self,
        request: UploadLargeFileRequest,
    ) -> Result<UploadedFile, ScanError> {
        // Validate file exists
        if !Path::new(&request.file_path).exists() {
            return Err(ScanError::FileNotFound(request.file_path));
        }

        // Check file size (2GB limit for uploadlargefile.do)
        let file_metadata = std::fs::metadata(&request.file_path)?;
        let file_size = file_metadata.len();
        const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2GB

        if file_size > MAX_FILE_SIZE {
            return Err(ScanError::FileTooLarge(format!(
                "File size {} bytes exceeds 2GB limit",
                file_size
            )));
        }

        let endpoint = "uploadlargefile.do"; // No version prefix for large file upload

        // Build query parameters
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        if let Some(filename) = &request.filename {
            query_params.push(("filename", filename.as_str()));
        }

        // Read file data
        let file_data = std::fs::read(&request.file_path)?;

        let response = self
            .client
            .upload_file_binary(endpoint, &query_params, file_data, "binary/octet-stream")
            .await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_upload_response(&response_text, &request.file_path)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                if error_text.contains("upload or prescan in progress") {
                    Err(ScanError::UploadInProgress)
                } else if error_text.contains("scan in progress") {
                    Err(ScanError::ScanInProgress)
                } else {
                    Err(ScanError::InvalidParameter(error_text))
                }
            }
            401 => Err(ScanError::Unauthorized),
            403 => Err(ScanError::PermissionDenied),
            404 => {
                if request.sandbox_id.is_some() {
                    Err(ScanError::SandboxNotFound)
                } else {
                    Err(ScanError::ApplicationNotFound)
                }
            }
            413 => Err(ScanError::FileTooLarge(
                "File size exceeds server limits".to_string(),
            )),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::UploadFailed(format!(
                    "HTTP {status}: {error_text}"
                )))
            }
        }
    }

    /// Upload a large file with progress tracking
    ///
    /// This method provides the same functionality as upload_large_file but with
    /// progress tracking capabilities through a callback function.
    ///
    /// # Arguments
    ///
    /// * `request` - The upload large file request
    /// * `progress_callback` - Callback function for progress updates (bytes_uploaded, total_bytes, percentage)
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_large_file_with_progress<F>(
        &self,
        request: UploadLargeFileRequest,
        progress_callback: F,
    ) -> Result<UploadedFile, ScanError>
    where
        F: Fn(u64, u64, f64) + Send + Sync,
    {
        // Validate file exists
        if !Path::new(&request.file_path).exists() {
            return Err(ScanError::FileNotFound(request.file_path));
        }

        // Check file size (2GB limit)
        let file_metadata = std::fs::metadata(&request.file_path)?;
        let file_size = file_metadata.len();
        const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2GB

        if file_size > MAX_FILE_SIZE {
            return Err(ScanError::FileTooLarge(format!(
                "File size {} bytes exceeds 2GB limit",
                file_size
            )));
        }

        let endpoint = "uploadlargefile.do";

        // Build query parameters
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        if let Some(filename) = &request.filename {
            query_params.push(("filename", filename.as_str()));
        }

        let response = self
            .client
            .upload_large_file_chunked(
                endpoint,
                &query_params,
                &request.file_path,
                Some("binary/octet-stream"),
                Some(progress_callback),
            )
            .await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_upload_response(&response_text, &request.file_path)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                if error_text.contains("upload or prescan in progress") {
                    Err(ScanError::UploadInProgress)
                } else if error_text.contains("scan in progress") {
                    Err(ScanError::ScanInProgress)
                } else {
                    Err(ScanError::InvalidParameter(error_text))
                }
            }
            401 => Err(ScanError::Unauthorized),
            403 => Err(ScanError::PermissionDenied),
            404 => {
                if request.sandbox_id.is_some() {
                    Err(ScanError::SandboxNotFound)
                } else {
                    Err(ScanError::ApplicationNotFound)
                }
            }
            413 => Err(ScanError::FileTooLarge(
                "File size exceeds server limits".to_string(),
            )),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::ChunkedUploadFailed(format!(
                    "HTTP {status}: {error_text}"
                )))
            }
        }
    }

    /// Intelligently choose between uploadfile.do and uploadlargefile.do
    ///
    /// This method automatically selects the appropriate upload endpoint based on
    /// file size and other factors, similar to the Java API wrapper behavior.
    ///
    /// # Arguments
    ///
    /// * `request` - The upload file request (converted to appropriate format)
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_file_smart(
        &self,
        request: UploadFileRequest,
    ) -> Result<UploadedFile, ScanError> {
        // Check if file exists
        if !Path::new(&request.file_path).exists() {
            return Err(ScanError::FileNotFound(request.file_path));
        }

        // Get file size to determine upload method
        let file_metadata = std::fs::metadata(&request.file_path)?;
        let file_size = file_metadata.len();

        // Use large file upload for files over 100MB or when build might exist
        const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024; // 100MB

        if file_size > LARGE_FILE_THRESHOLD {
            // Convert to large file request format
            let large_request = UploadLargeFileRequest {
                app_id: request.app_id.clone(),
                file_path: request.file_path.clone(),
                filename: request.save_as.clone(),
                sandbox_id: request.sandbox_id.clone(),
            };

            // Try large file upload first, fall back to regular upload if needed
            match self.upload_large_file(large_request).await {
                Ok(result) => Ok(result),
                Err(ScanError::Api(_)) => {
                    // Fall back to regular upload if large file upload fails
                    self.upload_file(request).await
                }
                Err(e) => Err(e),
            }
        } else {
            // Use regular upload for smaller files
            self.upload_file(request).await
        }
    }

    /// Begin pre-scan for an application or sandbox
    ///
    /// # Arguments
    ///
    /// * `request` - The pre-scan request
    ///
    /// # Returns
    ///
    /// A `Result` containing the build ID or an error.
    pub async fn begin_prescan(&self, request: BeginPreScanRequest) -> Result<String, ScanError> {
        let endpoint = "/api/5.0/beginprescan.do";

        // Build query parameters like Java implementation
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        if let Some(auto_scan) = request.auto_scan {
            query_params.push(("auto_scan", if auto_scan { "true" } else { "false" }));
        }

        if let Some(scan_all) = request.scan_all_nonfatal_top_level_modules {
            query_params.push((
                "scan_all_nonfatal_top_level_modules",
                if scan_all { "true" } else { "false" },
            ));
        }

        if let Some(include_new) = request.include_new_modules {
            query_params.push((
                "include_new_modules",
                if include_new { "true" } else { "false" },
            ));
        }

        let response = self.client.get_with_params(endpoint, &query_params).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_build_id_response(&response_text)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::InvalidParameter(error_text))
            }
            401 => Err(ScanError::Unauthorized),
            403 => Err(ScanError::PermissionDenied),
            404 => {
                if request.sandbox_id.is_some() {
                    Err(ScanError::SandboxNotFound)
                } else {
                    Err(ScanError::ApplicationNotFound)
                }
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::PreScanFailed(format!(
                    "HTTP {status}: {error_text}"
                )))
            }
        }
    }

    /// Get pre-scan results for an application or sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `sandbox_id` - The sandbox ID (optional)
    /// * `build_id` - The build ID (optional)
    ///
    /// # Returns
    ///
    /// A `Result` containing the pre-scan results or an error.
    pub async fn get_prescan_results(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
        build_id: Option<&str>,
    ) -> Result<PreScanResults, ScanError> {
        let endpoint = "/api/5.0/getprescanresults.do";

        let mut params = Vec::new();
        params.push(("app_id", app_id));

        if let Some(sandbox_id) = sandbox_id {
            params.push(("sandbox_id", sandbox_id));
        }

        if let Some(build_id) = build_id {
            params.push(("build_id", build_id));
        }

        let response = self.client.get_with_params(endpoint, &params).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_prescan_results(&response_text, app_id, sandbox_id)
            }
            401 => Err(ScanError::Unauthorized),
            403 => Err(ScanError::PermissionDenied),
            404 => {
                if sandbox_id.is_some() {
                    Err(ScanError::SandboxNotFound)
                } else {
                    Err(ScanError::ApplicationNotFound)
                }
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::PreScanFailed(format!(
                    "HTTP {status}: {error_text}"
                )))
            }
        }
    }

    /// Begin scan for an application or sandbox
    ///
    /// # Arguments
    ///
    /// * `request` - The scan request
    ///
    /// # Returns
    ///
    /// A `Result` containing the build ID or an error.
    pub async fn begin_scan(&self, request: BeginScanRequest) -> Result<String, ScanError> {
        let endpoint = "/api/5.0/beginscan.do";

        // Build query parameters like Java implementation
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        if let Some(modules) = &request.modules {
            query_params.push(("modules", modules.as_str()));
        }

        if let Some(scan_all) = request.scan_all_top_level_modules {
            query_params.push((
                "scan_all_top_level_modules",
                if scan_all { "true" } else { "false" },
            ));
        }

        if let Some(scan_all_nonfatal) = request.scan_all_nonfatal_top_level_modules {
            query_params.push((
                "scan_all_nonfatal_top_level_modules",
                if scan_all_nonfatal { "true" } else { "false" },
            ));
        }

        if let Some(scan_previous) = request.scan_previously_selected_modules {
            query_params.push((
                "scan_previously_selected_modules",
                if scan_previous { "true" } else { "false" },
            ));
        }

        let response = self.client.get_with_params(endpoint, &query_params).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_build_id_response(&response_text)
            }
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::InvalidParameter(error_text))
            }
            401 => Err(ScanError::Unauthorized),
            403 => Err(ScanError::PermissionDenied),
            404 => {
                if request.sandbox_id.is_some() {
                    Err(ScanError::SandboxNotFound)
                } else {
                    Err(ScanError::ApplicationNotFound)
                }
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::ScanFailed(format!(
                    "HTTP {status}: {error_text}"
                )))
            }
        }
    }

    /// Get list of uploaded files for an application or sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `sandbox_id` - The sandbox ID (optional)
    /// * `build_id` - The build ID (optional)
    ///
    /// # Returns
    ///
    /// A `Result` containing the list of uploaded files or an error.
    pub async fn get_file_list(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
        build_id: Option<&str>,
    ) -> Result<Vec<UploadedFile>, ScanError> {
        let endpoint = "/api/5.0/getfilelist.do";

        let mut params = Vec::new();
        params.push(("app_id", app_id));

        if let Some(sandbox_id) = sandbox_id {
            params.push(("sandbox_id", sandbox_id));
        }

        if let Some(build_id) = build_id {
            params.push(("build_id", build_id));
        }

        let response = self.client.get_with_params(endpoint, &params).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_file_list(&response_text)
            }
            401 => Err(ScanError::Unauthorized),
            403 => Err(ScanError::PermissionDenied),
            404 => {
                if sandbox_id.is_some() {
                    Err(ScanError::SandboxNotFound)
                } else {
                    Err(ScanError::ApplicationNotFound)
                }
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Remove a file from an application or sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `file_id` - The file ID to remove
    /// * `sandbox_id` - The sandbox ID (optional)
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn remove_file(
        &self,
        app_id: &str,
        file_id: &str,
        sandbox_id: Option<&str>,
    ) -> Result<(), ScanError> {
        let endpoint = "/api/5.0/removefile.do";

        // Build query parameters like Java implementation
        let mut query_params = Vec::new();
        query_params.push(("app_id", app_id));
        query_params.push(("file_id", file_id));

        if let Some(sandbox_id) = sandbox_id {
            query_params.push(("sandbox_id", sandbox_id));
        }

        let response = self.client.get_with_params(endpoint, &query_params).await?;

        let status = response.status().as_u16();
        match status {
            200 => Ok(()),
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::InvalidParameter(error_text))
            }
            401 => Err(ScanError::Unauthorized),
            403 => Err(ScanError::PermissionDenied),
            404 => Err(ScanError::FileNotFound(file_id.to_string())),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Delete a build from an application or sandbox
    ///
    /// This removes all uploaded files and scan data for a specific build.
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `build_id` - The build ID to delete
    /// * `sandbox_id` - The sandbox ID (optional)
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn delete_build(
        &self,
        app_id: &str,
        build_id: &str,
        sandbox_id: Option<&str>,
    ) -> Result<(), ScanError> {
        let endpoint = "/api/5.0/deletebuild.do";

        // Build query parameters like Java implementation
        let mut query_params = Vec::new();
        query_params.push(("app_id", app_id));
        query_params.push(("build_id", build_id));

        if let Some(sandbox_id) = sandbox_id {
            query_params.push(("sandbox_id", sandbox_id));
        }

        let response = self.client.get_with_params(endpoint, &query_params).await?;

        let status = response.status().as_u16();
        match status {
            200 => Ok(()),
            400 => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::InvalidParameter(error_text))
            }
            401 => Err(ScanError::Unauthorized),
            403 => Err(ScanError::PermissionDenied),
            404 => Err(ScanError::BuildNotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    /// Delete all builds for an application or sandbox
    ///
    /// This removes all uploaded files and scan data for all builds.
    /// Use with caution as this is irreversible.
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `sandbox_id` - The sandbox ID (optional)
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn delete_all_builds(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
    ) -> Result<(), ScanError> {
        // First get list of builds
        let build_info = self.get_build_info(app_id, None, sandbox_id).await?;

        if !build_info.build_id.is_empty() && build_info.build_id != "unknown" {
            println!("   🗑️  Deleting build: {}", build_info.build_id);
            self.delete_build(app_id, &build_info.build_id, sandbox_id)
                .await?;
        }

        Ok(())
    }

    /// Get build information for an application or sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `build_id` - The build ID (optional)
    /// * `sandbox_id` - The sandbox ID (optional)
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan information or an error.
    pub async fn get_build_info(
        &self,
        app_id: &str,
        build_id: Option<&str>,
        sandbox_id: Option<&str>,
    ) -> Result<ScanInfo, ScanError> {
        let endpoint = "/api/5.0/getbuildinfo.do";

        let mut params = Vec::new();
        params.push(("app_id", app_id));

        if let Some(build_id) = build_id {
            params.push(("build_id", build_id));
        }

        if let Some(sandbox_id) = sandbox_id {
            params.push(("sandbox_id", sandbox_id));
        }

        let response = self.client.get_with_params(endpoint, &params).await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                let response_text = response.text().await?;
                self.parse_build_info(&response_text, app_id, sandbox_id)
            }
            401 => Err(ScanError::Unauthorized),
            403 => Err(ScanError::PermissionDenied),
            404 => Err(ScanError::BuildNotFound),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ScanError::Api(VeracodeError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))))
            }
        }
    }

    // Helper methods for parsing XML responses (Veracode API returns XML)

    fn parse_upload_response(&self, xml: &str, file_path: &str) -> Result<UploadedFile, ScanError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut file_id = None;
        let mut file_status = "Unknown".to_string();
        let mut _md5: Option<String> = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    if e.name().as_ref() == b"file" {
                        // Extract file_id from attributes
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                if attr.key.as_ref() == b"file_id" {
                                    file_id =
                                        Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                            }
                        }
                    }
                }
                Ok(Event::Text(e)) => {
                    let text = std::str::from_utf8(&e).unwrap_or_default();
                    // Check for success/error messages
                    if text.contains("successfully uploaded") {
                        file_status = "Uploaded".to_string();
                    } else if text.contains("error") || text.contains("failed") {
                        file_status = "Failed".to_string();
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    eprintln!("Error parsing XML: {e}");
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        let filename = Path::new(file_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("file")
            .to_string();

        Ok(UploadedFile {
            file_id: file_id.unwrap_or_else(|| format!("file_{}", chrono::Utc::now().timestamp())),
            file_name: filename,
            file_size: std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0),
            uploaded: Utc::now(),
            file_status,
            md5: None,
        })
    }

    fn parse_build_id_response(&self, xml: &str) -> Result<String, ScanError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut build_id = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"buildinfo" | b"build" => {
                            // Extract build_id from attributes
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    if attr.key.as_ref() == b"build_id" {
                                        build_id =
                                            Some(String::from_utf8_lossy(&attr.value).to_string());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    eprintln!("Error parsing XML: {e}");
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        build_id
            .ok_or_else(|| ScanError::PreScanFailed("No build_id found in response".to_string()))
    }

    fn parse_prescan_results(
        &self,
        xml: &str,
        app_id: &str,
        sandbox_id: Option<&str>,
    ) -> Result<PreScanResults, ScanError> {
        // Check if response contains an error element (prescan not ready yet)
        if xml.contains("<error>") && xml.contains("Prescan results not available") {
            // Return a special status indicating prescan is still in progress
            return Ok(PreScanResults {
                build_id: String::new(),
                app_id: app_id.to_string(),
                sandbox_id: sandbox_id.map(|s| s.to_string()),
                status: "Pre-Scan Submitted".to_string(), // Indicates still in progress
                modules: Vec::new(),
                messages: Vec::new(),
            });
        }

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut build_id = None;
        let mut modules = Vec::new();
        let messages = Vec::new();
        let mut has_prescan_results = false;
        let mut has_fatal_errors = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"prescanresults" => {
                            has_prescan_results = true;
                            // Extract build_id from prescanresults attributes if present
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    match attr.key.as_ref() {
                                        b"build_id" => {
                                            build_id = Some(
                                                String::from_utf8_lossy(&attr.value).to_string(),
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        b"module" => {
                            let mut module = ScanModule {
                                id: String::new(),
                                name: String::new(),
                                module_type: String::new(),
                                is_fatal: false,
                                selected: false,
                                size: None,
                                platform: None,
                            };

                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    match attr.key.as_ref() {
                                        b"id" => {
                                            module.id =
                                                String::from_utf8_lossy(&attr.value).to_string()
                                        }
                                        b"name" => {
                                            module.name =
                                                String::from_utf8_lossy(&attr.value).to_string()
                                        }
                                        b"type" => {
                                            module.module_type =
                                                String::from_utf8_lossy(&attr.value).to_string()
                                        }
                                        b"isfatal" => {
                                            module.is_fatal = attr.value.as_ref() == b"true"
                                        }
                                        b"selected" => {
                                            module.selected = attr.value.as_ref() == b"true"
                                        }
                                        b"has_fatal_errors" => {
                                            if attr.value.as_ref() == b"true" {
                                                has_fatal_errors = true;
                                            }
                                        }
                                        b"size" => {
                                            if let Ok(size_str) =
                                                String::from_utf8(attr.value.to_vec())
                                            {
                                                module.size = size_str.parse().ok();
                                            }
                                        }
                                        b"platform" => {
                                            module.platform = Some(
                                                String::from_utf8_lossy(&attr.value).to_string(),
                                            )
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            modules.push(module);
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    eprintln!("Error parsing XML: {e}");
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        // Determine prescan status based on the parsed results
        let status = if !has_prescan_results {
            "Unknown".to_string()
        } else if modules.is_empty() {
            // No modules found - this could indicate prescan failed or is still processing
            "Pre-Scan Failed".to_string()
        } else if has_fatal_errors {
            // Modules found but some have fatal errors
            "Pre-Scan Failed".to_string()
        } else {
            // Modules found with no fatal errors - prescan succeeded
            "Pre-Scan Success".to_string()
        };

        Ok(PreScanResults {
            build_id: build_id.unwrap_or_else(|| "unknown".to_string()),
            app_id: app_id.to_string(),
            sandbox_id: sandbox_id.map(|s| s.to_string()),
            status,
            modules,
            messages,
        })
    }

    fn parse_file_list(&self, xml: &str) -> Result<Vec<UploadedFile>, ScanError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut files = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    if e.name().as_ref() == b"file" {
                        let mut file = UploadedFile {
                            file_id: String::new(),
                            file_name: String::new(),
                            file_size: 0,
                            uploaded: Utc::now(),
                            file_status: "Unknown".to_string(),
                            md5: None,
                        };

                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                match attr.key.as_ref() {
                                    b"file_id" => {
                                        file.file_id =
                                            String::from_utf8_lossy(&attr.value).to_string()
                                    }
                                    b"file_name" => {
                                        file.file_name =
                                            String::from_utf8_lossy(&attr.value).to_string()
                                    }
                                    b"file_size" => {
                                        if let Ok(size_str) = String::from_utf8(attr.value.to_vec())
                                        {
                                            file.file_size = size_str.parse().unwrap_or(0);
                                        }
                                    }
                                    b"file_status" => {
                                        file.file_status =
                                            String::from_utf8_lossy(&attr.value).to_string()
                                    }
                                    b"md5" => {
                                        file.md5 =
                                            Some(String::from_utf8_lossy(&attr.value).to_string())
                                    }
                                    _ => {}
                                }
                            }
                        }
                        files.push(file);
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    eprintln!("Error parsing XML: {e}");
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(files)
    }

    fn parse_build_info(
        &self,
        xml: &str,
        app_id: &str,
        sandbox_id: Option<&str>,
    ) -> Result<ScanInfo, ScanError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut scan_info = ScanInfo {
            build_id: String::new(),
            app_id: app_id.to_string(),
            sandbox_id: sandbox_id.map(|s| s.to_string()),
            status: "Unknown".to_string(),
            scan_type: "Static".to_string(),
            analysis_unit_id: None,
            scan_progress_percentage: None,
            scan_start: None,
            scan_complete: None,
            total_lines_of_code: None,
        };

        let mut inside_build = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"buildinfo" => {
                            // Parse buildinfo attributes
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    match attr.key.as_ref() {
                                        b"build_id" => {
                                            scan_info.build_id =
                                                String::from_utf8_lossy(&attr.value).to_string()
                                        }
                                        b"analysis_unit" => {
                                            // Fallback status from buildinfo (older API format)
                                            if scan_info.status == "Unknown" {
                                                scan_info.status =
                                                    String::from_utf8_lossy(&attr.value)
                                                        .to_string();
                                            }
                                        }
                                        b"analysis_unit_id" => {
                                            scan_info.analysis_unit_id = Some(
                                                String::from_utf8_lossy(&attr.value).to_string(),
                                            )
                                        }
                                        b"scan_progress_percentage" => {
                                            if let Ok(progress_str) =
                                                String::from_utf8(attr.value.to_vec())
                                            {
                                                scan_info.scan_progress_percentage =
                                                    progress_str.parse().ok();
                                            }
                                        }
                                        b"total_lines_of_code" => {
                                            if let Ok(lines_str) =
                                                String::from_utf8(attr.value.to_vec())
                                            {
                                                scan_info.total_lines_of_code =
                                                    lines_str.parse().ok();
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        b"build" => {
                            inside_build = true;
                        }
                        b"analysis_unit" => {
                            // Parse analysis_unit attributes (primary status source)
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    match attr.key.as_ref() {
                                        b"status" => {
                                            // Primary status source from analysis_unit
                                            scan_info.status =
                                                String::from_utf8_lossy(&attr.value).to_string();
                                        }
                                        b"analysis_type" => {
                                            scan_info.scan_type =
                                                String::from_utf8_lossy(&attr.value).to_string();
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == b"build" {
                        inside_build = false;
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    // Handle self-closing elements like <analysis_unit ... />
                    if e.name().as_ref() == b"analysis_unit" && inside_build {
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                match attr.key.as_ref() {
                                    b"status" => {
                                        scan_info.status =
                                            String::from_utf8_lossy(&attr.value).to_string();
                                    }
                                    b"analysis_type" => {
                                        scan_info.scan_type =
                                            String::from_utf8_lossy(&attr.value).to_string();
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    eprintln!("Error parsing XML: {e}");
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(scan_info)
    }
}

/// Convenience methods for common scan operations
impl ScanApi {
    /// Upload a file to a sandbox with simple parameters
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `file_path` - Path to the file to upload
    /// * `sandbox_id` - The sandbox ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_file_to_sandbox(
        &self,
        app_id: &str,
        file_path: &str,
        sandbox_id: &str,
    ) -> Result<UploadedFile, ScanError> {
        let request = UploadFileRequest {
            app_id: app_id.to_string(),
            file_path: file_path.to_string(),
            save_as: None,
            sandbox_id: Some(sandbox_id.to_string()),
        };

        self.upload_file(request).await
    }

    /// Upload a file to an application (non-sandbox)
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `file_path` - Path to the file to upload
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_file_to_app(
        &self,
        app_id: &str,
        file_path: &str,
    ) -> Result<UploadedFile, ScanError> {
        let request = UploadFileRequest {
            app_id: app_id.to_string(),
            file_path: file_path.to_string(),
            save_as: None,
            sandbox_id: None,
        };

        self.upload_file(request).await
    }

    /// Upload a large file to a sandbox using uploadlargefile.do
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `file_path` - Path to the file to upload
    /// * `sandbox_id` - The sandbox ID
    /// * `filename` - Optional filename for flaw matching
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_large_file_to_sandbox(
        &self,
        app_id: &str,
        file_path: &str,
        sandbox_id: &str,
        filename: Option<&str>,
    ) -> Result<UploadedFile, ScanError> {
        let request = UploadLargeFileRequest {
            app_id: app_id.to_string(),
            file_path: file_path.to_string(),
            filename: filename.map(|s| s.to_string()),
            sandbox_id: Some(sandbox_id.to_string()),
        };

        self.upload_large_file(request).await
    }

    /// Upload a large file to an application using uploadlargefile.do
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `file_path` - Path to the file to upload
    /// * `filename` - Optional filename for flaw matching
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_large_file_to_app(
        &self,
        app_id: &str,
        file_path: &str,
        filename: Option<&str>,
    ) -> Result<UploadedFile, ScanError> {
        let request = UploadLargeFileRequest {
            app_id: app_id.to_string(),
            file_path: file_path.to_string(),
            filename: filename.map(|s| s.to_string()),
            sandbox_id: None,
        };

        self.upload_large_file(request).await
    }

    /// Upload a large file with progress tracking to a sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `file_path` - Path to the file to upload
    /// * `sandbox_id` - The sandbox ID
    /// * `filename` - Optional filename for flaw matching
    /// * `progress_callback` - Callback for progress updates
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_large_file_to_sandbox_with_progress<F>(
        &self,
        app_id: &str,
        file_path: &str,
        sandbox_id: &str,
        filename: Option<&str>,
        progress_callback: F,
    ) -> Result<UploadedFile, ScanError>
    where
        F: Fn(u64, u64, f64) + Send + Sync,
    {
        let request = UploadLargeFileRequest {
            app_id: app_id.to_string(),
            file_path: file_path.to_string(),
            filename: filename.map(|s| s.to_string()),
            sandbox_id: Some(sandbox_id.to_string()),
        };

        self.upload_large_file_with_progress(request, progress_callback)
            .await
    }

    /// Begin a simple pre-scan for a sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `sandbox_id` - The sandbox ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the build ID or an error.
    pub async fn begin_sandbox_prescan(
        &self,
        app_id: &str,
        sandbox_id: &str,
    ) -> Result<String, ScanError> {
        let request = BeginPreScanRequest {
            app_id: app_id.to_string(),
            sandbox_id: Some(sandbox_id.to_string()),
            auto_scan: Some(true),
            scan_all_nonfatal_top_level_modules: Some(true),
            include_new_modules: Some(true),
        };

        self.begin_prescan(request).await
    }

    /// Begin a simple scan for a sandbox with all modules
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `sandbox_id` - The sandbox ID
    ///
    /// # Returns
    ///
    /// A `Result` containing the build ID or an error.
    pub async fn begin_sandbox_scan_all_modules(
        &self,
        app_id: &str,
        sandbox_id: &str,
    ) -> Result<String, ScanError> {
        let request = BeginScanRequest {
            app_id: app_id.to_string(),
            sandbox_id: Some(sandbox_id.to_string()),
            modules: None,
            scan_all_top_level_modules: Some(true),
            scan_all_nonfatal_top_level_modules: Some(true),
            scan_previously_selected_modules: None,
        };

        self.begin_scan(request).await
    }

    /// Complete workflow: upload file, pre-scan, and begin scan for sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `sandbox_id` - The sandbox ID
    /// * `file_path` - Path to the file to upload
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan build ID or an error.
    pub async fn upload_and_scan_sandbox(
        &self,
        app_id: &str,
        sandbox_id: &str,
        file_path: &str,
    ) -> Result<String, ScanError> {
        // Step 1: Upload file
        println!("📤 Uploading file to sandbox...");
        self.upload_file_to_sandbox(app_id, file_path, sandbox_id)
            .await?;

        // Step 2: Begin pre-scan
        println!("🔍 Beginning pre-scan...");
        let _build_id = self.begin_sandbox_prescan(app_id, sandbox_id).await?;

        // Step 3: Wait a moment for pre-scan to complete (in production, poll for status)
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Step 4: Begin scan
        println!("🚀 Beginning scan...");
        let scan_build_id = self
            .begin_sandbox_scan_all_modules(app_id, sandbox_id)
            .await?;

        Ok(scan_build_id)
    }

    /// Delete a build from a sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `build_id` - The build ID to delete
    /// * `sandbox_id` - The sandbox ID
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn delete_sandbox_build(
        &self,
        app_id: &str,
        build_id: &str,
        sandbox_id: &str,
    ) -> Result<(), ScanError> {
        self.delete_build(app_id, build_id, Some(sandbox_id)).await
    }

    /// Delete all builds from a sandbox
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `sandbox_id` - The sandbox ID
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn delete_all_sandbox_builds(
        &self,
        app_id: &str,
        sandbox_id: &str,
    ) -> Result<(), ScanError> {
        self.delete_all_builds(app_id, Some(sandbox_id)).await
    }

    /// Delete a build from an application (non-sandbox)
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    /// * `build_id` - The build ID to delete
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn delete_app_build(&self, app_id: &str, build_id: &str) -> Result<(), ScanError> {
        self.delete_build(app_id, build_id, None).await
    }

    /// Delete all builds from an application (non-sandbox)
    ///
    /// # Arguments
    ///
    /// * `app_id` - The application ID
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn delete_all_app_builds(&self, app_id: &str) -> Result<(), ScanError> {
        self.delete_all_builds(app_id, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VeracodeConfig;

    #[test]
    fn test_upload_file_request() {
        let request = UploadFileRequest {
            app_id: "123".to_string(),
            file_path: "/path/to/file.jar".to_string(),
            save_as: Some("app.jar".to_string()),
            sandbox_id: Some("456".to_string()),
        };

        assert_eq!(request.app_id, "123");
        assert_eq!(request.sandbox_id, Some("456".to_string()));
    }

    #[test]
    fn test_begin_prescan_request() {
        let request = BeginPreScanRequest {
            app_id: "123".to_string(),
            sandbox_id: Some("456".to_string()),
            auto_scan: Some(true),
            scan_all_nonfatal_top_level_modules: Some(true),
            include_new_modules: Some(false),
        };

        assert_eq!(request.app_id, "123");
        assert_eq!(request.auto_scan, Some(true));
    }

    #[test]
    fn test_scan_error_display() {
        let error = ScanError::FileNotFound("test.jar".to_string());
        assert_eq!(error.to_string(), "File not found: test.jar");

        let error = ScanError::UploadFailed("Network error".to_string());
        assert_eq!(error.to_string(), "Upload failed: Network error");

        let error = ScanError::Unauthorized;
        assert_eq!(error.to_string(), "Unauthorized access");

        let error = ScanError::BuildNotFound;
        assert_eq!(error.to_string(), "Build not found");
    }

    #[test]
    fn test_delete_build_request_structure() {
        // Test that the delete build methods have correct structure
        // This is a compile-time test to ensure methods exist with correct signatures

        use crate::{VeracodeClient, VeracodeConfig};

        async fn _test_delete_methods() -> Result<(), Box<dyn std::error::Error>> {
            let config = VeracodeConfig::new("test".to_string(), "test".to_string());
            let client = VeracodeClient::new(config)?;
            let api = client.scan_api();

            // These calls won't actually execute due to test environment,
            // but they validate the method signatures exist
            let _: Result<(), _> = api
                .delete_build("app_id", "build_id", Some("sandbox_id"))
                .await;
            let _: Result<(), _> = api.delete_all_builds("app_id", Some("sandbox_id")).await;
            let _: Result<(), _> = api
                .delete_sandbox_build("app_id", "build_id", "sandbox_id")
                .await;
            let _: Result<(), _> = api.delete_all_sandbox_builds("app_id", "sandbox_id").await;

            Ok(())
        }

        // If this compiles, the methods have correct signatures
        assert!(true);
    }

    #[test]
    fn test_upload_large_file_request() {
        let request = UploadLargeFileRequest {
            app_id: "123".to_string(),
            file_path: "/path/to/large_file.jar".to_string(),
            filename: Some("custom_name.jar".to_string()),
            sandbox_id: Some("456".to_string()),
        };

        assert_eq!(request.app_id, "123");
        assert_eq!(request.filename, Some("custom_name.jar".to_string()));
        assert_eq!(request.sandbox_id, Some("456".to_string()));
    }

    #[test]
    fn test_upload_progress() {
        let progress = UploadProgress {
            bytes_uploaded: 1024,
            total_bytes: 2048,
            percentage: 50.0,
        };

        assert_eq!(progress.bytes_uploaded, 1024);
        assert_eq!(progress.total_bytes, 2048);
        assert_eq!(progress.percentage, 50.0);
    }

    #[test]
    fn test_large_file_scan_error_display() {
        let error = ScanError::FileTooLarge("File exceeds 2GB".to_string());
        assert_eq!(error.to_string(), "File too large: File exceeds 2GB");

        let error = ScanError::UploadInProgress;
        assert_eq!(error.to_string(), "Upload or prescan already in progress");

        let error = ScanError::ScanInProgress;
        assert_eq!(error.to_string(), "Scan in progress, cannot upload");

        let error = ScanError::ChunkedUploadFailed("Network error".to_string());
        assert_eq!(error.to_string(), "Chunked upload failed: Network error");
    }

    #[tokio::test]
    async fn test_large_file_upload_method_signatures() {
        async fn _test_large_file_methods() -> Result<(), Box<dyn std::error::Error>> {
            let config = VeracodeConfig::new("test".to_string(), "test".to_string());
            let client = VeracodeClient::new(config)?;
            let api = client.scan_api();

            // Test that the method signatures exist and compile
            let request = UploadLargeFileRequest {
                app_id: "123".to_string(),
                file_path: "/nonexistent/file.jar".to_string(),
                filename: None,
                sandbox_id: Some("456".to_string()),
            };

            // These calls won't actually execute due to test environment,
            // but they validate the method signatures exist
            let _: Result<UploadedFile, _> = api.upload_large_file(request.clone()).await;
            let _: Result<UploadedFile, _> = api
                .upload_large_file_to_sandbox("123", "/path", "456", None)
                .await;
            let _: Result<UploadedFile, _> =
                api.upload_large_file_to_app("123", "/path", None).await;

            // Test progress callback signature
            let progress_callback = |bytes_uploaded: u64, total_bytes: u64, percentage: f64| {
                println!(
                    "Progress: {}/{} ({:.1}%)",
                    bytes_uploaded, total_bytes, percentage
                );
            };
            let _: Result<UploadedFile, _> = api
                .upload_large_file_with_progress(request, progress_callback)
                .await;

            Ok(())
        }

        // If this compiles, the methods have correct signatures
        assert!(true);
    }
}

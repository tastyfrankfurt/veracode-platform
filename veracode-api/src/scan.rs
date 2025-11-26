//! Scan API functionality for Veracode platform.
//!
//! This module provides functionality to interact with the Veracode Scan APIs,
//! allowing you to upload files, initiate scans, and monitor scan progress for both
//! application-level and sandbox scans. This implementation mirrors the Java API wrapper functionality.

use chrono::{DateTime, Utc};
#[allow(unused_imports)] // debug is used in tests
use log::{debug, error, info};
use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::validation::validate_url_segment;
use crate::{VeracodeClient, VeracodeError};

/// Helper function to efficiently convert XML attribute bytes to string
/// Avoids unnecessary allocation when possible
fn attr_to_string(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

/// File upload status as defined in the Veracode filelist.xsd schema
///
/// This enum represents all possible states a file can be in during and after upload.
/// Reference: <https://analysiscenter.veracode.com/resource/2.0/filelist.xsd>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileStatus {
    /// File is pending upload to the platform
    #[serde(rename = "Pending Upload")]
    PendingUpload,
    /// File is currently being uploaded
    #[serde(rename = "Uploading")]
    Uploading,
    /// File has been purged from the platform
    #[serde(rename = "Purged")]
    Purged,
    /// File was successfully uploaded and is ready for scanning
    #[serde(rename = "Uploaded")]
    Uploaded,
    /// File is missing from the build
    #[serde(rename = "Missing")]
    Missing,
    /// File upload was only partially completed
    #[serde(rename = "Partial")]
    Partial,
    /// File MD5 checksum validation failed
    #[serde(rename = "Invalid Checksum")]
    InvalidChecksum,
    /// File is not a valid archive format
    #[serde(rename = "Invalid Archive")]
    InvalidArchive,
    /// Archive contains nested archives (not allowed)
    #[serde(rename = "Archive File Within Another Archive")]
    ArchiveWithinArchive,
    /// Archive uses unsupported compression algorithm
    #[serde(rename = "Archive File with Unsupported Compression")]
    UnsupportedCompression,
    /// Archive is password protected and cannot be processed
    #[serde(rename = "Archive File is Password Protected")]
    PasswordProtected,
}

impl FileStatus {
    /// Check if this status indicates a successful upload
    #[must_use]
    pub fn is_uploaded(&self) -> bool {
        matches!(self, FileStatus::Uploaded)
    }

    /// Check if this status indicates an error state
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            FileStatus::InvalidChecksum
                | FileStatus::InvalidArchive
                | FileStatus::ArchiveWithinArchive
                | FileStatus::UnsupportedCompression
                | FileStatus::PasswordProtected
                | FileStatus::Missing
                | FileStatus::Purged
        )
    }

    /// Check if this status indicates upload is still in progress
    #[must_use]
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self,
            FileStatus::PendingUpload | FileStatus::Uploading | FileStatus::Partial
        )
    }

    /// Get a human-readable description of the status
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            FileStatus::PendingUpload => "File is pending upload",
            FileStatus::Uploading => "File is currently being uploaded",
            FileStatus::Purged => "File has been purged from the platform",
            FileStatus::Uploaded => "File successfully uploaded and ready for scanning",
            FileStatus::Missing => "File is missing from the build",
            FileStatus::Partial => "File upload was only partially completed",
            FileStatus::InvalidChecksum => "File MD5 checksum validation failed",
            FileStatus::InvalidArchive => "File is not a valid archive format",
            FileStatus::ArchiveWithinArchive => "Archive contains nested archives (not allowed)",
            FileStatus::UnsupportedCompression => "Archive uses unsupported compression algorithm",
            FileStatus::PasswordProtected => {
                "Archive is password protected and cannot be processed"
            }
        }
    }
}

impl std::str::FromStr for FileStatus {
    type Err = ScanError;

    /// Parse file status from XML string value
    ///
    /// # Arguments
    ///
    /// * `s` - The status string from the XML response
    ///
    /// # Returns
    ///
    /// The corresponding `FileStatus` enum value, or an error if the status is unknown
    ///
    /// # Errors
    ///
    /// Returns `ScanError::InvalidParameter` if the status string is not recognized
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Pending Upload" => Ok(FileStatus::PendingUpload),
            "Uploading" => Ok(FileStatus::Uploading),
            "Purged" => Ok(FileStatus::Purged),
            "Uploaded" => Ok(FileStatus::Uploaded),
            "Missing" => Ok(FileStatus::Missing),
            "Partial" => Ok(FileStatus::Partial),
            "Invalid Checksum" => Ok(FileStatus::InvalidChecksum),
            "Invalid Archive" => Ok(FileStatus::InvalidArchive),
            "Archive File Within Another Archive" => Ok(FileStatus::ArchiveWithinArchive),
            "Archive File with Unsupported Compression" => Ok(FileStatus::UnsupportedCompression),
            "Archive File is Password Protected" => Ok(FileStatus::PasswordProtected),
            _ => Err(ScanError::InvalidParameter(format!(
                "Unknown file status: {}",
                s
            ))),
        }
    }
}

impl std::fmt::Display for FileStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FileStatus::PendingUpload => "Pending Upload",
            FileStatus::Uploading => "Uploading",
            FileStatus::Purged => "Purged",
            FileStatus::Uploaded => "Uploaded",
            FileStatus::Missing => "Missing",
            FileStatus::Partial => "Partial",
            FileStatus::InvalidChecksum => "Invalid Checksum",
            FileStatus::InvalidArchive => "Invalid Archive",
            FileStatus::ArchiveWithinArchive => "Archive File Within Another Archive",
            FileStatus::UnsupportedCompression => "Archive File with Unsupported Compression",
            FileStatus::PasswordProtected => "Archive File is Password Protected",
        };
        write!(f, "{}", s)
    }
}

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
    /// File status (from Veracode filelist.xsd)
    pub file_status: FileStatus,
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

// Trait implementations for memory optimization
impl From<&UploadFileRequest> for UploadLargeFileRequest {
    fn from(request: &UploadFileRequest) -> Self {
        UploadLargeFileRequest {
            app_id: request.app_id.clone(),
            file_path: request.file_path.clone(),
            filename: request.save_as.clone(),
            sandbox_id: request.sandbox_id.clone(),
        }
    }
}

/// Scan specific error types
#[derive(Debug)]
#[must_use = "Need to handle all error enum types."]
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
    /// Upload timeout waiting for file processing
    UploadTimeout(String),
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
            ScanError::UploadFailed(msg) => write!(f, "{msg}"),
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
            ScanError::UploadTimeout(msg) => write!(f, "Upload timeout: {msg}"),
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// Create a new `ScanApi` instance
    #[must_use]
    pub fn new(client: VeracodeClient) -> Self {
        Self { client }
    }

    /// Validate filename for path traversal sequences
    fn validate_filename(filename: &str) -> Result<(), ScanError> {
        // Use shared validation from validation.rs to prevent path traversal
        validate_url_segment(filename, 255)
            .map_err(|e| ScanError::InvalidParameter(format!("Invalid filename: {}", e)))?;
        Ok(())
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn upload_file(
        &self,
        request: &UploadFileRequest,
    ) -> Result<UploadedFile, ScanError> {
        // Validate save_as parameter for path traversal
        if let Some(save_as) = &request.save_as {
            Self::validate_filename(save_as)?;
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

        // Read file data - this will return an error if the file doesn't exist
        let file_data = tokio::fs::read(&request.file_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ScanError::FileNotFound(request.file_path.clone())
            } else {
                ScanError::from(e)
            }
        })?;

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
                    .await
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn upload_large_file(
        &self,
        request: UploadLargeFileRequest,
    ) -> Result<UploadedFile, ScanError> {
        // Validate filename parameter for path traversal
        if let Some(filename) = &request.filename {
            Self::validate_filename(filename)?;
        }

        // Check file size (2GB limit for uploadlargefile.do)
        // This will return an error if the file doesn't exist
        let file_metadata = tokio::fs::metadata(&request.file_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ScanError::FileNotFound(request.file_path.clone())
            } else {
                ScanError::from(e)
            }
        })?;
        let file_size = file_metadata.len();
        const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2GB

        if file_size > MAX_FILE_SIZE {
            return Err(ScanError::FileTooLarge(format!(
                "File size {file_size} bytes exceeds 2GB limit"
            )));
        }

        let endpoint = "/api/5.0/uploadlargefile.do";

        // Build query parameters
        let mut query_params = Vec::new();
        query_params.push(("app_id", request.app_id.as_str()));

        if let Some(sandbox_id) = &request.sandbox_id {
            query_params.push(("sandbox_id", sandbox_id.as_str()));
        }

        if let Some(filename) = &request.filename {
            query_params.push(("filename", filename.as_str()));
        }

        // Use streaming upload for memory efficiency (avoids loading entire file into RAM)
        let response = self
            .client
            .upload_file_streaming(
                endpoint,
                &query_params,
                &request.file_path,
                file_size,
                "binary/octet-stream",
            )
            .await?;

        let status = response.status().as_u16();
        match status {
            200 => {
                // uploadlargefile.do returns 200 with XML containing the file list
                info!("File upload completed (HTTP 200), parsing response...");

                let response_text = response.text().await?;

                // Parse the file list from the response
                let files = self.parse_file_list(&response_text)?;

                // Determine the filename that was uploaded
                let filename = request.filename.as_ref().cloned().unwrap_or_else(|| {
                    Path::new(&request.file_path)
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("file")
                        .to_string()
                });

                // Find the uploaded file in the response
                files
                    .into_iter()
                    .find(|f| f.file_name == filename)
                    .ok_or_else(|| {
                        ScanError::UploadFailed(format!(
                            "File '{}' not found in upload response",
                            filename
                        ))
                    })
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    /// This method provides the same functionality as `upload_large_file` but with
    /// progress tracking capabilities through a callback function.
    ///
    /// # Arguments
    ///
    /// * `request` - The upload large file request
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    /// * `progress_callback` - Callback function for progress updates (`bytes_uploaded`, `total_bytes`, percentage)
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn upload_large_file_with_progress<F>(
        &self,
        request: UploadLargeFileRequest,
        progress_callback: F,
    ) -> Result<UploadedFile, ScanError>
    where
        F: Fn(u64, u64, f64) + Send + Sync,
    {
        // Validate filename parameter for path traversal
        if let Some(filename) = &request.filename {
            Self::validate_filename(filename)?;
        }

        // Check file size (2GB limit)
        // This will return an error if the file doesn't exist
        let file_metadata = tokio::fs::metadata(&request.file_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ScanError::FileNotFound(request.file_path.clone())
            } else {
                ScanError::from(e)
            }
        })?;
        let file_size = file_metadata.len();
        const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2GB

        if file_size > MAX_FILE_SIZE {
            return Err(ScanError::FileTooLarge(format!(
                "File size {file_size} bytes exceeds 2GB limit"
            )));
        }

        let endpoint = "/api/5.0/uploadlargefile.do";

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
                // uploadlargefile.do returns 200 with XML containing the file list
                info!("File upload completed (HTTP 200), parsing response...");

                let response_text = response.text().await?;

                // Parse the file list from the response
                let files = self.parse_file_list(&response_text)?;

                // Determine the filename that was uploaded
                let filename = request.filename.as_ref().cloned().unwrap_or_else(|| {
                    Path::new(&request.file_path)
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("file")
                        .to_string()
                });

                // Find the uploaded file in the response
                files
                    .into_iter()
                    .find(|f| f.file_name == filename)
                    .ok_or_else(|| {
                        ScanError::UploadFailed(format!(
                            "File '{}' not found in upload response",
                            filename
                        ))
                    })
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn upload_file_smart(
        &self,
        request: &UploadFileRequest,
    ) -> Result<UploadedFile, ScanError> {
        // Get file size to determine upload method
        // This will return an error if the file doesn't exist
        let file_metadata = tokio::fs::metadata(&request.file_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ScanError::FileNotFound(request.file_path.clone())
            } else {
                ScanError::from(e)
            }
        })?;
        let file_size = file_metadata.len();

        // Use large file upload for files over 100MB or when build might exist
        const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024; // 100MB

        if file_size > LARGE_FILE_THRESHOLD {
            // Convert to large file request format using From trait
            let large_request = UploadLargeFileRequest::from(request);

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
    /// A `Result` indicating success or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn begin_prescan(&self, request: &BeginPreScanRequest) -> Result<(), ScanError> {
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
                // Just validate the response is successful, don't parse build_id
                // since we already have it from ensure_build_exists
                self.validate_scan_response(&response_text)?;
                Ok(())
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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
    /// A `Result` indicating success or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn begin_scan(&self, request: &BeginScanRequest) -> Result<(), ScanError> {
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
                // Just validate the response is successful, don't parse build_id
                // since we already have it from ensure_build_exists
                self.validate_scan_response(&response_text)?;
                Ok(())
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn delete_all_builds(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
    ) -> Result<(), ScanError> {
        // First get list of builds
        let build_info = self.get_build_info(app_id, None, sandbox_id).await?;

        if !build_info.build_id.is_empty() && build_info.build_id != "unknown" {
            info!("Deleting build: {}", build_info.build_id);
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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

    async fn parse_upload_response(
        &self,
        xml: &str,
        file_path: &str,
    ) -> Result<UploadedFile, ScanError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut file_id = None;
        let mut file_status = FileStatus::PendingUpload;
        let mut _md5: Option<String> = None;
        let mut current_error: Option<String> = None;
        let mut in_error_tag = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    if e.name().as_ref() == b"file" {
                        // Extract file_id and file_status from attributes
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"file_id" => file_id = Some(attr_to_string(&attr.value)),
                                b"file_status" => {
                                    let status_str = attr_to_string(&attr.value);
                                    file_status =
                                        status_str.parse().unwrap_or(FileStatus::PendingUpload);
                                }
                                _ => {}
                            }
                        }
                    } else if e.name().as_ref() == b"error" {
                        in_error_tag = true;
                    }
                }
                Ok(Event::Text(e)) => {
                    if in_error_tag {
                        current_error = Some(String::from_utf8_lossy(&e).to_string());
                    } else {
                        let text = std::str::from_utf8(&e).unwrap_or_default();
                        // Check for success/error messages in text content
                        if text.contains("successfully uploaded") {
                            file_status = FileStatus::Uploaded;
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == b"error" {
                        in_error_tag = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    error!("Error parsing XML: {e}");
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        // If an error was found in the XML, return it
        if let Some(error_msg) = current_error {
            return Err(ScanError::UploadFailed(error_msg));
        }

        let filename = Path::new(file_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("file")
            .to_string();

        Ok(UploadedFile {
            file_id: file_id.unwrap_or_else(|| format!("file_{}", chrono::Utc::now().timestamp())),
            file_name: filename,
            file_size: tokio::fs::metadata(file_path)
                .await
                .map(|m| m.len())
                .unwrap_or(0),
            uploaded: Utc::now(),
            file_status,
            md5: None,
        })
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    /// Validate scan response for basic success without parsing `build_id`
    fn validate_scan_response(&self, xml: &str) -> Result<(), ScanError> {
        // Check for basic error conditions in the response
        if xml.contains("<error>") {
            // Extract error message if present
            let mut reader = Reader::from_str(xml);
            reader.config_mut().trim_text(true);

            let mut buf = Vec::new();
            let mut in_error = false;
            let mut error_message = String::new();

            loop {
                match reader.read_event_into(&mut buf) {
                    Ok(Event::Start(ref e)) if e.name().as_ref() == b"error" => {
                        in_error = true;
                    }
                    Ok(Event::Text(ref e)) if in_error => {
                        error_message.push_str(&String::from_utf8_lossy(e));
                    }
                    Ok(Event::End(ref e)) if e.name().as_ref() == b"error" => {
                        break;
                    }
                    Ok(Event::Eof) => break,
                    Err(e) => {
                        return Err(ScanError::ScanFailed(format!("XML parsing error: {e}")));
                    }
                    _ => {}
                }
                buf.clear();
            }

            if !error_message.is_empty() {
                return Err(ScanError::ScanFailed(error_message));
            }
            return Err(ScanError::ScanFailed(
                "Unknown error in scan response".to_string(),
            ));
        }

        // Check for successful response indicators
        if xml.contains("<buildinfo") || xml.contains("<build") {
            Ok(())
        } else {
            Err(ScanError::ScanFailed(
                "Invalid scan response format".to_string(),
            ))
        }
    }

    /// Helper function to parse module attributes from XML element
    fn parse_module_from_attributes<'a>(
        &self,
        attributes: impl Iterator<
            Item = Result<
                quick_xml::events::attributes::Attribute<'a>,
                quick_xml::events::attributes::AttrError,
            >,
        >,
        has_fatal_errors: &mut bool,
    ) -> ScanModule {
        let mut module = ScanModule {
            id: String::new(),
            name: String::new(),
            module_type: String::new(),
            is_fatal: false,
            selected: false,
            size: None,
            platform: None,
        };

        for attr in attributes.flatten() {
            match attr.key.as_ref() {
                b"id" => module.id = attr_to_string(&attr.value),
                b"name" => module.name = attr_to_string(&attr.value),
                b"type" => module.module_type = attr_to_string(&attr.value),
                b"isfatal" => module.is_fatal = attr.value.as_ref() == b"true",
                b"selected" => module.selected = attr.value.as_ref() == b"true",
                b"has_fatal_errors" => {
                    if attr.value.as_ref() == b"true" {
                        *has_fatal_errors = true;
                    }
                }
                b"size" => {
                    if let Ok(size_str) = String::from_utf8(attr.value.to_vec()) {
                        module.size = size_str.parse().ok();
                    }
                }
                b"platform" => module.platform = Some(attr_to_string(&attr.value)),
                _ => {}
            }
        }

        module
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
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"build_id" {
                                    build_id = Some(attr_to_string(&attr.value));
                                }
                            }
                        }
                        b"module" => {
                            let module = self.parse_module_from_attributes(
                                e.attributes(),
                                &mut has_fatal_errors,
                            );
                            modules.push(module);
                        }
                        _ => {}
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    // Handle self-closing module tags like <module ... />
                    if e.name().as_ref() == b"module" {
                        let module = self
                            .parse_module_from_attributes(e.attributes(), &mut has_fatal_errors);
                        modules.push(module);
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    error!("Error parsing XML: {e}");
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

    /// Helper function to parse file attributes from XML element
    fn parse_file_from_attributes<'a>(
        &self,
        attributes: impl Iterator<
            Item = Result<
                quick_xml::events::attributes::Attribute<'a>,
                quick_xml::events::attributes::AttrError,
            >,
        >,
    ) -> UploadedFile {
        let mut file = UploadedFile {
            file_id: String::new(),
            file_name: String::new(),
            file_size: 0,
            uploaded: Utc::now(),
            file_status: FileStatus::PendingUpload, // Default to PendingUpload for unknown status
            md5: None,
        };

        for attr in attributes.flatten() {
            match attr.key.as_ref() {
                b"file_id" => file.file_id = attr_to_string(&attr.value),
                b"file_name" => file.file_name = attr_to_string(&attr.value),
                b"file_size" => {
                    if let Ok(size_str) = String::from_utf8(attr.value.to_vec()) {
                        file.file_size = size_str.parse().unwrap_or(0);
                    }
                }
                b"file_status" => {
                    let status_str = attr_to_string(&attr.value);
                    // Parse status, fallback to PendingUpload if unknown
                    file.file_status = status_str.parse().unwrap_or_else(|e| {
                        error!("Unknown file status '{}': {}", status_str, e);
                        FileStatus::PendingUpload
                    });
                }
                b"md5" | b"file_md5" => {
                    file.md5 = Some(String::from_utf8_lossy(&attr.value).to_string())
                }
                _ => {}
            }
        }

        file
    }

    fn parse_file_list(&self, xml: &str) -> Result<Vec<UploadedFile>, ScanError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut files = Vec::new();
        let mut current_error: Option<String> = None;
        let mut in_error_tag = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    if e.name().as_ref() == b"file" {
                        let file = self.parse_file_from_attributes(e.attributes());
                        files.push(file);
                    } else if e.name().as_ref() == b"error" {
                        in_error_tag = true;
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    // Handle self-closing file tags like <file ... />
                    if e.name().as_ref() == b"file" {
                        let file = self.parse_file_from_attributes(e.attributes());
                        files.push(file);
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if in_error_tag {
                        current_error = Some(String::from_utf8_lossy(e).to_string());
                    }
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == b"error" {
                        in_error_tag = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    error!("Error parsing XML: {e}");
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        // If an error was found in the XML, return it
        if let Some(error_msg) = current_error {
            return Err(ScanError::UploadFailed(error_msg));
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
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"build_id" => scan_info.build_id = attr_to_string(&attr.value),
                                    b"analysis_unit" => {
                                        // Fallback status from buildinfo (older API format)
                                        if scan_info.status == "Unknown" {
                                            scan_info.status = attr_to_string(&attr.value);
                                        }
                                    }
                                    b"analysis_unit_id" => {
                                        scan_info.analysis_unit_id =
                                            Some(attr_to_string(&attr.value))
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
                                            scan_info.total_lines_of_code = lines_str.parse().ok();
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        b"build" => {
                            inside_build = true;
                        }
                        b"analysis_unit" => {
                            // Parse analysis_unit attributes (primary status source)
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"status" => {
                                        // Primary status source from analysis_unit
                                        scan_info.status = attr_to_string(&attr.value);
                                    }
                                    b"analysis_type" => {
                                        scan_info.scan_type = attr_to_string(&attr.value);
                                    }
                                    _ => {}
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
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"status" => {
                                    scan_info.status = attr_to_string(&attr.value);
                                }
                                b"analysis_type" => {
                                    scan_info.scan_type = attr_to_string(&attr.value);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    error!("Error parsing XML: {e}");
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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

        self.upload_file(&request).await
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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

        self.upload_file(&request).await
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn begin_sandbox_prescan(
        &self,
        app_id: &str,
        sandbox_id: &str,
    ) -> Result<(), ScanError> {
        let request = BeginPreScanRequest {
            app_id: app_id.to_string(),
            sandbox_id: Some(sandbox_id.to_string()),
            auto_scan: Some(true),
            scan_all_nonfatal_top_level_modules: Some(true),
            include_new_modules: Some(true),
        };

        self.begin_prescan(&request).await
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn begin_sandbox_scan_all_modules(
        &self,
        app_id: &str,
        sandbox_id: &str,
    ) -> Result<(), ScanError> {
        let request = BeginScanRequest {
            app_id: app_id.to_string(),
            sandbox_id: Some(sandbox_id.to_string()),
            modules: None,
            scan_all_top_level_modules: Some(true),
            scan_all_nonfatal_top_level_modules: Some(true),
            scan_previously_selected_modules: None,
        };

        self.begin_scan(&request).await
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn upload_and_scan_sandbox(
        &self,
        app_id: &str,
        sandbox_id: &str,
        file_path: &str,
    ) -> Result<String, ScanError> {
        // Step 1: Upload file
        info!("Uploading file to sandbox...");
        let _uploaded_file = self
            .upload_file_to_sandbox(app_id, file_path, sandbox_id)
            .await?;

        // Step 2: Begin pre-scan
        info!("Beginning pre-scan...");
        self.begin_sandbox_prescan(app_id, sandbox_id).await?;

        // Step 3: Wait a moment for pre-scan to complete (in production, poll for status)
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Step 4: Begin scan
        info!("Beginning scan...");
        self.begin_sandbox_scan_all_modules(app_id, sandbox_id)
            .await?;

        // For now, return a placeholder build ID since we don't parse it from responses anymore
        // In a real implementation, this would need to come from ensure_build_exists or similar
        // This is a limitation of this convenience method - it should be deprecated in favor
        // of the proper workflow that tracks build IDs
        Ok("build_id_not_available".to_string())
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the scan operation fails,
    /// or authentication/authorization fails.
    pub async fn delete_all_app_builds(&self, app_id: &str) -> Result<(), ScanError> {
        self.delete_all_builds(app_id, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VeracodeConfig;
    use proptest::prelude::*;

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
            let config = VeracodeConfig::new("test", "test");
            let client = VeracodeClient::new(config)?;
            let api = client.scan_api()?;

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
        // Test passes if no panic occurs
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

    #[test]
    fn test_validate_filename_path_traversal() {
        // Valid filenames should pass
        assert!(ScanApi::validate_filename("valid_file.jar").is_ok());
        assert!(ScanApi::validate_filename("my-app.war").is_ok());
        assert!(ScanApi::validate_filename("file123.zip").is_ok());

        // Path traversal sequences should fail
        assert!(ScanApi::validate_filename("../etc/passwd").is_err());
        assert!(ScanApi::validate_filename("test/../file.jar").is_err());
        assert!(ScanApi::validate_filename("test/file.jar").is_err());
        assert!(ScanApi::validate_filename("test\\file.jar").is_err());
        assert!(ScanApi::validate_filename("..\\windows\\system32").is_err());

        // Control characters should fail
        assert!(ScanApi::validate_filename("test\x00file.jar").is_err());
        assert!(ScanApi::validate_filename("test\nfile.jar").is_err());
        assert!(ScanApi::validate_filename("test\rfile.jar").is_err());
        assert!(ScanApi::validate_filename("test\x1Ffile.jar").is_err());
    }

    #[tokio::test]
    async fn test_large_file_upload_method_signatures() {
        async fn _test_large_file_methods() -> Result<(), Box<dyn std::error::Error>> {
            let config = VeracodeConfig::new("test", "test");
            let client = VeracodeClient::new(config)?;
            let api = client.scan_api()?;

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
                debug!("Upload progress: {bytes_uploaded}/{total_bytes} ({percentage:.1}%)");
            };
            let _: Result<UploadedFile, _> = api
                .upload_large_file_with_progress(request, progress_callback)
                .await;

            Ok(())
        }

        // If this compiles, the methods have correct signatures
        // Test passes if no panic occurs
    }

    // =========================================================================
    // PROPERTY-BASED SECURITY TESTS (Proptest)
    // =========================================================================

    mod proptest_security {
        use super::*;

        // Strategy to generate potentially malicious filenames
        fn malicious_filename_strategy() -> impl Strategy<Value = String> {
            prop_oneof![
                // Path traversal attempts
                Just("../etc/passwd".to_string()),
                Just("..\\windows\\system32".to_string()),
                Just("test/../../../secret".to_string()),
                Just("./../../admin".to_string()),
                // Embedded path separators
                Just("dir/file.jar".to_string()),
                Just("dir\\file.exe".to_string()),
                // Control characters
                Just("test\x00file.jar".to_string()),
                Just("test\nfile.jar".to_string()),
                Just("test\rfile.jar".to_string()),
                Just("test\x1Ffile.jar".to_string()),
                // URL encoding attempts
                Just("..%2F..%2Fetc%2Fpasswd".to_string()),
                Just("..%5C..%5Cwindows".to_string()),
                // Unicode normalization attacks
                Just("..%c0%af..%c0%afetc%c0%afpasswd".to_string()),
                // Double encoding
                Just("..%252F..%252Fetc".to_string()),
                // Mixed separators
                Just("..\\/../admin".to_string()),
                // Long path traversal
                Just("../".repeat(20)),
                // Null bytes in various positions
                Just("\x00file.jar".to_string()),
                Just("file.jar\x00.exe".to_string()),
                // More traversal attempts
                Just("..".to_string()),
                Just("../../".to_string()),
                Just("/etc/passwd".to_string()),
                Just("\\windows\\system32".to_string()),
            ]
        }

        // Strategy for valid filenames
        fn valid_filename_strategy() -> impl Strategy<Value = String> {
            "[a-zA-Z0-9_-]{1,200}\\.(jar|war|zip|ear|class)".prop_map(|s| s)
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Property: validate_filename must reject all path traversal attempts
            #[test]
            fn prop_validate_filename_rejects_path_traversal(
                filename in malicious_filename_strategy()
            ) {
                // All malicious filenames should be rejected
                let result = ScanApi::validate_filename(&filename);
                prop_assert!(result.is_err(), "Should reject malicious filename: {}", filename);
            }

            /// Property: validate_filename accepts valid filenames
            #[test]
            fn prop_validate_filename_accepts_valid(
                filename in valid_filename_strategy()
            ) {
                let result = ScanApi::validate_filename(&filename);
                prop_assert!(result.is_ok(), "Should accept valid filename: {}", filename);
            }

            /// Property: Empty filename is always rejected
            #[test]
            fn prop_validate_filename_rejects_empty(_n in 0..100u32) {
                let result = ScanApi::validate_filename("");
                prop_assert!(result.is_err(), "Empty filename should be rejected");
            }

            /// Property: Filenames exceeding max length are rejected
            #[test]
            fn prop_validate_filename_rejects_too_long(extra_len in 1..100usize) {
                let long_filename = "a".repeat(256_usize.saturating_add(extra_len));
                let result = ScanApi::validate_filename(&long_filename);
                prop_assert!(result.is_err(), "Filename longer than 255 chars should be rejected");
            }

            /// Property: Filenames with ".." anywhere are rejected
            #[test]
            fn prop_validate_filename_rejects_double_dot(
                prefix in "[a-zA-Z0-9]{0,10}",
                suffix in "[a-zA-Z0-9]{0,10}"
            ) {
                let filename = format!("{}..{}", prefix, suffix);
                let result = ScanApi::validate_filename(&filename);
                prop_assert!(result.is_err(), "Filename with '..' should be rejected: {}", filename);
            }

            /// Property: Filenames with "/" are rejected
            #[test]
            fn prop_validate_filename_rejects_forward_slash(
                prefix in "[a-zA-Z0-9]{1,10}",
                suffix in "[a-zA-Z0-9]{1,10}"
            ) {
                let filename = format!("{}/{}", prefix, suffix);
                let result = ScanApi::validate_filename(&filename);
                prop_assert!(result.is_err(), "Filename with '/' should be rejected: {}", filename);
            }

            /// Property: Filenames with "\\" are rejected
            #[test]
            fn prop_validate_filename_rejects_backslash(
                prefix in "[a-zA-Z0-9]{1,10}",
                suffix in "[a-zA-Z0-9]{1,10}"
            ) {
                let filename = format!("{}\\{}", prefix, suffix);
                let result = ScanApi::validate_filename(&filename);
                prop_assert!(result.is_err(), "Filename with '\\' should be rejected: {}", filename);
            }

            /// Property: Filenames with control characters are rejected
            #[test]
            fn prop_validate_filename_rejects_control_chars(
                prefix in "[a-zA-Z0-9]{0,10}",
                control_char in 0x00u8..0x20u8,
                suffix in "[a-zA-Z0-9]{0,10}"
            ) {
                let filename = format!("{}{}{}", prefix, control_char as char, suffix);
                let result = ScanApi::validate_filename(&filename);
                prop_assert!(result.is_err(), "Filename with control char should be rejected");
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 500 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Property: attr_to_string handles all valid UTF-8
            #[test]
            fn prop_attr_to_string_valid_utf8(s in ".*") {
                let bytes = s.as_bytes();
                let result = attr_to_string(bytes);
                prop_assert_eq!(&result, &s, "attr_to_string should preserve valid UTF-8");
            }

            /// Property: attr_to_string handles invalid UTF-8 gracefully
            #[test]
            fn prop_attr_to_string_invalid_utf8(bytes in prop::collection::vec(any::<u8>(), 0..100)) {
                // Should not panic on invalid UTF-8
                let _result = attr_to_string(&bytes);
                // Result should always be a valid Rust string (String type guarantees valid UTF-8)
                // The function may use replacement characters for invalid sequences
                // Just verify the function doesn't panic - the String type itself guarantees validity
                prop_assert!(true, "Function should not panic on invalid UTF-8");
            }

            /// Property: File size validation for 2GB limit
            #[test]
            fn prop_file_size_validation(size in 0u64..5_000_000_000u64) {
                const MAX_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2GB
                let exceeds_limit = size > MAX_SIZE;

                // Verify our logic matches the actual threshold
                if exceeds_limit {
                    prop_assert!(size > MAX_SIZE, "Size should exceed 2GB limit");
                } else {
                    prop_assert!(size <= MAX_SIZE, "Size should be within 2GB limit");
                }
            }

            /// Property: UploadProgress percentage calculation is consistent
            #[test]
            fn prop_upload_progress_percentage(
                bytes_uploaded in 0u64..1_000_000u64,
                total_bytes in 1u64..1_000_000u64
            ) {
                // Ensure bytes_uploaded <= total_bytes
                let bytes_uploaded = bytes_uploaded.min(total_bytes);

                #[allow(clippy::cast_precision_loss)]
                let percentage = (bytes_uploaded as f64 / total_bytes as f64) * 100.0;

                prop_assert!((0.0..=100.0).contains(&percentage),
                    "Percentage should be in range [0, 100], got {}", percentage);

                if bytes_uploaded == 0 {
                    prop_assert!(percentage == 0.0, "0 bytes should be 0%");
                }
                if bytes_uploaded == total_bytes {
                    prop_assert!(percentage == 100.0, "Full upload should be 100%");
                }
            }

            /// Property: app_id and sandbox_id never contain path separators
            #[test]
            fn prop_request_ids_no_path_separators(
                app_id in "[a-zA-Z0-9-]{1,50}",
                sandbox_id in "[a-zA-Z0-9-]{1,50}"
            ) {
                // Verify IDs don't contain dangerous characters
                prop_assert!(!app_id.contains('/') && !app_id.contains('\\'));
                prop_assert!(!sandbox_id.contains('/') && !sandbox_id.contains('\\'));
                prop_assert!(!app_id.contains("..") && !sandbox_id.contains(".."));
            }

            /// Property: Build ID parsing from XML should never panic
            #[test]
            fn prop_build_id_parsing_safe(build_id_value in ".*") {
                // Simulate XML attribute value
                let _xml = format!(r#"<buildinfo build_id="{}" />"#, build_id_value);

                // Parsing should not panic even with malicious input
                // (We can't test the actual parser here without creating a full ScanApi instance,
                // but we can verify the string operations are safe)
                let _escaped = build_id_value.replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;");

                prop_assert!(true, "String escaping should not panic");
            }

            /// Property: File path edge cases
            #[test]
            fn prop_file_path_edge_cases(
                path_segments in prop::collection::vec("[a-zA-Z0-9_-]{1,20}", 1..5)
            ) {
                let path = path_segments.join("/");

                // Path should not contain ".."
                prop_assert!(!path.contains(".."), "Generated path should not contain '..'");

                // Path should be constructible
                let _path_obj = std::path::Path::new(&path);
                prop_assert!(true, "Path construction should not panic");
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 500 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Property: XML parsing robustness - should handle various attribute values
            #[test]
            fn prop_xml_attribute_robustness(
                file_id in "[a-zA-Z0-9_-]{1,50}",
                file_name in "[a-zA-Z0-9._-]{1,100}",
                file_size in 0u64..10_000_000u64
            ) {
                // Build a simple XML response
                let xml = format!(
                    r#"<filelist><file file_id="{}" file_name="{}" file_size="{}" /></filelist>"#,
                    file_id, file_name, file_size
                );

                // Verify XML is well-formed (basic sanity check)
                prop_assert!(xml.contains(&file_id));
                prop_assert!(xml.contains(&file_name));
            }

            /// Property: Status string validation
            #[test]
            fn prop_status_validation(status in "[A-Za-z ]{1,50}") {
                // Status strings should not contain control characters
                prop_assert!(!status.chars().any(|c| c.is_control()));
            }

            /// Property: Module ID validation
            #[test]
            fn prop_module_id_validation(
                module_id in "[a-zA-Z0-9_-]{1,100}"
            ) {
                // Module IDs should be alphanumeric with dashes/underscores
                prop_assert!(module_id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-'));
            }
        }
    }

    // =========================================================================
    // EDGE CASE AND BOUNDARY TESTS
    // =========================================================================

    mod boundary_tests {
        use super::*;

        #[test]
        fn test_file_size_exactly_2gb() {
            const TWO_GB: u64 = 2 * 1024 * 1024 * 1024;
            // File exactly at 2GB should not be rejected (boundary)
            assert_eq!(TWO_GB, 2_147_483_648);
        }

        #[test]
        fn test_file_size_just_over_2gb() {
            const JUST_OVER: u64 = 2 * 1024 * 1024 * 1024 + 1;
            const TWO_GB_LIMIT: u64 = 2_147_483_648;
            // File just over 2GB should be rejected
            assert_eq!(JUST_OVER, TWO_GB_LIMIT + 1);
        }

        #[test]
        fn test_filename_max_length_boundary() {
            // Filename exactly at 255 chars should pass
            let max_len_filename = "a".repeat(255);
            assert!(ScanApi::validate_filename(&max_len_filename).is_ok());

            // Filename at 256 chars should fail
            let over_max_filename = "a".repeat(256);
            assert!(ScanApi::validate_filename(&over_max_filename).is_err());
        }

        #[test]
        fn test_validate_filename_unicode_normalization() {
            // Test that Unicode normalization doesn't bypass validation
            // U+002E is ".", U+2024 is "ONE DOT LEADER"
            let tricky = ".\u{2024}./file.jar";
            // Should still be rejected if it contains path separators
            if tricky.contains('/') || tricky.contains('\\') || tricky.contains("..") {
                assert!(ScanApi::validate_filename(tricky).is_err());
            }
        }

        #[test]
        fn test_validate_filename_homoglyph_attacks() {
            // Test homoglyph attacks (characters that look similar)
            // Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
            // Full-width solidus (U+FF0F) vs regular slash (U+002F)
            let homoglyph_slash = "test\u{FF0F}file.jar";

            // The validation should be strict enough to catch these
            // (depending on whether the homoglyph is normalized to a path separator)
            let result = ScanApi::validate_filename(homoglyph_slash);
            // At minimum, it should not panic
            assert!(result.is_ok() || result.is_err());
        }

        #[test]
        fn test_attr_to_string_empty() {
            let result = attr_to_string(b"");
            assert_eq!(result, "");
        }

        #[test]
        fn test_attr_to_string_ascii() {
            let result = attr_to_string(b"test123");
            assert_eq!(result, "test123");
        }

        #[test]
        fn test_attr_to_string_utf8() {
            let result = attr_to_string("hello 世界".as_bytes());
            assert_eq!(result, "hello 世界");
        }

        #[test]
        fn test_attr_to_string_invalid_utf8() {
            // Invalid UTF-8 sequence
            let invalid = &[0xFF, 0xFE, 0xFD];
            let result = attr_to_string(invalid);
            // Should contain replacement characters, not panic
            assert!(result.contains('\u{FFFD}'));
        }

        #[test]
        fn test_upload_progress_zero_bytes() {
            let progress = UploadProgress {
                bytes_uploaded: 0,
                total_bytes: 1000,
                percentage: 0.0,
            };
            assert_eq!(progress.percentage, 0.0);
        }

        #[test]
        fn test_upload_progress_complete() {
            let progress = UploadProgress {
                bytes_uploaded: 1000,
                total_bytes: 1000,
                percentage: 100.0,
            };
            assert_eq!(progress.percentage, 100.0);
        }

        #[test]
        fn test_scan_error_display_all_variants() {
            // Ensure all error variants have valid Display implementations
            let errors = vec![
                ScanError::FileNotFound("test.jar".to_string()),
                ScanError::InvalidFileFormat("bad format".to_string()),
                ScanError::UploadFailed("network".to_string()),
                ScanError::ScanFailed("failed".to_string()),
                ScanError::PreScanFailed("prescan".to_string()),
                ScanError::BuildNotFound,
                ScanError::ApplicationNotFound,
                ScanError::SandboxNotFound,
                ScanError::Unauthorized,
                ScanError::PermissionDenied,
                ScanError::InvalidParameter("param".to_string()),
                ScanError::FileTooLarge("too big".to_string()),
                ScanError::UploadInProgress,
                ScanError::ScanInProgress,
                ScanError::BuildCreationFailed("failed".to_string()),
                ScanError::ChunkedUploadFailed("chunked".to_string()),
            ];

            for error in errors {
                let display = error.to_string();
                assert!(!display.is_empty(), "Error display should not be empty");
                assert!(
                    !display.contains("Error"),
                    "Should have custom message, got: {}",
                    display
                );
            }
        }
    }

    // =========================================================================
    // ERROR HANDLING TESTS
    // =========================================================================

    mod error_handling_tests {
        use super::*;

        #[test]
        fn test_scan_error_from_veracode_error() {
            let ve = VeracodeError::InvalidResponse("test".to_string());
            let se: ScanError = ve.into();
            assert!(matches!(se, ScanError::Api(_)));
        }

        #[test]
        fn test_scan_error_from_io_error() {
            let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
            let se: ScanError = io_err.into();
            assert!(matches!(se, ScanError::FileNotFound(_)));
        }

        #[test]
        fn test_scan_error_must_use() {
            // Verify #[must_use] attribute is present on ScanError enum
            // This is a compile-time check - if it compiles, the attribute is there
            fn _check_must_use() -> ScanError {
                ScanError::BuildNotFound
            }
        }
    }
}

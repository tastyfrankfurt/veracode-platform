use std::borrow::Cow;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::task::JoinSet;

use crate::filevalidator::{FileValidator, ValidationError};

// Constants for commonly used strings to reduce allocations
const DEFAULT_EXPORT_RESULTS_PATH: &str = "assessment-results.json";
const SANDBOX_NAME_REQUIRED_ERROR: &str = "Sandbox name required for sandbox scans";
const SANDBOX_ID_REQUIRED_ERROR: &str = "Sandbox legacy ID required for sandbox scans";
const UNKNOWN_UPLOAD_ERROR: &str = "Unknown upload error";
const TOOL_NAME: &str = "verascan";
use veracode_platform::scan::{UploadFileRequest, UploadLargeFileRequest};
use veracode_platform::workflow::VeracodeWorkflow;
use veracode_platform::{VeracodeClient, VeracodeConfig, VeracodeRegion};

/// Application identifier that contains both GUID (for REST API) and numeric ID (for XML API)
#[derive(Debug, Clone)]
pub struct ApplicationId {
    /// Application GUID - used for REST API calls (sandbox operations)
    pub guid: Cow<'static, str>,
    /// Application numeric ID - used for XML API calls (build, scan operations)
    pub legacy_id: Cow<'static, str>,
}

impl ApplicationId {
    /// Create new ApplicationId from both identifiers
    pub fn new(
        guid: impl Into<Cow<'static, str>>,
        legacy_id: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            guid: guid.into(),
            legacy_id: legacy_id.into(),
        }
    }

    /// Get the appropriate ID for REST API calls (sandbox operations)
    pub fn for_rest_api(&self) -> &str {
        &self.guid
    }

    /// Get the appropriate ID for XML API calls (build, scan operations)
    pub fn for_xml_api(&self) -> &str {
        &self.legacy_id
    }
}

/// Sandbox identifier that contains both GUID (for REST API) and numeric ID (for XML API)
#[derive(Debug, Clone)]
pub struct SandboxId {
    /// Sandbox GUID - used for REST API calls (sandbox management)
    pub guid: Cow<'static, str>,
    /// Sandbox numeric ID - used for XML API calls (build, scan operations)
    pub legacy_id: Cow<'static, str>,
    /// Sandbox name for reference
    pub name: Cow<'static, str>,
}

/// Build identifier for Veracode assessment scans
#[derive(Debug, Clone)]
pub struct BuildId {
    /// Build ID - used for XML API calls (scan operations)
    pub id: Cow<'static, str>,
}

impl BuildId {
    /// Create new BuildId from identifier
    pub fn new(id: impl Into<Cow<'static, str>>) -> Self {
        Self { id: id.into() }
    }

    /// Get the build ID as string
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl std::fmt::Display for BuildId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl SandboxId {
    /// Create new SandboxId from all identifiers
    pub fn new(
        guid: impl Into<Cow<'static, str>>,
        legacy_id: impl Into<Cow<'static, str>>,
        name: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            guid: guid.into(),
            legacy_id: legacy_id.into(),
            name: name.into(),
        }
    }

    /// Get the appropriate ID for REST API calls (sandbox management)
    pub fn for_rest_api(&self) -> &str {
        &self.guid
    }

    /// Get the appropriate ID for XML API calls (build, scan operations)
    pub fn for_xml_api(&self) -> &str {
        &self.legacy_id
    }

    /// Get the sandbox name
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Helper function to format bytes for display
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{bytes} {}", UNITS[unit_index])
    } else {
        format!("{size:.1} {}", UNITS[unit_index])
    }
}

#[derive(Debug)]
pub enum AssessmentError {
    VeracodeError(veracode_platform::VeracodeError),
    NoValidFiles,
    ConfigError(String),
    ScanError(String),
    UploadError(String),
    SandboxError(String),
    PolicyError(String),
    ValidationError(ValidationError),
}

impl std::fmt::Display for AssessmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssessmentError::VeracodeError(e) => write!(f, "Veracode API error: {e}"),
            AssessmentError::NoValidFiles => write!(f, "No valid files found for scanning"),
            AssessmentError::ConfigError(msg) => write!(f, "Configuration error: {msg}"),
            AssessmentError::ScanError(msg) => write!(f, "Scan error: {msg}"),
            AssessmentError::UploadError(msg) => write!(f, "Upload error: {msg}"),
            AssessmentError::SandboxError(msg) => write!(f, "Sandbox error: {msg}"),
            AssessmentError::PolicyError(msg) => write!(f, "Policy error: {msg}"),
            AssessmentError::ValidationError(e) => write!(f, "File validation error: {e}"),
        }
    }
}

impl std::error::Error for AssessmentError {}

impl From<veracode_platform::VeracodeError> for AssessmentError {
    fn from(err: veracode_platform::VeracodeError) -> Self {
        AssessmentError::VeracodeError(err)
    }
}

impl From<ValidationError> for AssessmentError {
    fn from(err: ValidationError) -> Self {
        AssessmentError::ValidationError(err)
    }
}

#[derive(Debug, Clone)]
pub enum ScanType {
    Sandbox,
    Policy,
}

#[derive(Debug, Clone)]
pub struct AssessmentScanConfig {
    pub app_profile_name: String,
    pub scan_type: ScanType,
    pub sandbox_name: Option<String>,
    pub selected_modules: Option<Vec<String>>,
    pub region: VeracodeRegion,
    pub timeout: u32,
    pub threads: usize,
    pub debug: bool,
    pub autoscan: bool,
    pub monitor_completion: bool,
    pub export_results_path: String,
    pub deleteincompletescan: u8,
    pub break_build: bool,
    /// Maximum retry attempts for policy evaluation (default: 30)
    pub policy_wait_max_retries: u32,
    /// Delay between policy evaluation retries in seconds (default: 10)
    pub policy_wait_retry_delay_seconds: u64,
}

impl Default for AssessmentScanConfig {
    fn default() -> Self {
        Self {
            app_profile_name: String::new(),
            scan_type: ScanType::Policy,
            sandbox_name: None,
            selected_modules: None,
            region: VeracodeRegion::Commercial,
            timeout: 60, // 60 minutes default for assessment scans
            threads: 4,  // 4 threads default for assessment uploads
            debug: false,
            autoscan: true,           // Enable autoscan by default
            monitor_completion: true, // Default to monitoring completion
            export_results_path: DEFAULT_EXPORT_RESULTS_PATH.into(),
            deleteincompletescan: 1, // Default to policy 1 (delete safe builds only)
            break_build: false,      // Default to not breaking build
            policy_wait_max_retries: 30, // 30 retries (5 minutes at 10s intervals)
            policy_wait_retry_delay_seconds: 10, // 10 seconds between retries
        }
    }
}

#[derive(Clone)]
pub struct AssessmentSubmitter {
    pub client: VeracodeClient,
    pub config: AssessmentScanConfig,
}

impl AssessmentSubmitter {
    /// Create a new assessment submitter
    pub fn new(
        veracode_config: VeracodeConfig,
        assessment_config: AssessmentScanConfig,
    ) -> Result<Self, AssessmentError> {
        let client = VeracodeClient::new(veracode_config)?;

        Ok(Self {
            client,
            config: assessment_config,
        })
    }

    /// Ensure sandbox exists and get sandbox ID (for sandbox scans only)
    async fn ensure_sandbox_and_get_id(
        &self,
        app_id: &str,
    ) -> Result<Option<SandboxId>, AssessmentError> {
        match self.config.scan_type {
            ScanType::Sandbox => {
                if let Some(ref sandbox_name) = self.config.sandbox_name {
                    if self.config.debug {
                        println!(
                            "🔍 Ensuring sandbox exists and getting legacy ID: {sandbox_name}"
                        );
                    }

                    let sandbox_api = self.client.sandbox_api();

                    // Check if sandbox exists, create if not
                    let sandbox = match sandbox_api.get_sandbox_by_name(app_id, sandbox_name).await
                    {
                        Ok(Some(sandbox)) => {
                            if self.config.debug {
                                println!("✅ Sandbox already exists: {sandbox_name}");
                            }
                            sandbox
                        }
                        Ok(None) | Err(_) => {
                            // Sandbox doesn't exist, create it
                            if self.config.debug {
                                println!("📦 Creating new sandbox: {sandbox_name}");
                            }

                            match sandbox_api
                                .create_simple_sandbox(app_id, sandbox_name)
                                .await
                            {
                                Ok(created_sandbox) => {
                                    println!("✅ Sandbox created: {sandbox_name}");
                                    created_sandbox
                                }
                                Err(e) => {
                                    eprintln!("❌ Failed to create sandbox: {e}");
                                    return Err(AssessmentError::SandboxError(format!(
                                        "Failed to create sandbox {sandbox_name}: {e}"
                                    )));
                                }
                            }
                        }
                    };

                    // Create SandboxId from sandbox information
                    let sandbox_id = SandboxId::new(
                        Cow::Owned(sandbox.guid),
                        sandbox
                            .id
                            .map(|id| Cow::Owned(id.to_string()))
                            .unwrap_or(Cow::Borrowed("")),
                        Cow::Owned(sandbox.name),
                    );

                    if self.config.debug {
                        println!(
                            "📋 Sandbox ID: {} (Legacy: {})",
                            sandbox_id.for_rest_api(),
                            sandbox_id.for_xml_api()
                        );
                    }

                    Ok(Some(sandbox_id))
                } else {
                    Err(AssessmentError::ConfigError(
                        SANDBOX_NAME_REQUIRED_ERROR.into(),
                    ))
                }
            }
            ScanType::Policy => Ok(None),
        }
    }

    /// Ensure build exists and get build ID for uploads (after sandbox is ready)
    async fn ensure_build_exists(
        &self,
        app_id: &str,
        sandbox_legacy_id: Option<&str>,
    ) -> Result<BuildId, AssessmentError> {
        if self.config.debug {
            println!("🔍 Checking/creating build for uploads...");
        }

        let workflow = VeracodeWorkflow::new(self.client.clone());

        // Use sandbox legacy ID instead of name for build creation
        let sandbox_id = match self.config.scan_type {
            ScanType::Sandbox => sandbox_legacy_id,
            ScanType::Policy => None,
        };

        match workflow
            .ensure_build_exists_with_policy(
                app_id,
                sandbox_id,
                None,
                self.config.deleteincompletescan,
            )
            .await
        {
            Ok(build) => {
                if self.config.debug {
                    println!("✅ Build ready for uploads: {}", build.build_id);
                }
                Ok(BuildId::new(Cow::Owned(build.build_id)))
            }
            Err(e) => {
                eprintln!("❌ Failed to ensure build exists: {e}");
                Err(AssessmentError::ScanError(format!(
                    "Failed to ensure build exists: {e}"
                )))
            }
        }
    }

    /// Check if autoscan is enabled in the configuration
    fn is_autoscan_enabled(&self) -> bool {
        self.config.autoscan
    }

    /// Upload files for assessment scanning using concurrent uploads
    pub async fn upload_files(
        &self,
        files: &[PathBuf],
        app_id: &ApplicationId,
        sandbox_id: Option<&SandboxId>,
    ) -> Result<Vec<String>, AssessmentError> {
        if files.is_empty() {
            return Err(AssessmentError::NoValidFiles);
        }

        // Validate cumulative file size (5GB limit for assessment scans)
        let validator = FileValidator::new();
        let file_paths: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
        let total_size_bytes = validator.validate_assessment_cumulative_size(&file_paths)?;

        if self.config.debug {
            let total_size_mb = total_size_bytes as f64 / (1024.0 * 1024.0);
            println!(
                "✅ Cumulative file size validation passed: {total_size_mb:.2} MB total (within 5120 MB limit)"
            );
            println!("📊 Files to process: {}", files.len());
        }

        // Get sandbox legacy ID if sandbox scan
        let sandbox_legacy_id = sandbox_id.map(|s| s.for_xml_api());

        // For single file or small number of files, use sequential upload
        if files.len() == 1 || self.config.threads == 1 {
            self.upload_files_sequential(files, app_id, sandbox_legacy_id)
                .await
        } else {
            // Use concurrent upload for multiple files
            self.upload_files_concurrent(files, app_id, sandbox_legacy_id)
                .await
        }
    }

    /// Upload files sequentially
    async fn upload_files_sequential(
        &self,
        files: &[PathBuf],
        app_id: &ApplicationId,
        sandbox_legacy_id: Option<&str>,
    ) -> Result<Vec<String>, AssessmentError> {
        if self.config.debug {
            println!("🚀 Starting sequential file upload for assessment scan");
            println!("📁 Files to upload: {}", files.len());
            println!("   App Profile: {}", self.config.app_profile_name);
            println!(
                "   App ID: {} (GUID: {})",
                app_id.for_xml_api(),
                app_id.for_rest_api()
            );
            match self.config.scan_type {
                ScanType::Sandbox => {
                    if let Some(ref sandbox_name) = self.config.sandbox_name {
                        println!("   Sandbox: {sandbox_name} (Legacy ID: {sandbox_legacy_id:?})");
                    }
                }
                ScanType::Policy => {
                    println!("   Scan Type: Policy Scan");
                }
            }
        }

        let mut uploaded_files = Vec::new();

        // Upload each file
        for (index, file) in files.iter().enumerate() {
            if self.config.debug {
                println!(
                    "📤 Uploading file {}/{}: {}",
                    index + 1,
                    files.len(),
                    file.display()
                );
            }

            // Use smart upload logic for this file with sandbox legacy ID
            match self
                .upload_single_file_internal(file, app_id, sandbox_legacy_id)
                .await
            {
                Ok(_) => {
                    let file_name = file
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    println!("✅ File uploaded: {file_name}");
                    uploaded_files.push(file_name);
                }
                Err(e) => {
                    eprintln!("❌ Failed to upload file: {e}");
                    return Err(e);
                }
            }
        }

        if self.config.debug {
            println!(
                "✅ All files uploaded successfully: {} files",
                uploaded_files.len()
            );
        }

        Ok(uploaded_files)
    }

    /// Upload multiple files concurrently for assessment scanning
    async fn upload_files_concurrent(
        &self,
        files: &[PathBuf],
        app_id: &ApplicationId,
        sandbox_legacy_id: Option<&str>,
    ) -> Result<Vec<String>, AssessmentError> {
        let num_threads = std::cmp::min(self.config.threads, files.len());

        if self.config.debug {
            println!("🚀 Starting concurrent file upload for assessment scan");
            println!("📁 Files to upload: {}", files.len());
            println!("   Using {num_threads} threads");
            println!("   App Profile: {}", self.config.app_profile_name);
            println!(
                "   App ID: {} (GUID: {})",
                app_id.for_xml_api(),
                app_id.for_rest_api()
            );
            match self.config.scan_type {
                ScanType::Sandbox => {
                    if let Some(ref sandbox_name) = self.config.sandbox_name {
                        println!("   Sandbox: {sandbox_name} (Legacy ID: {sandbox_legacy_id:?})");
                    }
                }
                ScanType::Policy => {
                    println!("   Scan Type: Policy Scan");
                }
            }
        } else {
            println!("🚀 Starting {} concurrent file uploads", files.len());
            if num_threads < files.len() {
                println!("   Using {} threads for {} files", num_threads, files.len());
            }
        }

        // Create a semaphore to limit concurrent operations
        let semaphore = Arc::new(tokio::sync::Semaphore::new(num_threads));
        let mut join_set = JoinSet::new();

        // Use Arc to avoid cloning expensive data for each task
        let submitter_arc = Arc::new(self.clone());
        let app_id_arc = Arc::new(app_id.clone());
        let sandbox_legacy_id_arc = sandbox_legacy_id.map(|s| Arc::new(s.to_string()));

        // Submit each file as a separate task
        for (index, file) in files.iter().enumerate() {
            let file_path = file.clone(); // Only clone the PathBuf
            let semaphore_ref = semaphore.clone();
            let submitter_ref = submitter_arc.clone();
            let app_id_ref = app_id_arc.clone();
            let sandbox_id_ref = sandbox_legacy_id_arc.clone();

            join_set.spawn(async move {
                let _permit = semaphore_ref.acquire().await.unwrap();

                let file_name = file_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                if submitter_ref.config.debug {
                    println!(
                        "📤 Thread {}: Starting upload for {}",
                        index + 1,
                        file_path.display()
                    );
                }

                match submitter_ref
                    .upload_single_file_internal(
                        &file_path,
                        &app_id_ref,
                        sandbox_id_ref.as_ref().map(|arc| arc.as_str()),
                    )
                    .await
                {
                    Ok(_) => {
                        if submitter_ref.config.debug {
                            println!(
                                "✅ Thread {}: Upload completed for {}",
                                index + 1,
                                file_name
                            );
                        } else {
                            println!("✅ File uploaded: {file_name}");
                        }
                        Ok((index, file_name))
                    }
                    Err(e) => {
                        eprintln!(
                            "❌ Thread {}: Failed to upload {}: {}",
                            index + 1,
                            file_name,
                            e
                        );
                        Err((index, e))
                    }
                }
            });
        }

        // Collect results from all tasks using Option for sparse storage
        let mut uploaded_files: Vec<Option<String>> = vec![None; files.len()];
        let mut has_error = false;
        let mut first_error = None;

        while let Some(task_result) = join_set.join_next().await {
            match task_result {
                Ok(upload_result) => match upload_result {
                    Ok((index, file_name)) => {
                        uploaded_files[index] = Some(file_name);
                    }
                    Err((index, e)) => {
                        has_error = true;
                        if first_error.is_none() {
                            first_error = Some(format!("Upload task {} failed: {}", index + 1, e));
                        }
                    }
                },
                Err(join_error) => {
                    has_error = true;
                    if first_error.is_none() {
                        first_error = Some(format!("Task join error: {join_error}"));
                    }
                }
            }
        }

        if has_error {
            return Err(AssessmentError::UploadError(
                first_error.unwrap_or_else(|| UNKNOWN_UPLOAD_ERROR.into()),
            ));
        }

        // Filter out None entries and collect successfully uploaded files
        let successful_uploads: Vec<String> = uploaded_files.into_iter().flatten().collect();

        if self.config.debug {
            println!(
                "✅ All {} files uploaded successfully using {} threads",
                successful_uploads.len(),
                num_threads
            );
        } else {
            println!(
                "✅ All {} files uploaded successfully",
                successful_uploads.len()
            );
        }

        Ok(successful_uploads)
    }

    /// Upload a single file using smart upload logic (internal helper for concurrent uploads)
    async fn upload_single_file_internal(
        &self,
        file: &Path,
        app_id: &ApplicationId,
        sandbox_legacy_id: Option<&str>,
    ) -> Result<(), AssessmentError> {
        const SIZE_THRESHOLD: u64 = 100 * 1024 * 1024; // 100MB

        let file_name = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Validate file size (2GB limit for assessment scans)
        let validator = FileValidator::new();
        let file_size = validator.validate_assessment_file_size(file)?;

        if self.config.debug {
            let size_mb = file_size as f64 / (1024.0 * 1024.0);
            println!("📁 File: {file_name} ({size_mb:.2} MB)");
            println!("✅ File size validation passed (within 2048 MB limit)");

            if file_size > SIZE_THRESHOLD {
                println!("   Using large file upload (>100MB)");
            } else {
                println!("   Using standard upload (<100MB)");
            }
        }

        let scan_api = self.client.scan_api();

        // Choose upload method based on file size and scan type
        let upload_result = if file_size > SIZE_THRESHOLD {
            // Use large file upload with progress for files over 100MB
            match self.config.scan_type {
                ScanType::Sandbox => {
                    if let Some(sandbox_id) = sandbox_legacy_id {
                        // Create progress callback for large file uploads
                        let progress_callback =
                            |bytes_sent: u64, total_bytes: u64, progress: f64| {
                                if progress > 0.0 && (progress * 100.0) as u64 % 25 == 0 {
                                    println!(
                                        "   📈 {}: {:.0}% ({}/{})",
                                        file_name,
                                        progress * 100.0,
                                        format_bytes(bytes_sent),
                                        format_bytes(total_bytes)
                                    );
                                }
                            };

                        let file_path_str = file.to_string_lossy();
                        scan_api
                            .upload_large_file_to_sandbox_with_progress(
                                app_id.for_xml_api(),
                                &file_path_str,
                                sandbox_id,
                                Some(&file_name),
                                progress_callback,
                            )
                            .await
                            .map(|_| ())
                    } else {
                        return Err(AssessmentError::ConfigError(
                            SANDBOX_ID_REQUIRED_ERROR.into(),
                        ));
                    }
                }
                ScanType::Policy => {
                    let file_path_owned = file.to_string_lossy().into_owned();
                    let request = UploadLargeFileRequest {
                        app_id: app_id.for_xml_api().to_string(),
                        file_path: file_path_owned,
                        filename: Some(file_name.clone()),
                        sandbox_id: None,
                    };

                    // Create progress callback for large file uploads
                    let progress_callback = |bytes_sent: u64, total_bytes: u64, progress: f64| {
                        if progress > 0.0 && (progress * 100.0) as u64 % 25 == 0 {
                            println!(
                                "   📈 {}: {:.0}% ({}/{})",
                                file_name,
                                progress * 100.0,
                                format_bytes(bytes_sent),
                                format_bytes(total_bytes)
                            );
                        }
                    };

                    scan_api
                        .upload_large_file_with_progress(request, progress_callback)
                        .await
                        .map(|_| ())
                }
            }
        } else {
            // Use standard upload for files under 100MB
            match self.config.scan_type {
                ScanType::Sandbox => {
                    if let Some(sandbox_id) = sandbox_legacy_id {
                        let file_path_str = file.to_string_lossy();
                        scan_api
                            .upload_file_to_sandbox(
                                app_id.for_xml_api(),
                                &file_path_str,
                                sandbox_id,
                            )
                            .await
                            .map(|_| ())
                    } else {
                        return Err(AssessmentError::ConfigError(
                            SANDBOX_ID_REQUIRED_ERROR.into(),
                        ));
                    }
                }
                ScanType::Policy => {
                    let file_path_owned = file.to_string_lossy().into_owned();
                    let request = UploadFileRequest {
                        app_id: app_id.for_xml_api().to_string(),
                        file_path: file_path_owned,
                        save_as: None,
                        sandbox_id: sandbox_legacy_id.map(|s| s.to_string()),
                    };
                    scan_api.upload_file(&request).await.map(|_| ())
                }
            }
        };

        match upload_result {
            Ok(_) => Ok(()),
            Err(e) => Err(AssessmentError::UploadError(format!(
                "Failed to upload {file_name}: {e}"
            ))),
        }
    }

    /// Start prescan analysis
    pub async fn start_prescan(
        &self,
        app_id: &str,
        build_id: &BuildId,
        sandbox_id: Option<&SandboxId>,
    ) -> Result<(), AssessmentError> {
        if self.config.debug {
            println!("🔍 Starting prescan analysis...");
        }

        let scan_api = self.client.scan_api();

        let prescan_result = match self.config.scan_type {
            ScanType::Sandbox => {
                if let Some(sandbox) = sandbox_id {
                    // Use begin_prescan directly to control autoscan setting
                    let request = veracode_platform::scan::BeginPreScanRequest {
                        app_id: app_id.to_string(),
                        sandbox_id: Some(sandbox.for_xml_api().to_string()),
                        auto_scan: Some(self.config.autoscan),
                        scan_all_nonfatal_top_level_modules: Some(true),
                        include_new_modules: Some(true),
                    };

                    if self.config.debug {
                        println!(
                            "🔧 Prescan request - App ID: {}, Sandbox ID: {}, Autoscan: {}",
                            request.app_id,
                            request.sandbox_id.as_ref().unwrap_or(&"None".to_string()),
                            request.auto_scan.unwrap_or(false)
                        );
                    }

                    scan_api.begin_prescan(&request).await
                } else {
                    return Err(AssessmentError::ConfigError(
                        "Sandbox ID required for sandbox scans".to_string(),
                    ));
                }
            }
            ScanType::Policy => {
                let request = veracode_platform::scan::BeginPreScanRequest {
                    app_id: app_id.to_string(),
                    sandbox_id: None,
                    auto_scan: Some(self.config.autoscan),
                    scan_all_nonfatal_top_level_modules: Some(true),
                    include_new_modules: Some(true),
                };
                scan_api.begin_prescan(&request).await
            }
        };

        match prescan_result {
            Ok(()) => {
                println!("✅ Prescan started");
                if self.config.debug {
                    println!("🔍 Prescan started for build ID: {}", build_id.id());
                }
                Ok(())
            }
            Err(e) => {
                eprintln!("❌ Failed to start prescan: {e}");
                Err(AssessmentError::ScanError(format!(
                    "Failed to start prescan: {e}"
                )))
            }
        }
    }

    /// Start scan with modules (always scans all nonfatal top level modules)
    pub async fn start_scan(
        &self,
        app_id: &str,
        build_id: &BuildId,
        sandbox_id: Option<&SandboxId>,
    ) -> Result<(), AssessmentError> {
        if self.config.debug {
            println!("🚀 Starting scan analysis...");
            println!("   Build ID: {}", build_id.id());
        }

        let scan_api = self.client.scan_api();

        let scan_result = match self.config.scan_type {
            ScanType::Sandbox => {
                if let Some(sandbox_id) = sandbox_id {
                    if self.config.selected_modules.is_some() {
                        // For sandbox scans with specific modules, use the general begin_scan method
                        let modules_string = self
                            .config
                            .selected_modules
                            .as_ref()
                            .map(|modules| modules.join(","));

                        let request = veracode_platform::scan::BeginScanRequest {
                            app_id: app_id.to_string(),
                            sandbox_id: Some(sandbox_id.for_xml_api().to_string()),
                            modules: modules_string,
                            scan_all_top_level_modules: None,
                            scan_all_nonfatal_top_level_modules: if self
                                .config
                                .selected_modules
                                .is_none()
                            {
                                Some(true)
                            } else {
                                None
                            },
                            scan_previously_selected_modules: None,
                        };
                        scan_api.begin_scan(&request).await
                    } else {
                        // Scan all modules for sandbox
                        scan_api
                            .begin_sandbox_scan_all_modules(app_id, sandbox_id.for_xml_api())
                            .await
                    }
                } else {
                    return Err(AssessmentError::ConfigError(
                        SANDBOX_ID_REQUIRED_ERROR.to_string(),
                    ));
                }
            }
            ScanType::Policy => {
                let modules_string = self
                    .config
                    .selected_modules
                    .as_ref()
                    .map(|modules| modules.join(","));

                let request = veracode_platform::scan::BeginScanRequest {
                    app_id: app_id.to_string(),
                    sandbox_id: None,
                    modules: modules_string,
                    scan_all_top_level_modules: None,
                    scan_all_nonfatal_top_level_modules: if self.config.selected_modules.is_none() {
                        Some(true)
                    } else {
                        None
                    },
                    scan_previously_selected_modules: None,
                };
                scan_api.begin_scan(&request).await
            }
        };

        match scan_result {
            Ok(_) => {
                println!("✅ Scan started successfully");
                if self.config.debug {
                    println!("🔍 Scan initiated for build: {build_id}");
                }
                Ok(())
            }
            Err(e) => {
                eprintln!("❌ Failed to start scan: {e}");
                Err(AssessmentError::ScanError(format!(
                    "Failed to start scan: {e}"
                )))
            }
        }
    }

    /// Upload files and run complete scan workflow
    pub async fn upload_and_scan(
        &self,
        files: &[PathBuf],
        app_id: &ApplicationId,
    ) -> Result<BuildId, AssessmentError> {
        // Step 1: Ensure sandbox exists first (if sandbox scan) and get sandbox ID
        let sandbox_id = self
            .ensure_sandbox_and_get_id(app_id.for_rest_api())
            .await?;

        // Step 2: Ensure build exists
        let sandbox_legacy_id = sandbox_id.as_ref().map(|s| s.for_xml_api());
        let build_id = self
            .ensure_build_exists(app_id.for_xml_api(), sandbox_legacy_id)
            .await?;

        // Step 3: Upload files (now simplified)
        let _uploaded_files = self
            .upload_files(files, app_id, sandbox_id.as_ref())
            .await?;

        // Step 4: Start prescan first (normal workflow)
        self.start_prescan(app_id.for_xml_api(), &build_id, sandbox_id.as_ref())
            .await?;

        // Check if we should exit early (--no-wait specified)
        if !self.config.monitor_completion {
            println!(
                "⏳ Prescan submitted successfully - not waiting for completion (--no-wait specified)"
            );
            println!("   Build ID: {}", &build_id);
            return Ok(build_id);
        }

        // Check if we need to manually start scan (only if autoscan is disabled)
        if !self.is_autoscan_enabled() {
            if self.config.debug {
                println!("🔄 Autoscan disabled, will manually start scan after prescan completes");
            }
        } else if self.config.debug {
            println!("🤖 Autoscan enabled, scan will start automatically after prescan");
        }

        // Use two-phase monitoring approach matching Java implementation
        // This handles both prescan completion and scan completion automatically
        if !self.is_autoscan_enabled() {
            // For manual scan workflows, monitor prescan first, then start scan, then monitor build
            self.monitor_prescan_phase(app_id.for_xml_api(), &build_id, sandbox_id.as_ref())
                .await?;

            if self.config.debug {
                println!("🔄 Prescan complete, manually starting scan...");
            }
            self.start_scan(app_id.for_xml_api(), &build_id, sandbox_id.as_ref())
                .await?;

            // Monitor build phase (scan completion)
            self.monitor_build_phase(app_id.for_xml_api(), &build_id, sandbox_id.as_ref())
                .await?;
        } else {
            // For autoscan workflows, use unified two-phase monitoring
            self.monitor_scan_progress(app_id.for_xml_api(), &build_id, sandbox_id.as_ref())
                .await?;
        }

        // Export results to file
        self.export_scan_results(&app_id.guid, &build_id, sandbox_id.as_ref())
            .await?;

        Ok(build_id)
    }

    /// Wait for prescan to complete
    pub async fn wait_for_prescan(
        &self,
        app_id: &str,
        build_id: &BuildId,
        sandbox_id: Option<&SandboxId>,
    ) -> Result<(), AssessmentError> {
        if self.config.debug {
            println!("⏳ Waiting for prescan to complete...");
        }

        let scan_api = self.client.scan_api();
        let timeout_minutes = self.config.timeout;
        let poll_interval = 30; // Poll every 30 seconds
        let max_polls = (timeout_minutes * 60) / poll_interval;

        for poll_count in 1..=max_polls {
            if self.config.debug {
                println!("🔄 Prescan poll attempt {poll_count}/{max_polls}");
            }

            let sandbox_legacy_id_str = match self.config.scan_type {
                ScanType::Sandbox => sandbox_id.map(|s| s.for_xml_api()),
                ScanType::Policy => None,
            };

            match scan_api
                .get_prescan_results(app_id, sandbox_legacy_id_str, Some(build_id.id()))
                .await
            {
                Ok(prescan_results) => {
                    if self.config.debug {
                        println!(
                            "🔍 Debug: Prescan status received: {}",
                            prescan_results.status
                        );
                    }
                    if prescan_results.status == "Pre-Scan Success" {
                        println!("✅ Prescan completed successfully");
                        if self.config.debug {
                            println!("📊 Prescan results ready - modules available for scanning");
                        }
                        return Ok(());
                    } else if prescan_results.status.contains("Failed")
                        || prescan_results.status.contains("Cancelled")
                    {
                        return Err(AssessmentError::ScanError(format!(
                            "Prescan failed with status: {}",
                            prescan_results.status
                        )));
                    } else {
                        if self.config.debug {
                            println!(
                                "⏳ Prescan status: {}, waiting {} seconds...",
                                prescan_results.status, poll_interval
                            );
                        } else {
                            print!(".");
                            std::io::stdout().flush().unwrap();
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                            .await;
                    }
                }
                Err(e) => {
                    if self.config.debug {
                        println!("⚠️  Error getting prescan status: {e}, retrying...");
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                        .await;
                }
            }
        }

        Err(AssessmentError::ScanError(format!(
            "Prescan timed out after {timeout_minutes} minutes"
        )))
    }

    /// Wait for main scan to complete
    pub async fn wait_for_scan_completion(
        &self,
        app_id: &str,
        build_id: &BuildId,
        sandbox_id: Option<&SandboxId>,
    ) -> Result<(), AssessmentError> {
        if self.config.debug {
            println!("⏳ Waiting for main scan to complete...");
        }

        let scan_api = self.client.scan_api();
        let timeout_minutes = self.config.timeout;
        let poll_interval = 60; // Poll every 60 seconds for main scan (longer than prescan)
        let max_polls = (timeout_minutes * 60) / poll_interval;

        for poll_count in 1..=max_polls {
            if self.config.debug {
                println!("🔄 Scan poll attempt {poll_count}/{max_polls}");
            }

            let sandbox_legacy_id_str = match self.config.scan_type {
                ScanType::Sandbox => sandbox_id.map(|s| s.for_xml_api()),
                ScanType::Policy => None,
            };

            // Use get_build_info to check scan status
            match scan_api
                .get_build_info(app_id, Some(build_id.id()), sandbox_legacy_id_str)
                .await
            {
                Ok(build_info) => {
                    let status = &build_info.status;

                    if self.config.debug {
                        println!("📊 Scan status: {status}");
                        if let Some(progress) = build_info.scan_progress_percentage {
                            println!("📈 Progress: {progress}%");
                        }
                    }

                    match status.as_str() {
                        "Results Ready" => {
                            println!("✅ Scan completed successfully");
                            if self.config.debug {
                                println!("📊 Results are ready for download");
                            }
                            return Ok(());
                        }
                        "Scan In Progress" | "Submitted to Engine" | "Pre-Scan Success" => {
                            if self.config.debug {
                                println!(
                                    "⏳ Scan status: {status}, waiting {poll_interval} seconds..."
                                );
                            } else {
                                print!(".");
                                std::io::stdout().flush().unwrap();
                            }
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                poll_interval.into(),
                            ))
                            .await;
                        }
                        status
                            if status.contains("Failed")
                                || status.contains("Error")
                                || status.contains("Cancelled") =>
                        {
                            return Err(AssessmentError::ScanError(format!(
                                "Scan failed with status: {status}"
                            )));
                        }
                        _ => {
                            if self.config.debug {
                                println!(
                                    "⏳ Scan status: {status}, waiting {poll_interval} seconds..."
                                );
                            } else {
                                print!(".");
                                std::io::stdout().flush().unwrap();
                            }
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                poll_interval.into(),
                            ))
                            .await;
                        }
                    }
                }
                Err(e) => {
                    if self.config.debug {
                        println!("⚠️  Error getting scan status: {e}, retrying...");
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                        .await;
                }
            }
        }

        Err(AssessmentError::ScanError(format!(
            "Scan timed out after {timeout_minutes} minutes"
        )))
    }

    /// Monitor scan progress using two-phase approach matching Java implementation
    ///
    /// Phase 1: Monitor prescan status with 30-second intervals
    /// Phase 2: Monitor build status with 60-second intervals
    pub async fn monitor_scan_progress(
        &self,
        app_id: &str,
        build_id: &BuildId,
        sandbox_id: Option<&SandboxId>,
    ) -> Result<(), AssessmentError> {
        if self.config.debug {
            println!("🔍 Starting two-phase scan monitoring (Java-compatible approach)");
            println!("   Phase 1: Prescan monitoring (30s intervals)");
            println!("   Phase 2: Build status monitoring (60s intervals)");
        }

        // Phase 1: Monitor prescan status until "Pre-Scan Success" or failure
        match self
            .monitor_prescan_phase(app_id, build_id, sandbox_id)
            .await
        {
            Ok(()) => {
                if self.config.debug {
                    println!("✅ Phase 1 complete - transitioning to main scan monitoring");
                }
            }
            Err(e) => return Err(e),
        }

        // Phase 2: Monitor build status until "Results Ready" or failure
        match self.monitor_build_phase(app_id, build_id, sandbox_id).await {
            Ok(()) => {
                if self.config.debug {
                    println!("✅ Phase 2 complete - scan finished successfully");
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Phase 1: Monitor prescan status (Java getprescanresults.do API)
    async fn monitor_prescan_phase(
        &self,
        app_id: &str,
        build_id: &BuildId,
        sandbox_id: Option<&SandboxId>,
    ) -> Result<(), AssessmentError> {
        if self.config.debug {
            println!("🔄 Phase 1: Monitoring prescan status...");
        }

        let scan_api = self.client.scan_api();
        let timeout_minutes = self.config.timeout;
        let poll_interval = 30; // Java uses 30-second intervals for prescan
        let max_polls = (timeout_minutes * 60) / poll_interval;

        for poll_count in 1..=max_polls {
            if self.config.debug {
                println!("🔄 Prescan poll attempt {poll_count}/{max_polls}");
            }

            let sandbox_legacy_id_str = match self.config.scan_type {
                ScanType::Sandbox => sandbox_id.map(|s| s.for_xml_api()),
                ScanType::Policy => None,
            };

            match scan_api
                .get_prescan_results(app_id, sandbox_legacy_id_str, Some(build_id.id()))
                .await
            {
                Ok(prescan_results) => {
                    if self.config.debug {
                        println!("📊 Prescan status: {}", prescan_results.status);
                    }

                    match prescan_results.status.as_str() {
                        "Pre-Scan Success" => {
                            println!("✅ Prescan completed successfully");
                            return Ok(());
                        }
                        "Pre-Scan Failed" | "Pre-Scan Cancelled" | "Prescan Failed"
                        | "Prescan Cancelled" => {
                            return Err(AssessmentError::ScanError(format!(
                                "Prescan failed with status: {}",
                                prescan_results.status
                            )));
                        }
                        _ => {
                            // Continue polling for other statuses (including "Pre-Scan Submitted")
                            if self.config.debug {
                                println!(
                                    "⏳ Prescan in progress, waiting {poll_interval} seconds..."
                                );
                            } else {
                                print!(".");
                                std::io::stdout().flush().unwrap();
                            }
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                poll_interval.into(),
                            ))
                            .await;
                        }
                    }
                }
                Err(e) => {
                    if self.config.debug {
                        println!("⚠️  Error getting prescan status: {e}, retrying...");
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                        .await;
                }
            }
        }

        Err(AssessmentError::ScanError(format!(
            "Prescan phase timed out after {timeout_minutes} minutes"
        )))
    }

    /// Phase 2: Monitor build status (Java getbuildinfo.do API)
    async fn monitor_build_phase(
        &self,
        app_id: &str,
        build_id: &BuildId,
        sandbox_id: Option<&SandboxId>,
    ) -> Result<(), AssessmentError> {
        if self.config.debug {
            println!("🔄 Phase 2: Monitoring build status...");
        }

        let scan_api = self.client.scan_api();
        let timeout_minutes = self.config.timeout;
        let poll_interval = 60; // Java uses 60-second intervals for build monitoring
        let max_polls = (timeout_minutes * 60) / poll_interval;

        for poll_count in 1..=max_polls {
            if self.config.debug {
                println!("🔄 Build status poll attempt {poll_count}/{max_polls}");
            }

            let sandbox_legacy_id_str = match self.config.scan_type {
                ScanType::Sandbox => sandbox_id.map(|s| s.for_xml_api()),
                ScanType::Policy => None,
            };

            match scan_api
                .get_build_info(app_id, Some(build_id.id()), sandbox_legacy_id_str)
                .await
            {
                Ok(build_info) => {
                    if self.config.debug {
                        println!("📊 Build status: {}", build_info.status);
                        if let Some(progress) = build_info.scan_progress_percentage {
                            println!("📈 Progress: {progress}%");
                        }
                    }

                    match build_info.status.as_str() {
                        "Results Ready" => {
                            println!("✅ Scan completed successfully");
                            return Ok(());
                        }
                        "Scan in Process"
                        | "Scan In Process"
                        | "Submitted to Engine"
                        | "Pre-Scan Success" => {
                            // Continue polling for active scan states
                            if self.config.debug {
                                println!("⏳ Scan in progress, waiting {poll_interval} seconds...");
                            } else {
                                print!(".");
                                std::io::stdout().flush().unwrap();
                            }
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                poll_interval.into(),
                            ))
                            .await;
                        }
                        status
                            if status.contains("Failed")
                                || status.contains("Error")
                                || status.contains("Cancelled") =>
                        {
                            return Err(AssessmentError::ScanError(format!(
                                "Scan failed with status: {status}"
                            )));
                        }
                        _ => {
                            // Continue polling for unknown statuses (defensive)
                            if self.config.debug {
                                println!(
                                    "⏳ Unknown status '{}', continuing to wait {} seconds...",
                                    build_info.status, poll_interval
                                );
                            } else {
                                print!(".");
                                std::io::stdout().flush().unwrap();
                            }
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                poll_interval.into(),
                            ))
                            .await;
                        }
                    }
                }
                Err(e) => {
                    if self.config.debug {
                        println!("⚠️  Error getting build status: {e}, retrying...");
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                        .await;
                }
            }
        }

        Err(AssessmentError::ScanError(format!(
            "Build monitoring phase timed out after {timeout_minutes} minutes"
        )))
    }

    /// Retrieve and export scan results with policy compliance check
    pub async fn export_scan_results(
        &self,
        app_guid: &str,
        build_id: &BuildId,
        sandbox_id: Option<&SandboxId>,
    ) -> Result<(), AssessmentError> {
        let policy_api = self.client.policy_api();
        let sandbox_guid = sandbox_id.map(|s| s.guid.as_ref());

        // Get summary report with policy compliance check (combined single API call)
        if self.config.debug {
            println!(
                "📝 Exporting summary report to: {}",
                self.config.export_results_path
            );
        }

        let (summary_report, compliance_status) = match policy_api
            .get_summary_report_with_policy_retry(
                app_guid,
                Some(build_id.id()),
                sandbox_guid,
                self.config.policy_wait_max_retries,
                self.config.policy_wait_retry_delay_seconds,
                self.config.debug,
                self.config.break_build,
            )
            .await
        {
            Ok((report, status)) => (report, status.map(|s| s.into_owned())),
            Err(e) => {
                eprintln!("❌ Failed to get summary report: {e}");
                if self.config.break_build {
                    eprintln!("   Break build evaluation will be skipped due to error");
                }
                return Err(AssessmentError::ScanError(format!(
                    "Failed to retrieve summary report: {e}"
                )));
            }
        };

        // Determine if build should break based on compliance status (if break_build enabled)
        let should_break_build = if let Some(ref status) = compliance_status {
            use veracode_platform::policy::PolicyApi;
            PolicyApi::should_break_build(status)
        } else {
            false
        };

        // Export summary report with compliance status metadata
        let results = serde_json::json!({
            "summary_report": summary_report,
            "export_metadata": {
                "exported_at": chrono::Utc::now().to_rfc3339(),
                "tool": TOOL_NAME,
                "export_type": "summary_report",
                "break_build_enabled": self.config.break_build,
                "will_break_build": should_break_build,
                "compliance_status_confirmed": compliance_status.is_some(),
                "scan_configuration": {
                    "autoscan": self.config.autoscan,
                    "scan_all_nonfatal_top_level_modules": true,
                    "include_new_modules": true
                }
            }
        });

        // Write results to file
        match serde_json::to_string_pretty(&results) {
            Ok(json_string) => {
                match std::fs::write(&self.config.export_results_path, json_string) {
                    Ok(_) => {
                        println!(
                            "✅ Summary report exported to: {}",
                            self.config.export_results_path
                        );
                        if self.config.debug {
                            println!(
                                "📊 Policy compliance status: {}",
                                summary_report.policy_compliance_status
                            );
                        }

                        // Break build if policy compliance failed (after successful export)
                        if should_break_build {
                            use veracode_platform::policy::PolicyApi;
                            if let Some(status) = compliance_status {
                                let exit_code = PolicyApi::get_exit_code_for_status(&status);
                                println!("\n❌ Platform policy compliance FAILED - breaking build");
                                println!("   Status: {status}");
                                println!("   Exit code: {exit_code}");
                                std::process::exit(exit_code);
                            }
                        }

                        Ok(())
                    }
                    Err(e) => {
                        eprintln!(
                            "❌ Failed to write results to {}: {}",
                            self.config.export_results_path, e
                        );
                        Err(AssessmentError::UploadError(format!(
                            "Failed to write results: {e}"
                        )))
                    }
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to serialize results: {e}");
                Err(AssessmentError::UploadError(format!(
                    "Failed to serialize results: {e}"
                )))
            }
        }
    }

    // Note: The ensure_sandbox_exists method has been replaced by ensure_sandbox_and_get_legacy_id
    // which handles both sandbox creation and legacy ID retrieval in one step

    /// Display scan configuration
    pub fn display_config(&self) {
        println!("📊 Assessment Scan Configuration:");
        println!("   App Profile: {}", self.config.app_profile_name);
        println!("   Scan Type: {:?}", self.config.scan_type);
        if let Some(ref sandbox_name) = self.config.sandbox_name {
            println!("   Sandbox: {sandbox_name}");
        }
        println!("   Auto-recreate Sandbox: enabled");
        println!(
            "   Autoscan: {}",
            if self.config.autoscan {
                "enabled"
            } else {
                "disabled"
            }
        );

        if let Some(ref modules) = self.config.selected_modules {
            println!("   Selected Modules: {}", modules.join(", "));
        } else {
            println!("   Scan All Modules: enabled (all nonfatal top-level modules)");
        }

        println!("   Upload Threads: {}", self.config.threads);
        println!("   Timeout: {} minutes", self.config.timeout);
        println!(
            "   Monitor Completion: {}",
            if self.config.monitor_completion {
                "enabled"
            } else {
                "disabled (--no-wait)"
            }
        );
        println!("   Export Results: {}", self.config.export_results_path);
        if self.config.break_build {
            println!(
                "   Policy Wait: {} retries, {} seconds interval (max {} minutes)",
                self.config.policy_wait_max_retries,
                self.config.policy_wait_retry_delay_seconds,
                (self.config.policy_wait_max_retries as u64
                    * self.config.policy_wait_retry_delay_seconds)
                    / 60
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assessment_config_default() {
        let config = AssessmentScanConfig::default();
        assert_eq!(config.timeout, 60);
        assert_eq!(config.threads, 4);
        assert_eq!(config.app_profile_name, "");
        matches!(config.scan_type, ScanType::Policy);
        assert!(config.sandbox_name.is_none());
        assert!(config.selected_modules.is_none());
        assert!(config.autoscan);
        assert!(config.monitor_completion);
        assert_eq!(config.export_results_path, "assessment-results.json");
        assert_eq!(config.deleteincompletescan, 1);
        assert!(!config.break_build);
        assert_eq!(config.policy_wait_max_retries, 30);
        assert_eq!(config.policy_wait_retry_delay_seconds, 10);
    }

    #[test]
    fn test_assessment_error_display() {
        let error = AssessmentError::NoValidFiles;
        assert_eq!(error.to_string(), "No valid files found for scanning");

        let error = AssessmentError::ConfigError("test error".to_string());
        assert_eq!(error.to_string(), "Configuration error: test error");
    }

    #[test]
    fn test_assessment_config_with_threads() {
        let config = AssessmentScanConfig {
            app_profile_name: "TestApp".to_string(),
            scan_type: ScanType::Sandbox,
            sandbox_name: Some("test-sandbox".to_string()),
            selected_modules: Some(vec!["module1".to_string(), "module2".to_string()]),
            region: VeracodeRegion::Commercial,
            timeout: 90,
            threads: 8,
            debug: true,
            autoscan: false,
            monitor_completion: false,
            export_results_path: "custom-results.json".to_string(),
            deleteincompletescan: 2,
            break_build: true,
            policy_wait_max_retries: 60,        // Custom: 60 retries
            policy_wait_retry_delay_seconds: 5, // Custom: 5 seconds between retries
        };

        assert_eq!(config.threads, 8);
        assert_eq!(config.timeout, 90);
        assert_eq!(config.app_profile_name, "TestApp");
        matches!(config.scan_type, ScanType::Sandbox);
        assert_eq!(config.sandbox_name, Some("test-sandbox".to_string()));
        assert!(config.selected_modules.is_some());
        assert_eq!(config.selected_modules.unwrap().len(), 2);
        assert!(!config.autoscan);
        assert_eq!(config.export_results_path, "custom-results.json");
        assert_eq!(config.deleteincompletescan, 2);
    }

    #[test]
    fn test_upload_decision_logic() {
        // Test that single file uses sequential upload
        let config = AssessmentScanConfig {
            threads: 4,
            ..Default::default()
        };

        // With 1 thread, should use sequential
        let config_single_thread = AssessmentScanConfig {
            threads: 1,
            ..Default::default()
        };

        assert_eq!(config.threads, 4);
        assert_eq!(config_single_thread.threads, 1);

        // The actual upload method selection is tested in integration tests
        // since it requires async setup and API mocking
    }
}

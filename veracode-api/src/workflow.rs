//! High-level workflow helpers for common Veracode operations.
//!
//! This module provides convenience functions that combine multiple API operations
//! to implement common workflows like the complete application/sandbox lifecycle.

use crate::{
    VeracodeClient, VeracodeError,
    app::{Application, BusinessCriticality},
    build::{Build, BuildError},
    sandbox::{Sandbox, SandboxError},
    scan::ScanError,
};

/// High-level workflow operations for Veracode platform
pub struct VeracodeWorkflow {
    client: VeracodeClient,
}

/// Result type for workflow operations
pub type WorkflowResult<T> = Result<T, WorkflowError>;

/// Errors that can occur during workflow operations
#[derive(Debug)]
pub enum WorkflowError {
    /// Veracode API error
    Api(VeracodeError),
    /// Sandbox operation error
    Sandbox(SandboxError),
    /// Scan operation error
    Scan(ScanError),
    /// Build operation error
    Build(BuildError),
    /// Workflow-specific error
    Workflow(String),
    /// Access denied
    AccessDenied(String),
    /// Resource not found
    NotFound(String),
}

impl std::fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkflowError::Api(err) => write!(f, "API error: {err}"),
            WorkflowError::Sandbox(err) => write!(f, "Sandbox error: {err}"),
            WorkflowError::Scan(err) => write!(f, "Scan error: {err}"),
            WorkflowError::Build(err) => write!(f, "Build error: {err}"),
            WorkflowError::Workflow(msg) => write!(f, "Workflow error: {msg}"),
            WorkflowError::AccessDenied(msg) => write!(f, "Access denied: {msg}"),
            WorkflowError::NotFound(msg) => write!(f, "Not found: {msg}"),
        }
    }
}

impl std::error::Error for WorkflowError {}

impl From<VeracodeError> for WorkflowError {
    fn from(err: VeracodeError) -> Self {
        WorkflowError::Api(err)
    }
}

impl From<SandboxError> for WorkflowError {
    fn from(err: SandboxError) -> Self {
        WorkflowError::Sandbox(err)
    }
}

impl From<ScanError> for WorkflowError {
    fn from(err: ScanError) -> Self {
        WorkflowError::Scan(err)
    }
}

impl From<BuildError> for WorkflowError {
    fn from(err: BuildError) -> Self {
        WorkflowError::Build(err)
    }
}

/// Configuration for the complete XML API workflow
#[derive(Debug, Clone)]
pub struct WorkflowConfig {
    /// Application name
    pub app_name: String,
    /// Sandbox name
    pub sandbox_name: String,
    /// Business criticality for new applications
    pub business_criticality: BusinessCriticality,
    /// Application description (optional)
    pub app_description: Option<String>,
    /// Sandbox description (optional)
    pub sandbox_description: Option<String>,
    /// Files to upload
    pub file_paths: Vec<String>,
    /// Whether to start scan automatically after upload
    pub auto_scan: bool,
    /// Whether to scan all modules
    pub scan_all_modules: bool,
}

impl WorkflowConfig {
    /// Create a new workflow configuration
    pub fn new(app_name: String, sandbox_name: String) -> Self {
        Self {
            app_name,
            sandbox_name,
            business_criticality: BusinessCriticality::Medium,
            app_description: None,
            sandbox_description: None,
            file_paths: Vec::new(),
            auto_scan: true,
            scan_all_modules: true,
        }
    }

    /// Set business criticality
    pub fn with_business_criticality(mut self, criticality: BusinessCriticality) -> Self {
        self.business_criticality = criticality;
        self
    }

    /// Set application description
    pub fn with_app_description(mut self, description: String) -> Self {
        self.app_description = Some(description);
        self
    }

    /// Set sandbox description
    pub fn with_sandbox_description(mut self, description: String) -> Self {
        self.sandbox_description = Some(description);
        self
    }

    /// Add file to upload
    pub fn with_file(mut self, file_path: String) -> Self {
        self.file_paths.push(file_path);
        self
    }

    /// Add multiple files to upload
    pub fn with_files(mut self, file_paths: Vec<String>) -> Self {
        self.file_paths.extend(file_paths);
        self
    }

    /// Set auto-scan behavior
    pub fn with_auto_scan(mut self, auto_scan: bool) -> Self {
        self.auto_scan = auto_scan;
        self
    }

    /// Set scan all modules behavior
    pub fn with_scan_all_modules(mut self, scan_all: bool) -> Self {
        self.scan_all_modules = scan_all;
        self
    }
}

/// Result of the complete workflow
#[derive(Debug, Clone)]
pub struct WorkflowResultData {
    /// Application information
    pub application: Application,
    /// Sandbox information
    pub sandbox: Sandbox,
    /// Numeric application ID for XML API
    pub app_id: String,
    /// Numeric sandbox ID for XML API
    pub sandbox_id: String,
    /// Build ID from scan initiation (if scan was started)
    pub build_id: Option<String>,
    /// Whether the application was newly created
    pub app_created: bool,
    /// Whether the sandbox was newly created
    pub sandbox_created: bool,
    /// Number of files uploaded
    pub files_uploaded: usize,
}

impl VeracodeWorkflow {
    /// Create a new workflow instance
    pub fn new(client: VeracodeClient) -> Self {
        Self { client }
    }

    /// Execute the complete XML API workflow
    ///
    /// This method implements the full workflow:
    /// 1. Check for application existence, create if not exist
    /// 2. Handle access denied scenarios
    /// 3. Check sandbox exists, if not create
    /// 4. Handle access denied scenarios  
    /// 5. Upload multiple files to sandbox
    /// 6. Start prescan with available options
    ///
    /// # Arguments
    ///
    /// * `config` - Workflow configuration
    ///
    /// # Returns
    ///
    /// A `Result` containing the workflow result or an error.
    pub async fn execute_complete_workflow(
        &self,
        config: WorkflowConfig,
    ) -> WorkflowResult<WorkflowResultData> {
        println!("🚀 Starting complete Veracode XML API workflow");
        println!("   Application: {}", config.app_name);
        println!("   Sandbox: {}", config.sandbox_name);
        println!("   Files to upload: {}", config.file_paths.len());

        // Step 1: Check for Application existence, create if not exist
        println!("\n📱 Step 1: Checking application existence...");
        let (application, app_created) =
            match self.client.get_application_by_name(&config.app_name).await {
                Ok(Some(app)) => {
                    println!(
                        "   ✅ Application '{}' found (GUID: {})",
                        config.app_name, app.guid
                    );
                    (app, false)
                }
                Ok(None) => {
                    println!(
                        "   ➕ Application '{}' not found, creating...",
                        config.app_name
                    );
                    match self
                        .client
                        .create_application_if_not_exists(
                            &config.app_name,
                            config.business_criticality,
                            config.app_description,
                            None, // No teams specified
                        )
                        .await
                    {
                        Ok(app) => {
                            println!(
                                "   ✅ Application '{}' created successfully (GUID: {})",
                                config.app_name, app.guid
                            );
                            (app, true)
                        }
                        Err(VeracodeError::InvalidResponse(msg))
                            if msg.contains("403") || msg.contains("401") =>
                        {
                            return Err(WorkflowError::AccessDenied(format!(
                                "Access denied creating application '{}': {}",
                                config.app_name, msg
                            )));
                        }
                        Err(e) => return Err(WorkflowError::Api(e)),
                    }
                }
                Err(VeracodeError::InvalidResponse(msg))
                    if msg.contains("403") || msg.contains("401") =>
                {
                    return Err(WorkflowError::AccessDenied(format!(
                        "Access denied checking application '{}': {}",
                        config.app_name, msg
                    )));
                }
                Err(e) => return Err(WorkflowError::Api(e)),
            };

        // Get numeric app_id for XML API
        let app_id = self.client.get_app_id_from_guid(&application.guid).await?;
        println!("   📊 Application ID for XML API: {app_id}");

        // Step 2: Check sandbox exists, if not create
        println!("\n🧪 Step 2: Checking sandbox existence...");
        let sandbox_api = self.client.sandbox_api();
        let (sandbox, sandbox_created) = match sandbox_api
            .get_sandbox_by_name(&application.guid, &config.sandbox_name)
            .await
        {
            Ok(Some(sandbox)) => {
                println!(
                    "   ✅ Sandbox '{}' found (GUID: {})",
                    config.sandbox_name, sandbox.guid
                );
                (sandbox, false)
            }
            Ok(None) => {
                println!(
                    "   ➕ Sandbox '{}' not found, creating...",
                    config.sandbox_name
                );
                match sandbox_api
                    .create_sandbox_if_not_exists(
                        &application.guid,
                        &config.sandbox_name,
                        config.sandbox_description,
                    )
                    .await
                {
                    Ok(sandbox) => {
                        println!(
                            "   ✅ Sandbox '{}' created successfully (GUID: {})",
                            config.sandbox_name, sandbox.guid
                        );
                        (sandbox, true)
                    }
                    Err(SandboxError::Api(VeracodeError::InvalidResponse(msg)))
                        if msg.contains("403") || msg.contains("401") =>
                    {
                        return Err(WorkflowError::AccessDenied(format!(
                            "Access denied creating sandbox '{}': {}",
                            config.sandbox_name, msg
                        )));
                    }
                    Err(e) => return Err(WorkflowError::Sandbox(e)),
                }
            }
            Err(SandboxError::Api(VeracodeError::InvalidResponse(msg)))
                if msg.contains("403") || msg.contains("401") =>
            {
                return Err(WorkflowError::AccessDenied(format!(
                    "Access denied checking sandbox '{}': {}",
                    config.sandbox_name, msg
                )));
            }
            Err(e) => return Err(WorkflowError::Sandbox(e)),
        };

        // Get numeric sandbox_id for XML API
        let sandbox_id = sandbox_api
            .get_sandbox_id_from_guid(&application.guid, &sandbox.guid)
            .await?;
        println!("   📊 Sandbox ID for XML API: {sandbox_id}");

        // Step 3: Upload multiple files to sandbox
        println!("\n📤 Step 3: Uploading files to sandbox...");
        let scan_api = self.client.scan_api();
        let mut files_uploaded = 0;

        for file_path in &config.file_paths {
            println!("   📁 Uploading file: {file_path}");
            match scan_api
                .upload_file_to_sandbox(&app_id, file_path, &sandbox_id)
                .await
            {
                Ok(uploaded_file) => {
                    println!(
                        "   ✅ File uploaded successfully: {} (ID: {})",
                        uploaded_file.file_name, uploaded_file.file_id
                    );
                    files_uploaded += 1;
                }
                Err(ScanError::FileNotFound(_)) => {
                    return Err(WorkflowError::NotFound(format!(
                        "File not found: {file_path}"
                    )));
                }
                Err(ScanError::Unauthorized) => {
                    return Err(WorkflowError::AccessDenied(format!(
                        "Access denied uploading file: {file_path}"
                    )));
                }
                Err(ScanError::PermissionDenied) => {
                    return Err(WorkflowError::AccessDenied(format!(
                        "Permission denied uploading file: {file_path}"
                    )));
                }
                Err(e) => return Err(WorkflowError::Scan(e)),
            }
        }

        println!("   📊 Total files uploaded: {files_uploaded}");

        // Step 4: Start prescan with available options
        let build_id = if config.auto_scan {
            println!("\n🔍 Step 4: Starting prescan and scan...");
            match scan_api
                .upload_and_scan_sandbox(&app_id, &sandbox_id, &config.file_paths[0])
                .await
            {
                Ok(build_id) => {
                    println!("   ✅ Scan started successfully with build ID: {build_id}");
                    Some(build_id)
                }
                Err(ScanError::Unauthorized) => {
                    return Err(WorkflowError::AccessDenied(
                        "Access denied starting scan".to_string(),
                    ));
                }
                Err(ScanError::PermissionDenied) => {
                    return Err(WorkflowError::AccessDenied(
                        "Permission denied starting scan".to_string(),
                    ));
                }
                Err(e) => {
                    println!("   ⚠️  Warning: Could not start scan automatically: {e}");
                    println!(
                        "   💡 You may need to start the scan manually from the Veracode platform"
                    );
                    None
                }
            }
        } else {
            println!("\n⏭️  Step 4: Skipping automatic scan (auto_scan = false)");
            None
        };

        println!("\n✅ Workflow completed successfully!");
        println!("   📊 Summary:");
        println!(
            "   - Application: {} (created: {})",
            config.app_name, app_created
        );
        println!(
            "   - Sandbox: {} (created: {})",
            config.sandbox_name, sandbox_created
        );
        println!("   - Files uploaded: {files_uploaded}");
        if let Some(ref build_id_ref) = build_id {
            println!(
                "   - Scan started: {} (build ID: {})",
                config.auto_scan, build_id_ref
            );
        } else {
            println!("   - Scan started: {}", config.auto_scan);
        }

        let result = WorkflowResultData {
            application,
            sandbox,
            app_id,
            sandbox_id,
            build_id,
            app_created,
            sandbox_created,
            files_uploaded,
        };

        Ok(result)
    }

    /// Execute a simplified workflow with just application and sandbox creation
    ///
    /// This method implements a subset of the full workflow for cases where
    /// you only need to ensure the application and sandbox exist.
    ///
    /// # Arguments
    ///
    /// * `app_name` - Application name
    /// * `sandbox_name` - Sandbox name
    /// * `business_criticality` - Business criticality for new applications
    ///
    /// # Returns
    ///
    /// A `Result` containing application and sandbox information.
    pub async fn ensure_app_and_sandbox(
        &self,
        app_name: &str,
        sandbox_name: &str,
        business_criticality: BusinessCriticality,
    ) -> WorkflowResult<(Application, Sandbox, String, String)> {
        let config = WorkflowConfig::new(app_name.to_string(), sandbox_name.to_string())
            .with_business_criticality(business_criticality)
            .with_auto_scan(false);

        let result = self.execute_complete_workflow(config).await?;
        Ok((
            result.application,
            result.sandbox,
            result.app_id,
            result.sandbox_id,
        ))
    }

    /// Get application by name with helpful error messages
    ///
    /// # Arguments
    ///
    /// * `app_name` - Application name to search for
    ///
    /// # Returns
    ///
    /// A `Result` containing the application or an error.
    pub async fn get_application_by_name(&self, app_name: &str) -> WorkflowResult<Application> {
        match self.client.get_application_by_name(app_name).await? {
            Some(app) => Ok(app),
            None => Err(WorkflowError::NotFound(format!(
                "Application '{app_name}' not found"
            ))),
        }
    }

    /// Get sandbox by name with helpful error messages
    ///
    /// # Arguments
    ///
    /// * `app_guid` - Application GUID
    /// * `sandbox_name` - Sandbox name to search for
    ///
    /// # Returns
    ///
    /// A `Result` containing the sandbox or an error.
    pub async fn get_sandbox_by_name(
        &self,
        app_guid: &str,
        sandbox_name: &str,
    ) -> WorkflowResult<Sandbox> {
        let sandbox_api = self.client.sandbox_api();
        match sandbox_api
            .get_sandbox_by_name(app_guid, sandbox_name)
            .await?
        {
            Some(sandbox) => Ok(sandbox),
            None => Err(WorkflowError::NotFound(format!(
                "Sandbox '{sandbox_name}' not found"
            ))),
        }
    }

    /// Delete all builds from a sandbox
    ///
    /// This removes all uploaded files and scan data from the sandbox.
    ///
    /// # Arguments
    ///
    /// * `app_name` - Application name
    /// * `sandbox_name` - Sandbox name
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn delete_sandbox_builds(
        &self,
        app_name: &str,
        sandbox_name: &str,
    ) -> WorkflowResult<()> {
        println!("🗑️  Deleting builds from sandbox '{sandbox_name}'...");

        // Get application and sandbox
        let app = self.get_application_by_name(app_name).await?;
        let sandbox = self.get_sandbox_by_name(&app.guid, sandbox_name).await?;

        // Get IDs for XML API
        let app_id = self.client.get_app_id_from_guid(&app.guid).await?;
        let sandbox_api = self.client.sandbox_api();
        let sandbox_id = sandbox_api
            .get_sandbox_id_from_guid(&app.guid, &sandbox.guid)
            .await?;

        // Delete all builds using XML API
        let scan_api = self.client.scan_api();
        match scan_api
            .delete_all_sandbox_builds(&app_id, &sandbox_id)
            .await
        {
            Ok(_) => {
                println!("   ✅ Successfully deleted all builds from sandbox '{sandbox_name}'");
                Ok(())
            }
            Err(ScanError::Unauthorized) => Err(WorkflowError::AccessDenied(
                "Access denied deleting sandbox builds".to_string(),
            )),
            Err(ScanError::PermissionDenied) => Err(WorkflowError::AccessDenied(
                "Permission denied deleting sandbox builds".to_string(),
            )),
            Err(ScanError::BuildNotFound) => {
                println!("   ℹ️  No builds found to delete in sandbox '{sandbox_name}'");
                Ok(())
            }
            Err(e) => Err(WorkflowError::Scan(e)),
        }
    }

    /// Delete a sandbox
    ///
    /// This removes the sandbox and all its associated data.
    ///
    /// # Arguments
    ///
    /// * `app_name` - Application name
    /// * `sandbox_name` - Sandbox name
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn delete_sandbox(&self, app_name: &str, sandbox_name: &str) -> WorkflowResult<()> {
        println!("🗑️  Deleting sandbox '{sandbox_name}'...");

        // Get application and sandbox
        let app = self.get_application_by_name(app_name).await?;
        let sandbox = self.get_sandbox_by_name(&app.guid, sandbox_name).await?;

        // First delete all builds
        let _ = self.delete_sandbox_builds(app_name, sandbox_name).await;

        // Delete the sandbox using REST API
        let sandbox_api = self.client.sandbox_api();
        match sandbox_api.delete_sandbox(&app.guid, &sandbox.guid).await {
            Ok(_) => {
                println!("   ✅ Successfully deleted sandbox '{sandbox_name}'");
                Ok(())
            }
            Err(SandboxError::Api(VeracodeError::InvalidResponse(msg)))
                if msg.contains("403") || msg.contains("401") =>
            {
                Err(WorkflowError::AccessDenied(format!(
                    "Access denied deleting sandbox '{sandbox_name}': {msg}"
                )))
            }
            Err(SandboxError::NotFound) => {
                println!(
                    "   ℹ️  Sandbox '{sandbox_name}' not found (may have been already deleted)"
                );
                Ok(())
            }
            Err(e) => Err(WorkflowError::Sandbox(e)),
        }
    }

    /// Delete an application
    ///
    /// This removes the application and all its associated data including all sandboxes.
    /// Use with extreme caution as this is irreversible.
    ///
    /// # Arguments
    ///
    /// * `app_name` - Application name
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn delete_application(&self, app_name: &str) -> WorkflowResult<()> {
        println!("🗑️  Deleting application '{app_name}'...");

        // Get application
        let app = self.get_application_by_name(app_name).await?;

        // First, delete all sandboxes
        let sandbox_api = self.client.sandbox_api();
        match sandbox_api.list_sandboxes(&app.guid, None).await {
            Ok(sandboxes) => {
                for sandbox in sandboxes {
                    println!("   🗑️  Deleting sandbox: {}", sandbox.name);
                    let _ = self.delete_sandbox(app_name, &sandbox.name).await;
                }
            }
            Err(e) => {
                println!("   ⚠️  Warning: Could not list sandboxes for cleanup: {e}");
            }
        }

        // Delete main application builds
        let app_id = self.client.get_app_id_from_guid(&app.guid).await?;
        let scan_api = self.client.scan_api();
        match scan_api.delete_all_app_builds(&app_id).await {
            Ok(_) => println!("   ✅ Deleted all application builds"),
            Err(e) => println!("   ⚠️  Warning: Could not delete application builds: {e}"),
        }

        // Delete the application using REST API
        match self.client.delete_application(&app.guid).await {
            Ok(_) => {
                println!("   ✅ Successfully deleted application '{app_name}'");
                Ok(())
            }
            Err(VeracodeError::InvalidResponse(msg))
                if msg.contains("403") || msg.contains("401") =>
            {
                Err(WorkflowError::AccessDenied(format!(
                    "Access denied deleting application '{app_name}': {msg}"
                )))
            }
            Err(VeracodeError::NotFound(_)) => {
                println!(
                    "   ℹ️  Application '{app_name}' not found (may have been already deleted)"
                );
                Ok(())
            }
            Err(e) => Err(WorkflowError::Api(e)),
        }
    }

    /// Complete cleanup workflow
    ///
    /// This method performs a complete cleanup of an application and all its resources:
    /// 1. Delete all builds from all sandboxes
    /// 2. Delete all sandboxes  
    /// 3. Delete all application builds
    /// 4. Delete the application
    ///
    /// # Arguments
    ///
    /// * `app_name` - Application name to clean up
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    pub async fn complete_cleanup(&self, app_name: &str) -> WorkflowResult<()> {
        println!("🧹 Starting complete cleanup for application '{app_name}'");
        println!("   ⚠️  WARNING: This will delete ALL data associated with this application");
        println!("   This includes all sandboxes, builds, and scan results");

        match self.delete_application(app_name).await {
            Ok(_) => {
                println!("✅ Complete cleanup finished successfully");
                Ok(())
            }
            Err(WorkflowError::NotFound(_)) => {
                println!("ℹ️  Application '{app_name}' not found - nothing to clean up");
                Ok(())
            }
            Err(e) => {
                println!("❌ Cleanup encountered errors: {e}");
                Err(e)
            }
        }
    }

    /// Ensure a build exists for an application or sandbox
    ///
    /// This method checks if a build exists and creates one if it doesn't.
    /// This is required for uploadlargefile.do operations.
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID (numeric)
    /// * `sandbox_id` - Optional sandbox ID (numeric)
    /// * `version` - Optional build version
    ///
    /// # Returns
    ///
    /// A `Result` containing the build information or an error.
    pub async fn ensure_build_exists(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
        version: Option<&str>,
    ) -> WorkflowResult<Build> {
        self.ensure_build_exists_with_policy(app_id, sandbox_id, version, 1)
            .await
    }

    /// Ensure a build exists for the application/sandbox with configurable deletion policy
    ///
    /// This method checks if a build already exists and handles it according to the deletion policy:
    /// - Policy 0: Never delete builds, fail if build exists
    /// - Policy 1: Delete only "safe" builds (incomplete, failed, cancelled states)
    /// - Policy 2: Delete any build except "Results Ready"
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID (numeric)
    /// * `sandbox_id` - Optional sandbox ID (numeric)
    /// * `version` - Optional build version
    /// * `deletion_policy` - Build deletion policy level (0, 1, or 2)
    ///
    /// # Returns
    ///
    /// A `Result` containing the build information or an error.
    pub async fn ensure_build_exists_with_policy(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
        version: Option<&str>,
        deletion_policy: u8,
    ) -> WorkflowResult<Build> {
        println!("🔍 Checking if build exists (deletion policy: {deletion_policy})...");

        let build_api = self.client.build_api();

        // Try to get existing build info
        match build_api
            .get_build_info(&crate::build::GetBuildInfoRequest {
                app_id: app_id.to_string(),
                build_id: None, // Get most recent
                sandbox_id: sandbox_id.map(|s| s.to_string()),
            })
            .await
        {
            Ok(build) => {
                println!("   📋 Build already exists: {}", build.build_id);
                if let Some(build_version) = &build.version {
                    println!("      Existing Version: {build_version}");
                }

                // Parse build status from attributes
                let build_status_str = build
                    .attributes
                    .get("status")
                    .or_else(|| build.attributes.get("analysis_status"))
                    .or_else(|| build.attributes.get("scan_status"))
                    .map(|s| s.as_str())
                    .unwrap_or("Unknown");

                let build_status = crate::build::BuildStatus::from_string(build_status_str);
                println!("      Build Status: {build_status}");

                // Check deletion policy
                if deletion_policy == 0 {
                    return Err(WorkflowError::Workflow(format!(
                        "Build {} already exists and deletion policy is set to 'Never delete' (0). Cannot proceed with upload.",
                        build.build_id
                    )));
                }

                // Special handling for "Results Ready" builds - create new build to preserve results
                if build_status == crate::build::BuildStatus::ResultsReady {
                    println!(
                        "   📋 Build has 'Results Ready' status - creating new build to preserve existing results"
                    );
                    self.create_build_for_upload(app_id, sandbox_id, version)
                        .await
                }
                // Check if build is safe to delete according to policy
                else if build_status.is_safe_to_delete(deletion_policy) {
                    println!(
                        "   🗑️  Build is safe to delete according to policy {deletion_policy}. Deleting..."
                    );

                    // Delete the existing build
                    match build_api
                        .delete_build(&crate::build::DeleteBuildRequest {
                            app_id: app_id.to_string(),
                            sandbox_id: sandbox_id.map(|s| s.to_string()),
                        })
                        .await
                    {
                        Ok(_) => {
                            println!("   ✅ Existing build deleted successfully");
                        }
                        Err(e) => {
                            return Err(WorkflowError::Build(e));
                        }
                    }

                    // Wait for build deletion to be fully processed by Veracode API
                    println!("   ⏳ Waiting for build deletion to be fully processed...");
                    self.wait_for_build_deletion(app_id, sandbox_id).await?;

                    // Create new build
                    println!("   ➕ Creating new build...");
                    self.create_build_for_upload(app_id, sandbox_id, version)
                        .await
                } else {
                    return Err(WorkflowError::Workflow(format!(
                        "Build {} has status '{}' which is not safe to delete with policy {} (0=Never, 1=Safe only, 2=Except Results Ready). Cannot proceed with upload.",
                        build.build_id, build_status, deletion_policy
                    )));
                }
            }
            Err(crate::build::BuildError::BuildNotFound) => {
                println!("   ➕ No build found, creating new build...");
                self.create_build_for_upload(app_id, sandbox_id, version)
                    .await
            }
            Err(e) => {
                println!("   ⚠️  Error checking build existence: {e}");
                // Try to create a build anyway
                println!("   ➕ Attempting to create new build...");
                self.create_build_for_upload(app_id, sandbox_id, version)
                    .await
            }
        }
    }

    /// Create a build for file upload operations
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID (numeric)
    /// * `sandbox_id` - Optional sandbox ID (numeric)
    /// * `version` - Optional build version
    ///
    /// # Returns
    ///
    /// A `Result` containing the created build information or an error.
    async fn create_build_for_upload(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
        version: Option<&str>,
    ) -> WorkflowResult<Build> {
        let build_api = self.client.build_api();

        let build_version = version.map(|v| v.to_string()).unwrap_or_else(|| {
            // Generate a version based on timestamp if none provided
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            format!("build-{timestamp}")
        });

        match build_api
            .create_build(&crate::build::CreateBuildRequest {
                app_id: app_id.to_string(),
                version: Some(build_version.clone()),
                lifecycle_stage: Some(crate::build::default_lifecycle_stage().to_string()),
                launch_date: None,
                sandbox_id: sandbox_id.map(|s| s.to_string()),
            })
            .await
        {
            Ok(build) => {
                println!("   ✅ Build created successfully: {}", build.build_id);
                println!("      Version: {build_version}");
                if sandbox_id.is_some() {
                    println!("      Type: Sandbox build");
                } else {
                    println!("      Type: Application build");
                }
                Ok(build)
            }
            Err(e) => {
                println!("   ❌ Build creation failed: {e}");
                Err(WorkflowError::Build(e))
            }
        }
    }

    /// Wait for build deletion to be fully processed by the Veracode API
    ///
    /// This method waits up to 15 seconds (5 attempts × 3 seconds) for the build
    /// to be completely removed from the Veracode system before allowing recreation.
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID (numeric)
    /// * `sandbox_id` - Optional sandbox ID (numeric)
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or timeout error.
    async fn wait_for_build_deletion(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
    ) -> WorkflowResult<()> {
        let build_api = self.client.build_api();
        let max_attempts = 5;
        let delay_seconds = 3;

        // Keep this outside the loop to avoid repeated Duration creation
        let sleep_duration = tokio::time::Duration::from_secs(delay_seconds);

        for attempt in 1..=max_attempts {
            // Wait 3 seconds before checking
            tokio::time::sleep(sleep_duration).await;

            // Check build status directly without intermediate variable
            match build_api
                .get_build_info(&crate::build::GetBuildInfoRequest {
                    app_id: app_id.to_string(),
                    build_id: None,
                    sandbox_id: sandbox_id.map(|s| s.to_string()),
                })
                .await
            {
                Ok(_build) => {
                    // Build still exists, continue waiting
                    if attempt < max_attempts {
                        println!(
                            "      ⏳ Build still exists, waiting {delay_seconds} more seconds... (attempt {attempt}/{max_attempts})"
                        );
                    } else {
                        println!(
                            "      ⚠️  Build still exists after {max_attempts} attempts, proceeding anyway"
                        );
                    }
                }
                Err(crate::build::BuildError::BuildNotFound) => {
                    // Build is gone, we can proceed
                    println!(
                        "      ✅ Build deletion confirmed (attempt {attempt}/{max_attempts})"
                    );
                    return Ok(());
                }
                Err(e) => {
                    // Other error, might be temporary API issue, continue waiting
                    println!("      ⚠️  Error checking build status: {e} (attempt {attempt})");
                }
            }
        }

        // Even if build still exists after max attempts, continue with creation
        // The create operation might still succeed or provide a clearer error
        Ok(())
    }

    /// Upload a large file with automatic build management
    ///
    /// This method ensures a build exists before attempting to use uploadlargefile.do.
    /// If no build exists, it creates one automatically.
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID (numeric)
    /// * `sandbox_id` - Optional sandbox ID (numeric)
    /// * `file_path` - Path to the file to upload
    /// * `filename` - Optional custom filename for flaw matching
    /// * `version` - Optional build version (auto-generated if not provided)
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_large_file_with_build_management(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
        file_path: &str,
        filename: Option<&str>,
        version: Option<&str>,
    ) -> WorkflowResult<crate::scan::UploadedFile> {
        println!("🚀 Starting large file upload with build management");
        println!("   File: {file_path}");
        if let Some(sandbox_id) = sandbox_id {
            println!("   Target: Sandbox {sandbox_id}");
        } else {
            println!("   Target: Application {app_id}");
        }

        // Step 1: Ensure build exists
        let _build = self
            .ensure_build_exists(app_id, sandbox_id, version)
            .await?;

        // Step 2: Upload file using large file API
        println!("\n📤 Uploading file using uploadlargefile.do...");
        let scan_api = self.client.scan_api();

        match scan_api
            .upload_large_file(crate::scan::UploadLargeFileRequest {
                app_id: app_id.to_string(),
                file_path: file_path.to_string(),
                filename: filename.map(|s| s.to_string()),
                sandbox_id: sandbox_id.map(|s| s.to_string()),
            })
            .await
        {
            Ok(uploaded_file) => {
                println!("   ✅ Large file uploaded successfully:");
                println!("      File ID: {}", uploaded_file.file_id);
                println!("      File Name: {}", uploaded_file.file_name);
                println!("      Size: {} bytes", uploaded_file.file_size);
                Ok(uploaded_file)
            }
            Err(e) => {
                println!("   ❌ Large file upload failed: {e}");
                Err(WorkflowError::Scan(e))
            }
        }
    }

    /// Upload a large file with progress tracking and build management
    ///
    /// This method ensures a build exists before attempting to use uploadlargefile.do
    /// and provides progress tracking capabilities.
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID (numeric)
    /// * `sandbox_id` - Optional sandbox ID (numeric)
    /// * `file_path` - Path to the file to upload
    /// * `filename` - Optional custom filename for flaw matching
    /// * `version` - Optional build version (auto-generated if not provided)
    /// * `progress_callback` - Callback function for progress updates
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_large_file_with_progress_and_build_management<F>(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
        file_path: &str,
        filename: Option<&str>,
        version: Option<&str>,
        progress_callback: F,
    ) -> WorkflowResult<crate::scan::UploadedFile>
    where
        F: Fn(u64, u64, f64) + Send + Sync,
    {
        println!("🚀 Starting large file upload with progress tracking and build management");
        println!("   File: {file_path}");

        // Step 1: Ensure build exists
        let _build = self
            .ensure_build_exists(app_id, sandbox_id, version)
            .await?;

        // Step 2: Upload file with progress tracking
        println!("\n📤 Uploading file with progress tracking...");
        let scan_api = self.client.scan_api();

        match scan_api
            .upload_large_file_with_progress(
                crate::scan::UploadLargeFileRequest {
                    app_id: app_id.to_string(),
                    file_path: file_path.to_string(),
                    filename: filename.map(|s| s.to_string()),
                    sandbox_id: sandbox_id.map(|s| s.to_string()),
                },
                progress_callback,
            )
            .await
        {
            Ok(uploaded_file) => {
                println!("   ✅ Large file uploaded successfully with progress tracking");
                Ok(uploaded_file)
            }
            Err(e) => {
                println!("   ❌ Large file upload with progress failed: {e}");
                Err(WorkflowError::Scan(e))
            }
        }
    }

    /// Complete file upload workflow with intelligent endpoint selection and build management
    ///
    /// This method automatically chooses between uploadfile.do and uploadlargefile.do
    /// based on file size and ensures builds exist when needed.
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID (numeric)
    /// * `sandbox_id` - Optional sandbox ID (numeric)
    /// * `file_path` - Path to the file to upload
    /// * `filename` - Optional custom filename
    /// * `version` - Optional build version
    ///
    /// # Returns
    ///
    /// A `Result` containing the uploaded file information or an error.
    pub async fn upload_file_with_smart_build_management(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
        file_path: &str,
        filename: Option<&str>,
        version: Option<&str>,
    ) -> WorkflowResult<crate::scan::UploadedFile> {
        // Check file size to determine upload strategy
        let file_metadata = std::fs::metadata(file_path)
            .map_err(|e| WorkflowError::Workflow(format!("Cannot access file {file_path}: {e}")))?;

        let file_size = file_metadata.len();
        const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024; // 100MB

        println!("🔍 File size: {file_size} bytes");

        if file_size > LARGE_FILE_THRESHOLD {
            println!("📦 Using large file upload (uploadlargefile.do) with build management");
            self.upload_large_file_with_build_management(
                app_id, sandbox_id, file_path, filename, version,
            )
            .await
        } else {
            println!("📦 Using standard file upload (uploadfile.do)");
            let scan_api = self.client.scan_api();

            match scan_api
                .upload_file(&crate::scan::UploadFileRequest {
                    app_id: app_id.to_string(),
                    file_path: file_path.to_string(),
                    save_as: filename.map(|s| s.to_string()),
                    sandbox_id: sandbox_id.map(|s| s.to_string()),
                })
                .await
            {
                Ok(uploaded_file) => {
                    println!("   ✅ File uploaded successfully via uploadfile.do");
                    Ok(uploaded_file)
                }
                Err(e) => {
                    println!("   ❌ Standard upload failed: {e}");
                    Err(WorkflowError::Scan(e))
                }
            }
        }
    }

    /// Get or create a build for upload operations
    ///
    /// This is a convenience method that handles the build dependency for upload operations.
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application ID (numeric)
    /// * `sandbox_id` - Optional sandbox ID (numeric)
    /// * `version` - Optional build version
    ///
    /// # Returns
    ///
    /// A `Result` containing the build information or an error.
    pub async fn get_or_create_build(
        &self,
        app_id: &str,
        sandbox_id: Option<&str>,
        version: Option<&str>,
    ) -> WorkflowResult<Build> {
        self.ensure_build_exists(app_id, sandbox_id, version).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workflow_config_builder() {
        let config = WorkflowConfig::new("MyApp".to_string(), "MySandbox".to_string())
            .with_business_criticality(BusinessCriticality::High)
            .with_app_description("Test application".to_string())
            .with_file("test.jar".to_string())
            .with_auto_scan(false);

        assert_eq!(config.app_name, "MyApp");
        assert_eq!(config.sandbox_name, "MySandbox");
        assert_eq!(
            config.business_criticality as i32,
            BusinessCriticality::High as i32
        );
        assert_eq!(config.app_description, Some("Test application".to_string()));
        assert_eq!(config.file_paths, vec!["test.jar"]);
        assert!(!config.auto_scan);
    }

    #[test]
    fn test_workflow_error_display() {
        let error = WorkflowError::NotFound("Application not found".to_string());
        assert_eq!(error.to_string(), "Not found: Application not found");

        let error = WorkflowError::AccessDenied("Permission denied".to_string());
        assert_eq!(error.to_string(), "Access denied: Permission denied");

        let error = WorkflowError::Workflow("Custom error".to_string());
        assert_eq!(error.to_string(), "Workflow error: Custom error");
    }
}

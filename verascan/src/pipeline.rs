use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::task::JoinSet;
use veracode_platform::pipeline::{CreateScanRequest, DevStage, ScanConfig};
use veracode_platform::{VeracodeClient, VeracodeConfig, VeracodeRegion};

use crate::filevalidator::{FileValidator, ValidationError};

#[derive(Debug)]
pub enum PipelineError {
    VeracodeError(veracode_platform::VeracodeError),
    PlatformPipelineError(veracode_platform::pipeline::PipelineError),
    NoValidFiles,
    ConfigError(String),
    ScanError(String),
    ValidationError(ValidationError),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::VeracodeError(e) => write!(f, "Veracode API error: {e}"),
            PipelineError::PlatformPipelineError(e) => write!(f, "Pipeline API error: {e}"),
            PipelineError::NoValidFiles => write!(f, "No valid files found for scanning"),
            PipelineError::ConfigError(msg) => write!(f, "Configuration error: {msg}"),
            PipelineError::ScanError(msg) => write!(f, "Scan error: {msg}"),
            PipelineError::ValidationError(e) => write!(f, "File validation error: {e}"),
        }
    }
}

impl std::error::Error for PipelineError {}

impl From<veracode_platform::VeracodeError> for PipelineError {
    fn from(err: veracode_platform::VeracodeError) -> Self {
        PipelineError::VeracodeError(err)
    }
}

impl From<veracode_platform::pipeline::PipelineError> for PipelineError {
    fn from(err: veracode_platform::pipeline::PipelineError) -> Self {
        PipelineError::PlatformPipelineError(err)
    }
}

impl From<ValidationError> for PipelineError {
    fn from(err: ValidationError) -> Self {
        PipelineError::ValidationError(err)
    }
}

#[derive(Debug, Clone)]
pub struct PipelineScanConfig {
    pub project_name: String,
    pub project_uri: Option<String>,
    pub dev_stage: DevStage,
    pub region: VeracodeRegion,
    pub timeout: Option<u32>,
    pub include_low_severity: Option<bool>,
    pub max_findings: Option<u32>,
    pub selected_modules: Option<Vec<String>>,
    pub debug: bool,
    pub app_profile_name: Option<String>,
    pub threads: usize,
}

impl Default for PipelineScanConfig {
    fn default() -> Self {
        Self {
            project_name: "Verascan Pipeline Scan".into(),
            project_uri: None,
            dev_stage: DevStage::Development,
            region: VeracodeRegion::Commercial,
            timeout: Some(60), // 1 hour default in minutes
            include_low_severity: Some(true),
            max_findings: None,
            selected_modules: None,
            debug: false,
            app_profile_name: None,
            threads: 4,
        }
    }
}

pub struct PipelineSubmitter {
    client: VeracodeClient,
    config: PipelineScanConfig,
}

impl PipelineSubmitter {
    /// Create a new pipeline submitter
    pub fn new(
        veracode_config: VeracodeConfig,
        pipeline_config: PipelineScanConfig,
    ) -> Result<Self, PipelineError> {
        let client = VeracodeClient::new(veracode_config)?;

        Ok(Self {
            client,
            config: pipeline_config,
        })
    }

    /// Submit files for pipeline scanning (processes first file only)
    pub async fn submit_files(&self, files: &[PathBuf]) -> Result<String, PipelineError> {
        if files.is_empty() {
            return Err(PipelineError::NoValidFiles);
        }

        // Take the first file for pipeline scan (pipeline API works with single binaries)
        let file = &files[0];

        if self.config.debug {
            println!("🚀 Starting pipeline scan submission");
            println!("📁 File to scan: {}", file.display());
            if files.len() > 1 {
                println!("⚠️  Note: Pipeline API processes single files. Using first file only.");
                println!("   Other files found: {}", files.len() - 1);
            }
        }

        // Validate file size (200MB limit for pipeline scans)
        let validator = FileValidator::new();
        let file_size = validator.validate_pipeline_file_size(file)?;

        if self.config.debug {
            let size_mb = file_size as f64 / (1024.0 * 1024.0);
            println!("✅ File size validation passed: {size_mb:.2} MB (within 200 MB limit)");
        }

        // Read file to get hash (we already have the validated size)
        let file_data = std::fs::read(file).map_err(|e| {
            PipelineError::ConfigError(format!("Failed to read file {}: {}", file.display(), e))
        })?;
        let binary_hash = format!("{:x}", Sha256::digest(&file_data));
        let binary_name = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();

        if self.config.debug {
            println!("📊 File Information:");
            println!("   Binary Name: {binary_name}");
            println!("   Binary Size: {file_size} bytes");
            println!("   Binary Hash: {binary_hash}");
        }

        // Convert selected modules to comma-separated string
        let include_modules = self
            .config
            .selected_modules
            .as_ref()
            .map(|modules| modules.join(","));

        // Create scan request - minimize clones by using references where possible
        let mut scan_request = CreateScanRequest {
            binary_name,
            binary_size: file_size,
            binary_hash,
            project_name: self.config.project_name.clone(), // Clone needed for owned CreateScanRequest
            project_uri: self.config.project_uri.clone(), // Clone needed for owned CreateScanRequest
            dev_stage: self.config.dev_stage.clone(),     // DevStage doesn't implement Copy
            app_id: None,
            project_ref: None,
            scan_timeout: self.config.timeout,
            plugin_version: Some("verascan-0.1.0".to_string()),
            emit_stack_dump: None,
            include_modules,
        };

        if self.config.debug {
            println!("📊 Scan Configuration:");
            println!("   Project Name: {}", scan_request.project_name);
            println!("   Project URI: {:?}", scan_request.project_uri);
            println!("   Dev Stage: {:?}", scan_request.dev_stage);
            println!("   Timeout: {:?} minutes", scan_request.scan_timeout);
            if let Some(ref modules) = scan_request.include_modules {
                println!("   Selected Modules: {modules}");
            } else {
                println!("   Modules: All available modules");
            }
        }

        // Submit the scan
        if self.config.debug {
            println!("📤 Submitting pipeline scan...");
        }
        let pipeline_api = self.client.pipeline_api_with_debug(self.config.debug);

        // Store binary name for display before moving scan_request
        let binary_name = scan_request.binary_name.clone();

        // Use app lookup if app_profile_name is provided
        let scan_result = if let Some(ref app_name) = self.config.app_profile_name {
            if self.config.debug {
                println!("🔍 Looking up application profile: {app_name}");
            }
            pipeline_api
                .create_scan_with_app_lookup(&mut scan_request, Some(app_name))
                .await
        } else {
            pipeline_api.create_scan(&mut scan_request).await
        };

        match scan_result {
            Ok(scan_result) => {
                println!("✅ Pipeline scan created for file: {binary_name}");
                if self.config.debug {
                    println!(
                        "✅ Pipeline scan created with scan id: {}",
                        scan_result.scan_id
                    );
                    println!("   Scan ID: {}", scan_result.scan_id);
                }

                if let Some(upload_uri) = &scan_result.upload_uri {
                    if self.config.debug {
                        println!("🔍 Upload URI: {upload_uri}");
                        println!("🔍 Expected segments: {:?}", scan_result.expected_segments);
                    }

                    // Upload the file using proper segmented upload
                    if self.config.debug {
                        println!("📤 Uploading file...");
                    }

                    // Get expected segments and filename
                    let expected_segments = scan_result.expected_segments.unwrap_or(1) as i32;
                    let file_name = file
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("binary.jar");

                    // Use upload_binary_segments method with proper parameters
                    match pipeline_api
                        .upload_binary_segments(
                            upload_uri,
                            expected_segments,
                            &file_data,
                            file_name,
                        )
                        .await
                    {
                        Ok(_) => {
                            if self.config.debug {
                                println!("✅ File uploaded successfully!");
                            }

                            // Start the scan with ScanConfig
                            if self.config.debug {
                                println!("🚀 Starting scan analysis...");
                            }
                            let scan_config = Some(ScanConfig {
                                timeout: self.config.timeout,
                                include_low_severity: self.config.include_low_severity,
                                max_findings: self.config.max_findings,
                            });

                            match pipeline_api
                                .start_scan(&scan_result.scan_id, scan_config)
                                .await
                            {
                                Ok(_) => {
                                    println!("✅ Scan started: {binary_name}");
                                    if self.config.debug {
                                        println!("✅ Scan started: {}", scan_result.scan_id);
                                    }
                                    Ok(scan_result.scan_id)
                                }
                                Err(e) => {
                                    eprintln!("❌ Failed to start scan: {e}");
                                    Err(PipelineError::from(e))
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to upload file: {e}");
                            Err(PipelineError::from(e))
                        }
                    }
                } else {
                    Err(PipelineError::ConfigError(
                        "No upload URI provided".to_string(),
                    ))
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to create pipeline scan: {e}");
                Err(PipelineError::from(e))
            }
        }
    }

    /// Submit a single file for pipeline scanning
    pub async fn submit_single_file(&self, file: &Path) -> Result<String, PipelineError> {
        self.submit_files(&[file.to_path_buf()]).await
    }

    /// Submit files and wait for results
    pub async fn submit_and_wait(
        &self,
        files: &[PathBuf],
    ) -> Result<veracode_platform::pipeline::ScanResults, PipelineError> {
        let scan_id = self.submit_files(files).await?;

        // Poll for results with timeout (convert minutes to seconds)
        let timeout_minutes = self.config.timeout.unwrap_or(60);
        let timeout_seconds = timeout_minutes * 60;

        if self.config.debug {
            println!("⏳ Waiting for scan to complete (timeout: {timeout_minutes} minutes)...");
            println!("🔍 Polling scan status for ID: {scan_id}");
        } else {
            print!("⏳ Waiting for scan to complete");
            std::io::Write::flush(&mut std::io::stdout()).unwrap_or(());
        }

        let pipeline_api = self.client.pipeline_api_with_debug(self.config.debug);
        let poll_interval = 30; // Poll every 30 seconds
        let max_polls = timeout_seconds / poll_interval;

        for poll_count in 1..=max_polls {
            if self.config.debug {
                println!("🔄 Poll attempt {poll_count}/{max_polls}");
            }

            // First check scan status without trying to get findings
            match pipeline_api.get_scan(&scan_id).await {
                Ok(scan) => {
                    if scan.scan_status.is_successful() {
                        if self.config.debug {
                            println!("✅ Scan {scan_id} completed successfully!");
                        } else {
                            println!("\n✅ Scan completed: {scan_id}");
                        }
                        // Now that scan is complete, get the full results with findings
                        return pipeline_api
                            .get_results(&scan_id)
                            .await
                            .map_err(PipelineError::from);
                    } else if scan.scan_status.is_failed() {
                        return Err(PipelineError::ScanError(format!(
                            "Scan {} failed with status: {:?}",
                            scan_id, scan.scan_status
                        )));
                    } else if scan.scan_status.is_in_progress() {
                        if self.config.debug {
                            println!(
                                "⏳ Scan {scan_id} in progress, waiting {poll_interval} seconds..."
                            );
                        } else {
                            print!(".");
                            std::io::Write::flush(&mut std::io::stdout()).unwrap_or(());
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                            .await;
                    } else {
                        if self.config.debug {
                            println!(
                                "❓ Scan {} unknown status: {:?}, continuing to wait...",
                                scan_id, scan.scan_status
                            );
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                            .await;
                    }
                }
                Err(e) => {
                    if self.config.debug {
                        println!("⚠️  Error getting scan status for {scan_id}: {e}, retrying...");
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                        .await;
                }
            }
        }

        Err(PipelineError::ScanError(format!(
            "Scan timed out after {timeout_minutes} minutes"
        )))
    }

    /// Get scan results for a given scan ID
    pub async fn get_results(
        &self,
        scan_id: &str,
    ) -> Result<veracode_platform::pipeline::ScanResults, PipelineError> {
        if self.config.debug {
            println!("📊 Retrieving results for scan ID: {scan_id}");
        }

        let pipeline_api = self.client.pipeline_api_with_debug(self.config.debug);
        let results = pipeline_api.get_results(scan_id).await?;

        if self.config.debug {
            println!("🔍 Scan results retrieved successfully");
        }

        Ok(results)
    }

    /// Display scan results summary
    pub fn display_results_summary(&self, results: &veracode_platform::pipeline::ScanResults) {
        println!("\n📊 Scan Results Summary:");
        println!("   Project: {}", results.scan.project_name);
        println!("   Status: {}", results.scan.scan_status);

        let findings_summary = &results.summary;
        println!("   Total Findings: {}", findings_summary.total);

        if findings_summary.very_high > 0 {
            println!("   Very High: {}", findings_summary.very_high);
        }
        if findings_summary.high > 0 {
            println!("   High: {}", findings_summary.high);
        }
        if findings_summary.medium > 0 {
            println!("   Medium: {}", findings_summary.medium);
        }
        if findings_summary.low > 0 {
            println!("   Low: {}", findings_summary.low);
        }
        if findings_summary.very_low > 0 {
            println!("   Very Low: {}", findings_summary.very_low);
        }
        if findings_summary.informational > 0 {
            println!("   Informational: {}", findings_summary.informational);
        }

        if let Some(project_uri) = &results.scan.project_uri {
            println!("   Project URI: {project_uri}");
        }
    }

    /// Submit multiple files concurrently for pipeline scanning
    pub async fn submit_files_concurrent(
        &self,
        files: &[PathBuf],
    ) -> Result<Vec<String>, PipelineError> {
        if files.is_empty() {
            return Err(PipelineError::NoValidFiles);
        }

        let num_threads = std::cmp::min(self.config.threads, files.len());
        println!("🚀 Starting {} concurrent pipeline scans", files.len());
        if self.config.debug {
            println!("   Using {num_threads} threads");
        }

        // Create a semaphore to limit concurrent operations
        let semaphore = Arc::new(tokio::sync::Semaphore::new(num_threads));
        let mut join_set = JoinSet::new();

        // Share submitter efficiently via Arc - clone once and share references
        let submitter_arc = Arc::new(self.clone());

        // Submit each file as a separate task
        for (index, file) in files.iter().enumerate() {
            let file_path = file.clone(); // PathBuf clone necessary for move
            let semaphore_ref = Arc::clone(&semaphore);
            let submitter_ref = Arc::clone(&submitter_arc);

            join_set.spawn(async move {
                let _permit = semaphore_ref.acquire().await.unwrap();

                if submitter_ref.config.debug {
                    println!(
                        "📤 Thread {}: Starting scan for {}",
                        index + 1,
                        file_path.display()
                    );
                }

                match submitter_ref.submit_single_file(&file_path).await {
                    Ok(scan_id) => {
                        let filename = file_path.file_name().unwrap_or_default().to_string_lossy();
                        if submitter_ref.config.debug {
                            println!("✅ Scan submitted: {filename} - ID: {scan_id}");
                        } else {
                            println!("✅ Scan submitted: {filename}");
                        }
                        Ok((index, scan_id))
                    }
                    Err(e) => {
                        eprintln!(
                            "❌ Failed to submit scan for {}: {}",
                            file_path.file_name().unwrap_or_default().to_string_lossy(),
                            e
                        );
                        Err((index, e))
                    }
                }
            });
        }

        // Collect results
        let mut scan_ids = Vec::new();
        let mut errors = Vec::new();

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((index, scan_id))) => {
                    scan_ids.push((index, scan_id));
                }
                Ok(Err((index, error))) => {
                    errors.push((index, error));
                }
                Err(join_error) => {
                    eprintln!("❌ Task join error: {join_error}");
                }
            }
        }

        if !errors.is_empty() {
            eprintln!("❌ {} scan submissions failed", errors.len());
            for (index, error) in errors {
                eprintln!("   File {}: {}", index + 1, error);
            }
        }

        // Sort scan IDs by original file order
        scan_ids.sort_by_key(|(index, _)| *index);
        let sorted_scan_ids: Vec<String> =
            scan_ids.into_iter().map(|(_, scan_id)| scan_id).collect();

        println!(
            "✅ Successfully submitted {} pipeline scans",
            sorted_scan_ids.len()
        );
        Ok(sorted_scan_ids)
    }

    /// Submit multiple files concurrently and wait for all results
    pub async fn submit_files_concurrent_and_wait(
        &self,
        files: &[PathBuf],
    ) -> Result<Vec<veracode_platform::pipeline::ScanResults>, PipelineError> {
        let scan_ids = self.submit_files_concurrent(files).await?;

        if scan_ids.is_empty() {
            return Ok(Vec::new());
        }

        let timeout_minutes = self.config.timeout.unwrap_or(60);
        if self.config.debug {
            println!(
                "⏳ Waiting for {} scans to complete (timeout: {} minutes each)...",
                scan_ids.len(),
                timeout_minutes
            );
        }

        // Create a semaphore to limit concurrent polling operations
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.threads));
        let mut join_set = JoinSet::new();

        // Share submitter efficiently via Arc - clone once and share references
        let submitter_arc = Arc::new(self.clone());

        // Wait for each scan as a separate task
        for (index, scan_id) in scan_ids.iter().enumerate() {
            let scan_id_ref = scan_id.clone(); // String clone needed for move
            let semaphore_ref = Arc::clone(&semaphore);
            let submitter_ref = Arc::clone(&submitter_arc);

            join_set.spawn(async move {
                let _permit = semaphore_ref.acquire().await.unwrap();

                if submitter_ref.config.debug {
                    println!("⏳ Thread {}: Waiting for scan {}", index + 1, scan_id_ref);
                }

                match submitter_ref.wait_for_scan_completion(&scan_id_ref).await {
                    Ok(results) => {
                        if submitter_ref.config.debug {
                            println!("✅ Scan completed: {scan_id_ref}");
                        } else {
                            println!("✅ Scan completed");
                        }
                        Ok((index, results))
                    }
                    Err(e) => {
                        eprintln!("❌ Scan failed: {scan_id_ref} - {e}");
                        Err((index, e))
                    }
                }
            });
        }

        // Collect results
        let mut scan_results = Vec::new();
        let mut errors = Vec::new();

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((index, results))) => {
                    scan_results.push((index, results));
                }
                Ok(Err((index, error))) => {
                    errors.push((index, error));
                }
                Err(join_error) => {
                    eprintln!("❌ Task join error: {join_error}");
                }
            }
        }

        if !errors.is_empty() {
            eprintln!("❌ {} scans failed or timed out", errors.len());
            for (index, error) in errors {
                eprintln!("   Scan {}: {}", index + 1, error);
            }
        }

        // Sort results by original scan order
        scan_results.sort_by_key(|(index, _)| *index);
        let sorted_results: Vec<veracode_platform::pipeline::ScanResults> = scan_results
            .into_iter()
            .map(|(_, results)| results)
            .collect();

        println!("✅ {} scans completed successfully", sorted_results.len());
        Ok(sorted_results)
    }

    /// Wait for a specific scan to complete
    async fn wait_for_scan_completion(
        &self,
        scan_id: &str,
    ) -> Result<veracode_platform::pipeline::ScanResults, PipelineError> {
        let timeout_minutes = self.config.timeout.unwrap_or(60);
        let timeout_seconds = timeout_minutes * 60;
        let poll_interval = 30; // Poll every 30 seconds
        let max_polls = timeout_seconds / poll_interval;

        let pipeline_api = self.client.pipeline_api_with_debug(self.config.debug);

        for poll_count in 1..=max_polls {
            if self.config.debug {
                println!("🔄 Scan {scan_id}: Poll attempt {poll_count}/{max_polls}");
            }

            // First check scan status without trying to get findings
            match pipeline_api.get_scan(scan_id).await {
                Ok(scan) => {
                    if scan.scan_status.is_successful() {
                        if self.config.debug {
                            println!("✅ Scan {scan_id} completed successfully!");
                        }
                        // Only get full results when scan status is SUCCESS
                        return pipeline_api
                            .get_results(scan_id)
                            .await
                            .map_err(PipelineError::from);
                    } else if scan.scan_status.is_failed() {
                        return Err(PipelineError::ScanError(format!(
                            "Scan {} failed with status: {:?}",
                            scan_id, scan.scan_status
                        )));
                    } else if scan.scan_status.is_in_progress() {
                        if self.config.debug {
                            println!(
                                "⏳ Scan {scan_id} in progress, waiting {poll_interval} seconds..."
                            );
                        } else {
                            print!(".");
                            std::io::Write::flush(&mut std::io::stdout()).unwrap_or(());
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                            .await;
                    } else {
                        if self.config.debug {
                            println!(
                                "❓ Scan {} unknown status: {:?}, continuing to wait...",
                                scan_id, scan.scan_status
                            );
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                            .await;
                    }
                }
                Err(e) => {
                    if self.config.debug {
                        println!("⚠️  Error getting scan status for {scan_id}: {e}, retrying...");
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval.into()))
                        .await;
                }
            }
        }

        Err(PipelineError::ScanError(format!(
            "Scan {scan_id} timed out after {timeout_minutes} minutes"
        )))
    }
}

impl Clone for PipelineSubmitter {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineScanConfig::default();
        assert_eq!(config.project_name, "Verascan Pipeline Scan");
        assert_eq!(config.dev_stage, DevStage::Development);
        assert_eq!(config.timeout, Some(60));
        assert_eq!(config.threads, 4);
    }

    #[test]
    fn test_pipeline_error_display() {
        let error = PipelineError::NoValidFiles;
        assert_eq!(error.to_string(), "No valid files found for scanning");
    }
}

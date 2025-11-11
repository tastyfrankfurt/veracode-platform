#![allow(clippy::expect_used)]

use veracode_platform::{
    VeracodeClient, VeracodeConfig,
    pipeline::{CreateScanRequest, DevStage, Finding, PipelineError, ScanConfig},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VeracodeConfig::new(
        &std::env::var("VERACODE_API_ID").expect("VERACODE_API_ID environment variable required"),
        &std::env::var("VERACODE_API_KEY").expect("VERACODE_API_KEY environment variable required"),
    );

    let client = VeracodeClient::new(config)?;
    let pipeline_api = client.pipeline_api();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_secs();

    println!("🔍 Pipeline Scan Lifecycle Example\n");

    // Example 1: Create a new pipeline scan using actual sample file
    println!("🔧 Creating a new pipeline scan...");

    // Check for sample file in multiple possible locations
    let possible_paths = vec![
        "examples/samples/vulnerable_test_app.tar.gz",
        "veracode-api/examples/samples/vulnerable_test_app.tar.gz",
        "samples/vulnerable_test_app.tar.gz",
    ];

    let sample_file_path = possible_paths
        .iter()
        .find(|path| std::path::Path::new(path).exists())
        .copied();

    let sample_file_path = match sample_file_path {
        Some(path) => {
            println!("✅ Sample file found: {path}");
            path
        }
        None => {
            eprintln!("❌ Sample file not found in any of these locations:");
            for path in &possible_paths {
                eprintln!("   - {path}");
            }
            println!("💡 Please ensure the sample file exists at one of the expected locations.");
            println!("   You can create it by running the vulnerable test app generator or");
            println!("   place your own binary file at that location.");
            return Ok(());
        }
    };

    // Read the actual sample file
    let binary_data = match tokio::fs::read(sample_file_path).await {
        Ok(data) => {
            println!("📁 File size: {} bytes", data.len());
            data
        }
        Err(e) => {
            eprintln!("❌ Failed to read sample file {sample_file_path}: {e}");
            println!("💡 Check file permissions and try again.");
            return Ok(());
        }
    };

    let binary_name = format!("vulnerable_test_app-{timestamp}.tar.gz");

    // Generate proper SHA-256 hash (64 characters) as required by Veracode API
    let binary_hash = calculate_sha256_hash(&binary_data);

    let mut scan_request = CreateScanRequest {
        binary_name: binary_name.clone(),
        binary_size: binary_data.len() as u64,
        binary_hash: binary_hash.clone(),
        project_name: format!("Demo Project {timestamp}"),
        project_uri: Some("https://github.com/example/demo-project".to_string()),
        dev_stage: DevStage::Development,
        app_id: None, // Optional: set if linking to existing Veracode app
        project_ref: Some("main".to_string()), // Optional: branch/commit reference
        scan_timeout: Some(5), // Optional: timeout in minutes
        plugin_version: None, // Will be auto-set to "25.2.0-0"
        emit_stack_dump: None, // Optional: "true" to emit stack dumps
        include_modules: None, // Optional: comma-separated module names
    };

    println!("📋 Scan Request Details:");
    println!("   Binary Name: {}", scan_request.binary_name);
    println!("   Binary Size: {} bytes", scan_request.binary_size);
    println!(
        "   Binary Hash: {} (length: {} chars)",
        binary_hash,
        binary_hash.len()
    );
    println!("   Project Name: {}", scan_request.project_name);
    println!("   Project URI: {:?}", scan_request.project_uri);
    println!("   Dev Stage: {:?}", scan_request.dev_stage);
    println!();

    let scan_result = match pipeline_api.create_scan(&mut scan_request).await {
        Ok(result) => {
            println!("✅ Created scan with ID: {}", result.scan_id);
            result
        }
        Err(PipelineError::PermissionDenied(msg)) => {
            println!("⚠️  Permission denied to create scan: {msg}");
            println!("   This is expected if your API credentials don't have scan permissions");
            return Ok(());
        }
        Err(e) => {
            eprintln!("❌ Failed to create scan: {e}");
            return Ok(());
        }
    };

    let scan_id = &scan_result.scan_id;

    // Example 2: Get details of the scan we just created
    println!("\n📋 Getting details of our newly created scan...");
    let scan_details_result = if let Some(ref details_uri) = scan_result.details_uri {
        println!("🔗 Using details URI from _links: {details_uri}");
        pipeline_api.get_scan_with_uri(details_uri).await
    } else {
        println!("🔄 Fallback: Using scan ID for details");
        pipeline_api.get_scan(scan_id).await
    };

    match scan_details_result {
        Ok(scan) => {
            println!("✅ Retrieved scan details:");
            println!("   ID: {}", scan.scan_id);
            println!("   Project: {}", scan.project_name);
            println!("   Binary: {}", scan.binary_name);
            println!("   Status: {}", scan.scan_status);
            println!("   Dev Stage: {}", scan.dev_stage);
            println!("   Created: {}", scan.created);
            println!("   Last Changed: {}", scan.changed);
            println!("   Binary Size: {} bytes", scan.binary_size);
            println!("   Binary Hash: {}", scan.binary_hash);
            println!("   Segments Expected: {}", scan.binary_segments_expected);
            println!("   Segments Uploaded: {}", scan.binary_segments_uploaded);

            if let Some(project_uri) = &scan.project_uri {
                println!("   Project URI: {project_uri}");
            }
            if let Some(timeout) = scan.scan_timeout {
                println!("   Scan Timeout: {timeout} minutes");
            }
            if let Some(duration) = scan.scan_duration {
                println!("   Scan Duration: {duration:.2} minutes");
            }
            if let Some(msg) = &scan.message {
                println!("   Message: {msg}");
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to get scan details: {e}");
        }
    }

    // Example 3: Upload binary data using proper segmented upload (matching Java implementation)
    println!("\n📤 Uploading binary data using segmented upload...");

    // Use upload URI from scan creation response (matching Java implementation)
    #[allow(clippy::cast_possible_wrap)]
    let (upload_uri, expected_segments) = if let (Some(uri), Some(segments)) =
        (&scan_result.upload_uri, scan_result.expected_segments)
    {
        (uri.clone(), segments.saturating_add(0) as i32)
    } else {
        // Fallback: get upload details from scan details (if not in creation response)
        println!("📋 Upload URI not in creation response, fetching from scan details...");
        match pipeline_api.get_scan(scan_id).await {
            Ok(scan) => {
                let segments = scan.binary_segments_expected;
                // Fallback construction (should not be needed with correct API)
                let upload_uri = format!("/scans/{scan_id}/segments/1");
                (upload_uri, segments.saturating_add(0) as i32)
            }
            Err(e) => {
                eprintln!("❌ Failed to get scan details for upload: {e}");
                println!("🔄 Using emergency fallback upload configuration");
                (format!("/scans/{scan_id}/segments/1"), 1)
            }
        }
    };

    let file_name = sample_file_path
        .split('/')
        .next_back()
        .unwrap_or("binary.tar.gz");

    let upload_successful = match pipeline_api
        .upload_binary_segments(&upload_uri, expected_segments, &binary_data, file_name)
        .await
    {
        Ok(_) => {
            println!("✅ Binary uploaded successfully using proper segmented upload");
            true
        }
        Err(e) => {
            eprintln!("❌ Segmented upload failed: {e}");
            println!("💡 Upload failed - this may indicate:");
            println!("   - Invalid upload URI or segment configuration");
            println!("   - Incorrect API permissions for file upload");
            println!("   - Network connectivity issues");
            println!("   Proceeding with scan start to see if upload was actually successful...");
            false
        }
    };

    if upload_successful {
        println!("🎯 Upload completed - proceeding to start scan");
    }

    // Example 4: Start the scan
    println!("\n🚀 Starting pipeline scan...");
    let scan_config = ScanConfig {
        timeout: Some(5), // 5 minutes timeout for demo
        include_low_severity: Some(true),
        max_findings: Some(100),
    };

    let start_scan_result = if let Some(ref start_uri) = scan_result.start_uri {
        println!("🔗 Using start URI from _links: {start_uri}");
        pipeline_api
            .start_scan_with_uri(start_uri, Some(scan_config))
            .await
    } else {
        println!("🔄 Fallback: Using scan ID for start");
        pipeline_api.start_scan(scan_id, Some(scan_config)).await
    };

    match start_scan_result {
        Ok(_) => {
            println!("✅ Scan started successfully");
        }
        Err(e) => {
            eprintln!("❌ Failed to start scan: {e}");
            return Ok(());
        }
    }

    // Example 5: Monitor scan progress
    println!("\n⏳ Monitoring scan progress...");
    match pipeline_api.get_scan(scan_id).await {
        Ok(scan) => {
            println!("📊 Scan Details:");
            println!("   Project: {}", scan.project_name);
            println!("   Binary: {}", scan.binary_name);
            println!("   Status: {}", scan.scan_status);
            println!(
                "   Upload Progress: {}/{} segments",
                scan.binary_segments_uploaded, scan.binary_segments_expected
            );
            println!("   Created: {}", scan.created);

            if let Some(duration) = scan.scan_duration {
                println!("   Duration: {duration:.2} minutes");
            }
            if let Some(msg) = &scan.message {
                println!("   Message: {msg}");
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to get scan details: {e}");
        }
    }

    // Example 6: Monitor scan status with detailed progress
    println!("\n⏱️  Monitoring scan progress...");
    let mut poll_count: u32 = 0;
    let max_polls = 60; // Monitor for up to 30 minutes (30 second intervals)

    loop {
        poll_count = poll_count.saturating_add(1);

        match pipeline_api.get_scan(scan_id).await {
            Ok(scan) => {
                println!("📊 Poll #{}: Status = {}", poll_count, scan.scan_status);
                println!(
                    "   Upload Progress: {}/{} segments",
                    scan.binary_segments_uploaded, scan.binary_segments_expected
                );

                if let Some(duration) = scan.scan_duration {
                    println!("   Duration: {duration:.2} minutes");
                }
                if let Some(msg) = &scan.message {
                    println!("   Message: {msg}");
                }

                // Check if scan is complete
                if scan.scan_status.is_successful() {
                    println!("✅ Scan completed successfully!");
                    println!("   Final status: {}", scan.scan_status);
                    println!("   Last changed: {}", scan.changed);
                    break;
                } else if scan.scan_status.is_failed() {
                    println!("❌ Scan failed!");
                    println!("   Status: {}", scan.scan_status);
                    if let Some(msg) = &scan.message {
                        println!("   Failure message: {msg}");
                    }
                    break;
                } else if poll_count >= max_polls {
                    println!("⏰ Maximum polling time reached (scan may still be running)");
                    println!("   Current status: {}", scan.scan_status);
                    println!("   You can check back later or increase the timeout");
                    break;
                }
            }
            Err(e) => {
                eprintln!("❌ Error getting scan status: {e}");
                break;
            }
        }

        // Wait 30 seconds before next poll
        println!("   Waiting 10 seconds before next check...\n");
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    }

    // Example 7: Download and save scan results
    println!("\n📋 Downloading scan results...");
    // println!("🔍 Debug - About to call get_results() for scan ID: {}", scan_id);
    match pipeline_api.get_results(scan_id).await {
        Ok(results) => {
            println!("✅ Retrieved scan results:");
            println!("   Project: {}", results.scan.project_name);
            println!("   Total findings: {}", results.findings.len());

            // Save results to JSON file
            let results_filename = format!("pipeline_scan_results_{timestamp}.json");
            match serde_json::to_string_pretty(&results) {
                Ok(json_data) => match tokio::fs::write(&results_filename, json_data).await {
                    Ok(_) => {
                        println!("💾 Results saved to: {results_filename}");
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to save results file: {e}");
                    }
                },
                Err(e) => {
                    eprintln!("❌ Failed to serialize results: {e}");
                }
            }

            // Display findings summary
            let summary = &results.summary;
            println!("\n📊 Findings Summary:");
            if summary.very_high > 0 {
                println!("   Very High: {}", summary.very_high);
            }
            if summary.high > 0 {
                println!("   High: {}", summary.high);
            }
            if summary.medium > 0 {
                println!("   Medium: {}", summary.medium);
            }
            if summary.low > 0 {
                println!("   Low: {}", summary.low);
            }
            if summary.very_low > 0 {
                println!("   Very Low: {}", summary.very_low);
            }
            if summary.informational > 0 {
                println!("   Informational: {}", summary.informational);
            }

            // Display top findings
            if !results.findings.is_empty() {
                println!("\n🔍 Top Findings:");
                for (i, finding) in results.findings.iter().take(3).enumerate() {
                    let i: usize = i;
                    println!(
                        "   {}. {} (CWE-{})",
                        i.saturating_add(1),
                        finding.issue_type,
                        finding.cwe_id
                    );
                    println!(
                        "      File: {} (line {})",
                        finding.files.source_file.file, finding.files.source_file.line
                    );
                    println!(
                        "      Severity: {} ({})",
                        get_severity_name(finding.severity),
                        finding.severity
                    );
                    println!("      Title: {}", finding.title);
                    if !finding
                        .files
                        .source_file
                        .function_name
                        .as_deref()
                        .unwrap_or("")
                        .is_empty()
                    {
                        println!(
                            "      Function: {}",
                            finding
                                .files
                                .source_file
                                .function_name
                                .as_deref()
                                .unwrap_or("")
                        );
                    }
                    println!("      Issue ID: {}", finding.issue_id);
                    println!();
                }

                if results.findings.len() > 3 {
                    println!(
                        "   ... and {} more findings",
                        results.findings.len().saturating_sub(3)
                    );
                }

                // Save findings to CSV file for easy analysis
                let csv_filename = format!("pipeline_scan_findings_{timestamp}.csv");
                match save_findings_to_csv(&results.findings, &csv_filename) {
                    Ok(_) => {
                        println!("📊 Findings exported to CSV: {csv_filename}");
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to save CSV file: {e}");
                    }
                }
            } else {
                println!("   🎉 No security findings detected!");
            }
        }
        Err(PipelineError::FindingsNotReady) => {
            println!("⏳ Scan findings are not ready yet.");
            println!("   This can happen if:");
            println!("   - The scan just completed and findings are still being processed");
            println!("   - The scan failed during analysis");
            println!("   - The scan is still running");
            println!();
            println!("💡 Let's check the current scan status and try findings separately...");

            // Check current scan status
            match pipeline_api.get_scan(scan_id).await {
                Ok(scan) => {
                    println!("📊 Current Scan Status: {}", scan.scan_status);
                    println!("   Last changed: {}", scan.changed);
                    if let Some(msg) = &scan.message {
                        println!("   Message: {msg}");
                    }

                    // If scan is complete, try to get findings separately
                    if scan.scan_status.is_successful() {
                        println!(
                            "\n🔍 Scan shows {}, attempting to get findings separately...",
                            scan.scan_status
                        );
                        match pipeline_api.get_findings(scan_id).await {
                            Ok(findings) => {
                                println!("✅ Successfully retrieved {} findings", findings.len());

                                // Save findings to CSV if any exist
                                if !findings.is_empty() {
                                    let csv_filename =
                                        format!("pipeline_scan_findings_{timestamp}.csv");
                                    match save_findings_to_csv(&findings, &csv_filename) {
                                        Ok(_) => {
                                            println!("📊 Findings exported to CSV: {csv_filename}");
                                        }
                                        Err(e) => {
                                            eprintln!("❌ Failed to save CSV file: {e}");
                                        }
                                    }

                                    // Show summary of findings
                                    println!("\n📋 Quick Findings Summary:");
                                    let mut severity_counts: [usize; 6] = [0; 6]; // 0-5 severity levels
                                    for finding in &findings {
                                        if finding.severity <= 5
                                            && let Some(count) =
                                                severity_counts.get_mut(finding.severity as usize)
                                        {
                                            *count = (*count).saturating_add(1);
                                        }
                                    }

                                    let severity_names = [
                                        "Informational",
                                        "Very Low",
                                        "Low",
                                        "Medium",
                                        "High",
                                        "Very High",
                                    ];
                                    for (severity, count) in severity_counts.iter().enumerate() {
                                        if *count > 0
                                            && let Some(name) = severity_names.get(severity)
                                        {
                                            println!("   {}: {}", name, count);
                                        }
                                    }
                                } else {
                                    println!("   🎉 No security findings detected!");
                                }
                            }
                            Err(PipelineError::FindingsNotReady) => {
                                println!(
                                    "⏳ Findings still not ready - may need more time to process"
                                );
                                println!("   Try running the example again in a few minutes");
                            }
                            Err(e) => {
                                eprintln!("❌ Error getting findings: {e}");
                            }
                        }
                    } else {
                        println!("   Scan is not yet complete (status: {})", scan.scan_status);
                        println!(
                            "   You can run this example again once the scan reaches SUCCESS status"
                        );
                    }
                }
                Err(e) => {
                    eprintln!("❌ Error checking scan status: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to get scan results: {e}");
        }
    }

    // Example 8: Cancel scan (optional - commented out to avoid interfering with results)
    // println!("\n🛑 Canceling scan (demo)...");
    // match pipeline_api.cancel_scan(&scan_id).await {
    //     Ok(_) => {
    //         println!("✅ Scan canceled successfully");
    //     }
    //     Err(e) => {
    //         eprintln!("❌ Failed to cancel scan: {}", e);
    //     }
    // }

    println!("\n✅ Pipeline scan lifecycle example completed!");
    println!("\nThis example demonstrated:");
    println!("  ✓ Creating a new pipeline scan using real sample file");
    println!("  ✓ Getting details of a specific scan");
    println!("  ✓ Uploading binary data (actual sample file)");
    println!("  ✓ Starting a scan with configuration");
    println!("  ✓ Continuous monitoring of scan progress");
    println!("  ✓ Automatic detection of scan completion");
    println!("  ✓ Downloading and saving scan results to JSON");
    println!("  ✓ Exporting findings to CSV for analysis");
    println!("  ⏭️ Canceling scans (disabled in demo)");
    println!("\nNote: Some operations may fail with permission errors");
    println!("      if your API credentials don't have pipeline scan privileges.");
    println!("\n💡 For production use:");
    println!("  - This example uses a real sample file (vulnerable_test_app.tar.gz)");
    println!("  - Results are automatically saved to timestamped files");
    println!("  - Scan monitoring runs for up to 30 minutes with 30-second intervals");
    println!("  - Adjust max_polls and interval for different applications");
    println!("  - Store scan IDs for later retrieval if needed");
    println!("  - Implement proper error handling and retry logic");

    Ok(())
}

/// Helper function to convert severity number to readable name
fn get_severity_name(severity: u32) -> &'static str {
    match severity {
        5 => "Very High",
        4 => "High",
        3 => "Medium",
        2 => "Low",
        1 => "Very Low",
        0 => "Informational",
        _ => "Unknown",
    }
}

/// Helper function to calculate SHA-256 hash of file contents
/// In production, you would use this with actual file data
fn calculate_sha256_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Save findings to CSV file for easy analysis
fn save_findings_to_csv(
    findings: &[Finding],
    filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(filename)?;

    // Write CSV header
    writeln!(
        file,
        "File,Line,Function,Issue Type,Severity,Severity Name,Title,CWE ID,Issue ID,Grade,Issue Type ID"
    )?;

    // Write findings data
    for finding in findings {
        writeln!(
            file,
            "\"{}\",{},\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\"",
            finding.files.source_file.file.replace("\"", "\"\""), // Escape quotes in file paths
            finding.files.source_file.line,
            finding
                .files
                .source_file
                .function_name
                .as_deref()
                .unwrap_or("")
                .replace("\"", "\"\""),
            finding.issue_type.replace("\"", "\"\""), // Escape quotes
            finding.severity,
            get_severity_name(finding.severity),
            finding.title.replace("\"", "\"\""), // Escape quotes in title
            finding.cwe_id.replace("\"", "\"\""), // CWE ID is now a string
            finding.issue_id,
            finding.gob.replace("\"", "\"\""),
            finding.issue_type_id.replace("\"", "\"\"")
        )?;
    }

    Ok(())
}

/// Example of how to hash a real file in production
#[allow(dead_code)]
async fn hash_file_example(file_path: &str) -> Result<(String, u64), Box<dyn std::error::Error>> {
    // This would be used in production with real files
    // let file_data = std::fs::read(file_path)?;
    // let hash = calculate_sha256_hash(&file_data);
    // let size = file_data.len() as u64;
    // Ok((hash, size))

    // For demo purposes:
    let demo_data = format!("Demo file content for {file_path}");
    let hash = calculate_sha256_hash(demo_data.as_bytes());
    let size = demo_data.len() as u64;
    Ok((hash, size))
}

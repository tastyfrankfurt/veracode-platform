use veracode_platform::app::{BusinessCriticality, CreateApplicationProfile};
use veracode_platform::{
    CreateApplicationRequest, CreateSandboxRequest, VeracodeClient, VeracodeConfig,
    scan::{BeginPreScanRequest, BeginScanRequest, ScanError, UploadFileRequest},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VeracodeConfig::new(
        &std::env::var("VERACODE_API_ID").expect("VERACODE_API_ID environment variable required"),
        &std::env::var("VERACODE_API_KEY").expect("VERACODE_API_KEY environment variable required"),
    );

    let client = VeracodeClient::new(config)?;
    let scan_api = client.scan_api(); // Automatically uses XML API
    let sandbox_api = client.sandbox_api(); // Uses REST API

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    println!("🔧 Complete Sandbox Scan Lifecycle Example\n");

    // Step 1: Create a new application
    println!("🏗️  Step 1: Creating new application...");

    let app_name = format!("Test Application {timestamp}");
    let app_request = CreateApplicationRequest {
        profile: CreateApplicationProfile {
            name: app_name.clone(),
            description: Some("Test application for sandbox scan lifecycle demo".to_string()),
            business_criticality: BusinessCriticality::Medium,
            business_unit: None,
            business_owners: None,
            policies: None,
            teams: None,
            custom_fields: None,
            tags: None,
        },
    };

    let app_id = match client.create_application(&app_request).await {
        Ok(app) => {
            println!("✅ Application created successfully:");
            println!("   Application ID: {}", app.guid);
            println!(
                "   Application Name: {}",
                app.profile.as_ref().map(|p| &p.name).unwrap_or(&app_name)
            );
            app.guid
        }
        Err(e) => {
            eprintln!("❌ Failed to create application: {e}");
            println!("💡 Using example application ID for demonstration purposes");
            "123456".to_string() // Fallback to example ID
        }
    };

    // Step 2: Create a sandbox in the application
    println!("\n🧪 Step 2: Creating sandbox in application...");

    let sandbox_name = format!("Test Sandbox {timestamp}");
    let sandbox_request = CreateSandboxRequest {
        name: sandbox_name.clone(),
        description: Some("Test sandbox for lifecycle demo".to_string()),
        auto_recreate: Some(true),
        custom_fields: None,
        team_identifiers: None,
    };

    let sandbox_id = match sandbox_api.create_sandbox(&app_id, sandbox_request).await {
        Ok(sandbox) => {
            println!("✅ Sandbox created successfully:");
            println!("   Sandbox ID: {}", sandbox.guid);
            println!("   Sandbox Name: {}", sandbox.name);
            sandbox.guid
        }
        Err(e) => {
            eprintln!("❌ Failed to create sandbox: {e}");
            println!("💡 Using example sandbox ID for demonstration purposes");
            "789012".to_string() // Fallback to example ID
        }
    };

    // Step 3: Create a new scan in the sandbox
    println!("\n🔬 Step 3: Creating new scan in sandbox...");

    // Note: In the Veracode platform, scans are created implicitly when files are uploaded
    // and pre-scans are initiated. This step represents the conceptual scan creation.
    let scan_name = format!("Lifecycle Scan {timestamp}");
    println!("✅ Scan context prepared:");
    println!("   Scan Name: {scan_name}");
    println!("   Target Sandbox: {sandbox_id}");
    println!("   Target Application: {app_id}");

    // Check for sample file for uploading
    println!("\n📁 Step 4: Preparing application file for upload...");

    let possible_paths = vec![
        "examples/samples/vulnerable_test_app.tar.gz",
        "veracode-api/examples/samples/vulnerable_test_app.tar.gz",
        "samples/vulnerable_test_app.tar.gz",
        "test.jar", // Example placeholder file
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
            println!("⚠️  Sample file not found in any of these locations:");
            for path in &possible_paths {
                println!("   - {path}");
            }
            println!("\n💡 For a complete demonstration, you would:");
            println!(
                "   1. Package your application code into a supported format (.war, .jar, .zip, etc.)"
            );
            println!("   2. Upload it to the sandbox using the upload_file method");
            println!("   3. Begin pre-scan to analyze the uploaded files");
            println!("   4. Begin scan to perform static analysis");
            println!("\n🔄 Continuing with API method demonstrations using mock data...");

            // Demonstrate API methods even without actual file
            demonstrate_api_methods(&scan_api, &app_id, &sandbox_id).await?;
            return Ok(());
        }
    };

    // Step 5: Upload file to sandbox
    println!("\n📤 Step 5: Uploading file to sandbox...");

    let upload_request = UploadFileRequest {
        app_id: app_id.clone(),
        file_path: sample_file_path.to_string(),
        save_as: Some(format!(
            "{}-{}.tar.gz",
            scan_name.replace(" ", "_"),
            timestamp
        )),
        sandbox_id: Some(sandbox_id.clone()),
    };

    match scan_api.upload_file(&upload_request).await {
        Ok(uploaded_file) => {
            println!("✅ File uploaded successfully:");
            println!("   File ID: {}", uploaded_file.file_id);
            println!("   File Name: {}", uploaded_file.file_name);
            println!("   File Size: {} bytes", uploaded_file.file_size);
            println!("   Status: {}", uploaded_file.file_status);
            println!("   Uploaded: {}", uploaded_file.uploaded);
        }
        Err(ScanError::FileNotFound(path)) => {
            eprintln!("❌ File not found: {path}");
            return Ok(());
        }
        Err(ScanError::UploadFailed(msg)) => {
            eprintln!("❌ Upload failed: {msg}");
            println!("💡 This could be due to:");
            println!("   - Invalid application ID or sandbox ID");
            println!("   - Insufficient permissions for file upload");
            println!("   - Network connectivity issues");
            println!("   - Unsupported file format");
        }
        Err(ScanError::Unauthorized) => {
            eprintln!("❌ Unauthorized: Invalid API credentials");
            println!("💡 Check your VERACODE_API_ID and VERACODE_API_KEY environment variables");
        }
        Err(ScanError::SandboxNotFound) => {
            eprintln!("❌ Sandbox not found: {sandbox_id}");
            println!("💡 Make sure the sandbox exists and you have access to it");
        }
        Err(e) => {
            eprintln!("❌ Unexpected error during upload: {e}");
        }
    }

    // Step 6: Begin pre-scan
    println!("\n🔍 Step 6: Beginning pre-scan...");

    let prescan_request = BeginPreScanRequest {
        app_id: app_id.clone(),
        sandbox_id: Some(sandbox_id.clone()),
        auto_scan: Some(false),
        scan_all_nonfatal_top_level_modules: Some(true),
        include_new_modules: Some(false),
    };

    match scan_api.begin_prescan(&prescan_request).await {
        Ok(()) => {
            println!("✅ Pre-scan started successfully");

            // Step 7: Get pre-scan results
            println!("\n📋 Step 7: Getting pre-scan results...");

            match scan_api
                .get_prescan_results(&app_id, Some(&sandbox_id), None)
                .await
            {
                Ok(prescan_results) => {
                    println!("✅ Pre-scan results retrieved:");
                    println!("   Build ID: {}", prescan_results.build_id);
                    println!("   Status: {}", prescan_results.status);
                    println!("   Modules found: {}", prescan_results.modules.len());
                    println!("   Messages: {}", prescan_results.messages.len());

                    // Display modules
                    for (i, module) in prescan_results.modules.iter().enumerate() {
                        println!(
                            "   Module {}: {} ({})",
                            i + 1,
                            module.name,
                            module.module_type
                        );
                        println!(
                            "      Selected: {}, Fatal: {}",
                            module.selected, module.is_fatal
                        );
                    }

                    // Display messages
                    for (i, message) in prescan_results.messages.iter().enumerate() {
                        println!(
                            "   Message {}: [{}] {}",
                            i + 1,
                            message.severity,
                            message.text
                        );
                    }

                    // Step 8: Begin scan
                    println!("\n🚀 Step 8: Beginning static analysis scan...");

                    let scan_request = BeginScanRequest {
                        app_id: app_id.clone(),
                        sandbox_id: Some(sandbox_id.clone()),
                        modules: None, // Scan all modules
                        scan_all_top_level_modules: Some(true),
                        scan_all_nonfatal_top_level_modules: Some(true),
                        scan_previously_selected_modules: None,
                    };

                    match scan_api.begin_scan(&scan_request).await {
                        Ok(()) => {
                            println!("✅ Scan started successfully");

                            // Step 9: Monitor scan progress
                            println!("\n⏳ Step 9: Monitoring scan progress...");

                            match scan_api
                                .get_build_info(
                                    &app_id,
                                    Some(&prescan_results.build_id),
                                    Some(&sandbox_id),
                                )
                                .await
                            {
                                Ok(scan_info) => {
                                    println!("✅ Scan information retrieved:");
                                    println!("   Build ID: {}", scan_info.build_id);
                                    println!("   Status: {}", scan_info.status);
                                    println!("   Scan Type: {}", scan_info.scan_type);

                                    if let Some(progress) = scan_info.scan_progress_percentage {
                                        println!("   Progress: {progress}%");
                                    }

                                    if let Some(start_time) = scan_info.scan_start {
                                        println!("   Started: {start_time}");
                                    }

                                    if let Some(complete_time) = scan_info.scan_complete {
                                        println!("   Completed: {complete_time}");
                                    } else {
                                        println!("   Status: Scan in progress");
                                    }

                                    if let Some(loc) = scan_info.total_lines_of_code {
                                        println!("   Total Lines of Code: {loc}");
                                    }
                                }
                                Err(e) => {
                                    eprintln!("❌ Failed to get scan information: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to start scan: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to get prescan results: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to start pre-scan: {e}");
        }
    }

    // Step 10: Get file list
    println!("\n📄 Step 10: Getting uploaded file list...");

    match scan_api
        .get_file_list(&app_id, Some(&sandbox_id), None)
        .await
    {
        Ok(files) => {
            println!("✅ Found {} uploaded file(s):", files.len());
            for (i, file) in files.iter().enumerate() {
                println!("   {}. {}", i + 1, file.file_name);
                println!("      File ID: {}", file.file_id);
                println!("      Size: {} bytes", file.file_size);
                println!("      Status: {}", file.file_status);
                println!("      Uploaded: {}", file.uploaded);
                if let Some(md5) = &file.md5 {
                    println!("      MD5: {md5}");
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to get file list: {e}");
        }
    }

    println!("\n✅ Sandbox Scan lifecycle example completed!");

    // Demonstrate convenience methods
    println!("\n🎯 Demonstrating convenience methods...");

    match scan_api
        .upload_and_scan_sandbox(&app_id, &sandbox_id, sample_file_path)
        .await
    {
        Ok(scan_build_id) => {
            println!("✅ Complete workflow executed successfully:");
            println!("   Final scan build ID: {scan_build_id}");
        }
        Err(e) => {
            println!("⚠️  Complete workflow encountered an issue: {e}");
        }
    }

    // Wait a moment before deletion
    println!("\n⏳ Waiting 3 seconds before cleanup...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Cleanup steps - delete the created resources
    println!("\n🧹 Cleanup: Deleting created resources...");

    // Step 11: Delete the sandbox
    println!("\n🗑️  Step 11: Deleting sandbox...");
    match sandbox_api.delete_sandbox(&app_id, &sandbox_id).await {
        Ok(_) => {
            println!("✅ Sandbox deleted successfully");
        }
        Err(e) => {
            eprintln!("❌ Failed to delete sandbox: {e}");
            println!("💡 The sandbox may need to be manually deleted from the Veracode platform");
        }
    }

    // Step 12: Delete the application
    println!("\n🗑️  Step 12: Deleting application...");
    match client.delete_application(&app_id).await {
        Ok(_) => {
            println!("✅ Application deleted successfully");
        }
        Err(e) => {
            eprintln!("❌ Failed to delete application: {e}");
            println!(
                "💡 The application may need to be manually deleted from the Veracode platform"
            );
        }
    }

    println!("\n✅ Sandbox Scan lifecycle example completed with cleanup!");

    Ok(())
}

async fn demonstrate_api_methods(
    scan_api: &veracode_platform::ScanApi,
    app_id: &str,
    sandbox_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔧 Demonstrating API methods without file upload...\n");

    // Demonstrate get file list
    println!("📄 Getting file list for sandbox...");
    match scan_api.get_file_list(app_id, Some(sandbox_id), None).await {
        Ok(files) => {
            println!("✅ File list retrieved: {} files", files.len());
            for file in files {
                println!("   - {}", file.file_name);
            }
        }
        Err(e) => {
            println!("⚠️  Could not retrieve file list: {e}");
        }
    }

    // Demonstrate get build info
    println!("\n📊 Getting build information...");
    match scan_api
        .get_build_info(app_id, None, Some(sandbox_id))
        .await
    {
        Ok(scan_info) => {
            println!("✅ Build info retrieved:");
            println!("   Build ID: {}", scan_info.build_id);
            println!("   Status: {}", scan_info.status);
            println!("   Type: {}", scan_info.scan_type);
        }
        Err(e) => {
            println!("⚠️  Could not retrieve build info: {e}");
        }
    }

    // Demonstrate get pre-scan results
    println!("\n🔍 Getting pre-scan results...");
    match scan_api
        .get_prescan_results(app_id, Some(sandbox_id), None)
        .await
    {
        Ok(prescan_results) => {
            println!("✅ Pre-scan results retrieved:");
            println!("   Build ID: {}", prescan_results.build_id);
            println!("   Status: {}", prescan_results.status);
            println!("   Modules: {}", prescan_results.modules.len());
            println!("   Messages: {}", prescan_results.messages.len());
        }
        Err(e) => {
            println!("⚠️  Could not retrieve pre-scan results: {e}");
        }
    }

    println!("\n📚 Available Scan API methods:");
    println!("  • upload_file() - Upload files to application/sandbox");
    println!("  • upload_file_to_sandbox() - Convenience method for sandbox uploads");
    println!("  • upload_file_to_app() - Convenience method for application uploads");
    println!("  • begin_prescan() - Begin pre-scan analysis");
    println!("  • begin_sandbox_prescan() - Convenience method for sandbox pre-scan");
    println!("  • get_prescan_results() - Get pre-scan analysis results");
    println!("  • begin_scan() - Begin static analysis scan");
    println!("  • begin_sandbox_scan_all_modules() - Convenience method for full sandbox scan");
    println!("  • get_file_list() - Get list of uploaded files");
    println!("  • remove_file() - Remove uploaded files");
    println!("  • get_build_info() - Get build/scan information");
    println!("  • upload_and_scan_sandbox() - Complete workflow method");

    println!("\n💡 Usage Tips:");
    println!("  - Always upload files before beginning pre-scan");
    println!("  - Check pre-scan results before beginning full scan");
    println!("  - Use sandbox_id parameter to target sandbox scans");
    println!("  - Monitor scan progress using get_build_info()");
    println!("  - Remove unnecessary files to optimize scan performance");

    println!("\n⚙️  API Endpoints Used:");
    println!("  - /api/5.0/uploadfile.do - File uploads");
    println!("  - /api/5.0/beginprescan.do - Pre-scan initiation");
    println!("  - /api/5.0/getprescanresults.do - Pre-scan results");
    println!("  - /api/5.0/beginscan.do - Scan initiation");
    println!("  - /api/5.0/getfilelist.do - File listing");
    println!("  - /api/5.0/removefile.do - File removal");
    println!("  - /api/5.0/getbuildinfo.do - Build information");

    Ok(())
}

//! Build Lifecycle Example
//!
//! This example demonstrates the complete Veracode Build XML API functionality including:
//! - createbuild.do - Creating new builds
//! - updatebuild.do - Updating build information
//! - getbuildinfo.do - Retrieving build details
//! - getbuildlist.do - Listing all builds
//! - deletebuild.do - Deleting builds

use veracode_platform::{
    VeracodeConfig, VeracodeClient, VeracodeRegion,
    CreateBuildRequest, UpdateBuildRequest, DeleteBuildRequest,
    GetBuildInfoRequest, GetBuildListRequest,
    app::BusinessCriticality,
};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🏗️  Veracode Build API Lifecycle Example");
    println!("=========================================\n");

    // Check for required environment variables
    let api_id = env::var("VERACODE_API_ID")
        .expect("VERACODE_API_ID environment variable is required");
    let api_key = env::var("VERACODE_API_KEY")
        .expect("VERACODE_API_KEY environment variable is required");

    // Create configuration
    let config = VeracodeConfig::new(api_id, api_key)
        .with_region(VeracodeRegion::Commercial);

    println!("🔧 Creating Veracode client...");
    let client = VeracodeClient::new(config)?;
    let build_api = client.build_api();
    println!("   ✅ Client created successfully");
    println!("   🔗 Using XML API: analysiscenter.veracode.com");

    // Create a test application and sandbox for demonstration
    let test_app_name = "build-api-test";
    let test_sandbox_name = "build-api-test-sandbox";

    println!("\n📱 Setting up test application and sandbox...");
    let workflow = client.workflow();
    
    match workflow.ensure_app_and_sandbox(
        test_app_name,
        test_sandbox_name,
        BusinessCriticality::Low,
    ).await {
        Ok((app, sandbox, app_id, sandbox_id)) => {
            println!("   ✅ Test environment ready:");
            println!("      - App: {} (ID: {})", app.profile.as_ref().unwrap().name, app_id);
            println!("      - Sandbox: {} (ID: {})", sandbox.name, sandbox_id);

            // Example 1: Create builds
            println!("\n🏗️  Example 1: Creating Builds");
            println!("=============================");
            
            demonstrate_create_builds(&build_api, &app_id, &sandbox_id).await?;

            // Example 2: Get build information
            println!("\n📊 Example 2: Getting Build Information");
            println!("======================================");
            
            demonstrate_get_build_info(&build_api, &app_id, &sandbox_id).await?;

            // Example 3: List builds
            println!("\n📋 Example 3: Listing Builds");
            println!("===========================");
            
            demonstrate_list_builds(&build_api, &app_id, &sandbox_id).await?;

            // Example 4: Update builds
            println!("\n✏️  Example 4: Updating Builds");
            println!("=============================");
            
            demonstrate_update_builds(&build_api, &app_id, &sandbox_id).await?;

            // Example 5: Delete builds
            println!("\n🗑️  Example 5: Deleting Builds");
            println!("=============================");
            
            demonstrate_delete_builds(&build_api, &app_id, &sandbox_id).await?;

            // Example 6: Convenience methods
            println!("\n🛠️  Example 6: Convenience Methods");
            println!("=================================");
            
            demonstrate_convenience_methods(&build_api, &app_id, &sandbox_id).await?;

        }
        Err(e) => {
            println!("   ⚠️  Could not create test environment: {e}");
            println!("   💡 Demonstrating with mock data instead...");
            
            // Demonstrate API methods with mock data
            demonstrate_mock_scenarios(&build_api).await?;
        }
    }

    println!("\n✅ Build API lifecycle examples completed!");
    println!("\n📚 Available Build API Methods:");
    println!("===============================");
    println!("  🏗️  Create Operations:");
    println!("     • create_build() - Create build with full options");
    println!("     • create_simple_build() - Create build with minimal parameters");
    println!("     • create_sandbox_build() - Create build in sandbox");
    
    println!("\n  📊 Information Operations:");
    println!("     • get_build_info() - Get detailed build information");
    println!("     • get_app_build_info() - Get application build info");
    println!("     • get_sandbox_build_info() - Get sandbox build info");
    
    println!("\n  📋 List Operations:");
    println!("     • get_build_list() - Get build list with options");
    println!("     • get_app_builds() - Get all application builds");
    println!("     • get_sandbox_builds() - Get all sandbox builds");
    
    println!("\n  ✏️  Update Operations:");
    println!("     • update_build() - Update build with full options");
    
    println!("\n  🗑️  Delete Operations:");
    println!("     • delete_build() - Delete build with options");
    println!("     • delete_app_build() - Delete application build");
    println!("     • delete_sandbox_build() - Delete sandbox build");

    println!("\n🔍 Key Features:");
    println!("===============");
    println!("  ✅ Full XML API compatibility");
    println!("  ✅ Comprehensive build lifecycle management");
    println!("  ✅ Application and sandbox build support");
    println!("  ✅ Rich metadata handling (lifecycle stage, launch date, etc.)");
    println!("  ✅ Robust error handling and XML parsing");
    println!("  ✅ Regional endpoint support");

    println!("\n📋 XML API Endpoints Used:");
    println!("=========================");
    println!("  • api/5.0/createbuild.do - Build creation");
    println!("  • api/5.0/updatebuild.do - Build updates");
    println!("  • api/5.0/getbuildinfo.do - Build information");
    println!("  • api/5.0/getbuildlist.do - Build listings");
    println!("  • api/5.0/deletebuild.do - Build deletion");

    Ok(())
}

/// Demonstrate build creation functionality
async fn demonstrate_create_builds(
    build_api: &veracode_platform::BuildApi,
    app_id: &str,
    sandbox_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("   🏗️  Creating application build...");
    
    // Create a simple application build
    match build_api.create_simple_build(app_id, Some("1.0.0")).await {
        Ok(build) => {
            println!("   ✅ Application build created successfully:");
            println!("      - Build ID: {}", build.build_id);
            println!("      - Version: {}", build.version.unwrap_or("None".to_string()));
            println!("      - App ID: {}", build.app_id);
            if let Some(submitter) = build.submitter {
                println!("      - Submitter: {}", submitter);
            }
        }
        Err(e) => {
            println!("   ⚠️  Application build creation: {e}");
            println!("   💡 This might be expected if build already exists");
        }
    }

    println!("\n   🧪 Creating sandbox build...");
    
    // Create a sandbox build with more options
    let create_request = CreateBuildRequest {
        app_id: app_id.to_string(),
        version: Some("sandbox-1.0.0".to_string()),
        lifecycle_stage: Some("Development".to_string()),
        launch_date: Some("12/31/2024".to_string()),
        sandbox_id: Some(sandbox_id.to_string()),
    };

    match build_api.create_build(create_request).await {
        Ok(build) => {
            println!("   ✅ Sandbox build created successfully:");
            println!("      - Build ID: {}", build.build_id);
            println!("      - Version: {}", build.version.unwrap_or("None".to_string()));
            println!("      - Sandbox ID: {}", build.sandbox_id.unwrap_or("None".to_string()));
            println!("      - Lifecycle Stage: {}", build.lifecycle_stage.unwrap_or("None".to_string()));
        }
        Err(e) => {
            println!("   ⚠️  Sandbox build creation: {e}");
            println!("   💡 This might be expected if build already exists");
        }
    }

    println!("\n   🔧 Testing convenience method...");
    
    // Test convenience method
    match build_api.create_sandbox_build(app_id, sandbox_id, Some("convenience-1.0")).await {
        Ok(build) => {
            println!("   ✅ Convenience method build created:");
            println!("      - Build ID: {}", build.build_id);
            println!("      - Version: {}", build.version.unwrap_or("None".to_string()));
        }
        Err(e) => {
            println!("   ⚠️  Convenience method: {e}");
        }
    }

    Ok(())
}

/// Demonstrate getting build information
async fn demonstrate_get_build_info(
    build_api: &veracode_platform::BuildApi,
    app_id: &str,
    sandbox_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("   📊 Getting application build info...");
    
    // Get application build info
    match build_api.get_app_build_info(app_id).await {
        Ok(build) => {
            println!("   ✅ Application build info retrieved:");
            println!("      - Build ID: {}", build.build_id);
            println!("      - App ID: {}", build.app_id);
            if let Some(version) = build.version {
                println!("      - Version: {}", version);
            }
            if let Some(submitter) = build.submitter {
                println!("      - Submitter: {}", submitter);
            }
            if let Some(platform) = build.platform {
                println!("      - Platform: {}", platform);
            }
            if let Some(analysis_unit) = build.analysis_unit {
                println!("      - Analysis Unit: {}", analysis_unit);
            }
            if let Some(policy_compliance) = build.policy_compliance_status {
                println!("      - Policy Compliance: {}", policy_compliance);
            }
        }
        Err(e) => {
            println!("   ⚠️  Application build info: {e}");
        }
    }

    println!("\n   🧪 Getting sandbox build info...");
    
    // Get sandbox build info
    match build_api.get_sandbox_build_info(app_id, sandbox_id).await {
        Ok(build) => {
            println!("   ✅ Sandbox build info retrieved:");
            println!("      - Build ID: {}", build.build_id);
            println!("      - Sandbox ID: {}", build.sandbox_id.unwrap_or("None".to_string()));
            if let Some(version) = build.version {
                println!("      - Version: {}", version);
            }
            if let Some(lifecycle_stage) = build.lifecycle_stage {
                println!("      - Lifecycle Stage: {}", lifecycle_stage);
            }
            if let Some(launch_date) = build.launch_date {
                println!("      - Launch Date: {}", launch_date.format("%m/%d/%Y"));
            }
        }
        Err(e) => {
            println!("   ⚠️  Sandbox build info: {e}");
        }
    }

    println!("\n   🎯 Getting specific build info...");
    
    // Get specific build info with full request
    let get_request = GetBuildInfoRequest {
        app_id: app_id.to_string(),
        build_id: None, // Get most recent
        sandbox_id: Some(sandbox_id.to_string()),
    };

    match build_api.get_build_info(get_request).await {
        Ok(build) => {
            println!("   ✅ Specific build info retrieved:");
            println!("      - Build ID: {}", build.build_id);
            println!("      - Attributes count: {}", build.attributes.len());
            
            // Show additional attributes if any
            if !build.attributes.is_empty() {
                println!("      - Additional attributes:");
                for (key, value) in build.attributes.iter().take(3) {
                    println!("        • {}: {}", key, value);
                }
            }
        }
        Err(e) => {
            println!("   ⚠️  Specific build info: {e}");
        }
    }

    Ok(())
}

/// Demonstrate listing builds
async fn demonstrate_list_builds(
    build_api: &veracode_platform::BuildApi,
    app_id: &str,
    sandbox_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("   📋 Listing application builds...");
    
    // List application builds
    match build_api.get_app_builds(app_id).await {
        Ok(build_list) => {
            println!("   ✅ Application builds retrieved:");
            println!("      - Account ID: {}", build_list.account_id.unwrap_or("None".to_string()));
            println!("      - App ID: {}", build_list.app_id);
            println!("      - App Name: {}", build_list.app_name.unwrap_or("None".to_string()));
            println!("      - Total builds: {}", build_list.builds.len());
            
            // Show first few builds
            for (i, build) in build_list.builds.iter().take(3).enumerate() {
                println!("      Build {}:", i + 1);
                println!("        - Build ID: {}", build.build_id);
                if let Some(version) = &build.version {
                    println!("        - Version: {}", version);
                }
                if let Some(lifecycle_stage) = &build.lifecycle_stage {
                    println!("        - Lifecycle: {}", lifecycle_stage);
                }
            }
        }
        Err(e) => {
            println!("   ⚠️  Application builds list: {e}");
        }
    }

    println!("\n   🧪 Listing sandbox builds...");
    
    // List sandbox builds
    match build_api.get_sandbox_builds(app_id, sandbox_id).await {
        Ok(build_list) => {
            println!("   ✅ Sandbox builds retrieved:");
            println!("      - App ID: {}", build_list.app_id);
            println!("      - Total sandbox builds: {}", build_list.builds.len());
            
            // Show sandbox-specific builds
            for (i, build) in build_list.builds.iter().take(3).enumerate() {
                if build.sandbox_id.is_some() {
                    println!("      Sandbox Build {}:", i + 1);
                    println!("        - Build ID: {}", build.build_id);
                    println!("        - Sandbox ID: {}", build.sandbox_id.as_ref().unwrap());
                    if let Some(version) = &build.version {
                        println!("        - Version: {}", version);
                    }
                }
            }
        }
        Err(e) => {
            println!("   ⚠️  Sandbox builds list: {e}");
        }
    }

    println!("\n   🎯 Custom build list request...");
    
    // Custom build list request
    let list_request = GetBuildListRequest {
        app_id: app_id.to_string(),
        sandbox_id: None, // Get all builds
    };

    match build_api.get_build_list(list_request).await {
        Ok(build_list) => {
            println!("   ✅ Custom build list retrieved:");
            println!("      - Total builds (all): {}", build_list.builds.len());
            
            // Categorize builds
            let app_builds = build_list.builds.iter().filter(|b| b.sandbox_id.is_none()).count();
            let sandbox_builds = build_list.builds.iter().filter(|b| b.sandbox_id.is_some()).count();
            
            println!("      - Application builds: {}", app_builds);
            println!("      - Sandbox builds: {}", sandbox_builds);
        }
        Err(e) => {
            println!("   ⚠️  Custom build list: {e}");
        }
    }

    Ok(())
}

/// Demonstrate updating builds
async fn demonstrate_update_builds(
    build_api: &veracode_platform::BuildApi,
    app_id: &str,
    sandbox_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("   ✏️  Updating application build...");
    
    // Update application build
    let update_request = UpdateBuildRequest {
        app_id: app_id.to_string(),
        build_id: None, // Update most recent
        version: Some("1.1.0-updated".to_string()),
        lifecycle_stage: Some("QA".to_string()),
        launch_date: Some("01/15/2025".to_string()),
        sandbox_id: None,
    };

    match build_api.update_build(update_request).await {
        Ok(build) => {
            println!("   ✅ Application build updated successfully:");
            println!("      - Build ID: {}", build.build_id);
            println!("      - New Version: {}", build.version.unwrap_or("None".to_string()));
            println!("      - New Lifecycle: {}", build.lifecycle_stage.unwrap_or("None".to_string()));
            if let Some(launch_date) = build.launch_date {
                println!("      - New Launch Date: {}", launch_date.format("%m/%d/%Y"));
            }
        }
        Err(e) => {
            println!("   ⚠️  Application build update: {e}");
            println!("   💡 This might be expected if no build exists to update");
        }
    }

    println!("\n   🧪 Updating sandbox build...");
    
    // Update sandbox build
    let sandbox_update_request = UpdateBuildRequest {
        app_id: app_id.to_string(),
        build_id: None,
        version: Some("sandbox-1.1.0-updated".to_string()),
        lifecycle_stage: Some("Testing".to_string()),
        launch_date: None,
        sandbox_id: Some(sandbox_id.to_string()),
    };

    match build_api.update_build(sandbox_update_request).await {
        Ok(build) => {
            println!("   ✅ Sandbox build updated successfully:");
            println!("      - Build ID: {}", build.build_id);
            println!("      - New Version: {}", build.version.unwrap_or("None".to_string()));
            println!("      - Sandbox ID: {}", build.sandbox_id.unwrap_or("None".to_string()));
            println!("      - New Lifecycle: {}", build.lifecycle_stage.unwrap_or("None".to_string()));
        }
        Err(e) => {
            println!("   ⚠️  Sandbox build update: {e}");
            println!("   💡 This might be expected if no sandbox build exists to update");
        }
    }

    Ok(())
}

/// Demonstrate deleting builds
async fn demonstrate_delete_builds(
    build_api: &veracode_platform::BuildApi,
    app_id: &str,
    sandbox_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("   🗑️  Deleting sandbox build...");
    
    // Delete sandbox build first (safer)
    match build_api.delete_sandbox_build(app_id, sandbox_id).await {
        Ok(result) => {
            println!("   ✅ Sandbox build deleted successfully:");
            println!("      - Result: {}", result.result);
        }
        Err(e) => {
            println!("   ⚠️  Sandbox build deletion: {e}");
            println!("   💡 This might be expected if no sandbox build exists");
        }
    }

    println!("\n   🗑️  Testing application build deletion...");
    
    // Test application build deletion (be careful in real scenarios)
    let delete_request = DeleteBuildRequest {
        app_id: app_id.to_string(),
        sandbox_id: None,
    };

    match build_api.delete_build(delete_request).await {
        Ok(result) => {
            println!("   ✅ Application build deletion result:");
            println!("      - Result: {}", result.result);
        }
        Err(e) => {
            println!("   ⚠️  Application build deletion: {e}");
            println!("   💡 This might be expected if no application build exists");
        }
    }

    Ok(())
}

/// Demonstrate convenience methods
async fn demonstrate_convenience_methods(
    build_api: &veracode_platform::BuildApi,
    app_id: &str,
    sandbox_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("   🛠️  Testing convenience methods:");
    
    println!("      📦 Simple build creation...");
    match build_api.create_simple_build(app_id, Some("convenience-test")).await {
        Ok(_) => println!("         ✅ Simple build creation works"),
        Err(e) => println!("         ⚠️  Simple build creation: {e}"),
    }
    
    println!("      📦 Sandbox build creation...");
    match build_api.create_sandbox_build(app_id, sandbox_id, Some("sandbox-convenience")).await {
        Ok(_) => println!("         ✅ Sandbox build creation works"),
        Err(e) => println!("         ⚠️  Sandbox build creation: {e}"),
    }
    
    println!("      📊 App build info retrieval...");
    match build_api.get_app_build_info(app_id).await {
        Ok(_) => println!("         ✅ App build info retrieval works"),
        Err(e) => println!("         ⚠️  App build info retrieval: {e}"),
    }
    
    println!("      📊 Sandbox build info retrieval...");
    match build_api.get_sandbox_build_info(app_id, sandbox_id).await {
        Ok(_) => println!("         ✅ Sandbox build info retrieval works"),
        Err(e) => println!("         ⚠️  Sandbox build info retrieval: {e}"),
    }
    
    println!("      📋 App builds listing...");
    match build_api.get_app_builds(app_id).await {
        Ok(builds) => println!("         ✅ App builds listing works ({} builds)", builds.builds.len()),
        Err(e) => println!("         ⚠️  App builds listing: {e}"),
    }
    
    println!("      📋 Sandbox builds listing...");
    match build_api.get_sandbox_builds(app_id, sandbox_id).await {
        Ok(builds) => println!("         ✅ Sandbox builds listing works ({} builds)", builds.builds.len()),
        Err(e) => println!("         ⚠️  Sandbox builds listing: {e}"),
    }

    Ok(())
}

/// Demonstrate API capabilities when environment setup fails
async fn demonstrate_mock_scenarios(
    _build_api: &veracode_platform::BuildApi,
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("   🎭 Mock scenarios (API structure validation):");
    
    // Show that all the methods exist and have correct signatures
    println!("      ✅ create_build() - Available");
    println!("      ✅ create_simple_build() - Available");
    println!("      ✅ create_sandbox_build() - Available");
    println!("      ✅ update_build() - Available");
    println!("      ✅ delete_build() - Available");
    println!("      ✅ delete_app_build() - Available");
    println!("      ✅ delete_sandbox_build() - Available");
    println!("      ✅ get_build_info() - Available");
    println!("      ✅ get_app_build_info() - Available");
    println!("      ✅ get_sandbox_build_info() - Available");
    println!("      ✅ get_build_list() - Available");
    println!("      ✅ get_app_builds() - Available");
    println!("      ✅ get_sandbox_builds() - Available");
    
    println!("\n   📋 XML API Capabilities:");
    println!("      • Full buildinfo XML schema support");
    println!("      • Comprehensive build metadata parsing");
    println!("      • Policy compliance status tracking");
    println!("      • Lifecycle stage management");
    println!("      • Launch date handling");
    println!("      • Sandbox and application build separation");
    println!("      • Rich attribute collection");

    println!("\n   🔍 Key Implementation Features:");
    println!("      • Native XML parsing with quick-xml");
    println!("      • Comprehensive error handling");
    println!("      • HMAC authentication support");
    println!("      • Regional endpoint compatibility");
    println!("      • Type-safe request/response handling");
    println!("      • Convenient method shortcuts");

    Ok(())
}
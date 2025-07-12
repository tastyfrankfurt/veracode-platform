use veracode_platform::{VeracodeConfig, VeracodeClient, VeracodeError};
use veracode_platform::sandbox::{SandboxApi, CreateSandboxRequest, SandboxError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VeracodeConfig::new(
        std::env::var("VERACODE_API_ID")
            .expect("VERACODE_API_ID environment variable required"),
        std::env::var("VERACODE_API_KEY")
            .expect("VERACODE_API_KEY environment variable required"),
    );
    let search_name = std::env::var("APP_NAME")
        .unwrap_or_else(|_| {
            println!("💡 Tip: Set APP_NAME environment variable to search for specific applications");
            "Test Application".to_string()
        });
    
    let client = VeracodeClient::new(config)?;
    let sandbox_api = SandboxApi::new(&client);
    
    let application_guid = search_applications(&client,&search_name).await?;  
    
    println!("🏗️  Creating sandbox examples...\n");
    
    // Example 1: Create a simple sandbox
    println!("📦 Creating a simple sandbox...");
    let simple_sandbox = match sandbox_api.create_simple_sandbox(
        &application_guid,
        "my-dev-sandbox"
    ).await {
        Ok(sandbox) => {
            println!("✅ Created simple sandbox: {} ({})", sandbox.name, sandbox.guid);
            sandbox
        }
        Err(SandboxError::AlreadyExists(_)) => {
            println!("⚠️  Sandbox 'my-dev-sandbox' already exists, retrieving it...");
            sandbox_api.get_sandbox_by_name(&application_guid, "my-dev-sandbox").await?
                .expect("Sandbox should exist")
        }
        Err(e) => return Err(e.into()),
    };
    
    // Example 2: Create a sandbox with description and auto-recreate
    println!("\n📦 Creating an auto-recreate sandbox...");
    let auto_recreate_sandbox = match sandbox_api.create_auto_recreate_sandbox(
        &application_guid,
        "auto-recreate-sandbox",
        Some("This sandbox will auto-recreate after promotion".to_string())
    ).await {
        Ok(sandbox) => {
            println!("✅ Created auto-recreate sandbox: {} ({})", sandbox.name, sandbox.guid);
            sandbox
        }
        Err(SandboxError::AlreadyExists(_)) => {
            println!("⚠️  Sandbox 'auto-recreate-sandbox' already exists, retrieving it...");
            sandbox_api.get_sandbox_by_name(&application_guid, "auto-recreate-sandbox").await?
                .expect("Sandbox should exist")
        }
        Err(e) => return Err(e.into()),
    };
    
    // Example 3: Create a sandbox with custom configuration (without unsupported fields)
    println!("\n📦 Creating a sandbox with custom configuration...");
    
    let custom_request = CreateSandboxRequest {
        name: "feature-xyz-sandbox".to_string(),
        description: Some("Sandbox for developing feature XYZ".to_string()),
        auto_recreate: Some(true),
        custom_fields: None, // Not supported by API
        team_identifiers: None, // Not supported by API or requires different format
    };
    
    let custom_sandbox = match sandbox_api.create_sandbox(&application_guid, custom_request).await {
        Ok(sandbox) => {
            println!("✅ Created custom sandbox: {} ({})", sandbox.name, sandbox.guid);
            sandbox
        }
        Err(SandboxError::AlreadyExists(_)) => {
            println!("⚠️  Sandbox 'feature-xyz-sandbox' already exists, retrieving it...");
            sandbox_api.get_sandbox_by_name(&application_guid, "feature-xyz-sandbox").await?
                .expect("Sandbox should exist")
        }
        Err(e) => return Err(e.into()),
    };
    
    // Example 4: List all sandboxes to verify creation
    println!("\n📋 Listing all sandboxes...");
    let all_sandboxes = sandbox_api.list_sandboxes(&application_guid, None).await?;
    println!("Found {} sandboxes:", all_sandboxes.len());
    for sandbox in &all_sandboxes {
        println!("  - {} ({}) - Created: {}", 
                 sandbox.name, 
                 sandbox.guid, 
                 sandbox.created.format("%Y-%m-%d %H:%M:%S"));
    }
    
    // Example 5: Check if a sandbox exists
    println!("\n🔍 Checking if sandbox exists...");
    let exists = sandbox_api.sandbox_exists(&application_guid, &simple_sandbox.guid).await?;
    println!("Simple sandbox exists: {exists}");
    
    // Example 6: Get sandbox by name
    println!("\n🔍 Finding sandbox by name...");
    match sandbox_api.get_sandbox_by_name(&application_guid, "my-dev-sandbox").await? {
        Some(found_sandbox) => {
            println!("Found sandbox: {} ({})", found_sandbox.name, found_sandbox.guid);
        }
        None => {
            println!("Sandbox not found");
        }
    }
    
    // Example 7: Update sandbox name
    println!("\n✏️  Updating sandbox name...");
    let updated_sandbox = sandbox_api.update_sandbox_name(
        &application_guid,
        &simple_sandbox.guid,
        "my-renamed-dev-sandbox"
    ).await?;
    println!("✅ Updated sandbox name: {} -> {}", 
             simple_sandbox.name, 
             updated_sandbox.name);
    
    // Wait a bit before cleanup (optional)
    println!("\n⏳ Waiting 5 seconds before cleanup...");
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    
    // Example 8: Delete sandboxes
    println!("\n🗑️  Deleting sandboxes...");
    
    // Delete the simple sandbox (now renamed)
    match sandbox_api.delete_sandbox(&application_guid, &simple_sandbox.guid).await {
        Ok(_) => println!("✅ Deleted simple sandbox"),
        Err(SandboxError::NotFound) => println!("⚠️  Simple sandbox not found (already deleted?)"),
        Err(e) => println!("❌ Failed to delete simple sandbox: {e}"),
    }
    
    // Delete the auto-recreate sandbox
    match sandbox_api.delete_sandbox(&application_guid, &auto_recreate_sandbox.guid).await {
        Ok(_) => println!("✅ Deleted auto-recreate sandbox"),
        Err(SandboxError::NotFound) => println!("⚠️  Auto-recreate sandbox not found (already deleted?)"),
        Err(e) => println!("❌ Failed to delete auto-recreate sandbox: {e}"),
    }
    
    // Delete the custom sandbox
    match sandbox_api.delete_sandbox(&application_guid, &custom_sandbox.guid).await {
        Ok(_) => println!("✅ Deleted custom sandbox"),
        Err(SandboxError::NotFound) => println!("⚠️  Custom sandbox not found (already deleted?)"),
        Err(e) => println!("❌ Failed to delete custom sandbox: {e}"),
    }
    
    // Example 9: Verify deletion
    println!("\n🔍 Verifying sandboxes were deleted...");
    let remaining_sandboxes = sandbox_api.list_sandboxes(&application_guid, None).await?;
    println!("Remaining sandboxes: {}", remaining_sandboxes.len());
    
    println!("\n✅ Sandbox lifecycle example completed!");
    
    Ok(())
}

async fn search_applications(
    client: &VeracodeClient, 
    search_name: &str
) -> Result<String, VeracodeError> {
    println!("🔍 Searching for applications containing '{search_name}'...");

    // Search for applications
    let matching_apps = client.search_applications_by_name(search_name).await?;

    let app_found = match matching_apps.first() {
        Some(app) => app,
        None => {
            println!("❌ No applications found matching '{search_name}'");
            return Err(VeracodeError::NotFound("No applications found".to_string()));
        }
    };
    Ok(app_found.guid.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_sandbox_creation_validation() {
        // This test doesn't make actual API calls
        // It just tests the validation logic
        
        let config = VeracodeConfig::new(
            "test-api-id".to_string(),
            "test-api-key".to_string(),
        );
        
        let client = VeracodeClient::new(config).unwrap();
        let sandbox_api = SandboxApi::new(&client);
        
        // Test creating a request with invalid name
        let invalid_request = CreateSandboxRequest {
            name: "".to_string(), // Empty name should fail validation
            description: None,
            auto_recreate: None,
            custom_fields: None,
            team_identifiers: None,
        };
        
        // This would fail validation before making the API call
        let result = sandbox_api.create_sandbox("dummy-guid", invalid_request).await;
        assert!(result.is_err());
        
        if let Err(SandboxError::InvalidInput(_)) = result {
            // Expected error type
        } else {
            panic!("Expected InvalidInput error");
        }
    }
}
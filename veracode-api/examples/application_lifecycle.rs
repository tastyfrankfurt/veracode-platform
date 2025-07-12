use veracode_platform::{
    VeracodeConfig, VeracodeClient, VeracodeError,
    app::{
        CreateApplicationRequest, CreateApplicationProfile, BusinessCriticality,
        UpdateApplicationRequest, UpdateApplicationProfile
    }
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VeracodeConfig::new(
        std::env::var("VERACODE_API_ID")
            .expect("VERACODE_API_ID environment variable required"),
        std::env::var("VERACODE_API_KEY")
            .expect("VERACODE_API_KEY environment variable required"),
    );
    
    let client = VeracodeClient::new(config)?;
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    println!("🏗️  Application Lifecycle Example\n");
    
    // Example 1: Create a new application
    println!("📦 Creating a new application...");
    let app_name = format!("Lifecycle Test App {timestamp}");
    
    let create_request = CreateApplicationRequest {
        profile: CreateApplicationProfile {
            name: app_name.clone(),
            description: Some("A test application for lifecycle demonstration".to_string()),
            business_unit: None,
            business_criticality: BusinessCriticality::VeryHigh,
            business_owners: None,
            policies: None,
            teams: None,
            tags: Some("test,lifecycle,rust-api".to_string()),
            custom_fields: None,
        },
    };

    let created_app = match client.create_application(create_request).await {
        Ok(app) => {
            println!("✅ Created application: {} ({})", 
                     app.profile.as_ref().unwrap().name, 
                     app.guid);
            app
        }
        Err(e) => {
            eprintln!("❌ Failed to create application: {e}");
            return Err(e.into());
        }
    };
    
    // Example 2: Get/List applications to verify creation
    println!("\n📋 Listing applications to verify creation...");
    let search_results = client.search_applications_by_name(&app_name).await?;
    
    if let Some(found_app) = search_results.first() {
        println!("✅ Found created application: {} ({})", 
                 found_app.profile.as_ref().unwrap().name, 
                 found_app.guid);
    } else {
        println!("⚠️  Created application not found in search results");
    }
    
    // Example 3: Update the application
    println!("\n✏️  Updating application...");
    let update_request = UpdateApplicationRequest {
        profile: UpdateApplicationProfile {
            name: Some(format!("{app_name} - Updated")),
            description: Some("Updated description for lifecycle demonstration".to_string()),
            business_unit: None,
            business_criticality: BusinessCriticality::High,
            business_owners: None,
            policies: None,
            teams: None,
            tags: Some("test,lifecycle,rust-api,updated".to_string()),
            custom_fields: None,
        },
    };

    let updated_app = match client.update_application(&created_app.guid, update_request).await {
        Ok(app) => {
            println!("✅ Updated application: {} ({})", 
                     app.profile.as_ref().unwrap().name, 
                     app.guid);
            app
        }
        Err(e) => {
            eprintln!("❌ Failed to update application: {e}");
            println!("🗑️  Cleaning up created application...");
            let _ = client.delete_application(&created_app.guid).await;
            return Err(e.into());
        }
    };
    
    // Example 4: Get the updated application to verify changes
    println!("\n🔍 Retrieving updated application to verify changes...");
    match client.get_application(&updated_app.guid).await {
        Ok(retrieved_app) => {
            let profile = retrieved_app.profile.as_ref().unwrap();
            println!("✅ Retrieved application details:");
            println!("   Name: {}", profile.name);
            println!("   Description: {}", profile.description.as_ref().unwrap_or(&"None".to_string()));
            println!("   Business Criticality: {:?}", profile.business_criticality);
            println!("   Tags: {}", profile.tags.as_ref().unwrap_or(&"None".to_string()));
        }
        Err(e) => {
            eprintln!("❌ Failed to retrieve application: {e}");
        }
    }
    
    // Example 5: List all applications (with pagination)
    println!("\n📋 Listing all applications (first page)...");
    match client.get_applications(None).await {
        Ok(apps_response) => {
            if let Some(page) = &apps_response.page {
                if let Some(total) = page.total_elements {
                    println!("✅ Found {total} total applications");
                } else {
                    println!("✅ Found applications (total count not available)");
                }
            }
            
            if let Some(embedded) = &apps_response.embedded {
                println!("   Showing {} applications on this page", embedded.applications.len());
                
                // Show first few applications
                for (i, app) in embedded.applications.iter().take(3).enumerate() {
                    if let Some(profile) = &app.profile {
                        println!("   {}. {} ({})", i + 1, profile.name, app.guid);
                    } else {
                        println!("   {}. [No profile] ({})", i + 1, app.guid);
                    }
                }
                
                if embedded.applications.len() > 3 {
                    println!("   ... and {} more", embedded.applications.len() - 3);
                }
            } else {
                println!("   No applications found");
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to list applications: {e}");
        }
    }
    
    // Wait a moment before deletion
    println!("\n⏳ Waiting 3 seconds before cleanup...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    
    // Example 6: Delete the application
    println!("\n🗑️  Deleting the test application...");
    match client.delete_application(&updated_app.guid).await {
        Ok(_) => {
            println!("✅ Successfully deleted application: {}", updated_app.guid);
        }
        Err(e) => {
            eprintln!("❌ Failed to delete application: {e}");
            eprintln!("   You may need to manually delete: {}", updated_app.guid);
        }
    }
    
    // Example 7: Verify deletion
    println!("\n🔍 Verifying application deletion...");
    match client.get_application(&updated_app.guid).await {
        Ok(_) => {
            println!("⚠️  Application still exists after deletion attempt");
        }
        Err(VeracodeError::InvalidResponse(msg)) if msg.contains("404") => {
            println!("✅ Application successfully deleted (404 Not Found)");
        }
        Err(e) => {
            println!("⚠️  Error checking deletion status: {e}");
        }
    }
    
    println!("\n✅ Application lifecycle example completed!");
    println!("\nThis example demonstrated:");
    println!("  ✓ Creating a new application");
    println!("  ✓ Searching for applications");
    println!("  ✓ Updating an application");
    println!("  ✓ Retrieving application details");
    println!("  ✓ Listing all applications");
    println!("  ✓ Deleting an application");
    println!("  ✓ Verifying deletion");
    
    Ok(())
}
//! Example demonstrating how to look up teams by name and use them for application creation
//!
//! This example shows:
//! 1. How to find a team by name using the new get_team_by_name() method
//! 2. How to get just the team GUID using get_team_guid_by_name()  
//! 3. How to use the team GUID when creating applications

use veracode_platform::{
    VeracodeClient, VeracodeConfig, VeracodeRegion,
    app::{
        BusinessCriticality, CreateApplicationProfile, CreateApplicationRequest, Team as AppTeam,
    },
    validation::{AppName, Description},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging (optional)
    // env_logger::init();

    // Create configuration
    let config =
        VeracodeConfig::new("your_api_id", "your_api_key").with_region(VeracodeRegion::Commercial);

    let client = VeracodeClient::new(config)?;
    let identity_api = client.identity_api();

    println!("🔍 Looking up team by name...");

    // Example 1: Get full team information
    let team_name = "Security Team"; // Replace with actual team name
    match identity_api.get_team_by_name(team_name).await {
        Ok(Some(team)) => {
            println!("✅ Found team: {} (ID: {})", team.team_name, team.team_id);
            if let Some(description) = &team.team_description {
                println!("   Description: {}", description);
            }
        }
        Ok(None) => {
            println!("❌ Team '{}' not found", team_name);
        }
        Err(e) => {
            eprintln!("❌ Error looking up team: {}", e);
        }
    }

    println!("\n🎯 Getting team GUID for application creation...");

    // Example 2: Get just the team GUID (convenience method)
    match identity_api.get_team_guid_by_name(team_name).await {
        Ok(Some(team_guid)) => {
            println!("✅ Team GUID: {}", team_guid);

            // Example 3: Use the team GUID to create an application
            println!("\n🏗️  Creating application with team assignment...");

            let teams = vec![AppTeam {
                guid: Some(team_guid),
                team_id: None,
                team_name: None,
                team_legacy_id: None,
            }];

            let _create_request = CreateApplicationRequest {
                profile: CreateApplicationProfile {
                    name: AppName::new("Example App with Team")?,
                    business_criticality: BusinessCriticality::Medium,
                    description: Some(Description::new(
                        "Application created with team assignment",
                    )?),
                    business_unit: None,
                    business_owners: None,
                    policies: None,
                    teams: Some(teams),
                    tags: None,
                    custom_fields: None,
                    custom_kms_alias: None,
                    repo_url: None,
                },
            };

            // Note: Uncomment to actually create the application
            // match client.create_application(&create_request).await {
            //     Ok(app) => println!("✅ Created application: {} (GUID: {})",
            //                        app.profile.as_ref().map(|p| &p.name).unwrap_or(&"Unknown".to_string()),
            //                        app.guid),
            //     Err(e) => eprintln!("❌ Error creating application: {}", e),
            // }
            println!("   (Application creation commented out - uncomment to test)");
        }
        Ok(None) => {
            println!("❌ Team '{}' not found", team_name);
        }
        Err(e) => {
            eprintln!("❌ Error getting team GUID: {}", e);
        }
    }

    println!("\n🎉 Team lookup example completed!");
    Ok(())
}

use veracode_platform::{
    VeracodeClient, VeracodeConfig,
    identity::{
        CreateApiCredentialRequest, CreateTeamRequest, CreateUserRequest, IdentityError,
        UpdateUserRequest, UserQuery, UserType,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VeracodeConfig::new(
        &std::env::var("VERACODE_API_ID").expect("VERACODE_API_ID environment variable required"),
        &std::env::var("VERACODE_API_KEY").expect("VERACODE_API_KEY environment variable required"),
    );

    let client = VeracodeClient::new(config)?;
    let identity_api = client.identity_api();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    println!("🏗️  Identity Management Lifecycle Example\n");

    // Example 1: List all roles to understand available permissions
    println!("📋 Listing all available roles...");
    let available_roles = match identity_api.list_roles().await {
        Ok(roles) => {
            println!("✅ Found {} roles:", roles.len());
            for (i, role) in roles.iter().take(5).enumerate() {
                println!("   {}. {} ({})", i + 1, role.role_name, role.role_id);
                if let Some(desc) = &role.role_description {
                    println!("      Description: {desc}");
                }
            }
            if roles.len() > 5 {
                println!("   ... and {} more roles", roles.len() - 5);
            }
            roles
        }
        Err(e) => {
            eprintln!("❌ Failed to list roles: {e}");
            Vec::new()
        }
    };

    // Example 2: List existing teams
    println!("\n📋 Listing existing teams...");
    match identity_api.list_teams().await {
        Ok(teams) => {
            println!("✅ Found {} teams:", teams.len());
            for (i, team) in teams.iter().take(3).enumerate() {
                println!("   {}. {} ({})", i + 1, team.team_name, team.team_id);
                if let Some(desc) = &team.team_description {
                    println!("      Description: {desc}");
                }
            }
            if teams.len() > 3 {
                println!("   ... and {} more teams", teams.len() - 3);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to list teams: {e}");
        }
    }

    // Example 3: Create a new team
    println!("\n📦 Creating a new team...");
    let team_name = format!("Test Team {timestamp}");

    let team_request = CreateTeamRequest {
        team_name: team_name.clone(),
        team_description: Some("A test team created for demonstration purposes".to_string()),
        business_unit_id: None,
        user_ids: None,
    };

    let created_team = match identity_api.create_team(team_request).await {
        Ok(team) => {
            println!("✅ Created team: {} ({})", team.team_name, team.team_id);
            Some(team)
        }
        Err(IdentityError::TeamAlreadyExists(_)) => {
            println!("⚠️  Team already exists, continuing with example...");
            None
        }
        Err(IdentityError::PermissionDenied(msg)) => {
            println!("⚠️  Permission denied to create team: {msg}");
            println!("   This is expected if your API credentials don't have admin permissions");
            None
        }
        Err(e) => {
            eprintln!("❌ Failed to create team: {e}");
            None
        }
    };

    // Example 4: Create a new user
    println!("\n👤 Creating a new user...");
    let user_email = format!("testuser{timestamp}@example.com");

    let username = format!("testuser{timestamp}");

    // Find the submitter role specifically (human-only role)
    let user_role_ids = if !available_roles.is_empty() {
        // Look specifically for submitter role by description (with debug info)
        println!(
            "🔍 Searching for Submitter role in {} available roles...",
            available_roles.len()
        );

        // First, let's specifically look for extsubmitter
        if let Some(extsubmitter_role) = available_roles
            .iter()
            .find(|r| r.role_name == "extsubmitter")
        {
            println!(
                "📝 Found extsubmitter role for test user: {} ({})",
                extsubmitter_role.role_name,
                extsubmitter_role
                    .role_description
                    .as_ref()
                    .unwrap_or(&"No description".to_string())
            );
            Some(vec![extsubmitter_role.role_id.clone()])
        } else if let Some(submitter_role) = available_roles.iter().find(|r| {
            r.role_description
                .as_ref()
                .is_some_and(|desc| desc.trim() == "Submitter")
        }) {
            println!(
                "📝 Found submitter role for test user: {} ({})",
                submitter_role.role_name,
                submitter_role
                    .role_description
                    .as_ref()
                    .unwrap_or(&"No description".to_string())
            );
            Some(vec![submitter_role.role_id.clone()])
        } else {
            // Debug: show first few role descriptions to help troubleshoot
            println!(
                "⚠️  Neither extsubmitter nor Submitter role found. First 25 role descriptions:"
            );
            for (i, role) in available_roles.iter().take(25).enumerate() {
                println!(
                    "   {}. {} - Description: '{}'",
                    i + 1,
                    role.role_name,
                    role.role_description
                        .as_ref()
                        .unwrap_or(&"None".to_string())
                );
            }
            println!("⚠️  Using default role assignment.");
            None
        }
    } else {
        None
    };

    let user_request = CreateUserRequest {
        email_address: user_email.clone(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        user_name: Some(username),
        user_type: Some(UserType::Human),
        send_email_invitation: Some(false), // Don't send real emails in demo
        role_ids: user_role_ids.clone(),    // Use submitter role specifically
        team_ids: created_team.as_ref().map(|t| vec![t.team_id.clone()]),
        permissions: None, // Will use default permissions for human users
    };

    let created_user = match identity_api.create_user(user_request).await {
        Ok(user) => {
            println!(
                "✅ Created user: {} {} ({})",
                user.first_name, user.last_name, user.user_id
            );
            println!("   Email: {}", user.email_address);
            println!("   Username: {}", user.user_name);
            Some(user)
        }
        Err(IdentityError::UserAlreadyExists(_)) => {
            println!("⚠️  User already exists, continuing with example...");
            None
        }
        Err(IdentityError::PermissionDenied(msg)) => {
            println!("⚠️  Permission denied to create user: {msg}");
            println!("   This is expected if your API credentials don't have admin permissions");
            None
        }
        Err(e) => {
            eprintln!("❌ Failed to create user: {e}");
            None
        }
    };

    // Example 4b: Create a Security Lead user (can work without team assignment) - DISABLED
    // println!("\n👤 Creating a Security Lead user (ignore team restrictions)...");
    // let admin_user_email = format!("SecurityLead{}@example.com", timestamp);
    // let admin_username = format!("SecurityLead{}", timestamp);
    //
    // // Find the Security Lead role which has ignore_team_restrictions: true
    // let admin_role_ids = if !available_roles.is_empty() {
    //     // Look specifically for the Security Lead role
    //     if let Some(securitylead_role) = available_roles.iter().find(|r|
    //         r.role_name == "extseclead" ||
    //         r.role_description.as_ref().map_or(false, |desc| desc.trim() == "Security Lead")
    //     ) {
    //         println!("📝 Found Security Lead role: {} ({})",
    //                  securitylead_role.role_name,
    //                  securitylead_role.role_description.as_ref().unwrap_or(&"No description".to_string()));
    //         println!("   This role has ignore_team_restrictions: {:?}", securitylead_role.ignore_team_restrictions);
    //
    //         // Show all available roles that ignore team restrictions for reference
    //         let team_restriction_roles: Vec<_> = available_roles.iter()
    //             .filter(|r| r.ignore_team_restrictions == Some(true) && r.is_api != Some(true))
    //             .collect();
    //
    //         if team_restriction_roles.len() > 1 {
    //             println!("   Other available roles that ignore team restrictions:");
    //             for other_role in team_restriction_roles.iter().filter(|r| r.role_name != securitylead_role.role_name) {
    //                 println!("   - {} ({})", other_role.role_name,
    //                          other_role.role_description.as_ref().unwrap_or(&"No description".to_string()));
    //             }
    //         }
    //
    //         Some(vec![securitylead_role.role_id.clone()])
    //     } else {
    //         println!("⚠️  Security Lead role not found. Using regular submitter role with team assignment.");
    //         user_role_ids.clone()
    //     }
    // } else {
    //     None
    // };
    //
    // let admin_user_request = CreateUserRequest {
    //     email_address: admin_user_email.clone(),
    //     first_name: "Security Lead".to_string(),
    //     last_name: "User".to_string(),
    //     user_name: Some(admin_username),
    //     user_type: Some(UserType::Human),
    //     send_email_invitation: Some(false),
    //     role_ids: admin_role_ids.clone(),
    //     team_ids: if admin_role_ids.is_some() && available_roles.iter().any(|r|
    //         r.ignore_team_restrictions == Some(true) && r.is_api != Some(true)
    //     ) {
    //         None // Users with ignore_team_restrictions roles can be created without team assignment
    //     } else {
    //         created_team.as_ref().map(|t| vec![t.team_id.clone()]) // Fallback to team assignment
    //     },
    //     permissions: None,
    // };

    // let created_admin_user = match identity_api.create_user(admin_user_request).await {
    //     Ok(user) => {
    //         println!("✅ Created Security Lead user: {} {} ({})",
    //                  user.first_name, user.last_name, user.user_id);
    //         println!("   Email: {}", user.email_address);
    //         println!("   This user can work without team assignment due to ignore_team_restrictions");
    //         Some(user)
    //     }
    //     Err(IdentityError::PermissionDenied(msg)) => {
    //         println!("⚠️  Permission denied to create Security Lead user: {}", msg);
    //         None
    //     }
    //     Err(e) => {
    //         eprintln!("❌ Failed to create Security Lead user: {}", e);
    //         None
    //     }
    // };

    println!("⏭️  Skipping Security Lead user creation...");
    //let created_admin_user: Option<veracode_api::identity::User> = None;

    // Example 5: Search for users
    println!("\n🔍 Searching for users...");
    let query = UserQuery::new()
        .with_user_type(UserType::Human)
        .with_pagination(0, 10);

    match identity_api.list_users(Some(query)).await {
        Ok(users) => {
            println!("✅ Found {} users (showing first 5):", users.len());
            for (i, user) in users.iter().take(5).enumerate() {
                println!(
                    "   {}. {} {} - {}",
                    i + 1,
                    user.first_name,
                    user.last_name,
                    user.email_address
                );
                println!(
                    "      Active: {:?}, Type: {:?}",
                    user.active, user.user_type
                );
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to search users: {e}");
        }
    }

    // Example 5.5: Search for teams
    println!("\n🔍 Searching for teams...");
    match identity_api.list_teams().await {
        Ok(teams) => {
            println!("✅ Found {} teams (showing first 5):", teams.len());
            for (i, team) in teams.iter().take(5).enumerate() {
                println!("   {}. {} ({})", i + 1, team.team_name, team.team_id);
                if let Some(desc) = &team.team_description {
                    println!("      Description: {desc}");
                }
                if let Some(bu) = &team.business_unit {
                    println!("      Business Unit: {}", bu.bu_name);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to search teams: {e}");
        }
    }

    // Example 6: Find a specific user by email
    if let Some(ref user) = created_user {
        println!("\n🔍 Finding user by email...");
        match identity_api.find_user_by_email(&user.email_address).await {
            Ok(Some(found_user)) => {
                println!(
                    "✅ Found user: {} {} ({})",
                    found_user.first_name, found_user.last_name, found_user.user_id
                );
            }
            Ok(None) => {
                println!("⚠️  User not found by email search");
            }
            Err(e) => {
                eprintln!("❌ Error searching for user: {e}");
            }
        }
    }

    // Example 7: Update user information
    if let Some(ref user) = created_user {
        println!("\n✏️  Updating user information...");
        // Get current user's roles or use default roles
        let current_roles = user
            .roles
            .as_ref()
            .map(|roles| roles.iter().map(|r| r.role_id.clone()).collect())
            .unwrap_or_else(|| {
                // Fallback to submitter role if user has no roles (by description)
                available_roles
                    .iter()
                    .find(|r| {
                        r.role_description
                            .as_ref()
                            .is_some_and(|desc| desc == "Submitter")
                    })
                    .map(|r| vec![r.role_id.clone()])
                    .unwrap_or_default()
            });

        // Get current user's teams or use the created team
        let current_teams = user
            .teams
            .as_ref()
            .map(|teams| teams.iter().map(|t| t.team_id.clone()).collect())
            .unwrap_or_else(|| {
                // Use the team that was assigned during creation
                created_team
                    .as_ref()
                    .map(|t| vec![t.team_id.clone()])
                    .unwrap_or_default()
            });

        let update_request = UpdateUserRequest {
            email_address: user.email_address.clone(),
            user_name: user.user_name.clone(),
            first_name: Some("Updated".to_string()),
            last_name: Some("TestUser".to_string()),
            active: None,
            role_ids: current_roles,
            team_ids: current_teams,
        };

        match identity_api
            .update_user(&user.user_id, update_request)
            .await
        {
            Ok(updated_user) => {
                println!(
                    "✅ Updated user: {} {} -> {} {}",
                    user.first_name,
                    user.last_name,
                    updated_user.first_name,
                    updated_user.last_name
                );
            }
            Err(IdentityError::PermissionDenied(msg)) => {
                println!("⚠️  Permission denied to update user: {msg}");
            }
            Err(e) => {
                eprintln!("❌ Failed to update user: {e}");
            }
        }
    }

    // Example 8: Create API service account
    println!("\n🔑 Creating API service account...");
    let service_email = format!("serviceaccount{timestamp}@example.com");

    // Find API roles for the service account - specifically look for apisubmitanyscan and noteamrestrictionapi
    let api_role_ids = if !available_roles.is_empty() {
        let mut api_roles: Vec<String> = Vec::new();

        // Find apisubmitanyscan role
        if let Some(submit_role) = available_roles
            .iter()
            .find(|r| r.role_name.to_lowercase() == "apisubmitanyscan" && r.is_api == Some(true))
        {
            api_roles.push(submit_role.role_id.clone());
        }

        // Find noteamrestrictionapi role
        if let Some(noteam_role) = available_roles.iter().find(|r| {
            r.role_name.to_lowercase() == "noteamrestrictionapi" && r.is_api == Some(true)
        }) {
            api_roles.push(noteam_role.role_id.clone());
        }

        api_roles
    } else {
        vec![]
    };

    let service_username = format!("serviceaccount{timestamp}");
    match identity_api
        .create_api_service_account(
            &service_email,
            &service_username,
            "API",
            "Service",
            api_role_ids,
            created_team.as_ref().map(|t| vec![t.team_id.clone()]), // Assign to test team
        )
        .await
    {
        Ok(service_user) => {
            println!(
                "✅ Created API service account: {} ({})",
                service_user.email_address, service_user.user_id
            );

            // Example 9: Create API credentials for the service account
            println!("\n🔐 Creating API credentials...");
            let creds_request = CreateApiCredentialRequest {
                user_id: Some(service_user.user_id.clone()),
                expiration_ts: None,
            };

            match identity_api.create_api_credentials(creds_request).await {
                Ok(credentials) => {
                    println!("✅ Created API credentials:");
                    println!("   API ID: {}", credentials.api_id);
                    if let Some(api_key) = &credentials.api_key {
                        println!("   API Key: {api_key}");
                    }
                    println!("   Active: {:?}", credentials.active);

                    // Clean up: Revoke the API credentials
                    println!("\n🗑️  Revoking API credentials...");
                    match identity_api
                        .revoke_api_credentials(&credentials.api_id)
                        .await
                    {
                        Ok(_) => {
                            println!("✅ Successfully revoked API credentials");
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to revoke credentials: {e}");
                        }
                    }
                }
                Err(IdentityError::PermissionDenied(msg)) => {
                    println!("⚠️  Permission denied to create API credentials: {msg}");
                }
                Err(e) => {
                    eprintln!("❌ Failed to create API credentials: {e}");
                }
            }

            // Clean up: Delete the service account
            println!("\n🗑️  Deleting API service account...");
            match identity_api.delete_user(&service_user.user_id).await {
                Ok(_) => {
                    println!("✅ Successfully deleted API service account");
                }
                Err(IdentityError::PermissionDenied(msg)) => {
                    println!("⚠️  Permission denied to delete user: {msg}");
                }
                Err(e) => {
                    eprintln!("❌ Failed to delete service account: {e}");
                }
            }
        }
        Err(IdentityError::PermissionDenied(msg)) => {
            println!("⚠️  Permission denied to create API service account: {msg}");
        }
        Err(e) => {
            eprintln!("❌ Failed to create API service account: {e}");
        }
    }

    // Clean up: Delete the test user
    if let Some(ref user) = created_user {
        println!("\n🗑️  Deleting test user...");
        match identity_api.delete_user(&user.user_id).await {
            Ok(_) => {
                println!("✅ Successfully deleted test user");
            }
            Err(IdentityError::PermissionDenied(msg)) => {
                println!("⚠️  Permission denied to delete user: {msg}");
            }
            Err(e) => {
                eprintln!("❌ Failed to delete test user: {e}");
            }
        }
    }

    // Clean up: Delete the Security Lead test user (DISABLED)
    // if let Some(ref user) = created_admin_user {
    //     println!("\n🗑️  Deleting Security Lead test user...");
    //     match identity_api.delete_user(&user.user_id).await {
    //         Ok(_) => {
    //             println!("✅ Successfully deleted Security Lead test user");
    //         }
    //         Err(IdentityError::PermissionDenied(msg)) => {
    //             println!("⚠️  Permission denied to delete user: {}", msg);
    //         }
    //         Err(e) => {
    //             eprintln!("❌ Failed to delete Security Lead test user: {}", e);
    //         }
    //     }
    // }

    // Clean up: Delete the test team
    if let Some(ref team) = created_team {
        println!("\n🗑️  Deleting test team...");
        match identity_api.delete_team(&team.team_id).await {
            Ok(_) => {
                println!("✅ Successfully deleted test team");
            }
            Err(IdentityError::PermissionDenied(msg)) => {
                println!("⚠️  Permission denied to delete team: {msg}");
            }
            Err(IdentityError::TeamNotFound) => {
                println!("⚠️  Team not found (may have been already deleted)");
            }
            Err(e) => {
                eprintln!("❌ Failed to delete test team: {e}");
            }
        }
    }

    // Final cleanup: Delete all teams that start with "Test Team "
    println!("\n🧹 Final cleanup: Deleting all teams starting with 'Test Team '...");
    match identity_api.list_teams().await {
        Ok(teams) => {
            let test_teams: Vec<_> = teams
                .iter()
                .filter(|team| team.team_name.starts_with("Test Team "))
                .collect();

            if test_teams.is_empty() {
                println!("✅ No test teams found to clean up");
            } else {
                println!("🔍 Found {} test teams to delete:", test_teams.len());
                for team in &test_teams {
                    println!("   - {} ({})", team.team_name, team.team_id);
                }

                let mut deleted_count = 0;
                let mut failed_count = 0;

                for team in test_teams {
                    match identity_api.delete_team(&team.team_id).await {
                        Ok(_) => {
                            println!("✅ Deleted team: {}", team.team_name);
                            deleted_count += 1;
                        }
                        Err(IdentityError::PermissionDenied(_)) => {
                            println!("⚠️  Permission denied to delete team: {}", team.team_name);
                            failed_count += 1;
                        }
                        Err(IdentityError::TeamNotFound) => {
                            println!("⚠️  Team not found (already deleted): {}", team.team_name);
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to delete team {}: {}", team.team_name, e);
                            failed_count += 1;
                        }
                    }
                }

                println!("📊 Cleanup summary: {deleted_count} deleted, {failed_count} failed");
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to list teams for cleanup: {e}");
        }
    }

    println!("\n✅ Identity lifecycle example completed!");
    println!("\nThis example demonstrated:");
    println!("  ✓ Listing roles and teams");
    println!("  ✓ Creating teams and users (with team assignment)");
    println!("  ⏭️ Creating Security Lead users (DISABLED)");
    println!("  ✓ Searching for users and teams");
    println!("  ✓ Updating user information");
    println!("  ✓ Creating API service accounts (with team assignment and proper roles)");
    println!("  ✓ Managing API credentials (create and revoke for service user)");
    println!("  ✓ Team restriction validation for all user types");
    println!("  ✓ Cleaning up all resources (users, teams)");
    println!("  ✓ Final cleanup of all test teams");
    println!("\nNote: Some operations may fail with permission errors");
    println!("      if your API credentials don't have administrator privileges.");

    Ok(())
}

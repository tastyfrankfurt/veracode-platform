use veracode_platform::{VeracodeClient, VeracodeConfig, policy::PolicyError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VeracodeConfig::new(
        std::env::var("VERACODE_API_ID").expect("VERACODE_API_ID environment variable required"),
        std::env::var("VERACODE_API_KEY").expect("VERACODE_API_KEY environment variable required"),
    );

    let client = VeracodeClient::new(config)?;
    let policy_api = client.policy_api();

    println!("🔐 Policy API Lifecycle Example\n");

    // Example 1: List all available policies
    println!("📋 Listing available security policies...");
    match policy_api.list_policies(None).await {
        Ok(policies) => {
            println!("✅ Found {} policies:", policies.len());
            for (i, policy) in policies.iter().take(3).enumerate() {
                println!("   {}. {} ({})", i + 1, policy.name, policy.guid);
                if policy.policy_type == "CUSTOMER" && policy.organization_id.is_some() {
                    println!("      ⭐ Customer Policy");
                }
            }
            if policies.len() > 3 {
                println!("   ... and {} more", policies.len() - 3);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to list policies: {e}");
        }
    }

    // Example 2: Get the default policy
    println!("\n🎯 Getting default policy...");
    match policy_api.get_default_policy().await {
        Ok(default_policy) => {
            println!(
                "✅ Default policy: {} ({})",
                default_policy.name, default_policy.guid
            );
            if let Some(description) = &default_policy.description {
                println!("   Description: {description}");
            }
            println!("   Type: {}", default_policy.policy_type);
        }
        Err(PolicyError::NotFound) => {
            println!("⚠️  No default policy found");
        }
        Err(e) => {
            eprintln!("❌ Failed to get default policy: {e}");
        }
    }

    // Example 3: List only active policies
    println!("\n🟢 Listing active policies...");
    match policy_api.get_active_policies().await {
        Ok(active_policies) => {
            println!("✅ Found {} active policies:", active_policies.len());
            for policy in active_policies.iter().take(5) {
                println!("   • {} ({})", policy.name, policy.guid);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to list active policies: {e}");
        }
    }

    // Example 4: Demonstrate policy compliance evaluation (would need valid app GUID)
    println!("\n🔍 Policy compliance evaluation example...");
    let example_app_guid = "00000000-0000-0000-0000-000000000000"; // Placeholder
    let example_policy_guid = "11111111-1111-1111-1111-111111111111"; // Placeholder

    println!(
        "   Note: This would evaluate compliance for application {example_app_guid} against policy {example_policy_guid}"
    );
    println!(
        "   Example call: policy_api.evaluate_policy_compliance(app_guid, policy_guid, None).await"
    );

    // Example 5: Demonstrate policy scan initiation (would need valid GUIDs)
    println!("\n⚡ Policy scan initiation example...");
    println!("   This would initiate a static analysis scan with policy evaluation:");
    println!("   ```rust");
    println!("   let scan_request = PolicyScanRequest {{");
    println!("       application_guid: app_guid.to_string(),");
    println!("       policy_guid: policy_guid.to_string(),");
    println!("       scan_type: ScanType::Static,");
    println!("       sandbox_guid: None,");
    println!("       config: None,");
    println!("   }};");
    println!("   let scan_result = policy_api.initiate_policy_scan(scan_request).await?;");
    println!("   ```");

    // Example 6: Show how to check compliance status
    println!("\n✔️  Compliance checking example...");
    println!("   You can check if an application is compliant:");
    println!("   ```rust");
    println!(
        "   let is_compliant = policy_api.is_application_compliant(app_guid, policy_guid).await?;"
    );
    println!("   let score = policy_api.get_compliance_score(app_guid, policy_guid).await?;");
    println!("   ```");

    println!("\n✅ Policy API lifecycle example completed!");
    println!("\nThis example demonstrated:");
    println!("  ✓ Listing available security policies");
    println!("  ✓ Getting the default organizational policy");
    println!("  ✓ Filtering active policies");
    println!("  ✓ Policy compliance evaluation patterns");
    println!("  ✓ Policy scan initiation workflow");
    println!("  ✓ Compliance status checking methods");

    println!("\n📚 Available Policy API methods:");
    println!("  • list_policies() - List all policies with optional filtering");
    println!("  • get_policy(guid) - Get specific policy details");
    println!("  • get_default_policy() - Get organization default policy");
    println!("  • get_active_policies() - Get only active policies");
    println!("  • evaluate_policy_compliance() - Check application compliance");
    println!("  • initiate_policy_scan() - Start policy-based security scan");
    println!("  • get_policy_scan_result() - Get scan results and status");
    println!("  • is_policy_scan_complete() - Check if scan is finished");
    println!("  • get_policy_violations() - Get specific policy violations");
    println!("  • is_application_compliant() - Quick compliance check");
    println!("  • get_compliance_score() - Get numeric compliance score");

    Ok(())
}

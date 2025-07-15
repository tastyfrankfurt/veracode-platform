use crate::cli::Args;
use crate::{check_secure_pipeline_credentials, load_secure_api_credentials};
use std::fs;
use std::path::PathBuf;
use veracode_platform::{VeracodeConfig, VeracodeRegion};

pub fn execute_policy_download(args: &Args, policy_name: &str) -> Result<(), i32> {
    println!("🔍 Policy Download requested for: {}", policy_name);

    // Use secure API credentials handling
    let secure_creds = load_secure_api_credentials().map_err(|_| 1)?;
    let (api_id, api_key) = check_secure_pipeline_credentials(&secure_creds).map_err(|_| 1)?;

    let region = parse_region(&args.region)?;
    let mut veracode_config = VeracodeConfig::new(api_id, api_key).with_region(region);

    // Check environment variable for certificate validation
    if std::env::var("VERASCAN_DISABLE_CERT_VALIDATION").is_ok() {
        veracode_config = veracode_config.with_certificate_validation_disabled();
        println!(
            "⚠️  WARNING: Certificate validation disabled for Veracode API via VERASCAN_DISABLE_CERT_VALIDATION"
        );
        println!("   This should only be used in development environments!");
    }

    execute_policy_download_with_runtime(veracode_config, policy_name, args)
}

fn parse_region(region_str: &str) -> Result<VeracodeRegion, i32> {
    match region_str.to_lowercase().as_str() {
        "commercial" => Ok(VeracodeRegion::Commercial),
        "european" => Ok(VeracodeRegion::European),
        "federal" => Ok(VeracodeRegion::Federal),
        _ => {
            eprintln!(
                "❌ Invalid region '{}'. Use: commercial, european, or federal",
                region_str
            );
            Err(1)
        }
    }
}

fn execute_policy_download_with_runtime(
    veracode_config: VeracodeConfig,
    policy_name: &str,
    args: &Args,
) -> Result<(), i32> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        eprintln!("❌ Failed to create async runtime: {}", e);
        1
    })?;

    rt.block_on(async { download_policy_by_name(veracode_config, policy_name, args).await })
}

async fn download_policy_by_name(
    veracode_config: VeracodeConfig,
    policy_name: &str,
    args: &Args,
) -> Result<(), i32> {
    use veracode_platform::VeracodeClient;

    let client = VeracodeClient::new(veracode_config).map_err(|e| {
        eprintln!("❌ Failed to create Veracode client: {}", e);
        1
    })?;

    let policy_api = client.policy_api();

    if args.debug {
        println!("🔍 Searching for policies...");
    }

    // Get list of policies to find the one matching the name
    let policies = policy_api.list_policies(None).await.map_err(|e| {
        eprintln!("❌ Failed to list policies: {}", e);
        1
    })?;

    if args.debug {
        println!("📋 Found {} total policies", policies.len());
    }

    // Find policy by name (case-insensitive)
    let target_policy = policies
        .iter()
        .find(|policy| policy.name.to_lowercase() == policy_name.to_lowercase())
        .ok_or_else(|| {
            eprintln!("❌ Policy '{}' not found", policy_name);
            eprintln!("💡 Available policies:");
            for policy in &policies {
                eprintln!("   - {}", policy.name);
            }
            1
        })?;

    if args.debug {
        println!(
            "✅ Found policy: {} (GUID: {})",
            target_policy.name, target_policy.guid
        );
    }

    // Get the full policy details
    let full_policy = policy_api
        .get_policy(&target_policy.guid)
        .await
        .map_err(|e| {
            eprintln!("❌ Failed to download policy details: {}", e);
            1
        })?;

    // Create filename by replacing spaces with underscores and adding .json extension
    let sanitized_name = policy_name.replace(' ', "_");
    let filename = format!("{}.json", sanitized_name);
    let filepath = PathBuf::from(&filename);

    if args.debug {
        println!("💾 Saving policy to: {}", filepath.display());
    }

    // Convert policy to JSON
    let json_content = serde_json::to_string_pretty(&full_policy).map_err(|e| {
        eprintln!("❌ Failed to serialize policy to JSON: {}", e);
        1
    })?;

    // Write to file
    fs::write(&filepath, json_content).map_err(|e| {
        eprintln!("❌ Failed to write policy file: {}", e);
        1
    })?;

    println!("✅ Policy '{}' downloaded successfully", target_policy.name);
    println!("📁 Saved as: {}", filepath.display());
    println!("📊 Policy details:");
    println!("   - GUID: {}", full_policy.guid);
    println!("   - Type: {}", full_policy.policy_type);
    println!("   - Version: {}", full_policy.version);
    if let Some(desc) = &full_policy.description {
        println!("   - Description: {}", desc);
    }

    Ok(())
}

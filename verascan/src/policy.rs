use crate::cli::Args;
use crate::scan::configure_veracode_with_env_vars;
use crate::{check_secure_pipeline_credentials, load_secure_api_credentials};
use log::{error, info};
use std::fs;
use std::path::PathBuf;
use veracode_platform::{VeracodeConfig, VeracodeRegion};

/// Efficiently create a sanitized filename for policy download
#[inline]
fn create_policy_filename(policy_name: &str) -> String {
    if policy_name.contains(' ') {
        format!("{}.json", policy_name.replace(' ', "_"))
    } else {
        format!("{policy_name}.json")
    }
}

pub fn execute_policy_download(args: &Args, policy_name: &str) -> Result<(), i32> {
    info!("🔍 Policy Download requested for: {policy_name}");

    // Use secure API credentials handling
    let secure_creds = load_secure_api_credentials().map_err(|_| 1)?;
    let (api_id, api_key) = check_secure_pipeline_credentials(&secure_creds).map_err(|_| 1)?;

    let region = parse_region(&args.region)?;
    let base_config = VeracodeConfig::new(&api_id, &api_key).with_region(region);
    let veracode_config = configure_veracode_with_env_vars(base_config, args.debug);

    execute_policy_download_with_runtime(veracode_config, policy_name, args)
}

fn parse_region(region_str: &str) -> Result<VeracodeRegion, i32> {
    // Use case-insensitive matching without allocating
    match region_str {
        s if s.eq_ignore_ascii_case("commercial") => Ok(VeracodeRegion::Commercial),
        s if s.eq_ignore_ascii_case("european") => Ok(VeracodeRegion::European),
        s if s.eq_ignore_ascii_case("federal") => Ok(VeracodeRegion::Federal),
        _ => {
            error!("❌ Invalid region '{region_str}'. Use: commercial, european, or federal");
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
        error!("❌ Failed to create async runtime: {e}");
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
        error!("❌ Failed to create Veracode client: {e}");
        1
    })?;

    let policy_api = client.policy_api();

    if args.debug {
        info!("🔍 Searching for policies...");
    }

    // Get list of policies to find the one matching the name
    let policies = policy_api.list_policies(None).await.map_err(|e| {
        error!("❌ Failed to list policies: {e}");
        1
    })?;

    if args.debug {
        info!("📋 Found {} total policies", policies.len());
    }

    // Find policy by name (case-insensitive) - avoid double allocation
    let target_policy = policies
        .iter()
        .find(|policy| policy.name.eq_ignore_ascii_case(policy_name))
        .ok_or_else(|| {
            error!("❌ Policy '{policy_name}' not found");
            error!("💡 Available policies:");
            for policy in &policies {
                error!("   - {}", policy.name);
            }
            1
        })?;

    if args.debug {
        info!(
            "✅ Found policy: {} (GUID: {})",
            target_policy.name, target_policy.guid
        );
    }

    // Get the full policy details
    let full_policy = policy_api
        .get_policy(&target_policy.guid)
        .await
        .map_err(|e| {
            error!("❌ Failed to download policy details: {e}");
            1
        })?;

    // Create filename efficiently using helper function
    let filename = create_policy_filename(policy_name);
    let filepath = PathBuf::from(&filename);

    if args.debug {
        info!("💾 Saving policy to: {}", filepath.display());
    }

    // Convert policy to JSON
    let json_content = serde_json::to_string_pretty(&full_policy).map_err(|e| {
        error!("❌ Failed to serialize policy to JSON: {e}");
        1
    })?;

    // Write to file
    fs::write(&filepath, json_content).map_err(|e| {
        error!("❌ Failed to write policy file: {e}");
        1
    })?;

    info!("✅ Policy '{}' downloaded successfully", target_policy.name);
    info!("📁 Saved as: {}", filepath.display());
    info!("📊 Policy details:");
    info!("   - GUID: {}", full_policy.guid);
    info!("   - Type: {}", full_policy.policy_type);
    info!("   - Version: {}", full_policy.version);
    if let Some(desc) = &full_policy.description {
        info!("   - Description: {desc}");
    }

    Ok(())
}

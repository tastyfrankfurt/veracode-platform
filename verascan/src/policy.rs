use log::{debug, error, info};
use std::path::PathBuf;
use veracode_platform::VeracodeConfig;

/// Efficiently create a sanitized filename for policy download
#[inline]
fn create_policy_filename(policy_name: &str) -> String {
    if policy_name.contains(' ') {
        format!("{}.json", policy_name.replace(' ', "_"))
    } else {
        format!("{policy_name}.json")
    }
}

pub fn execute_policy_download(
    veracode_config: VeracodeConfig,
    policy_name: &str,
) -> Result<(), i32> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        error!("❌ Failed to create async runtime: {e}");
        1
    })?;

    rt.block_on(async { download_policy_by_name(veracode_config, policy_name).await })
}

async fn download_policy_by_name(
    veracode_config: VeracodeConfig,
    policy_name: &str,
) -> Result<(), i32> {
    use veracode_platform::VeracodeClient;

    let client = VeracodeClient::new(veracode_config).map_err(|e| {
        error!("❌ Failed to create Veracode client: {e}");
        1
    })?;

    let policy_api = client.policy_api();

    debug!("🔍 Searching for policies...");

    // Get list of policies to find the one matching the name
    let policies = policy_api.list_policies(None).await.map_err(|e| {
        error!("❌ Failed to list policies: {e}");
        1
    })?;

    debug!("📋 Found {} total policies", policies.len());

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

    debug!(
        "✅ Found policy: {} (GUID: {})",
        target_policy.name, target_policy.guid
    );

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

    debug!("💾 Saving policy to: {}", filepath.display());

    // Convert policy to JSON
    let json_content = serde_json::to_string_pretty(&full_policy).map_err(|e| {
        error!("❌ Failed to serialize policy to JSON: {e}");
        1
    })?;

    // Write to file
    tokio::fs::write(&filepath, json_content)
        .await
        .map_err(|e| {
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

//! Veraaudit - Veracode Audit Log Retrieval Tool
//!
//! CLI/Service tool for retrieving and archiving Veracode audit logs
use clap::Parser;
use log::info;
use veraaudit::{
    Result, ServiceConfig, audit, cli, credentials, datetime, output, service, vault_client,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse CLI arguments
    let args = cli::Cli::parse();

    info!("Veraaudit - Veracode Audit Log Retrieval Tool");

    // Load credentials (Vault with environment fallback)
    let (veracode_credentials, proxy_url, proxy_username, proxy_password) =
        vault_client::load_credentials_and_proxy_from_vault().await?;

    // Create Veracode client configuration
    let config = credentials::create_veracode_config_with_proxy(
        veracode_credentials,
        args.region.as_str(),
        proxy_url,
        proxy_username,
        proxy_password,
    )
    .map_err(|_| {
        veraaudit::AuditError::InvalidConfig("Failed to create Veracode config".to_string())
    })?;

    // Create Veracode client
    let client = veracode_platform::VeracodeClient::new(config)?;

    // Execute command
    match args.command {
        cli::Commands::Run {
            start,
            start_offset,
            end,
            output_dir,
            audit_action,
            action_type,
            utc,
        } => {
            // Apply defaults: end = now
            let end_datetime = end.unwrap_or_else(datetime::format_now_utc);

            // Determine start datetime:
            // 1. If --start provided, use it
            // 2. Else if --start-offset provided, compute from offset
            // 3. Else default to 60 minutes before end
            let start_datetime = if let Some(start_val) = start {
                start_val
            } else if let Some(offset) = start_offset {
                datetime::format_utc_minus_offset(&offset)?
            } else {
                datetime::format_utc_minus_minutes(60)
            };

            // Validate the datetime range (converts to UTC if utc=false)
            let (validated_start, validated_end) =
                datetime::validate_date_range(&start_datetime, &end_datetime, utc)?;

            // Convert validated enum types to API strings
            let audit_action_strings: Vec<String> = audit_action
                .iter()
                .map(|a| a.as_str().to_string())
                .collect();
            let action_type_strings: Vec<String> =
                action_type.iter().map(|t| t.as_str().to_string()).collect();

            run_cli_mode(
                &client,
                &validated_start,
                &validated_end,
                &output_dir,
                audit_action_strings,
                action_type_strings,
            )
            .await?;
        }
        cli::Commands::Service {
            interval_minutes,
            output_dir,
            cleanup_count,
            cleanup_hours,
            audit_action,
            action_type,
            utc: _utc, // Service mode always uses UTC internally
        } => {
            // Convert validated enum types to API strings
            let audit_action_strings: Vec<String> = audit_action
                .iter()
                .map(|a| a.as_str().to_string())
                .collect();
            let action_type_strings: Vec<String> =
                action_type.iter().map(|t| t.as_str().to_string()).collect();

            run_service_mode(
                client,
                interval_minutes,
                &output_dir,
                cleanup_count,
                cleanup_hours,
                audit_action_strings,
                action_type_strings,
            )
            .await?;
        }
    }

    Ok(())
}

/// Run in CLI mode (one-time retrieval)
async fn run_cli_mode(
    client: &veracode_platform::VeracodeClient,
    start_datetime: &str,
    end_datetime: &str,
    output_dir: &str,
    audit_actions: Vec<String>,
    action_types: Vec<String>,
) -> Result<()> {
    info!("Running in CLI mode");
    info!("  Start datetime: {}", start_datetime);
    info!("  End datetime: {}", end_datetime);
    info!("  Output directory: {}", output_dir);

    // Retrieve audit logs
    let audit_data = audit::retrieve_audit_logs(
        client,
        start_datetime,
        Some(end_datetime.to_string()),
        if audit_actions.is_empty() {
            None
        } else {
            Some(audit_actions)
        },
        if action_types.is_empty() {
            None
        } else {
            Some(action_types)
        },
    )
    .await?;

    // Write to timestamped file
    let filepath = output::write_audit_log_file(output_dir, &audit_data)?;
    info!("Success! Audit log saved to: {}", filepath.display());

    Ok(())
}

/// Run in service mode (continuous retrieval)
async fn run_service_mode(
    client: veracode_platform::VeracodeClient,
    interval_minutes: u64,
    output_dir: &str,
    cleanup_count: Option<usize>,
    cleanup_hours: Option<u64>,
    audit_actions: Vec<String>,
    action_types: Vec<String>,
) -> Result<()> {
    let config = ServiceConfig {
        interval_minutes,
        output_dir: output_dir.to_string(),
        cleanup_count,
        cleanup_hours,
        audit_actions: if audit_actions.is_empty() {
            None
        } else {
            Some(audit_actions)
        },
        action_types: if action_types.is_empty() {
            None
        } else {
            Some(action_types)
        },
    };

    service::run_service(client, config).await?;

    Ok(())
}

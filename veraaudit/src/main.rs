//! Veraaudit - Veracode Audit Log Retrieval Tool
//!
//! CLI/Service tool for retrieving and archiving Veracode audit logs
use clap::Parser;
use log::info;
use std::sync::Arc;
use veraaudit::{
    Result, ServiceConfig, audit, cli, credentials, datetime, firehose, kinesis, output, service,
    vault_client,
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
            interval,
            output_dir,
            audit_action,
            action_type,
            utc,
            no_file_timestamp,
            no_dedup,
            backend_window,
            kinesis_stream,
            kinesis_region,
            firehose_stream,
            firehose_region,
        } => {
            // Determine start datetime with the following priority:
            // 1. If --no-file-timestamp is not set, check for last log file timestamp (if within 72 hours)
            // 2. If not found, too old, or flag is set, use --start if provided
            // 3. Else if --start-offset provided, compute from offset
            // 4. Else default to 60 minutes before end
            //
            // Track whether we're using a file timestamp (which is always in UTC)
            let (start_datetime, using_file_timestamp) = if !no_file_timestamp {
                if let Some(last_timestamp) = output::get_last_log_timestamp(&output_dir) {
                    // Found a valid timestamp from the last log file (within 72 hours)
                    info!(
                        "Using timestamp from last log file as start: {}",
                        last_timestamp
                    );
                    (last_timestamp, true) // File timestamps are always UTC
                } else if let Some(start_val) = start {
                    (start_val, false)
                } else if let Some(offset) = start_offset {
                    (datetime::format_utc_minus_offset(&offset)?, true) // Computed timestamps are UTC
                } else {
                    (datetime::format_utc_minus_minutes(60), true) // Computed timestamps are UTC
                }
            } else {
                // File timestamp check is disabled
                if let Some(start_val) = start {
                    (start_val, false)
                } else if let Some(offset) = start_offset {
                    (datetime::format_utc_minus_offset(&offset)?, true) // Computed timestamps are UTC
                } else {
                    (datetime::format_utc_minus_minutes(60), true) // Computed timestamps are UTC
                }
            };

            // Determine end datetime:
            // 1. If --interval provided, calculate as (now - backend_window) for continuous chunked querying
            //    - The interval value specifies the chunk size
            //    - Queries continue from start to (now - backend_window)
            // 2. Else if --end provided, use it
            // 3. Else default to now
            //
            // Track whether end is UTC (computed ends are always UTC)
            let (end_datetime, end_is_utc) = if let Some(ref interval_val) = interval {
                // When interval is provided, query continuously to (now - backend_window)
                // to get the freshest available data while avoiding incomplete backend data
                let now_utc = datetime::format_now_utc();
                let backend_offset_minutes = datetime::parse_time_offset(&backend_window)?;
                let calculated_end =
                    datetime::subtract_minutes_from_datetime(&now_utc, backend_offset_minutes)?;

                info!(
                    "Using interval-based chunked retrieval: start={}, end=(now - backend_window)={}, chunk_size={}",
                    start_datetime, calculated_end, interval_val
                );

                (calculated_end, true) // Backend-calculated timestamps are always UTC
            } else if let Some(end_val) = end {
                (end_val, false) // User-provided end, respect --utc flag
            } else {
                (datetime::format_now_utc(), true) // Computed timestamps are UTC
            };

            // Validate the datetime range
            // If timestamps came from files or were computed, they're already in UTC, so force utc=true
            // If they came from user input, respect the --utc flag
            let effective_utc_mode = utc || (using_file_timestamp && end_is_utc);
            let (validated_start, validated_end) = datetime::validate_date_range(
                &start_datetime,
                &end_datetime,
                effective_utc_mode,
                &args.region,
            )?;

            // Convert validated enum types to API strings
            let audit_action_strings: Vec<String> = audit_action
                .iter()
                .map(|a| a.as_str().to_string())
                .collect();
            let action_type_strings: Vec<String> =
                action_type.iter().map(|t| t.as_str().to_string()).collect();

            // Build Kinesis / Firehose output sink if the respective flag was provided
            let kinesis_output = build_kinesis_output(kinesis_stream, kinesis_region).await?;
            let kinesis_partition_key = format!("veraaudit-{}", args.region.as_str());
            let firehose_output = build_firehose_output(firehose_stream, firehose_region).await?;

            run_cli_mode(
                &client,
                args.region.as_str(), // Pass region for credential refresh
                &validated_start,
                &validated_end,
                &output_dir,
                interval,       // Pass interval for chunked retrieval
                backend_window, // Pass backend window for empty chunk handling
                audit_action_strings,
                action_type_strings,
                no_dedup,
                kinesis_output.as_ref(),
                &kinesis_partition_key,
                firehose_output.as_ref(),
            )
            .await?;
        }
        cli::Commands::Service {
            start_offset,
            interval,
            output_dir,
            cleanup_count,
            cleanup_hours,
            audit_action,
            action_type,
            utc: _utc, // Service mode always uses UTC internally
            no_file_timestamp,
            no_dedup,
            backend_window,
            kinesis_stream,
            kinesis_region,
            firehose_stream,
            firehose_region,
            cursor_file,
        } => {
            // Convert validated enum types to API strings
            let audit_action_strings: Vec<String> = audit_action
                .iter()
                .map(|a| a.as_str().to_string())
                .collect();
            let action_type_strings: Vec<String> =
                action_type.iter().map(|t| t.as_str().to_string()).collect();

            // Build Kinesis / Firehose output sink if the respective flag was provided
            let kinesis_partition_key = format!("veraaudit-{}", args.region.as_str());
            let kinesis_output = build_kinesis_output(kinesis_stream, kinesis_region)
                .await?
                .map(Arc::new);
            let firehose_output = build_firehose_output(firehose_stream, firehose_region)
                .await?
                .map(Arc::new);

            let config = ServiceConfig {
                start_offset,
                interval,
                output_dir,
                cleanup_count,
                cleanup_hours,
                audit_actions: if audit_action_strings.is_empty() {
                    None
                } else {
                    Some(audit_action_strings.into())
                },
                action_types: if action_type_strings.is_empty() {
                    None
                } else {
                    Some(action_type_strings.into())
                },
                no_file_timestamp,
                no_dedup,
                backend_window,
                region: args.region.as_str().to_string(),
                flush_threshold_bytes: 52_428_800, // 50MB default
                kinesis_output,
                kinesis_partition_key,
                firehose_output,
                cursor_file,
            };

            run_service_mode(client, config).await?;
        }
        cli::Commands::HelpEnv => {
            // This should never be reached as it's handled early
            unreachable!("HelpEnv is handled before credential loading")
        }
    }

    Ok(())
}

/// Run in CLI mode (one-time retrieval)
#[allow(clippy::too_many_arguments)]
async fn run_cli_mode(
    client: &veracode_platform::VeracodeClient,
    region_str: &str,
    start_datetime: &str,
    end_datetime: &str,
    output_dir: &str,
    interval: Option<String>,
    backend_window: String,
    audit_actions: Vec<String>,
    action_types: Vec<String>,
    no_dedup: bool,
    kinesis_output: Option<&kinesis::KinesisOutput>,
    kinesis_partition_key: &str,
    firehose_output: Option<&firehose::FirehoseOutput>,
) -> Result<()> {
    info!("Running in CLI mode");
    info!("  Start datetime: {}", start_datetime);
    info!("  End datetime: {}", end_datetime);
    if kinesis_output.is_some() {
        info!(
            "  Output: Kinesis (partition key: {})",
            kinesis_partition_key
        );
    } else if firehose_output.is_some() {
        info!("  Output: Kinesis Firehose (delivery stream)");
    } else {
        info!("  Output directory: {}", output_dir);
    }
    if let Some(ref interval_val) = interval {
        info!("  Interval: {} (chunked retrieval)", interval_val);
    }

    // Retrieve audit logs - use chunked retrieval if interval is provided
    // The tuple returns (data, Option<refreshed_client>) - we discard the client in CLI mode
    let (audit_data, _refreshed_client) = if let Some(interval_val) = interval {
        // Use chunked retrieval
        audit::retrieve_audit_logs_chunked(
            client,
            region_str,
            start_datetime,
            end_datetime,
            &interval_val,
            &backend_window,
            if audit_actions.is_empty() {
                None
            } else {
                Some(audit_actions.into())
            },
            if action_types.is_empty() {
                None
            } else {
                Some(action_types.into())
            },
        )
        .await?
    } else {
        // Use single query retrieval
        audit::retrieve_audit_logs(
            client,
            region_str,
            start_datetime,
            end_datetime,
            if audit_actions.is_empty() {
                None
            } else {
                Some(audit_actions.into())
            },
            if action_types.is_empty() {
                None
            } else {
                Some(action_types.into())
            },
        )
        .await?
    };

    // Route output: Kinesis, Firehose, or file
    if let Some(kinesis) = kinesis_output {
        let logs = audit_data.as_array().map(Vec::as_slice).unwrap_or(&[]);
        kinesis.send_records(logs, kinesis_partition_key).await?;
        info!("Success! {} audit log entries sent to Kinesis", logs.len());
    } else if let Some(fh) = firehose_output {
        let logs = audit_data.as_array().map(Vec::as_slice).unwrap_or(&[]);
        fh.send_records(logs).await?;
        info!("Success! {} audit log entries sent to Firehose", logs.len());
    } else {
        // Write to timestamped file (pass start_datetime for deduplication)
        match output::write_audit_log_file(output_dir, audit_data, no_dedup, Some(start_datetime))?
        {
            Some(filepath) => {
                info!("Success! Audit log saved to: {}", filepath.display());
            }
            None => {
                info!("No new logs found after deduplication, no file created");
            }
        }
    }

    Ok(())
}

/// Run in service mode (continuous retrieval)
async fn run_service_mode(
    client: veracode_platform::VeracodeClient,
    config: ServiceConfig,
) -> Result<()> {
    service::run_service(client, config).await?;
    Ok(())
}

/// Build a `KinesisOutput` when `--kinesis-stream` is provided.
///
/// Returns `None` if `stream_name` is `None` (file output mode).
async fn build_kinesis_output(
    stream_name: Option<String>,
    region: Option<String>,
) -> Result<Option<kinesis::KinesisOutput>> {
    match stream_name {
        None => Ok(None),
        Some(name) => {
            let cfg = kinesis::KinesisConfig::new(name, region);
            let output = kinesis::KinesisOutput::new(cfg).await?;
            Ok(Some(output))
        }
    }
}

/// Build a `FirehoseOutput` when `--firehose-stream` is provided.
///
/// Returns `None` if `delivery_stream_name` is `None` (file or Kinesis output mode).
async fn build_firehose_output(
    delivery_stream_name: Option<String>,
    region: Option<String>,
) -> Result<Option<firehose::FirehoseOutput>> {
    match delivery_stream_name {
        None => Ok(None),
        Some(name) => {
            let cfg = firehose::FirehoseConfig::new(name, region);
            let output = firehose::FirehoseOutput::new(cfg).await?;
            Ok(Some(output))
        }
    }
}

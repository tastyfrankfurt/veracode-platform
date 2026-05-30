//! Service/daemon mode implementation for continuous audit log retrieval
use crate::{
    cleanup,
    cursor::{CycleCursorState, StreamCursor},
    error::Result,
    firehose::FirehoseOutput,
    kinesis::KinesisOutput,
    output,
};
use log::{error, info, warn};
use std::sync::Arc;
use tokio::signal;
use tokio::time::{Duration as TokioDuration, interval};
use veracode_platform::{AuditReportRequest, VeracodeClient};

/// Service configuration
pub struct ServiceConfig {
    pub start_offset: String,
    pub interval: String,
    pub output_dir: String,
    pub cleanup_count: Option<usize>,
    pub cleanup_hours: Option<u64>,
    pub audit_actions: Option<Arc<[String]>>,
    pub action_types: Option<Arc<[String]>>,
    pub no_file_timestamp: bool,
    pub no_dedup: bool,
    pub backend_window: String,
    pub region: String,
    pub flush_threshold_bytes: usize,
    /// When set, audit logs are sent to this Kinesis sink instead of written to files
    pub kinesis_output: Option<Arc<KinesisOutput>>,
    /// Kinesis partition key (e.g. "veraaudit-commercial")
    pub kinesis_partition_key: String,
    /// When set, audit logs are sent to this Firehose delivery stream instead of written to files
    pub firehose_output: Option<Arc<FirehoseOutput>>,
    /// Path to the stream cursor file for Kinesis/Firehose progress tracking.
    /// Defaults to `{output_dir}/stream_cursor.json` when `None`.
    pub cursor_file: Option<String>,
}

/// Run the service in continuous mode
///
/// # Arguments
///
/// * `client` - Veracode API client
/// * `config` - Service configuration
///
/// # Errors
///
/// Returns error if service fails to start or encounters fatal error
pub async fn run_service(client: VeracodeClient, config: ServiceConfig) -> Result<()> {
    info!("Starting veraaudit service mode");
    info!("  Start offset: {}", config.start_offset);
    info!("  Interval: {}", config.interval);
    info!("  Output directory: {}", config.output_dir);

    if let Some(count) = config.cleanup_count {
        info!("  Cleanup: keep last {} files", count);
    }
    if let Some(hours) = config.cleanup_hours {
        info!("  Cleanup: delete files older than {} hours", hours);
    }

    // Wrap config in Arc for sharing across tasks
    let config = Arc::new(config);

    // Use mutable client to allow updates when credentials are refreshed
    let mut current_client = client;

    // Parse interval to get duration in minutes, then convert to seconds
    let interval_minutes = crate::datetime::parse_time_offset(&config.interval)?;

    // Main service loop
    #[allow(clippy::arithmetic_side_effects)] // interval_minutes is validated, multiplication won't overflow
    #[allow(clippy::cast_sign_loss)] // interval_minutes is validated to be positive
    let mut interval_timer = interval(TokioDuration::from_secs((interval_minutes * 60) as u64));
    interval_timer.tick().await; // First tick happens immediately

    loop {
        // Run audit log retrieval - update client if credentials were refreshed
        match run_audit_cycle(&current_client, &config).await {
            Ok(refreshed_client_opt) => {
                if let Some(refreshed_client) = refreshed_client_opt {
                    info!("Client updated with refreshed credentials for future cycles");
                    current_client = refreshed_client;
                }
                info!("Audit cycle completed successfully");
            }
            Err(e) => {
                error!("Audit cycle failed: {}", e);
                // Continue running even if one cycle fails
            }
        }

        // Run cleanup if configured (file output only — not applicable for Kinesis/Firehose)
        if config.kinesis_output.is_none()
            && config.firehose_output.is_none()
            && (config.cleanup_count.is_some() || config.cleanup_hours.is_some())
            && let Err(e) = run_cleanup_cycle(&config).await
        {
            warn!("Cleanup cycle failed: {}", e);
        }

        // Wait for next interval or shutdown signal
        tokio::select! {
            _ = interval_timer.tick() => {
                // Continue to next iteration
            }
            _ = signal::ctrl_c() => {
                info!("Shutdown signal received, gracefully stopping service...");
                break;
            }
        }
    }

    info!("Service shut down successfully");
    Ok(())
}

/// Derive the cursor file path from config: explicit path or `{output_dir}/stream_cursor.json`.
fn get_cursor_path(config: &ServiceConfig) -> std::path::PathBuf {
    config
        .cursor_file
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(&config.output_dir).join("stream_cursor.json"))
}

/// Run a single audit log retrieval cycle using streaming for progressive writes
///
/// Drives the chunk loop internally, using `get_audit_logs_stream` per chunk
/// to write batches as they arrive rather than holding the full dataset in memory.
///
/// Returns `Option<VeracodeClient>` - Some(client) if credentials were refreshed, None otherwise
async fn run_audit_cycle(
    client: &VeracodeClient,
    config: &ServiceConfig,
) -> Result<Option<VeracodeClient>> {
    use futures::StreamExt;

    let is_stream_output = config.kinesis_output.is_some() || config.firehose_output.is_some();

    // For Kinesis/Firehose: load cursor and resume from its timestamp.
    // Falls back to start_offset when the cursor file is absent or corrupt.
    let stream_cursor: Option<StreamCursor> = if is_stream_output {
        StreamCursor::load(&get_cursor_path(config))
    } else {
        None
    };

    // Determine start datetime with the following priority:
    // 1. Kinesis/Firehose + cursor present  → cursor.query_start()
    // 2. Kinesis/Firehose + no cursor       → start_offset
    // 3. File output, --no-file-timestamp not set → last log file timestamp
    // 4. File output fallback               → start_offset
    let start_datetime = if is_stream_output {
        if let Some(ref cursor) = stream_cursor {
            info!(
                "Resuming from stream cursor: start={}",
                cursor.query_start()
            );
            cursor.query_start().to_string()
        } else {
            crate::datetime::format_utc_minus_offset(&config.start_offset)?
        }
    } else if !config.no_file_timestamp {
        if let Some(last_timestamp) = output::get_last_log_timestamp(&config.output_dir) {
            info!(
                "Using timestamp from last log file as start: {}",
                last_timestamp
            );
            last_timestamp
        } else {
            crate::datetime::format_utc_minus_offset(&config.start_offset)?
        }
    } else {
        crate::datetime::format_utc_minus_offset(&config.start_offset)?
    };

    // Accumulates the high-water mark across all batches this cycle.
    let mut cycle_state = CycleCursorState::new();

    // Calculate end datetime: now - backend_window
    let now_utc = crate::datetime::format_now_utc();
    let backend_offset_minutes = crate::datetime::parse_time_offset(&config.backend_window)?;
    let end_datetime =
        crate::datetime::subtract_minutes_from_datetime(&now_utc, backend_offset_minutes)?;

    info!(
        "Service cycle will retrieve logs from {} to (now - backend_window) = {}",
        start_datetime, end_datetime
    );

    // Parse interval and backend window for chunk loop
    let interval_minutes = crate::datetime::parse_time_offset(&config.interval)?;
    let backend_window_minutes = crate::datetime::parse_time_offset(&config.backend_window)?;

    // Parse datetimes for chunk iteration
    let start_dt = crate::datetime::try_parse_datetime(&start_datetime)?;
    let end_dt = crate::datetime::try_parse_datetime(&end_datetime)?;
    let now_utc_str = crate::datetime::format_now_utc();
    let now_dt = crate::datetime::try_parse_datetime(&now_utc_str)?;

    // Cap end at current time
    let effective_end = if end_dt > now_dt { now_dt } else { end_dt };

    let mut current_start = start_dt;
    let mut chunk_count: usize = 0;
    let mut files_written: usize = 0;
    let mut refreshed_client: Option<VeracodeClient> = None;

    while current_start < effective_end {
        chunk_count = chunk_count.saturating_add(1);

        #[allow(clippy::arithmetic_side_effects)]
        let chunk_end_calc = current_start + chrono::Duration::minutes(interval_minutes);
        let chunk_end = if chunk_end_calc > effective_end {
            effective_end
        } else {
            chunk_end_calc
        };

        let chunk_start_str = current_start.format("%Y-%m-%d %H:%M:%S").to_string();
        let chunk_end_str = chunk_end.format("%Y-%m-%d %H:%M:%S").to_string();

        info!(
            "Querying chunk {} from {} to {}",
            chunk_count, chunk_start_str, chunk_end_str
        );

        // Build API request for this chunk
        let mut request = AuditReportRequest::new(&chunk_start_str, Some(chunk_end_str));
        if let Some(ref actions) = config.audit_actions
            && !actions.is_empty()
        {
            request = request.with_audit_actions(actions.to_vec());
        }
        if let Some(ref types) = config.action_types
            && !types.is_empty()
        {
            request = request.with_action_types(types.to_vec());
        }

        // Use refreshed client if available
        let active_client = refreshed_client.as_ref().unwrap_or(client);
        let reporting_api = active_client.reporting_api();

        // Stream batches for this chunk, writing each immediately
        let stream =
            reporting_api.get_audit_logs_stream(request.clone(), config.flush_threshold_bytes);
        tokio::pin!(stream);
        let mut chunk_had_data = false;
        let mut chunk_auth_error: Option<veracode_platform::VeracodeError> = None;

        while let Some(result) = stream.next().await {
            match result {
                Ok(batch) if batch.is_empty() => {
                    // Empty batch, continue
                }
                Ok(batch) => {
                    chunk_had_data = true;

                    if let Some(ref kinesis) = config.kinesis_output {
                        // Update cursor state with unfiltered batch (true high-water mark)
                        cycle_state.update(&batch);
                        let filtered = apply_cursor_filter(&batch, stream_cursor.as_ref());
                        let dup_count = batch.len().saturating_sub(filtered.len());
                        if dup_count > 0 {
                            info!("Filtered {} cursor-boundary duplicate(s)", dup_count);
                        }
                        if !filtered.is_empty() {
                            kinesis
                                .send_records(&filtered, &config.kinesis_partition_key)
                                .await?;
                            info!("Batch of {} records sent to Kinesis", filtered.len());
                        }
                    } else if let Some(ref firehose) = config.firehose_output {
                        cycle_state.update(&batch);
                        let filtered = apply_cursor_filter(&batch, stream_cursor.as_ref());
                        let dup_count = batch.len().saturating_sub(filtered.len());
                        if dup_count > 0 {
                            info!("Filtered {} cursor-boundary duplicate(s)", dup_count);
                        }
                        if !filtered.is_empty() {
                            firehose.send_records(&filtered).await?;
                            info!("Batch of {} records sent to Firehose", filtered.len());
                        }
                    } else {
                        // File output: write to timestamped JSON file
                        let batch_json = serde_json::Value::Array(batch);
                        match output::write_audit_log_file(
                            &config.output_dir,
                            batch_json,
                            config.no_dedup,
                            None,
                        )? {
                            Some(filepath) => {
                                files_written = files_written.saturating_add(1);
                                info!("Batch written to: {}", filepath.display());
                            }
                            None => {
                                info!("Batch had no new logs after deduplication");
                            }
                        }
                    }
                }
                Err(e) => {
                    let audit_err = crate::error::AuditError::from(e);
                    if crate::error::is_auth_error(&audit_err) {
                        // Capture auth error to handle credential refresh after stream drop
                        if let crate::error::AuditError::VeracodeApi(veracode_err) = audit_err {
                            chunk_auth_error = Some(veracode_err);
                        }
                        break;
                    }
                    return Err(audit_err);
                }
            }
        }

        // Handle auth error: refresh credentials and retry this chunk
        if let Some(_auth_err) = chunk_auth_error {
            warn!(
                "Authentication error on chunk {}, attempting credential refresh from Vault",
                chunk_count
            );

            match crate::vault_client::refresh_credentials_from_vault().await {
                Ok((fresh_credentials, proxy_url, proxy_username, proxy_password)) => {
                    info!("Successfully refreshed credentials from Vault, recreating client");

                    let fresh_config = crate::credentials::create_veracode_config_with_proxy(
                        fresh_credentials,
                        &config.region,
                        proxy_url,
                        proxy_username,
                        proxy_password,
                    )
                    .map_err(|_| {
                        crate::error::AuditError::InvalidConfig(
                            "Failed to create Veracode config with refreshed credentials"
                                .to_string(),
                        )
                    })?;

                    let fresh_client = VeracodeClient::new(fresh_config)?;

                    // Retry this chunk with fresh credentials
                    let retry_api = fresh_client.reporting_api();
                    let retry_stream =
                        retry_api.get_audit_logs_stream(request, config.flush_threshold_bytes);
                    tokio::pin!(retry_stream);

                    while let Some(result) = retry_stream.next().await {
                        match result {
                            Ok(batch) if batch.is_empty() => {}
                            Ok(batch) => {
                                chunk_had_data = true;

                                if let Some(ref kinesis) = config.kinesis_output {
                                    cycle_state.update(&batch);
                                    let filtered =
                                        apply_cursor_filter(&batch, stream_cursor.as_ref());
                                    if !filtered.is_empty() {
                                        kinesis
                                            .send_records(&filtered, &config.kinesis_partition_key)
                                            .await?;
                                        info!(
                                            "Batch of {} records sent to Kinesis (after credential refresh)",
                                            filtered.len()
                                        );
                                    }
                                } else if let Some(ref firehose) = config.firehose_output {
                                    cycle_state.update(&batch);
                                    let filtered =
                                        apply_cursor_filter(&batch, stream_cursor.as_ref());
                                    if !filtered.is_empty() {
                                        firehose.send_records(&filtered).await?;
                                        info!(
                                            "Batch of {} records sent to Firehose (after credential refresh)",
                                            filtered.len()
                                        );
                                    }
                                } else {
                                    let batch_json = serde_json::Value::Array(batch);
                                    if let Some(filepath) = output::write_audit_log_file(
                                        &config.output_dir,
                                        batch_json,
                                        config.no_dedup,
                                        None,
                                    )? {
                                        files_written = files_written.saturating_add(1);
                                        info!("Batch written to: {}", filepath.display());
                                    }
                                }
                            }
                            Err(retry_err) => {
                                warn!("Chunk {} failed even after credential refresh", chunk_count);
                                return Err(crate::error::AuditError::from(retry_err));
                            }
                        }
                    }

                    refreshed_client = Some(fresh_client);
                }
                Err(vault_error) => {
                    warn!("Failed to refresh credentials from Vault: {}", vault_error);
                    return Err(crate::error::AuditError::Credential(vault_error));
                }
            }
        }

        // Check backend window for early stop on empty chunks
        if !chunk_had_data {
            #[allow(clippy::arithmetic_side_effects)]
            let minutes_from_now = (now_dt - chunk_end).num_minutes().abs();

            if minutes_from_now <= backend_window_minutes {
                warn!(
                    "Chunk {} returned 0 logs and is within backend refresh window ({} from now, {} minutes old), stopping early",
                    chunk_count, config.backend_window, minutes_from_now
                );
                break;
            }
            info!(
                "Chunk {} returned 0 logs but is {} minutes old (outside {}-minute window), continuing (legitimate gap)",
                chunk_count, minutes_from_now, backend_window_minutes
            );
        }

        current_start = chunk_end;
    }

    info!(
        "Streaming cycle complete: {} chunks processed, {} files written",
        chunk_count, files_written
    );

    // Persist the updated cursor for Kinesis/Firehose output.
    // If no records were seen this cycle the cursor is unchanged (None → skip).
    if is_stream_output && let Some(new_cursor) = cycle_state.into_cursor() {
        let cursor_path = get_cursor_path(config);
        match new_cursor.save(&cursor_path) {
            Ok(()) => info!("Stream cursor updated: timestamp={}", new_cursor.timestamp),
            Err(e) => warn!("Failed to save stream cursor: {}", e),
        }
    }

    Ok(refreshed_client)
}

/// Filter `batch` by removing records already delivered in the previous cycle.
///
/// Only records whose `timestamp_utc` matches the cursor second AND whose hash
/// is in `cursor.last_second_hashes` are removed.  All other records pass through
/// unchanged, so this is a no-op when `cursor` is `None`.
fn apply_cursor_filter(
    batch: &[serde_json::Value],
    cursor: Option<&StreamCursor>,
) -> Vec<serde_json::Value> {
    match cursor {
        None => batch.to_vec(),
        Some(c) => batch
            .iter()
            .filter(|r| !c.is_duplicate(r))
            .cloned()
            .collect(),
    }
}

/// Run a single cleanup cycle
async fn run_cleanup_cycle(config: &ServiceConfig) -> Result<()> {
    if let Some(count) = config.cleanup_count {
        info!("Running cleanup by count (keep {})", count);
        cleanup::cleanup_by_count(&config.output_dir, count)?;
    }

    if let Some(hours) = config.cleanup_hours {
        info!("Running cleanup by age ({} hours)", hours);
        cleanup::cleanup_by_age(&config.output_dir, hours)?;
    }

    Ok(())
}

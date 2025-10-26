//! Service/daemon mode implementation for continuous audit log retrieval
use crate::{audit, cleanup, error::Result, output};
use log::{error, info, warn};
use std::sync::Arc;
use tokio::signal;
use tokio::time::{Duration as TokioDuration, interval};
use veracode_platform::VeracodeClient;

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
    let client = Arc::new(client);

    // Parse interval to get duration in minutes, then convert to seconds
    let interval_minutes = crate::datetime::parse_time_offset(&config.interval)?;

    // Main service loop
    let mut interval_timer = interval(TokioDuration::from_secs((interval_minutes * 60) as u64));
    interval_timer.tick().await; // First tick happens immediately

    loop {
        // Run audit log retrieval
        match run_audit_cycle(&client, &config).await {
            Ok(_) => {
                info!("Audit cycle completed successfully");
            }
            Err(e) => {
                error!("Audit cycle failed: {}", e);
                // Continue running even if one cycle fails
            }
        }

        // Run cleanup if configured
        if (config.cleanup_count.is_some() || config.cleanup_hours.is_some())
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

/// Run a single audit log retrieval cycle
///
/// Service mode retrieves audit logs based on configured start_offset and interval,
/// but will use the timestamp from the last log file if it exists, is within 72 hours,
/// and the no_file_timestamp flag is not set
async fn run_audit_cycle(client: &VeracodeClient, config: &ServiceConfig) -> Result<()> {
    // Determine start datetime with the following priority:
    // 1. If --no-file-timestamp is not set, check for last log file timestamp (if within 72 hours)
    // 2. If not found, too old, or flag is set, use start_offset
    let start_datetime = if !config.no_file_timestamp {
        if let Some(last_timestamp) = output::get_last_log_timestamp(&config.output_dir) {
            // Found a valid timestamp from the last log file (within 72 hours)
            info!(
                "Using timestamp from last log file as start: {}",
                last_timestamp
            );
            last_timestamp
        } else {
            // No valid log file found, use start_offset
            crate::datetime::format_utc_minus_offset(&config.start_offset)?
        }
    } else {
        // File timestamp check is disabled
        crate::datetime::format_utc_minus_offset(&config.start_offset)?
    };

    // Calculate end datetime: now - backend_window
    // This ensures service mode queries to the freshest available data each cycle,
    // properly catching up after downtime instead of only querying one interval at a time
    let now_utc = crate::datetime::format_now_utc();
    let backend_offset_minutes = crate::datetime::parse_time_offset(&config.backend_window)?;
    let end_datetime =
        crate::datetime::subtract_minutes_from_datetime(&now_utc, backend_offset_minutes)?;

    info!(
        "Service cycle will retrieve logs from {} to (now - backend_window) = {}",
        start_datetime, end_datetime
    );

    // Retrieve audit logs using chunked retrieval
    let audit_data = audit::retrieve_audit_logs_chunked(
        client,
        &start_datetime,
        &end_datetime,
        &config.interval,
        &config.backend_window,
        config.audit_actions.clone(),
        config.action_types.clone(),
    )
    .await?;

    // Write to timestamped file (pass start_datetime for deduplication)
    match output::write_audit_log_file(
        &config.output_dir,
        &audit_data,
        config.no_dedup,
        Some(&start_datetime),
    )? {
        Some(filepath) => {
            info!("Audit log saved to: {}", filepath.display());
        }
        None => {
            info!("No new logs found after deduplication, no file created");
        }
    }

    Ok(())
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

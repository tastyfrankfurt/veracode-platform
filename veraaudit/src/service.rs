//! Service/daemon mode implementation for continuous audit log retrieval
use crate::{audit, cleanup, error::Result, output};
use chrono::{Duration, Utc};
use log::{error, info, warn};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::{Duration as TokioDuration, interval};
use veracode_platform::VeracodeClient;

/// Service configuration
pub struct ServiceConfig {
    pub interval_minutes: u64,
    pub output_dir: String,
    pub cleanup_count: Option<usize>,
    pub cleanup_hours: Option<u64>,
    pub audit_actions: Option<Vec<String>>,
    pub action_types: Option<Vec<String>>,
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
    info!("  Interval: {} minutes", config.interval_minutes);
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

    // Create a shutdown signal handler
    let shutdown_flag = Arc::new(Mutex::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();

    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Shutdown signal received, gracefully stopping service...");
        *shutdown_flag_clone.lock().await = true;
    });

    // Main service loop
    let mut interval_timer = interval(TokioDuration::from_secs(config.interval_minutes * 60));
    interval_timer.tick().await; // First tick happens immediately

    loop {
        // Check shutdown flag
        if *shutdown_flag.lock().await {
            info!("Service shutting down");
            break;
        }

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

        // Wait for next interval
        interval_timer.tick().await;
    }

    Ok(())
}

/// Run a single audit log retrieval cycle
///
/// Service mode always retrieves the last 60 minutes of audit logs
async fn run_audit_cycle(client: &VeracodeClient, config: &ServiceConfig) -> Result<()> {
    let now = Utc::now();
    // Fixed 60-minute lookback window for service mode
    let start_time = now - Duration::minutes(60);

    let start_datetime = start_time.format("%Y-%m-%d %H:%M:%S").to_string();
    let end_datetime = now.format("%Y-%m-%d %H:%M:%S").to_string();

    info!(
        "Retrieving audit logs from {} to {}",
        start_datetime, end_datetime
    );

    // Retrieve audit logs
    let audit_data = audit::retrieve_audit_logs(
        client,
        &start_datetime,
        &end_datetime,
        config.audit_actions.clone(),
        config.action_types.clone(),
    )
    .await?;

    // Write to timestamped file
    let filepath = output::write_audit_log_file(&config.output_dir, &audit_data)?;
    info!("Audit log saved to: {}", filepath.display());

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

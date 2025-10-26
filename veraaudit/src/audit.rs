//! Audit log retrieval logic
use crate::error::Result;
use log::{debug, info, warn};
use veracode_platform::{AuditReportRequest, VeracodeClient};

/// Retrieve audit logs for a specific datetime range
///
/// # Arguments
///
/// * `client` - Veracode API client
/// * `start_datetime` - Start datetime (format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
/// * `end_datetime` - Optional end datetime (same formats as start_datetime)
/// * `audit_actions` - Optional list of audit actions to filter
/// * `action_types` - Optional list of action types to filter
///
/// # Returns
///
/// JSON data containing the audit logs
///
/// # Errors
///
/// Returns error if API request fails
pub async fn retrieve_audit_logs(
    client: &VeracodeClient,
    start_datetime: &str,
    end_datetime: &str,
    audit_actions: Option<Vec<String>>,
    action_types: Option<Vec<String>>,
) -> Result<serde_json::Value> {
    debug!(
        "Building audit report request for datetime range: {} to {}",
        start_datetime, end_datetime
    );

    // Build the audit report request
    let mut request = AuditReportRequest::new(start_datetime, Some(end_datetime.to_string()));

    if let Some(actions) = audit_actions
        && !actions.is_empty()
    {
        debug!("Adding audit action filters: [{}]", actions.join(", "));
        request = request.with_audit_actions(actions);
    }

    if let Some(types) = action_types
        && !types.is_empty()
    {
        debug!("Adding action type filters: [{}]", types.join(", "));
        request = request.with_action_types(types);
    }

    // Retrieve audit logs using the reporting API
    info!("Retrieving audit logs from Veracode API");
    let reporting_api = client.reporting_api();
    let audit_logs = reporting_api.get_audit_logs(&request).await?;

    info!("Successfully retrieved audit logs");
    Ok(audit_logs)
}

/// Retrieve audit logs in chunks to handle backend refresh cycles
///
/// Queries the API in smaller interval-sized chunks from start to end (or now, whichever is earlier).
/// Only stops early if a chunk returns no logs AND is within the backend refresh window from now.
///
/// # Arguments
///
/// * `client` - Veracode API client
/// * `start_datetime` - Start datetime (format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
/// * `end_datetime` - End datetime (format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
/// * `interval_str` - Interval/chunk size (format: Nm, Nh, Nd or just N for minutes)
/// * `backend_window_str` - Backend refresh window (format: Nm, Nh, e.g., "2h", "90m")
/// * `audit_actions` - Optional list of audit actions to filter
/// * `action_types` - Optional list of action types to filter
///
/// # Returns
///
/// JSON array containing aggregated audit logs from all chunks
///
/// # Errors
///
/// Returns error if API request fails or datetime parsing fails
pub async fn retrieve_audit_logs_chunked(
    client: &VeracodeClient,
    start_datetime: &str,
    end_datetime: &str,
    interval_str: &str,
    backend_window_str: &str,
    audit_actions: Option<Vec<String>>,
    action_types: Option<Vec<String>>,
) -> Result<serde_json::Value> {
    info!(
        "Starting chunked retrieval from {} to {} with interval {}",
        start_datetime, end_datetime, interval_str
    );

    // Parse interval to minutes
    let interval_minutes = crate::datetime::parse_time_offset(interval_str)?;
    debug!("Parsed interval: {} minutes", interval_minutes);

    // Parse backend refresh window to minutes
    let backend_window_minutes = crate::datetime::parse_time_offset(backend_window_str)?;
    debug!("Backend refresh window: {} minutes", backend_window_minutes);

    // Parse start and end datetimes
    let start_dt = crate::datetime::try_parse_datetime(start_datetime)?;
    let end_dt = crate::datetime::try_parse_datetime(end_datetime)?;

    // Get current UTC time and cap end_datetime at now
    let now_utc_str = crate::datetime::format_now_utc();
    let now_dt = crate::datetime::try_parse_datetime(&now_utc_str)?;

    let effective_end = if end_dt > now_dt {
        info!("End datetime {} is in the future, capping at current time {}", end_datetime, now_utc_str);
        now_dt
    } else {
        end_dt
    };

    // Prepare to aggregate logs
    let mut all_logs: Vec<serde_json::Value> = Vec::new();
    let mut current_start = start_dt;
    let mut chunk_count = 0;

    // Loop through chunks
    while current_start < effective_end {
        chunk_count += 1;

        // Calculate chunk end: current_start + interval (but not beyond effective_end)
        let chunk_end_calculated = current_start + chrono::Duration::minutes(interval_minutes);
        let chunk_end = if chunk_end_calculated > effective_end {
            effective_end
        } else {
            chunk_end_calculated
        };

        // Format datetimes for API
        let chunk_start_str = current_start.format("%Y-%m-%d %H:%M:%S").to_string();
        let chunk_end_str = chunk_end.format("%Y-%m-%d %H:%M:%S").to_string();

        info!(
            "Querying chunk {} from {} to {}",
            chunk_count, chunk_start_str, chunk_end_str
        );

        // Retrieve logs for this chunk
        let chunk_data = retrieve_audit_logs(
            client,
            &chunk_start_str,
            &chunk_end_str,
            audit_actions.clone(),
            action_types.clone(),
        )
        .await?;

        // Check if chunk returned logs
        let chunk_logs = chunk_data.as_array().ok_or_else(|| {
            crate::error::AuditError::InvalidConfig(
                "API response is not a JSON array".to_string()
            )
        })?;

        if chunk_logs.is_empty() {
            // Check if chunk end is within backend refresh window from now
            let minutes_from_now = (now_dt - chunk_end).num_minutes().abs();

            if minutes_from_now <= backend_window_minutes {
                warn!(
                    "Chunk {} returned 0 logs and is within backend refresh window ({} from now, {} minutes old), stopping early",
                    chunk_count, backend_window_str, minutes_from_now
                );
                break;
            } else {
                info!(
                    "Chunk {} returned 0 logs but is {} minutes old (outside {}-minute window), continuing (legitimate gap)",
                    chunk_count, minutes_from_now, backend_window_minutes
                );
                // Continue to next chunk without adding any logs
            }
        } else {
            info!("Chunk {} returned {} logs", chunk_count, chunk_logs.len());

            // Aggregate logs
            all_logs.extend(chunk_logs.iter().cloned());
        }

        // Move to next chunk
        current_start = chunk_end;
    }

    info!(
        "Chunked retrieval complete: {} chunks processed, {} total logs retrieved",
        chunk_count,
        all_logs.len()
    );

    // Return aggregated logs as JSON array
    Ok(serde_json::Value::Array(all_logs))
}

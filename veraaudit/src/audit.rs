//! Audit log retrieval logic
use crate::error::Result;
use log::{debug, info};
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
    end_datetime: Option<String>,
    audit_actions: Option<Vec<String>>,
    action_types: Option<Vec<String>>,
) -> Result<serde_json::Value> {
    debug!(
        "Building audit report request for datetime range: {} to {:?}",
        start_datetime, end_datetime
    );

    // Build the audit report request
    let mut request = AuditReportRequest::new(start_datetime, end_datetime);

    if let Some(actions) = audit_actions
        && !actions.is_empty()
    {
        debug!("Adding audit action filters: {:?}", actions);
        request = request.with_audit_actions(actions);
    }

    if let Some(types) = action_types
        && !types.is_empty()
    {
        debug!("Adding action type filters: {:?}", types);
        request = request.with_action_types(types);
    }

    // Retrieve audit logs using the reporting API
    info!("Retrieving audit logs from Veracode API");
    let reporting_api = client.reporting_api();
    let audit_logs = reporting_api.get_audit_logs(&request).await?;

    info!("Successfully retrieved audit logs");
    Ok(audit_logs)
}

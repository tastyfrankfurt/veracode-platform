//! Veracode Reporting API
//!
//! This module provides access to the Veracode Reporting REST API for retrieving
//! audit logs and generating compliance reports.
use crate::{VeracodeClient, VeracodeError};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::America::New_York;
use serde::{Deserialize, Serialize};

/// Request payload for generating an audit report
#[derive(Debug, Clone, Serialize)]
pub struct AuditReportRequest {
    /// The type of report to generate (always "AUDIT" for audit logs)
    pub report_type: String,
    /// Start date in YYYY-MM-DD format
    pub start_date: String,
    /// Optional end date in YYYY-MM-DD format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<String>,
    /// Optional list of audit actions to filter (e.g., "Delete", "Create", "Update")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_action: Option<Vec<String>>,
    /// Optional list of action types to filter (e.g., "Login", "Admin")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<Vec<String>>,
    /// Optional list of target user IDs to filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user_id: Option<Vec<String>>,
    /// Optional list of modifier user IDs to filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modifier_user_id: Option<Vec<String>>,
}

impl AuditReportRequest {
    /// Create a new audit report request with just start and end dates
    #[must_use]
    pub fn new(start_date: impl Into<String>, end_date: Option<String>) -> Self {
        Self {
            report_type: "AUDIT".to_string(),
            start_date: start_date.into(),
            end_date,
            audit_action: None,
            action_type: None,
            target_user_id: None,
            modifier_user_id: None,
        }
    }

    /// Add audit action filters
    #[must_use]
    pub fn with_audit_actions(mut self, actions: Vec<String>) -> Self {
        self.audit_action = Some(actions);
        self
    }

    /// Add action type filters
    #[must_use]
    pub fn with_action_types(mut self, types: Vec<String>) -> Self {
        self.action_type = Some(types);
        self
    }

    /// Add target user ID filters
    #[must_use]
    pub fn with_target_users(mut self, user_ids: Vec<String>) -> Self {
        self.target_user_id = Some(user_ids);
        self
    }

    /// Add modifier user ID filters
    #[must_use]
    pub fn with_modifier_users(mut self, user_ids: Vec<String>) -> Self {
        self.modifier_user_id = Some(user_ids);
        self
    }
}

/// Embedded data in generate report response
#[derive(Debug, Clone, Deserialize)]
pub struct GenerateReportData {
    /// The report ID used to retrieve the generated report
    pub id: String,
}

/// Response when generating a report
#[derive(Debug, Clone, Deserialize)]
pub struct GenerateReportResponse {
    /// Embedded report data
    #[serde(rename = "_embedded")]
    pub embedded: GenerateReportData,
}

/// Report status values
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ReportStatus {
    /// Report request has been queued
    Queued,
    /// Report request has been submitted
    Submitted,
    /// Report is being processed
    Processing,
    /// Report has been completed and is ready
    Completed,
    /// Report generation failed
    Failed,
}

/// Pagination links for navigating report pages
#[derive(Debug, Clone, Deserialize)]
pub struct ReportLinks {
    /// Link to first page
    pub first: Option<LinkHref>,
    /// Link to previous page
    pub prev: Option<LinkHref>,
    /// Link to current page (self)
    #[serde(rename = "self")]
    pub self_link: Option<LinkHref>,
    /// Link to next page
    pub next: Option<LinkHref>,
    /// Link to last page
    pub last: Option<LinkHref>,
}

/// A link with href field
#[derive(Debug, Clone, Deserialize)]
pub struct LinkHref {
    /// The URL path for the link
    pub href: String,
}

/// Page metadata for pagination
#[derive(Debug, Clone, Deserialize)]
pub struct PageMetadata {
    /// Current page number (0-indexed)
    pub number: u32,
    /// Number of items per page
    pub size: u32,
    /// Total number of audit log entries across all pages
    pub total_elements: u32,
    /// Total number of pages
    pub total_pages: u32,
}

/// A single audit log entry
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditLogEntry {
    /// Auditor ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auditor_id: Option<String>,
    /// Target login account ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_login_account_id: Option<String>,
    /// Modifier login account ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modifier_login_account_id: Option<String>,
    /// Target user username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user_username: Option<String>,
    /// Target user first name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user_first_name: Option<String>,
    /// Target user last name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user_last_name: Option<String>,
    /// Target user email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_user_email: Option<String>,
    /// Modifier user username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modifier_user_username: Option<String>,
    /// Modifier user first name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modifier_user_first_name: Option<String>,
    /// Modifier user last name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modifier_user_last_name: Option<String>,
    /// Modifier user email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modifier_user_email: Option<String>,
    /// Modifier host (IP address)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modifier_host: Option<String>,
    /// Action type (e.g., "Auth", "Admin", "Login")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    /// Action (e.g., "Delete", "Create", "Update")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Detailed action description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_detail: Option<String>,
    /// Timestamp of the action (US-East-1 timezone from API)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Timestamp converted to UTC (computed from timestamp field)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_utc: Option<String>,
}

/// Report data embedded in the response
#[derive(Debug, Clone, Deserialize)]
pub struct ReportData {
    /// Report ID
    pub id: String,
    /// Report type (always "AUDIT" for audit reports)
    pub report_type: String,
    /// Current status of the report
    pub status: ReportStatus,
    /// User who requested the report
    pub requested_by_user: String,
    /// Account ID that requested the report
    pub requested_by_account: u64,
    /// Date when report was requested
    pub date_report_requested: String,
    /// Date when report was completed (null if not completed)
    pub date_report_completed: Option<String>,
    /// Date when report expires (null if not completed)
    pub report_expiration_date: Option<String>,
    /// Array of audit log entries
    pub audit_logs: Vec<AuditLogEntry>,
    /// Links for pagination (null if not completed)
    #[serde(rename = "_links")]
    pub links: Option<ReportLinks>,
    /// Page metadata (null if not completed)
    pub page_metadata: Option<PageMetadata>,
}

/// Full report response with embedded data
#[derive(Debug, Clone, Deserialize)]
pub struct ReportResponse {
    /// Embedded report data
    #[serde(rename = "_embedded")]
    pub embedded: ReportData,
}

/// Convert a timestamp from US-East-1 timezone to UTC
///
/// The Veracode API returns timestamps in America/New_York timezone.
/// This function automatically handles Daylight Saving Time (DST) transitions:
/// - EDT (Eastern Daylight Time): UTC-4 (second Sunday in March - first Sunday in November)
/// - EST (Eastern Standard Time): UTC-5 (first Sunday in November - second Sunday in March)
///
/// # Arguments
///
/// * `timestamp_str` - Timestamp string in format "YYYY-MM-DD HH:MM:SS.sss"
///
/// # Returns
///
/// UTC timestamp string in same format, or None if parsing fails
///
/// # Examples
///
/// ```ignore
/// // Summer timestamp (EDT, UTC-4)
/// let utc = convert_us_east_to_utc("2025-06-15 14:30:00.000");
/// assert_eq!(utc, Some("2025-06-15 18:30:00.000".to_string()));
///
/// // Winter timestamp (EST, UTC-5)
/// let utc = convert_us_east_to_utc("2025-12-15 14:30:00.000");
/// assert_eq!(utc, Some("2025-12-15 19:30:00.000".to_string()));
/// ```
fn convert_us_east_to_utc(timestamp_str: &str) -> Option<String> {
    // Parse timestamp string - handle variable-length milliseconds
    let has_millis = timestamp_str.contains('.');

    // Parse the base datetime without milliseconds
    let naive_dt = if has_millis {
        // Try to parse with variable-length fractional seconds
        // The %.f format is flexible and handles 1-9 digits
        NaiveDateTime::parse_from_str(timestamp_str, "%Y-%m-%d %H:%M:%S%.f").ok()?
    } else {
        NaiveDateTime::parse_from_str(timestamp_str, "%Y-%m-%d %H:%M:%S").ok()?
    };

    // Convert to New York timezone (handles DST automatically)
    let ny_time: DateTime<_> = New_York.from_local_datetime(&naive_dt).single()?;

    // Convert to UTC
    let utc_time = ny_time.with_timezone(&Utc);

    // Format back to string (preserve original millisecond precision)
    if has_millis {
        // Format with the same number of decimal places as input
        let formatted = utc_time.format("%Y-%m-%d %H:%M:%S%.f").to_string();
        // Ensure we preserve the original precision
        Some(formatted)
    } else {
        Some(utc_time.format("%Y-%m-%d %H:%M:%S").to_string())
    }
}

/// The Reporting API interface
#[derive(Clone)]
pub struct ReportingApi {
    client: VeracodeClient,
}

impl ReportingApi {
    /// Create a new Reporting API instance
    #[must_use]
    pub fn new(client: VeracodeClient) -> Self {
        Self { client }
    }

    /// Generate an audit report (step 1 of the process)
    ///
    /// This sends a request to generate the report. The API returns a report_id
    /// which can be used to retrieve the report after it's generated.
    ///
    /// # Arguments
    ///
    /// * `request` - The audit report request parameters
    ///
    /// # Returns
    ///
    /// The report ID that can be used to retrieve the generated report
    ///
    /// # Errors
    ///
    /// Returns `VeracodeError` if the request fails
    pub async fn generate_audit_report(
        &self,
        request: &AuditReportRequest,
    ) -> Result<String, VeracodeError> {
        let response = self
            .client
            .post("/appsec/v1/analytics/report", Some(request))
            .await?;

        let response_text = response.text().await?;
        log::debug!("Generate report API response: {}", response_text);

        let generate_response: GenerateReportResponse = serde_json::from_str(&response_text)?;
        Ok(generate_response.embedded.id)
    }

    /// Retrieve a generated audit report (step 2 of the process)
    ///
    /// This retrieves the report content. The report may still be processing,
    /// so check the status field in the response.
    ///
    /// # Arguments
    ///
    /// * `report_id` - The report ID returned from `generate_audit_report`
    /// * `page` - Optional page number (0-indexed) for pagination
    ///
    /// # Returns
    ///
    /// The report response with status and audit log data
    ///
    /// # Errors
    ///
    /// Returns `VeracodeError` if the request fails
    pub async fn get_audit_report(
        &self,
        report_id: &str,
        page: Option<u32>,
    ) -> Result<ReportResponse, VeracodeError> {
        let endpoint = if let Some(page_num) = page {
            format!("/appsec/v1/analytics/report/{report_id}?page={page_num}")
        } else {
            format!("/appsec/v1/analytics/report/{report_id}")
        };

        let response = self.client.get(&endpoint, None).await?;
        let response_text = response.text().await?;
        log::debug!("Get audit report API response: {}", response_text);

        let report_response: ReportResponse = serde_json::from_str(&response_text)?;
        Ok(report_response)
    }

    /// Poll for report status until it's completed or failed
    ///
    /// This method polls the report status with exponential backoff until
    /// the report is either completed or failed.
    ///
    /// # Arguments
    ///
    /// * `report_id` - The report ID to poll
    /// * `max_attempts` - Maximum number of polling attempts (default: 30)
    /// * `initial_delay_secs` - Initial delay between polls in seconds (default: 2)
    ///
    /// # Returns
    ///
    /// The completed report response
    ///
    /// # Errors
    ///
    /// Returns `VeracodeError` if polling fails or report generation fails
    pub async fn poll_report_status(
        &self,
        report_id: &str,
        max_attempts: Option<u32>,
        initial_delay_secs: Option<u64>,
    ) -> Result<ReportResponse, VeracodeError> {
        let max_attempts = max_attempts.unwrap_or(30);
        let initial_delay = initial_delay_secs.unwrap_or(2);

        let mut attempts = 0;
        let mut delay_secs = initial_delay;

        loop {
            attempts += 1;

            // Get current report status
            let report = self.get_audit_report(report_id, None).await?;
            let status = &report.embedded.status;

            log::debug!(
                "Report {} status: {:?} (attempt {}/{})",
                report_id,
                status,
                attempts,
                max_attempts
            );

            match status {
                ReportStatus::Completed => {
                    log::info!("Report {} completed successfully", report_id);
                    return Ok(report);
                }
                ReportStatus::Failed => {
                    return Err(VeracodeError::InvalidResponse(format!(
                        "Report generation failed for report ID: {}",
                        report_id
                    )));
                }
                ReportStatus::Queued | ReportStatus::Submitted | ReportStatus::Processing => {
                    if attempts >= max_attempts {
                        return Err(VeracodeError::InvalidResponse(format!(
                            "Report polling timeout after {} attempts. Status: {:?}",
                            attempts, status
                        )));
                    }

                    log::debug!("Report still processing, waiting {} seconds...", delay_secs);
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;

                    // Exponential backoff with max delay of 30 seconds
                    delay_secs = std::cmp::min(delay_secs * 2, 30);
                }
            }
        }
    }

    /// Retrieve all audit logs across all pages
    ///
    /// This method handles pagination automatically and collects all audit log
    /// entries from all pages into a single vector.
    ///
    /// # Arguments
    ///
    /// * `report_id` - The report ID (must be in COMPLETED status)
    ///
    /// # Returns
    ///
    /// A vector containing all audit log entries from all pages
    ///
    /// # Errors
    ///
    /// Returns `VeracodeError` if any page retrieval fails
    pub async fn get_all_audit_log_pages(
        &self,
        report_id: &str,
    ) -> Result<Vec<AuditLogEntry>, VeracodeError> {
        let mut all_logs = Vec::new();

        // Get report status without page parameter first
        let initial_report = self.get_audit_report(report_id, None).await?;

        // Check if report is completed
        if initial_report.embedded.status != ReportStatus::Completed {
            return Err(VeracodeError::InvalidResponse(format!(
                "Report is not completed. Status: {:?}",
                initial_report.embedded.status
            )));
        }

        // Check if there are any results
        let page_metadata = match initial_report.embedded.page_metadata {
            Some(metadata) if metadata.total_elements > 0 => metadata,
            Some(metadata) => {
                // Report has metadata but no elements (total_elements = 0)
                log::info!(
                    "Report completed but contains no audit log entries (0 total elements, {} total pages)",
                    metadata.total_pages
                );
                return Ok(all_logs); // Return empty vector
            }
            None => {
                // No metadata at all
                log::info!("Report completed but contains no audit log entries (no page metadata)");
                return Ok(all_logs); // Return empty vector
            }
        };

        // Now get first page since we know there are results
        let first_page = self.get_audit_report(report_id, Some(0)).await?;

        // Add logs from first page
        let first_page_count = first_page.embedded.audit_logs.len();
        all_logs.extend(first_page.embedded.audit_logs);

        log::info!(
            "Retrieved page 1/{} ({} entries, {} total)",
            page_metadata.total_pages,
            first_page_count,
            page_metadata.total_elements
        );

        // If there are more pages, retrieve them
        if page_metadata.total_pages > 1 {
            for page_num in 1..page_metadata.total_pages {
                log::debug!(
                    "Retrieving page {}/{}",
                    page_num + 1,
                    page_metadata.total_pages
                );

                let page_response = self.get_audit_report(report_id, Some(page_num)).await?;
                let page_count = page_response.embedded.audit_logs.len();
                all_logs.extend(page_response.embedded.audit_logs);

                log::info!(
                    "Retrieved page {}/{} ({} entries)",
                    page_num + 1,
                    page_metadata.total_pages,
                    page_count
                );
            }
        }

        log::info!(
            "Successfully retrieved all {} audit log entries across {} pages",
            all_logs.len(),
            page_metadata.total_pages
        );

        // Convert timestamps from US-East-1 to UTC
        let mut conversion_stats = (0, 0); // (successes, failures)
        for entry in &mut all_logs {
            if let Some(ref timestamp) = entry.timestamp {
                match convert_us_east_to_utc(timestamp) {
                    Some(utc_timestamp) => {
                        entry.timestamp_utc = Some(utc_timestamp);
                        conversion_stats.0 += 1;
                    }
                    None => {
                        log::warn!("Failed to convert timestamp to UTC: {}", timestamp);
                        conversion_stats.1 += 1;
                    }
                }
            }
        }

        log::info!(
            "Converted {} timestamps from AWS US-East-1 timezone (EST/EDT, UTC-5/-4) to UTC ({} failures)",
            conversion_stats.0,
            conversion_stats.1
        );

        Ok(all_logs)
    }

    /// Convenience method to generate and retrieve audit logs in one call
    ///
    /// This method combines report generation, status polling, and pagination
    /// to retrieve all audit logs. It's the recommended way to retrieve audit logs.
    ///
    /// # Arguments
    ///
    /// * `request` - The audit report request parameters
    ///
    /// # Returns
    ///
    /// The audit log data as a JSON value containing all entries from all pages
    ///
    /// # Errors
    ///
    /// Returns `VeracodeError` if the request fails
    pub async fn get_audit_logs(
        &self,
        request: &AuditReportRequest,
    ) -> Result<serde_json::Value, VeracodeError> {
        // Step 1: Generate the report
        log::info!(
            "Generating audit report for date range: {} to {:?}",
            request.start_date,
            request.end_date
        );
        let report_id = self.generate_audit_report(request).await?;
        log::info!("Report generated with ID: {}", report_id);

        // Step 2: Poll for report completion
        log::info!("Polling for report completion...");
        let completed_report = self.poll_report_status(&report_id, None, None).await?;
        log::info!(
            "Report completed at: {:?}",
            completed_report.embedded.date_report_completed
        );

        // Step 3: Retrieve all pages
        log::info!("Retrieving all audit log pages...");
        let all_logs = self.get_all_audit_log_pages(&report_id).await?;

        // Convert to JSON for backward compatibility with veraaudit
        let json_logs = serde_json::to_value(&all_logs)?;
        log::info!(
            "Successfully retrieved {} total audit log entries",
            all_logs.len()
        );

        Ok(json_logs)
    }
}

/// Error type for reporting operations
#[derive(Debug, thiserror::Error)]
pub enum ReportingError {
    /// Wraps a Veracode API error
    #[error("Veracode API error: {0}")]
    VeracodeApi(#[from] VeracodeError),

    /// Invalid date format
    #[error("Invalid date format: {0}")]
    InvalidDate(String),

    /// Date range exceeds maximum allowed (6 months)
    #[error("Date range exceeds maximum allowed: {0}")]
    DateRangeExceeded(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_report_request_new() {
        let request = AuditReportRequest::new("2025-01-01", Some("2025-01-31".to_string()));

        assert_eq!(request.report_type, "AUDIT");
        assert_eq!(request.start_date, "2025-01-01");
        assert_eq!(request.end_date, Some("2025-01-31".to_string()));
        assert!(request.audit_action.is_none());
        assert!(request.action_type.is_none());
    }

    #[test]
    fn test_audit_report_request_with_filters() {
        let request = AuditReportRequest::new("2025-01-01", Some("2025-01-31".to_string()))
            .with_audit_actions(vec!["Delete".to_string(), "Create".to_string()])
            .with_action_types(vec!["Admin".to_string()]);

        assert_eq!(
            request.audit_action,
            Some(vec!["Delete".to_string(), "Create".to_string()])
        );
        assert_eq!(request.action_type, Some(vec!["Admin".to_string()]));
    }

    #[test]
    fn test_audit_report_request_serialization() {
        let request = AuditReportRequest::new("2025-01-01", Some("2025-01-31".to_string()));
        let json = serde_json::to_string(&request).unwrap();

        assert!(json.contains("\"report_type\":\"AUDIT\""));
        assert!(json.contains("\"start_date\":\"2025-01-01\""));
        assert!(json.contains("\"end_date\":\"2025-01-31\""));
    }

    #[test]
    fn test_audit_report_request_serialization_without_optional_fields() {
        let request = AuditReportRequest::new("2025-01-01", None);
        let json = serde_json::to_string(&request).unwrap();

        // Optional fields should not be present when None
        assert!(!json.contains("end_date"));
        assert!(!json.contains("audit_action"));
        assert!(!json.contains("action_type"));
    }
}

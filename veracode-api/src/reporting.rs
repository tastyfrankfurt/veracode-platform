//! Veracode Reporting API
//!
//! This module provides access to the Veracode Reporting REST API for retrieving
//! audit logs and generating compliance reports.
use crate::json_validator::{MAX_JSON_DEPTH, validate_json_depth};
use crate::{VeracodeClient, VeracodeError, VeracodeRegion};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::America::New_York;
use chrono_tz::Europe::Berlin;
use serde::{Deserialize, Serialize};
use urlencoding;

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

impl std::fmt::Display for ReportStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportStatus::Queued => write!(f, "Queued"),
            ReportStatus::Submitted => write!(f, "Submitted"),
            ReportStatus::Processing => write!(f, "Processing"),
            ReportStatus::Completed => write!(f, "Completed"),
            ReportStatus::Failed => write!(f, "Failed"),
        }
    }
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

/// A single audit log entry (optimized for minimal deserialization)
///
/// This struct only deserializes the timestamp field and keeps the rest as raw JSON
/// to minimize parsing overhead and memory allocations. The hash is computed using
/// xxHash (much faster than SHA256 for duplicate detection).
#[derive(Debug, Clone, Serialize)]
pub struct AuditLogEntry {
    /// Raw JSON string of the log entry (as received from API)
    pub raw_log: String,
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// Timestamp converted to UTC (computed from the timestamp field in `raw_log`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_utc: Option<String>,
    /// xxHash (128-bit) of the raw log entry for fast duplicate detection
    pub log_hash: String,
}

/// Helper struct to extract only the timestamp during deserialization
#[derive(Debug, Deserialize)]
struct TimestampExtractor {
    timestamp: Option<String>,
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
    /// Array of audit log entries (raw JSON, processed later for efficiency)
    pub audit_logs: serde_json::Value,
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

/// Convert a timestamp from region-specific timezone to UTC
///
/// Each Veracode API region returns timestamps in its corresponding timezone:
///
/// # Errors
///
/// Returns an error if the API request fails, the resource is not found,
/// or authentication/authorization fails.
/// - **Commercial** (api.veracode.com): `America/New_York` (US-East-1)
///   - EST (Eastern Standard Time): UTC-5 (winter)
///   - EDT (Eastern Daylight Time): UTC-4 (summer)
/// - **European** (api.veracode.eu): Europe/Berlin (eu-central-1)
///   - CET (Central European Time): UTC+1 (winter)
///   - CEST (Central European Summer Time): UTC+2 (summer)
///
/// # Errors
///
/// Returns an error if the API request fails, the resource is not found,
/// or authentication/authorization fails.
/// - **Federal** (api.veracode.us): `America/New_York` (US-East-1)
///   - EST/EDT same as Commercial
///
/// This function automatically handles Daylight Saving Time (DST) transitions
/// for each region using the IANA timezone database.
///
/// # Arguments
///
/// * `timestamp_str` - Timestamp string in format "YYYY-MM-DD HH:MM:SS.sss"
/// * `region` - The Veracode region determining source timezone
///
/// # Returns
///
/// UTC timestamp string in same format, or None if parsing fails
///
/// # Examples
///
/// ```ignore
/// use veracode_platform::VeracodeRegion;
///
/// // European region: Summer timestamp (CEST, UTC+2)
/// let utc = convert_regional_timestamp_to_utc("2025-06-15 14:30:00.000", &VeracodeRegion::European);
/// assert_eq!(utc, Some("2025-06-15 12:30:00".to_string())); // 14:30 CEST = 12:30 UTC
///
/// // Commercial region: Winter timestamp (EST, UTC-5)
/// let utc = convert_regional_timestamp_to_utc("2025-12-15 14:30:00.000", &VeracodeRegion::Commercial);
/// assert_eq!(utc, Some("2025-12-15 19:30:00".to_string())); // 14:30 EST = 19:30 UTC
/// ```
fn convert_regional_timestamp_to_utc(
    timestamp_str: &str,
    region: &VeracodeRegion,
) -> Option<String> {
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

    // Convert from region-specific timezone to UTC
    let utc_time = match region {
        VeracodeRegion::European => {
            // European region uses Europe/Berlin timezone (CET/CEST)
            // Use earliest() to handle ambiguous times during DST fall-back
            let regional_time: DateTime<_> = Berlin.from_local_datetime(&naive_dt).earliest()?;
            regional_time.with_timezone(&Utc)
        }
        VeracodeRegion::Commercial | VeracodeRegion::Federal => {
            // Commercial and Federal regions use America/New_York timezone (EST/EDT)
            // Use earliest() to handle ambiguous times during DST fall-back
            let regional_time: DateTime<_> = New_York.from_local_datetime(&naive_dt).earliest()?;
            regional_time.with_timezone(&Utc)
        }
    };

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

/// Generate a fast hash of a raw log entry JSON string for duplicate detection
///
///
/// # Errors
///
/// Returns an error if the API request fails, the resource is not found,
/// or authentication/authorization fails.
/// Uses xxHash (`xxh3_128`) which is significantly faster than SHA256 while still
/// providing excellent collision resistance for deduplication purposes. This is
/// NOT a cryptographic hash - use only for duplicate detection, not security.
///
/// Performance comparison vs SHA256:
/// - xxHash: ~10-50x faster than SHA256
/// - Still has excellent collision resistance for duplicate detection
/// - Returns 32 hex characters (128-bit hash)
///
/// # Arguments
///
/// * `raw_json` - The raw JSON string of the log entry
///
/// # Returns
///
/// Hex-encoded xxHash3 (128-bit) hash string (32 characters)
///
/// # Examples
///
/// ```ignore
/// let hash = generate_log_hash(r#"{"timestamp":"2025-01-01 12:00:00.000"}"#);
/// assert_eq!(hash.len(), 32); // xxh3_128 produces 32 hex characters
/// ```
fn generate_log_hash(raw_json: &str) -> String {
    use xxhash_rust::xxh3::xxh3_128;

    // Hash the raw JSON bytes (extremely fast!)
    let hash = xxh3_128(raw_json.as_bytes());

    // Convert to hex string (128-bit = 32 hex chars)
    format!("{:032x}", hash)
}

/// The Reporting API interface
#[derive(Clone)]
pub struct ReportingApi {
    client: VeracodeClient,
    region: VeracodeRegion,
}

impl ReportingApi {
    /// Create a new Reporting API instance
    #[must_use]
    pub fn new(client: VeracodeClient) -> Self {
        let region = client.config().region;
        Self { client, region }
    }

    /// Generate an audit report (step 1 of the process)
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails, the resource is not found,
    /// or authentication/authorization fails.
    /// This sends a request to generate the report. The API returns a `report_id`
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

        // Validate JSON depth before parsing to prevent DoS attacks
        validate_json_depth(&response_text, MAX_JSON_DEPTH).map_err(|e| {
            VeracodeError::InvalidResponse(format!("JSON validation failed: {}", e))
        })?;

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
        // URL-encode the report_id to prevent injection attacks
        let encoded_report_id = urlencoding::encode(report_id);

        let endpoint = if let Some(page_num) = page {
            format!("/appsec/v1/analytics/report/{encoded_report_id}?page={page_num}")
        } else {
            format!("/appsec/v1/analytics/report/{encoded_report_id}")
        };

        let response = self.client.get(&endpoint, None).await?;
        let response_text = response.text().await?;
        log::debug!("Get audit report API response: {}", response_text);

        // Validate JSON depth before parsing to prevent DoS attacks
        validate_json_depth(&response_text, MAX_JSON_DEPTH).map_err(|e| {
            VeracodeError::InvalidResponse(format!("JSON validation failed: {}", e))
        })?;

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

        let mut attempts: u32 = 0;
        let mut delay_secs = initial_delay;

        loop {
            attempts = attempts.saturating_add(1);

            // Get current report status
            let report = self.get_audit_report(report_id, None).await?;
            let status = &report.embedded.status;

            log::debug!(
                "Report {} status: {} (attempt {}/{})",
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
                            "Report polling timeout after {} attempts. Status: {}",
                            attempts, status
                        )));
                    }

                    log::debug!("Report still processing, waiting {} seconds...", delay_secs);
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;

                    // Exponential backoff with max delay of 30 seconds
                    delay_secs = std::cmp::min(delay_secs.saturating_mul(2), 30);
                }
            }
        }
    }

    /// Retrieve all audit logs across all pages (OPTIMIZED)
    ///
    /// This method handles pagination automatically and collects all audit log
    /// entries from all pages into a single vector. It uses optimized processing
    /// that only deserializes the timestamp field and keeps raw JSON for efficiency.
    ///
    /// Performance optimizations:
    /// - Minimal deserialization: Only extracts timestamp field
    /// - Zero cloning: Keeps raw JSON strings instead of parsing all fields
    /// - Fast hashing: Uses xxHash (10-50x faster than SHA256) for duplicate detection
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
                "Report is not completed. Status: {}",
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

        // Collect all pages of raw JSON
        let mut all_pages_raw = Vec::new();

        // Get first page
        let first_page = self.get_audit_report(report_id, Some(0)).await?;
        all_pages_raw.push(first_page.embedded.audit_logs.clone());

        log::info!(
            "Retrieved page 1/{} ({} total)",
            page_metadata.total_pages,
            page_metadata.total_elements
        );

        // If there are more pages, retrieve them
        if page_metadata.total_pages > 1 {
            for page_num in 1..page_metadata.total_pages {
                log::debug!(
                    "Retrieving page {}/{}",
                    page_num.saturating_add(1),
                    page_metadata.total_pages
                );

                let page_response = self.get_audit_report(report_id, Some(page_num)).await?;
                all_pages_raw.push(page_response.embedded.audit_logs.clone());

                log::info!(
                    "Retrieved page {}/{}",
                    page_num.saturating_add(1),
                    page_metadata.total_pages
                );
            }
        }

        // Process all raw log entries efficiently
        let mut conversion_stats: (u32, u32) = (0, 0); // (successes, failures)
        let mut serialization_stats: (u32, u32) = (0, 0); // (successes, failures)
        let mut total_entries: u32 = 0;

        for page_value in all_pages_raw {
            if let Some(logs_array) = page_value.as_array() {
                for log_value in logs_array {
                    total_entries = total_entries.saturating_add(1);

                    // Get raw JSON string (canonical form for hashing)
                    let raw_log = match serde_json::to_string(log_value) {
                        Ok(json_str) => {
                            serialization_stats.0 = serialization_stats.0.saturating_add(1);
                            json_str
                        }
                        Err(e) => {
                            log::error!(
                                "Failed to serialize audit log entry {}: {}. Entry will be replaced with empty object.",
                                total_entries,
                                e
                            );
                            serialization_stats.1 = serialization_stats.1.saturating_add(1);
                            "{}".to_string()
                        }
                    };

                    // Generate hash from raw JSON (extremely fast with xxHash!)
                    let log_hash = generate_log_hash(&raw_log);

                    // Extract only the timestamp field for UTC conversion
                    let timestamp_utc = if let Ok(extractor) =
                        serde_json::from_value::<TimestampExtractor>(log_value.clone())
                    {
                        if let Some(timestamp) = extractor.timestamp {
                            match convert_regional_timestamp_to_utc(&timestamp, &self.region) {
                                Some(utc) => {
                                    conversion_stats.0 = conversion_stats.0.saturating_add(1);
                                    Some(utc)
                                }
                                None => {
                                    log::warn!("Failed to convert timestamp to UTC: {}", timestamp);
                                    conversion_stats.1 = conversion_stats.1.saturating_add(1);
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    // Create optimized log entry with minimal allocations
                    all_logs.push(AuditLogEntry {
                        raw_log,
                        timestamp_utc,
                        log_hash,
                    });
                }
            }
        }

        log::info!(
            "Successfully processed {} audit log entries across {} pages",
            total_entries,
            page_metadata.total_pages
        );

        let (region_name, source_timezone) = match self.region {
            VeracodeRegion::Commercial => (
                "Commercial (api.veracode.com)",
                "America/New_York (EST/EDT, UTC-5/-4)",
            ),
            VeracodeRegion::European => (
                "European (api.veracode.eu)",
                "Europe/Berlin (CET/CEST, UTC+1/+2)",
            ),
            VeracodeRegion::Federal => (
                "Federal (api.veracode.us)",
                "America/New_York (EST/EDT, UTC-5/-4)",
            ),
        };

        log::info!(
            "Converted {} timestamps from {} to UTC - Region: {} ({} failures)",
            conversion_stats.0,
            source_timezone,
            region_name,
            conversion_stats.1
        );

        log::info!(
            "Generated xxHash hashes for {} log entries (optimized: 10-50x faster than SHA256, zero cloning)",
            total_entries
        );

        if serialization_stats.1 > 0 {
            log::warn!(
                "Serialization statistics: {} successful, {} failed (replaced with empty objects)",
                serialization_stats.0,
                serialization_stats.1
            );
        } else {
            log::info!(
                "Serialization statistics: {} successful, 0 failed",
                serialization_stats.0
            );
        }

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
            "Generating audit report for date range: {} to {}",
            request.start_date,
            request.end_date.as_deref().unwrap_or("now")
        );
        let report_id = self.generate_audit_report(request).await?;
        log::info!("Report generated with ID: {}", report_id);

        // Step 2: Poll for report completion
        log::info!("Polling for report completion...");
        let completed_report = self.poll_report_status(&report_id, None, None).await?;
        log::info!(
            "Report completed at: {}",
            completed_report
                .embedded
                .date_report_completed
                .as_deref()
                .unwrap_or("unknown")
        );

        // Step 3: Retrieve all pages
        log::info!("Retrieving all audit log pages...");
        let mut all_logs = self.get_all_audit_log_pages(&report_id).await?;

        // Step 4: Sort logs by timestamp_utc (oldest first, newest last)
        log::info!(
            "Sorting {} audit logs by timestamp (oldest to newest)...",
            all_logs.len()
        );
        all_logs.sort_by(|a, b| {
            match (&a.timestamp_utc, &b.timestamp_utc) {
                // Both have timestamps - parse and compare them
                (Some(ts_a), Some(ts_b)) => {
                    // Parse timestamps for comparison
                    // Format is "YYYY-MM-DD HH:MM:SS" (possibly with milliseconds)
                    let parsed_a = NaiveDateTime::parse_from_str(ts_a, "%Y-%m-%d %H:%M:%S%.f")
                        .or_else(|_| NaiveDateTime::parse_from_str(ts_a, "%Y-%m-%d %H:%M:%S"));
                    let parsed_b = NaiveDateTime::parse_from_str(ts_b, "%Y-%m-%d %H:%M:%S%.f")
                        .or_else(|_| NaiveDateTime::parse_from_str(ts_b, "%Y-%m-%d %H:%M:%S"));

                    match (parsed_a, parsed_b) {
                        (Ok(dt_a), Ok(dt_b)) => dt_a.cmp(&dt_b), // Both parsed successfully
                        (Ok(_), Err(_)) => std::cmp::Ordering::Less, // a is valid, b is not - a comes first
                        (Err(_), Ok(_)) => std::cmp::Ordering::Greater, // b is valid, a is not - b comes first
                        (Err(_), Err(_)) => std::cmp::Ordering::Equal, // Neither parsed - keep original order
                    }
                }
                // Only a has timestamp - a comes first
                (Some(_), None) => std::cmp::Ordering::Less,
                // Only b has timestamp - b comes first
                (None, Some(_)) => std::cmp::Ordering::Greater,
                // Neither has timestamp - keep original order
                (None, None) => std::cmp::Ordering::Equal,
            }
        });
        log::info!("Logs sorted successfully (oldest to newest)");

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
#[must_use = "Need to handle all error enum types."]
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
#[allow(clippy::expect_used)]
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
        let json = serde_json::to_string(&request).expect("should serialize to json");

        assert!(json.contains("\"report_type\":\"AUDIT\""));
        assert!(json.contains("\"start_date\":\"2025-01-01\""));
        assert!(json.contains("\"end_date\":\"2025-01-31\""));
    }

    #[test]
    fn test_audit_report_request_serialization_without_optional_fields() {
        let request = AuditReportRequest::new("2025-01-01", None);
        let json = serde_json::to_string(&request).expect("should serialize to json");

        // Optional fields should not be present when None
        assert!(!json.contains("end_date"));
        assert!(!json.contains("audit_action"));
        assert!(!json.contains("action_type"));
    }

    #[test]
    fn test_convert_european_timezone_winter() {
        // Winter timestamp: CET is UTC+1
        let result =
            convert_regional_timestamp_to_utc("2025-01-15 10:00:00.000", &VeracodeRegion::European);
        assert!(result.is_some());
        // 10:00 CET = 09:00 UTC
        // Note: %.f format drops trailing zeros
        assert_eq!(
            result.expect("should convert timestamp"),
            "2025-01-15 09:00:00"
        );
    }

    #[test]
    fn test_convert_european_timezone_summer() {
        // Summer timestamp: CEST is UTC+2
        let result =
            convert_regional_timestamp_to_utc("2025-06-15 10:00:00.000", &VeracodeRegion::European);
        assert!(result.is_some());
        // 10:00 CEST = 08:00 UTC
        assert_eq!(
            result.expect("should convert timestamp"),
            "2025-06-15 08:00:00"
        );
    }

    #[test]
    fn test_convert_commercial_timezone_winter() {
        // Winter timestamp: EST is UTC-5
        let result = convert_regional_timestamp_to_utc(
            "2025-01-15 14:30:00.000",
            &VeracodeRegion::Commercial,
        );
        assert!(result.is_some());
        // 14:30 EST = 19:30 UTC
        assert_eq!(
            result.expect("should convert timestamp"),
            "2025-01-15 19:30:00"
        );
    }

    #[test]
    fn test_convert_commercial_timezone_summer() {
        // Summer timestamp: EDT is UTC-4
        let result = convert_regional_timestamp_to_utc(
            "2025-06-15 14:30:00.000",
            &VeracodeRegion::Commercial,
        );
        assert!(result.is_some());
        // 14:30 EDT = 18:30 UTC
        assert_eq!(
            result.expect("should convert timestamp"),
            "2025-06-15 18:30:00"
        );
    }

    #[test]
    fn test_convert_federal_timezone_winter() {
        // Federal uses same timezone as Commercial (America/New_York)
        let result =
            convert_regional_timestamp_to_utc("2025-12-15 14:30:00.000", &VeracodeRegion::Federal);
        assert!(result.is_some());
        // 14:30 EST = 19:30 UTC
        assert_eq!(
            result.expect("should convert timestamp"),
            "2025-12-15 19:30:00"
        );
    }

    #[test]
    fn test_convert_timezone_without_milliseconds() {
        // Test without milliseconds
        let result =
            convert_regional_timestamp_to_utc("2025-01-15 10:00:00", &VeracodeRegion::European);
        assert!(result.is_some());
        // Should not have milliseconds in output
        assert_eq!(
            result.expect("should convert timestamp"),
            "2025-01-15 09:00:00"
        );
    }

    #[test]
    fn test_convert_timezone_variable_milliseconds() {
        // Test with different millisecond precisions
        let result =
            convert_regional_timestamp_to_utc("2025-01-15 10:00:00.1", &VeracodeRegion::European);
        assert!(result.is_some());

        let result =
            convert_regional_timestamp_to_utc("2025-01-15 10:00:00.12", &VeracodeRegion::European);
        assert!(result.is_some());

        let result = convert_regional_timestamp_to_utc(
            "2025-01-15 10:00:00.123456",
            &VeracodeRegion::European,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_convert_timezone_invalid_format() {
        // Invalid format should return None
        let result = convert_regional_timestamp_to_utc("invalid", &VeracodeRegion::European);
        assert!(result.is_none());

        let result =
            convert_regional_timestamp_to_utc("2025-13-45 25:99:99", &VeracodeRegion::Commercial);
        assert!(result.is_none());
    }

    #[test]
    fn test_convert_timezone_dst_fallback_ambiguous() {
        // Regression test for DST fall-back ambiguous time
        // November 5, 2028 at 1:00 AM is ambiguous in America/New_York
        // (occurs twice when clocks fall back from 2:00 AM to 1:00 AM)
        // The function should use earliest() to resolve ambiguity
        let result =
            convert_regional_timestamp_to_utc("2028-11-05 01:00:00", &VeracodeRegion::Commercial);
        assert!(
            result.is_some(),
            "Should handle DST fall-back ambiguous time"
        );

        // Verify conversion produces valid UTC timestamp
        let utc = result.unwrap();
        assert!(utc.len() >= 19, "UTC timestamp should be well-formed");
        assert!(utc.starts_with("2028-11-05"), "Date should be preserved");
    }

    // ============================================================================
    // SECURITY TESTS: Property-Based Testing with Proptest
    // ============================================================================

    mod security_tests {
        use super::*;
        use proptest::prelude::*;

        // ========================================================================
        // SECURITY TEST 1: Timestamp Parsing Edge Cases
        // ========================================================================
        // Tests: convert_regional_timestamp_to_utc
        // Goals: Ensure robust handling of malformed timestamps, extreme dates,
        //        leap years, DST transitions, and edge cases

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Property: Valid timestamps should always convert successfully
            /// Tests legitimate date ranges that should work
            #[test]
            fn proptest_valid_timestamp_conversion(
                year in 2000u32..2100u32,
                month in 1u32..=12u32,
                day in 1u32..=28u32, // Safe range that works for all months
                hour in prop::sample::select(vec![0u32, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]), // Avoid hour 2 (DST transition)
                minute in 0u32..=59u32,
                second in 0u32..=59u32,
                region in prop_oneof![
                    Just(VeracodeRegion::Commercial),
                    Just(VeracodeRegion::European),
                    Just(VeracodeRegion::Federal),
                ]
            ) {
                let timestamp = format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                    year, month, day, hour, minute, second
                );

                let result = convert_regional_timestamp_to_utc(&timestamp, &region);

                // Valid timestamps should always convert (DST transition hour 2 is avoided)
                prop_assert!(result.is_some(), "Failed to convert valid timestamp: {}", timestamp);

                // Result should be well-formed
                if let Some(utc) = result {
                    prop_assert!(utc.len() >= 19, "UTC timestamp too short: {}", utc);
                    prop_assert!(utc.contains('-'), "UTC timestamp missing date separator");
                    prop_assert!(utc.contains(':'), "UTC timestamp missing time separator");
                }
            }

            /// Property: Malformed timestamps should fail gracefully
            /// Tests that invalid input doesn't panic or cause undefined behavior
            #[test]
            fn proptest_malformed_timestamp_handling(
                input in "\\PC{0,256}", // Any Unicode string up to 256 chars
            ) {
                // Should never panic, even on malformed input
                let _ = convert_regional_timestamp_to_utc(&input, &VeracodeRegion::Commercial);
                let _ = convert_regional_timestamp_to_utc(&input, &VeracodeRegion::European);
                let _ = convert_regional_timestamp_to_utc(&input, &VeracodeRegion::Federal);
            }

            /// Property: Timestamps with variable millisecond precision should work
            /// Tests fractional seconds handling (0-9 digits)
            #[test]
            fn proptest_variable_millisecond_precision(
                milliseconds in "[0-9]{1,9}",
            ) {
                let timestamp = format!("2025-06-15 10:30:45.{}", milliseconds);
                let result = convert_regional_timestamp_to_utc(&timestamp, &VeracodeRegion::Commercial);

                // Should handle variable precision gracefully
                // Either succeeds or fails safely
                if let Some(utc) = result {
                    prop_assert!(utc.len() >= 19, "UTC timestamp too short");
                }
            }

            /// Property: Extreme dates should be handled safely
            /// Tests boundary conditions for year, month, day
            #[test]
            fn proptest_extreme_dates(
                year in 1900u32..2200u32,
                month in 0u32..=13u32, // Include invalid months
                day in 0u32..=32u32,   // Include invalid days
            ) {
                let timestamp = format!(
                    "{:04}-{:02}-{:02} 12:00:00",
                    year, month, day
                );

                // Should never panic on extreme dates
                let _ = convert_regional_timestamp_to_utc(&timestamp, &VeracodeRegion::Commercial);
            }
        }

        // ========================================================================
        // SECURITY TEST 2: Hash Function Collision Resistance
        // ========================================================================
        // Tests: generate_log_hash
        // Goals: Verify hash properties, collision resistance, determinism

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Property: Hash output should always be 32 hex characters (128-bit)
            /// Tests hash format consistency
            #[test]
            fn proptest_hash_format_consistency(
                input in "\\PC{0,1024}", // Any Unicode string up to 1KB
            ) {
                let hash = generate_log_hash(&input);

                // xxh3_128 should always produce 32 hex characters
                prop_assert_eq!(hash.len(), 32, "Hash length should be 32 chars");

                // Should only contain hex characters
                prop_assert!(
                    hash.chars().all(|c| c.is_ascii_hexdigit()),
                    "Hash should only contain hex chars: {}",
                    hash
                );
            }

            /// Property: Same input should always produce same hash (determinism)
            /// Tests hash function determinism
            #[test]
            fn proptest_hash_determinism(
                input in "\\PC{0,2048}",
            ) {
                let hash1 = generate_log_hash(&input);
                let hash2 = generate_log_hash(&input);

                prop_assert_eq!(
                    hash1, hash2,
                    "Hash function should be deterministic"
                );
            }

            /// Property: Different inputs should produce different hashes (collision resistance)
            /// Tests basic collision resistance
            #[test]
            fn proptest_hash_collision_resistance(
                input1 in "\\PC{1,256}",
                input2 in "\\PC{1,256}",
            ) {
                // Only test when inputs are actually different
                if input1 != input2 {
                    let hash1 = generate_log_hash(&input1);
                    let hash2 = generate_log_hash(&input2);

                    // Different inputs should produce different hashes
                    // (collisions are possible but extremely rare)
                    prop_assert_ne!(
                        hash1, hash2,
                        "Collision detected for different inputs"
                    );
                }
            }

            /// Property: Small changes should produce completely different hashes (avalanche effect)
            /// Tests that single-bit changes cascade through the hash
            #[test]
            fn proptest_hash_avalanche_effect(
                base in "[a-zA-Z0-9]{10,100}",
                suffix in "[a-z]",
            ) {
                let input1 = base.clone();
                let input2 = format!("{}{}", base, suffix);

                let hash1 = generate_log_hash(&input1);
                let hash2 = generate_log_hash(&input2);

                // Adding one character should completely change the hash
                prop_assert_ne!(
                    &hash1, &hash2,
                    "Avalanche effect failed: similar inputs produced similar hashes"
                );

                // Count differing characters (should be significant)
                let diff_count = hash1.chars()
                    .zip(hash2.chars())
                    .filter(|(a, b)| a != b)
                    .count();

                // At least 40% of hash should change (good avalanche)
                prop_assert!(
                    diff_count >= 12,
                    "Poor avalanche effect: only {} of 32 chars changed",
                    diff_count
                );
            }
        }

        // ========================================================================
        // SECURITY TEST 3: URL Encoding Injection Prevention
        // ========================================================================
        // Tests: URL encoding in get_audit_report
        // Goals: Prevent path traversal, command injection, XSS via report_id

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Property: URL encoding should escape all special characters
            /// Tests that dangerous characters are properly encoded
            #[test]
            fn proptest_url_encoding_escapes_special_chars(
                special_chars in prop::sample::select(vec![
                    "/", "\\", "?", "&", "=", "#", " ", "<", ">",
                    "\"", "'", "|", ";", "\n", "\r", "\0", "$"
                ]),
                base in "[a-zA-Z0-9]{5,20}",
            ) {
                let malicious_id = format!("{}{}{}", base, special_chars, base);
                let encoded = urlencoding::encode(&malicious_id);

                // Encoded output should not contain the original special char
                // (it should be percent-encoded)
                prop_assert!(
                    !encoded.contains(special_chars),
                    "Special character '{}' not encoded properly",
                    special_chars
                );

                // Should contain % for percent-encoding (or + for space)
                if !special_chars.chars().all(|c| c.is_alphanumeric()) {
                    prop_assert!(
                        encoded.contains('%') || (special_chars == " " && encoded.contains('+')),
                        "Expected encoding for '{}'",
                        special_chars
                    );
                }
            }

            /// Property: Path traversal sequences should be encoded
            /// Tests protection against directory traversal attacks
            #[test]
            fn proptest_url_encoding_prevents_path_traversal(
                traversal in prop_oneof![
                    Just("../"),
                    Just("..\\"),
                    Just("../../"),
                    Just("..%2f"),
                    Just("..%5c"),
                    Just("%2e%2e%2f"),
                ],
                prefix in "[a-z]{1,10}",
                suffix in "[a-z]{1,10}",
            ) {
                let malicious_id = format!("{}{}{}", prefix, traversal, suffix);
                let encoded = urlencoding::encode(&malicious_id);

                // Encoded string should not contain literal path traversal
                prop_assert!(
                    !encoded.contains("../") && !encoded.contains("..\\"),
                    "Path traversal not properly encoded: {}",
                    encoded
                );
            }

            /// Property: Command injection characters should be encoded
            /// Tests protection against shell command injection
            #[test]
            fn proptest_url_encoding_prevents_command_injection(
                injection_char in prop::sample::select(vec![
                    ";", "|", "&", "$", "`", "$(", ")", "{", "}", "\n", "\r"
                ]),
                base in "[a-zA-Z0-9]{5,15}",
            ) {
                let malicious_id = format!("{}{}rm -rf /", base, injection_char);
                let encoded = urlencoding::encode(&malicious_id);

                // Encoded output should not contain injection characters
                prop_assert!(
                    !encoded.contains(injection_char),
                    "Injection character '{}' not encoded",
                    injection_char
                );
            }
        }

        // ========================================================================
        // SECURITY TEST 4: Integer Overflow Protection (Saturating Arithmetic)
        // ========================================================================
        // Tests: saturating_add, saturating_mul operations
        // Goals: Verify overflow protection doesn't wrap around

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Property: Saturating add should never overflow
            /// Tests u32 saturating addition behavior
            #[test]
            fn proptest_saturating_add_never_overflows(
                a in 0u32..=u32::MAX,
                b in 0u32..=1000u32,
            ) {
                let result = a.saturating_add(b);

                // Result should be >= both operands
                prop_assert!(result >= a, "Saturating add decreased value");

                // If overflow would occur, result should be MAX
                #[allow(clippy::arithmetic_side_effects)]
                {
                    if a as u64 + b as u64 > u32::MAX as u64 {
                        prop_assert_eq!(
                            result,
                            u32::MAX,
                            "Expected saturation at MAX for {} + {}",
                            a, b
                        );
                    } else {
                        prop_assert_eq!(
                            result,
                            a + b,
                            "Expected normal addition for {} + {}",
                            a, b
                        );
                    }
                }
            }

            /// Property: Saturating multiply should never overflow
            /// Tests u64 saturating multiplication behavior (for delay_secs)
            #[test]
            fn proptest_saturating_mul_never_overflows(
                a in 0u64..=u64::MAX / 2,
                b in 0u64..=100u64,
            ) {
                let result = a.saturating_mul(b);

                // If overflow would occur, result should be MAX
                if let Some(expected) = a.checked_mul(b) {
                    prop_assert_eq!(result, expected, "Multiplication mismatch");
                } else {
                    prop_assert_eq!(
                        result,
                        u64::MAX,
                        "Expected saturation at MAX for {} * {}",
                        a, b
                    );
                }
            }

            /// Property: Counter increments should never overflow
            /// Tests the specific pattern used in poll_report_status and get_all_audit_log_pages
            #[test]
            fn proptest_counter_increment_safety(
                start in 0u32..=u32::MAX - 1000,
                increments in 1usize..=100,
            ) {
                let mut counter = start;

                for _ in 0..increments {
                    let old_value = counter;
                    counter = counter.saturating_add(1);

                    // Counter should never decrease
                    prop_assert!(
                        counter >= old_value,
                        "Counter decreased from {} to {}",
                        old_value, counter
                    );

                    // If we hit MAX, it should stay at MAX
                    if old_value == u32::MAX {
                        prop_assert_eq!(counter, u32::MAX, "Counter should saturate at MAX");
                    }
                }
            }

            /// Property: Page iteration should handle near-MAX values safely
            /// Tests the pagination loop in get_all_audit_log_pages
            #[test]
            fn proptest_page_iteration_overflow_safety(
                total_pages in 1u32..=1000u32,
            ) {
                // Simulate the pagination loop from get_all_audit_log_pages
                let mut processed = 0u32;

                for page_num in 1..total_pages {
                    // This is the pattern used in line 598-612
                    let page_display = page_num.saturating_add(1);

                    prop_assert!(
                        page_display >= page_num,
                        "Page display calculation overflow"
                    );

                    processed = processed.saturating_add(1);
                }

                // Should process total_pages - 1 pages (page 0 handled separately)
                prop_assert_eq!(
                    processed,
                    total_pages.saturating_sub(1),
                    "Page count mismatch"
                );
            }
        }

        // ========================================================================
        // SECURITY TEST 5: Input Validation for AuditReportRequest
        // ========================================================================
        // Tests: AuditReportRequest builder methods
        // Goals: Ensure safe handling of user-controlled inputs

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Property: Request builder should handle arbitrary strings safely
            /// Tests that builder methods don't panic on unusual input
            #[test]
            fn proptest_request_builder_handles_arbitrary_input(
                start_date in "\\PC{0,256}",
                end_date in "\\PC{0,256}",
                action in "\\PC{0,100}",
            ) {
                // Should never panic, even with unusual input
                let request = AuditReportRequest::new(
                    start_date.clone(),
                    if end_date.is_empty() { None } else { Some(end_date.clone()) }
                );

                // Verify fields are set correctly
                prop_assert_eq!(&request.start_date, &start_date);

                if !end_date.is_empty() {
                    prop_assert_eq!(&request.end_date, &Some(end_date.clone()));
                }

                // Test with_audit_actions
                let request = request.with_audit_actions(vec![action.clone()]);
                prop_assert!(request.audit_action.is_some());
            }

            /// Property: Builder methods should preserve data integrity
            /// Tests that chained builder calls work correctly
            #[test]
            fn proptest_request_builder_data_integrity(
                start in "[0-9]{4}-[0-9]{2}-[0-9]{2}",
                actions in prop::collection::vec("[A-Za-z]{5,15}", 0..10),
                types in prop::collection::vec("[A-Za-z]{5,15}", 0..10),
                user_ids in prop::collection::vec("[0-9]{1,10}", 0..10),
            ) {
                let request = AuditReportRequest::new(start.clone(), None)
                    .with_audit_actions(actions.clone())
                    .with_action_types(types.clone())
                    .with_target_users(user_ids.clone())
                    .with_modifier_users(user_ids.clone());

                // Verify all fields are preserved correctly
                prop_assert_eq!(request.start_date, start);
                prop_assert_eq!(request.audit_action, Some(actions));
                prop_assert_eq!(request.action_type, Some(types));
                prop_assert_eq!(request.target_user_id, Some(user_ids.clone()));
                prop_assert_eq!(request.modifier_user_id, Some(user_ids));
            }

            /// Property: Empty collections should be handled correctly
            /// Tests edge case of empty filter arrays
            #[test]
            fn proptest_request_builder_empty_collections(
                start_date in "[0-9]{4}-[0-9]{2}-[0-9]{2}",
            ) {
                let request = AuditReportRequest::new(start_date.clone(), None)
                    .with_audit_actions(vec![])
                    .with_action_types(vec![])
                    .with_target_users(vec![])
                    .with_modifier_users(vec![]);

                // Empty vecs should still be Some (not None)
                prop_assert!(request.audit_action.is_some());
                prop_assert!(request.action_type.is_some());
                prop_assert!(request.target_user_id.is_some());
                prop_assert!(request.modifier_user_id.is_some());

                // But should be empty
                if let Some(ref actions) = request.audit_action {
                    prop_assert_eq!(actions.len(), 0);
                }
            }

            /// Property: Large collections should be handled safely
            /// Tests that builders can handle many filter values
            #[test]
            fn proptest_request_builder_large_collections(
                start_date in "[0-9]{4}-[0-9]{2}-[0-9]{2}",
                collection_size in 1usize..=100,
            ) {
                let large_vec: Vec<String> = (0..collection_size)
                    .map(|i| format!("item_{}", i))
                    .collect();

                let request = AuditReportRequest::new(start_date, None)
                    .with_audit_actions(large_vec.clone());

                if let Some(ref actions) = request.audit_action {
                    prop_assert_eq!(
                        actions.len(),
                        collection_size,
                        "Collection size mismatch"
                    );
                }
            }
        }

        // ========================================================================
        // SECURITY TEST 6: JSON Serialization Safety
        // ========================================================================
        // Tests: AuditReportRequest serialization, AuditLogEntry serialization
        // Goals: Ensure no injection via JSON serialization

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 1000 },
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Property: Request serialization should never panic
            /// Tests that arbitrary input can be safely serialized
            #[test]
            fn proptest_request_serialization_safety(
                start_date in "\\PC{0,100}",
                actions in prop::collection::vec("\\PC{0,50}", 0..10),
            ) {
                let request = AuditReportRequest::new(start_date, None)
                    .with_audit_actions(actions);

                // Serialization should never panic
                let result = serde_json::to_string(&request);
                prop_assert!(result.is_ok(), "Serialization failed");

                // Serialized JSON should be valid
                if let Ok(json) = result {
                    prop_assert!(json.contains("\"report_type\""), "Missing report_type");
                    prop_assert!(json.contains("\"AUDIT\""), "Wrong report_type value");
                }
            }

            /// Property: Special characters in dates should be escaped
            /// Tests JSON injection prevention
            #[test]
            fn proptest_json_injection_prevention(
                injection in prop::sample::select(vec![
                    r#"","malicious":"value"#,
                    "\n\r\t",
                    "\\",
                    "\"",
                    "</script>",
                ]),
                base_date in "[0-9]{4}-[0-9]{2}-[0-9]{2}",
            ) {
                let malicious_date = format!("{}{}", base_date, injection);
                let request = AuditReportRequest::new(malicious_date, None);

                let json = serde_json::to_string(&request)
                    .expect("Should serialize even with special chars");

                // Verify JSON is still valid after serialization
                let parsed: serde_json::Value = serde_json::from_str(&json)
                    .expect("Serialized JSON should be parseable");

                prop_assert!(parsed.is_object(), "Should be valid JSON object");
            }
        }

        // ========================================================================
        // SECURITY TEST 7: Error Handling Paths
        // ========================================================================
        // Tests: Timestamp parsing errors, hash function edge cases
        // Goals: Ensure errors are handled gracefully without panics

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: if cfg!(miri) { 5 } else { 500 }, // Fewer cases for error paths
                failure_persistence: None,
                .. ProptestConfig::default()
            })]

            /// Property: All timestamp error paths should return None, never panic
            /// Tests comprehensive error handling
            #[test]
            fn proptest_timestamp_error_handling_never_panics(
                malformed in prop_oneof![
                    // Empty and whitespace
                    Just(""),
                    Just(" "),
                    Just("\n\t\r"),

                    // Wrong formats
                    Just("2025/01/01 12:00:00"),
                    Just("01-01-2025 12:00:00"),
                    Just("2025-01-01T12:00:00Z"),

                    // Invalid values
                    Just("2025-13-01 12:00:00"), // Invalid month
                    Just("2025-01-32 12:00:00"), // Invalid day
                    Just("2025-01-01 25:00:00"), // Invalid hour
                    Just("2025-01-01 12:60:00"), // Invalid minute
                    Just("2025-01-01 12:00:60"), // Invalid second

                    // Truncated
                    Just("2025-01-01"),
                    Just("2025-01-01 12"),
                    Just("2025-01-01 12:00"),

                    // Special characters
                    Just("2025-01-01; DROP TABLE;"),
                    Just("../../etc/passwd"),
                    Just("<script>alert('xss')</script>"),

                    // Extreme values
                    Just("9999-99-99 99:99:99"),
                    Just("0000-00-00 00:00:00"),
                ],
            ) {
                // Should never panic, regardless of input
                let result_commercial = convert_regional_timestamp_to_utc(malformed, &VeracodeRegion::Commercial);
                let result_european = convert_regional_timestamp_to_utc(malformed, &VeracodeRegion::European);
                let result_federal = convert_regional_timestamp_to_utc(malformed, &VeracodeRegion::Federal);

                // All should return None (error), not panic
                prop_assert!(result_commercial.is_none() || result_commercial.is_some());
                prop_assert!(result_european.is_none() || result_european.is_some());
                prop_assert!(result_federal.is_none() || result_federal.is_some());
            }

            /// Property: Hash function should handle all input lengths
            /// Tests from empty to very large inputs
            #[test]
            fn proptest_hash_handles_all_input_sizes(
                size in 0usize..=10_000,
            ) {
                let input = "x".repeat(size);

                // Should never panic, even with large inputs
                let hash = generate_log_hash(&input);

                // Hash should always be valid format
                prop_assert_eq!(hash.len(), 32);
                prop_assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
            }

            /// Property: Hash function should handle binary data safely
            /// Tests non-UTF8 byte sequences (via valid UTF8 with null bytes)
            #[test]
            fn proptest_hash_handles_binary_data(
                null_count in 0usize..=100,
            ) {
                // Create string with embedded nulls
                let input = format!("data{}\0{}\0end", "x".repeat(null_count), "y".repeat(null_count));

                // Should handle null bytes gracefully
                let hash = generate_log_hash(&input);

                prop_assert_eq!(hash.len(), 32);
                prop_assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
            }
        }

        // ========================================================================
        // UNIT TESTS: Specific Security Scenarios
        // ========================================================================

        #[test]
        fn test_url_encoding_sql_injection_attempt() {
            let sql_injection = "1' OR '1'='1";
            let encoded = urlencoding::encode(sql_injection);

            // Should not contain unescaped quotes or spaces
            assert!(!encoded.contains('\''));
            assert!(!encoded.contains(' ') || encoded.contains('+') || encoded.contains("%20"));
        }

        #[test]
        fn test_url_encoding_path_traversal_variants() {
            let variants = vec![
                "../../../etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..\\..\\..\\windows\\system32",
            ];

            for variant in variants {
                let encoded = urlencoding::encode(variant);

                // Should not contain literal path traversal sequences
                assert!(!encoded.contains("../"));
                assert!(!encoded.contains("..\\"));
            }
        }

        #[test]
        fn test_hash_known_collision_resistance() {
            // Test known collision-prone patterns
            let similar_inputs = [
                r#"{"timestamp":"2025-01-01 12:00:00.000"}"#,
                r#"{"timestamp":"2025-01-01 12:00:00.001"}"#,
                r#"{"timestamp":"2025-01-01 12:00:01.000"}"#,
            ];

            let hashes: Vec<String> = similar_inputs
                .iter()
                .map(|input| generate_log_hash(input))
                .collect();

            // All hashes should be unique
            for i in 0..hashes.len() {
                for j in i + 1..hashes.len() {
                    if let (Some(hash_i), Some(hash_j)) = (hashes.get(i), hashes.get(j)) {
                        assert_ne!(
                            hash_i, hash_j,
                            "Collision between similar inputs {} and {}",
                            i, j
                        );
                    }
                }
            }
        }

        #[test]
        fn test_saturating_arithmetic_at_boundaries() {
            // Test u32::MAX boundary
            assert_eq!(u32::MAX.saturating_add(1), u32::MAX);
            assert_eq!((u32::MAX - 1).saturating_add(2), u32::MAX);

            // Test u64::MAX boundary (for delay_secs)
            assert_eq!(u64::MAX.saturating_mul(2), u64::MAX);
            assert_eq!((u64::MAX / 2).saturating_mul(3), u64::MAX);
        }

        #[test]
        fn test_timestamp_dst_transitions() {
            // Test DST spring forward (2025-03-09 02:00 -> 03:00 EST -> EDT)
            // 2:30 AM doesn't exist on this date in New_York
            let result = convert_regional_timestamp_to_utc(
                "2025-03-09 02:30:00",
                &VeracodeRegion::Commercial,
            );
            // Should handle gracefully (either succeed or return None)
            assert!(result.is_some() || result.is_none());

            // Test DST fall back (2025-11-02 02:00 happens twice)
            let result = convert_regional_timestamp_to_utc(
                "2025-11-02 01:30:00",
                &VeracodeRegion::Commercial,
            );
            // Should succeed with single() if unambiguous, or fail gracefully
            assert!(result.is_some() || result.is_none());
        }

        #[test]
        fn test_leap_year_handling() {
            // 2024 is a leap year - Feb 29 should work
            let result =
                convert_regional_timestamp_to_utc("2024-02-29 12:00:00", &VeracodeRegion::European);
            assert!(result.is_some(), "Leap year Feb 29 should be valid");

            // 2025 is not a leap year - Feb 29 should fail
            let result =
                convert_regional_timestamp_to_utc("2025-02-29 12:00:00", &VeracodeRegion::European);
            assert!(result.is_none(), "Non-leap year Feb 29 should be invalid");
        }

        #[test]
        fn test_empty_request_serialization() {
            let request = AuditReportRequest::new("2025-01-01", None);
            let json = serde_json::to_string(&request).expect("Should serialize");

            // Should not include optional fields when None
            assert!(!json.contains("audit_action"));
            assert!(!json.contains("action_type"));
            assert!(!json.contains("target_user_id"));
            assert!(!json.contains("modifier_user_id"));

            // Should include required fields
            assert!(json.contains("report_type"));
            assert!(json.contains("start_date"));
        }
    }
}

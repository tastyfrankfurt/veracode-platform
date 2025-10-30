//! Timestamped file output for audit logs
use crate::error::Result;
use chrono::{NaiveDateTime, Utc};
use log::{debug, info, warn};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use xxhash_rust::xxh3::xxh3_64;

/// Extract the timestamp from the last audit log entry
///
/// Assumes logs are sorted chronologically (oldest first, newest last).
/// Returns None if the array is empty or timestamp is missing.
fn extract_last_timestamp(data: &serde_json::Value) -> Option<String> {
    let logs = data.as_array()?;
    let last_log = logs.last()?;
    let timestamp_utc = last_log.get("timestamp_utc")?.as_str()?;
    Some(timestamp_utc.to_string())
}

/// Extract the timestamp from the first audit log entry
///
/// Assumes logs are sorted chronologically (oldest first, newest last).
/// Returns None if the array is empty or timestamp is missing.
#[cfg(test)]
fn extract_first_timestamp(data: &serde_json::Value) -> Option<String> {
    let logs = data.as_array()?;
    let first_log = logs.first()?;
    let timestamp_utc = first_log.get("timestamp_utc")?.as_str()?;
    Some(timestamp_utc.to_string())
}

/// Format a UTC timestamp string for use in filename
///
/// Converts from "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DD HH:MM:SS.sss" format
/// to "YYYYMMDD_HHMMSS_UTC" format for filenames
fn format_timestamp_for_filename(timestamp_utc: &str) -> Option<String> {
    // Parse the timestamp (with or without milliseconds)
    let parsed = NaiveDateTime::parse_from_str(timestamp_utc, "%Y-%m-%d %H:%M:%S%.f")
        .or_else(|_| NaiveDateTime::parse_from_str(timestamp_utc, "%Y-%m-%d %H:%M:%S"))
        .ok()?;

    // Format for filename: YYYYMMDD_HHMMSS_UTC
    Some(parsed.format("%Y%m%d_%H%M%S_UTC").to_string())
}

/// Parse timestamp from filename back to API format
///
/// Converts from "YYYYMMDD_HHMMSS_UTC" format to "YYYY-MM-DD HH:MM:SS" format
fn parse_timestamp_from_filename(filename_timestamp: &str) -> Option<String> {
    // Parse the timestamp from filename format
    let parsed = NaiveDateTime::parse_from_str(filename_timestamp, "%Y%m%d_%H%M%S_UTC").ok()?;

    // Format for API: YYYY-MM-DD HH:MM:SS
    Some(parsed.format("%Y-%m-%d %H:%M:%S").to_string())
}

/// Check if a timestamp is within the specified hours from now
///
/// # Arguments
///
/// * `timestamp` - Timestamp string in "YYYY-MM-DD HH:MM:SS" format
/// * `max_hours` - Maximum age in hours
///
/// # Returns
///
/// true if the timestamp is within max_hours from now, false otherwise
fn is_timestamp_within_hours(timestamp: &str, max_hours: i64) -> bool {
    // Parse the timestamp
    let parsed = match NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S") {
        Ok(dt) => dt,
        Err(e) => {
            warn!("Failed to parse timestamp {}: {}", timestamp, e);
            return false;
        }
    };

    // Get current UTC time
    let now = Utc::now().naive_utc();

    // Calculate the difference in hours
    let duration = now.signed_duration_since(parsed);
    let hours_diff = duration.num_hours();

    debug!(
        "Timestamp {} is {} hours old (max: {})",
        timestamp, hours_diff, max_hours
    );

    hours_diff >= 0 && hours_diff <= max_hours
}

/// Compute xxHash (xxh3) of a log entry
///
/// Creates a stable JSON representation of the log entry and computes its xxHash.
/// This is used for deduplication to identify log entries that have already been written.
/// xxHash is significantly faster than SHA256 while maintaining excellent collision resistance
/// for hash table use cases.
///
/// # Arguments
///
/// * `log_entry` - A single log entry as JSON value
///
/// # Returns
///
/// 64-bit xxHash of the log entry
fn compute_log_entry_hash(log_entry: &serde_json::Value) -> u64 {
    // Serialize to a canonical JSON string
    let canonical_json = serde_json::to_string(log_entry).unwrap_or_default();

    // Compute xxHash (xxh3_64 is extremely fast)
    xxh3_64(canonical_json.as_bytes())
}

/// Extract xxHash values from existing log files
///
/// Reads the specified log files, computes xxHash for each log entry,
/// and returns them as a set for deduplication.
///
/// # Arguments
///
/// * `log_files` - Paths to log files to process
///
/// # Returns
///
/// Set of xxHash values (u64) from all log entries in the files
fn extract_hashes_from_log_files(log_files: &[PathBuf]) -> HashSet<u64> {
    let mut hashes = HashSet::new();

    for file_path in log_files {
        debug!("Extracting hashes from: {}", file_path.display());

        // Open file with buffered reader
        let file = match fs::File::open(file_path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to open file {}: {}", file_path.display(), e);
                continue;
            }
        };

        // Stream JSON parsing using from_reader instead of from_str
        let logs: serde_json::Value = match serde_json::from_reader(BufReader::new(file)) {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse JSON from {}: {}", file_path.display(), e);
                continue;
            }
        };

        // Extract hashes from log entries
        if let Some(log_array) = logs.as_array() {
            for log_entry in log_array {
                let hash = compute_log_entry_hash(log_entry);
                hashes.insert(hash);
            }
            debug!(
                "Extracted {} hashes from {}",
                log_array.len(),
                file_path.display()
            );
        }
    }

    info!("Total unique hashes extracted: {}", hashes.len());
    hashes
}

/// Find the last (most recent) audit log file by timestamp
///
/// Searches the output directory for audit log files matching the pattern
/// `audit_log_YYYYMMDD_HHMMSS_UTC.json` and returns the path to the newest one.
///
/// # Arguments
///
/// * `output_dir` - Directory to search for log files
///
/// # Returns
///
/// The path to the most recent log file, or None if no files found
fn get_last_log_file(output_dir: &str) -> Option<PathBuf> {
    // Check if directory exists
    let dir_path = std::path::Path::new(output_dir);
    if !dir_path.exists() || !dir_path.is_dir() {
        debug!("Output directory does not exist: {}", output_dir);
        return None;
    }

    // Read directory entries
    let entries = match fs::read_dir(dir_path) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to read output directory {}: {}", output_dir, e);
            return None;
        }
    };

    // Pattern to match audit log files: audit_log_YYYYMMDD_HHMMSS_UTC.json
    let pattern = match Regex::new(r"^audit_log_(\d{8}_\d{6}_UTC)\.json$") {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to compile regex pattern: {}", e);
            return None;
        }
    };

    // Collect all matching filenames with their timestamps and paths
    let mut files_with_timestamps: Vec<(String, PathBuf)> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let filename = entry.file_name();
            let filename_str = filename.to_str()?;

            // Extract timestamp from filename
            let captures = pattern.captures(filename_str)?;
            let timestamp = captures.get(1)?.as_str();
            Some((timestamp.to_string(), entry.path()))
        })
        .collect();

    // Sort timestamps (lexicographically, which works for YYYYMMDD_HHMMSS format)
    files_with_timestamps.sort_by(|a, b| b.0.cmp(&a.0)); // Sort descending (newest first)

    // Get the first (newest) file
    files_with_timestamps.first().map(|(_, path)| path.clone())
}

/// Find log files with timestamps newer than or equal to the specified cutoff
///
/// # Arguments
///
/// * `output_dir` - Directory to search for log files
/// * `cutoff_timestamp` - Cutoff timestamp in "YYYY-MM-DD HH:MM:SS" format
///
/// # Returns
///
/// Vector of PathBufs for log files with timestamps >= cutoff
#[cfg(test)]
fn find_log_files_newer_than(output_dir: &str, cutoff_timestamp: &str) -> Vec<PathBuf> {
    // Check if directory exists
    let dir_path = std::path::Path::new(output_dir);
    if !dir_path.exists() || !dir_path.is_dir() {
        return Vec::new();
    }

    // Read directory entries
    let entries = match fs::read_dir(dir_path) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    // Pattern to match audit log files: audit_log_YYYYMMDD_HHMMSS_UTC.json
    let pattern = match Regex::new(r"^audit_log_(\d{8}_\d{6}_UTC)\.json$") {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    // Collect all matching filenames with their timestamps and paths
    entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let filename = entry.file_name();
            let filename_str = filename.to_str()?;

            // Extract timestamp from filename
            let captures = pattern.captures(filename_str)?;
            let timestamp_str = captures.get(1)?.as_str();

            // Parse timestamp from filename format to API format
            let api_timestamp = parse_timestamp_from_filename(timestamp_str)?;

            // Compare with cutoff (string comparison works for YYYY-MM-DD HH:MM:SS format)
            if api_timestamp.as_str() >= cutoff_timestamp {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect()
}

/// Find the last audit log file and extract its timestamp
///
/// Searches the output directory for audit log files matching the pattern
/// `audit_log_YYYYMMDD_HHMMSS_UTC.json`, finds the newest one by timestamp,
/// validates it's within 72 hours, and returns the timestamp in API format.
///
/// # Arguments
///
/// * `output_dir` - Directory to search for log files
///
/// # Returns
///
/// The timestamp from the newest log file in API format if it's within 72 hours,
/// or None if no files found or timestamp is too old
pub fn get_last_log_timestamp(output_dir: &str) -> Option<String> {
    // Check if directory exists
    let dir_path = std::path::Path::new(output_dir);
    if !dir_path.exists() || !dir_path.is_dir() {
        debug!("Output directory does not exist: {}", output_dir);
        return None;
    }

    // Read directory entries
    let entries = match fs::read_dir(dir_path) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to read output directory {}: {}", output_dir, e);
            return None;
        }
    };

    // Pattern to match audit log files: audit_log_YYYYMMDD_HHMMSS_UTC.json
    let pattern = match Regex::new(r"^audit_log_(\d{8}_\d{6}_UTC)\.json$") {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to compile regex pattern: {}", e);
            return None;
        }
    };

    // Collect all matching filenames with their timestamps
    let mut timestamps: Vec<String> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let filename = entry.file_name();
            let filename_str = filename.to_str()?;

            // Extract timestamp from filename
            let captures = pattern.captures(filename_str)?;
            let timestamp = captures.get(1)?.as_str();
            Some(timestamp.to_string())
        })
        .collect();

    // Sort timestamps (lexicographically, which works for YYYYMMDD_HHMMSS format)
    timestamps.sort();

    // Get the last (newest) timestamp
    let last_timestamp = timestamps.last()?;

    info!("Found last log file timestamp: {}", last_timestamp);

    // Convert back to API format
    let api_timestamp = parse_timestamp_from_filename(last_timestamp)?;

    // Validate that timestamp is within 72 hours
    if is_timestamp_within_hours(&api_timestamp, 72) {
        // Subtract 1 second to create overlap with previous query
        // This ensures we don't miss logs that occurred in the same second
        // but after the last fetched log (sub-second precision issue)
        // Deduplication will filter out any duplicates from this overlap
        let parsed = NaiveDateTime::parse_from_str(&api_timestamp, "%Y-%m-%d %H:%M:%S").ok()?;
        let overlap_start = parsed + chrono::Duration::seconds(-1);
        let overlap_timestamp = overlap_start.format("%Y-%m-%d %H:%M:%S").to_string();

        info!(
            "Last log file timestamp {} is within 72 hours, using {} (last - 1 second) as start time to create overlap",
            api_timestamp, overlap_timestamp
        );
        Some(overlap_timestamp)
    } else {
        warn!(
            "Last log file timestamp {} is older than 72 hours, ignoring",
            api_timestamp
        );
        None
    }
}

/// Write audit log data to a timestamped file
///
/// Uses the timestamp from the last log entry (newest) to name the file.
/// Falls back to the current UTC timestamp if there are no logs.
///
/// Implements deduplication logic (unless disabled): before writing, checks the last log file
/// (most recent) for duplicate entries and filters them out.
///
/// # Arguments
///
/// * `output_dir` - Directory to write the file to
/// * `data` - JSON data to write (assumes logs are sorted chronologically)
/// * `skip_dedup` - If true, skip deduplication logic and write all logs
/// * `start_datetime` - Optional start datetime used for the API fetch (unused after optimization)
///
/// # Returns
///
/// The path to the created file, or None if no logs remain after deduplication
///
/// # Errors
///
/// Returns error if directory creation or file writing fails
pub fn write_audit_log_file(
    output_dir: &str,
    data: serde_json::Value,
    skip_dedup: bool,
    _start_datetime: Option<&str>,
) -> Result<Option<PathBuf>> {
    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir)?;

    // Perform deduplication if we have log entries (unless skip_dedup is true)
    let deduplicated_data = if skip_dedup {
        info!("Deduplication disabled, writing all logs");
        data
    } else if let serde_json::Value::Array(mut logs_array) = data {
        if !logs_array.is_empty() {
            // Only check the last (most recent) log file for duplicates
            // Since logs are chronological and we use -1 second overlap,
            // only the last file can contain duplicates from the current query
            if let Some(last_file_path) = get_last_log_file(output_dir) {
                info!(
                    "Checking for duplicates against last log file: {}",
                    last_file_path.display()
                );

                // Extract hashes from the last file only
                let existing_hashes = extract_hashes_from_log_files(&[last_file_path]);

                let original_count = logs_array.len();

                // Retain in place - no clone, no new allocation!
                logs_array.retain(|log_entry| {
                    let hash = compute_log_entry_hash(log_entry);
                    !existing_hashes.contains(&hash)
                });

                let duplicate_count = original_count - logs_array.len();

                info!(
                    "Deduplication: {} duplicates removed, {} unique logs remaining",
                    duplicate_count,
                    logs_array.len()
                );

                serde_json::Value::Array(logs_array)
            } else {
                // No existing log files to check against
                debug!("No existing log files found for deduplication");
                serde_json::Value::Array(logs_array)
            }
        } else {
            // Empty array
            serde_json::Value::Array(logs_array)
        }
    } else {
        // Not an array
        data
    };

    // Check if deduplicated data is empty - skip writing if so
    if let Some(logs_array) = deduplicated_data.as_array()
        && logs_array.is_empty()
    {
        info!("No logs to write after deduplication, skipping file creation");
        return Ok(None);
    }

    // Try to extract the timestamp from the last log entry (newest)
    let timestamp = if let Some(last_utc) = extract_last_timestamp(&deduplicated_data) {
        if let Some(formatted) = format_timestamp_for_filename(&last_utc) {
            info!("Using timestamp from newest log entry: {}", last_utc);
            formatted
        } else {
            warn!("Failed to format timestamp, using current time");
            Utc::now().format("%Y%m%d_%H%M%S_UTC").to_string()
        }
    } else {
        info!("No logs found, using current timestamp");
        Utc::now().format("%Y%m%d_%H%M%S_UTC").to_string()
    };

    let filename = format!("audit_log_{timestamp}.json");
    let filepath = PathBuf::from(output_dir).join(&filename);

    debug!("Writing audit log to: {}", filepath.display());

    // Serialize and write the data
    let json_string = serde_json::to_string_pretty(&deduplicated_data)?;
    fs::write(&filepath, json_string)?;

    info!("Audit log written to: {}", filepath.display());
    Ok(Some(filepath))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn test_write_audit_log_file() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        let test_data = json!({
            "report_type": "AUDIT",
            "logs": []
        });

        let result = write_audit_log_file(output_dir, test_data, false, None);
        assert!(result.is_ok());

        let filepath = result.unwrap().expect("Expected Some(PathBuf)");
        assert!(filepath.exists());
        assert!(filepath.to_str().unwrap().contains("audit_log_"));
        assert!(filepath.to_str().unwrap().ends_with("_UTC.json"));

        // Verify content
        let content = fs::read_to_string(&filepath).unwrap();
        assert!(content.contains("AUDIT"));
    }

    #[test]
    fn test_parse_timestamp_from_filename() {
        let filename_timestamp = "20250124_143000_UTC";
        let result = parse_timestamp_from_filename(filename_timestamp);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "2025-01-24 14:30:00");
    }

    #[test]
    fn test_format_timestamp_for_filename() {
        let api_timestamp = "2025-01-24 14:30:00";
        let result = format_timestamp_for_filename(api_timestamp);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "20250124_143000_UTC");
    }

    #[test]
    fn test_is_timestamp_within_hours_recent() {
        // Create a timestamp from 1 hour ago
        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        let timestamp = one_hour_ago.format("%Y-%m-%d %H:%M:%S").to_string();

        assert!(is_timestamp_within_hours(&timestamp, 72));
        assert!(is_timestamp_within_hours(&timestamp, 2));
    }

    #[test]
    fn test_is_timestamp_within_hours_old() {
        // Create a timestamp from 100 hours ago
        let old = Utc::now() - chrono::Duration::hours(100);
        let timestamp = old.format("%Y-%m-%d %H:%M:%S").to_string();

        assert!(!is_timestamp_within_hours(&timestamp, 72));
        assert!(is_timestamp_within_hours(&timestamp, 200));
    }

    #[test]
    fn test_get_last_log_timestamp_no_directory() {
        let result = get_last_log_timestamp("/nonexistent/directory");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_last_log_timestamp_with_files() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        // Create a recent log file (1 hour ago)
        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        let timestamp = one_hour_ago.format("%Y%m%d_%H%M%S_UTC").to_string();
        let filename = format!("audit_log_{}.json", timestamp);
        let filepath = temp_dir.path().join(&filename);
        fs::write(&filepath, "{}").unwrap();

        // Should find the file and return its timestamp
        let result = get_last_log_timestamp(output_dir);
        assert!(result.is_some());
        let returned_timestamp = result.unwrap();

        // Verify it's in API format
        assert!(returned_timestamp.contains("-"));
        assert!(returned_timestamp.contains(":"));
    }

    #[test]
    fn test_get_last_log_timestamp_too_old() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        // Create an old log file (100 hours ago)
        let old = Utc::now() - chrono::Duration::hours(100);
        let timestamp = old.format("%Y%m%d_%H%M%S_UTC").to_string();
        let filename = format!("audit_log_{}.json", timestamp);
        let filepath = temp_dir.path().join(&filename);
        fs::write(&filepath, "{}").unwrap();

        // Should not return the timestamp because it's too old
        let result = get_last_log_timestamp(output_dir);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_last_log_timestamp_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        // Create multiple log files
        let timestamps = vec![
            Utc::now() - chrono::Duration::hours(3),
            Utc::now() - chrono::Duration::hours(2),
            Utc::now() - chrono::Duration::hours(1),
        ];

        for ts in &timestamps {
            let timestamp = ts.format("%Y%m%d_%H%M%S_UTC").to_string();
            let filename = format!("audit_log_{}.json", timestamp);
            let filepath = temp_dir.path().join(&filename);
            fs::write(&filepath, "{}").unwrap();
        }

        // Should return the most recent one
        let result = get_last_log_timestamp(output_dir);
        assert!(result.is_some());

        // The returned timestamp should be close to 1 hour ago
        let returned = result.unwrap();
        let parsed = NaiveDateTime::parse_from_str(&returned, "%Y-%m-%d %H:%M:%S").unwrap();
        let now = Utc::now().naive_utc();
        let diff = now.signed_duration_since(parsed);

        // Should be around 1 hour (with some tolerance for test execution time)
        assert!(diff.num_hours() >= 0 && diff.num_hours() <= 2);
    }

    #[test]
    fn test_compute_log_entry_hash() {
        let log_entry1 = json!({
            "action": "Login",
            "timestamp_utc": "2025-01-24 14:30:00"
        });

        let log_entry2 = json!({
            "action": "Login",
            "timestamp_utc": "2025-01-24 14:30:00"
        });

        let log_entry3 = json!({
            "action": "Logout",
            "timestamp_utc": "2025-01-24 14:30:00"
        });

        let hash1 = compute_log_entry_hash(&log_entry1);
        let hash2 = compute_log_entry_hash(&log_entry2);
        let hash3 = compute_log_entry_hash(&log_entry3);

        // Same entries should have same hash
        assert_eq!(hash1, hash2);
        // Different entries should have different hashes
        assert_ne!(hash1, hash3);
        // Hash should be u64 (8 bytes)
        assert!(hash1 > 0);
    }

    #[test]
    fn test_extract_first_timestamp() {
        let logs = json!([
            {
                "action": "Login",
                "timestamp_utc": "2025-01-24 14:30:00"
            },
            {
                "action": "Logout",
                "timestamp_utc": "2025-01-24 15:30:00"
            }
        ]);

        let result = extract_first_timestamp(&logs);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "2025-01-24 14:30:00");
    }

    #[test]
    fn test_find_log_files_newer_than() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        // Create log files with different timestamps
        let timestamps = vec![
            "20250124_100000_UTC", // Older
            "20250124_120000_UTC", // Middle
            "20250124_140000_UTC", // Newer
        ];

        for ts in &timestamps {
            let filename = format!("audit_log_{}.json", ts);
            let filepath = temp_dir.path().join(&filename);
            fs::write(&filepath, "[]").unwrap();
        }

        // Find files newer than the middle timestamp
        let cutoff = "2025-01-24 12:00:00";
        let result = find_log_files_newer_than(output_dir, cutoff);

        // Should find 2 files (middle and newer, since >= cutoff)
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_deduplication_removes_duplicates() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        // Create an existing log file with some entries
        let existing_logs = json!([
            {
                "action": "Login",
                "timestamp_utc": "2025-01-24 14:00:00",
                "user": "test_user"
            },
            {
                "action": "Logout",
                "timestamp_utc": "2025-01-24 14:30:00",
                "user": "test_user"
            }
        ]);

        let existing_filename = "audit_log_20250124_143000_UTC.json";
        let existing_filepath = temp_dir.path().join(existing_filename);
        fs::write(
            &existing_filepath,
            serde_json::to_string_pretty(&existing_logs).unwrap(),
        )
        .unwrap();

        // Create new logs that include some duplicates
        let new_logs = json!([
            {
                "action": "Login",
                "timestamp_utc": "2025-01-24 14:00:00",
                "user": "test_user"
            },  // Duplicate
            {
                "action": "Create",
                "timestamp_utc": "2025-01-24 15:00:00",
                "user": "test_user"
            },  // New
            {
                "action": "Logout",
                "timestamp_utc": "2025-01-24 14:30:00",
                "user": "test_user"
            }  // Duplicate
        ]);

        // Write the new logs with deduplication
        let result = write_audit_log_file(output_dir, new_logs, false, None);
        assert!(result.is_ok());

        let new_filepath = result.unwrap().expect("Expected Some(PathBuf)");
        let content = fs::read_to_string(&new_filepath).unwrap();
        let saved_logs: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Should only have 1 entry (the new "Create" action)
        assert_eq!(saved_logs.as_array().unwrap().len(), 1);
        assert_eq!(
            saved_logs[0].get("action").unwrap().as_str().unwrap(),
            "Create"
        );
    }

    #[test]
    fn test_deduplication_with_no_existing_files() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        // Create new logs without any existing files
        let new_logs = json!([
            {
                "action": "Login",
                "timestamp_utc": "2025-01-24 14:00:00",
                "user": "test_user"
            },
            {
                "action": "Logout",
                "timestamp_utc": "2025-01-24 15:00:00",
                "user": "test_user"
            }
        ]);

        // Write the new logs
        let result = write_audit_log_file(output_dir, new_logs, false, None);
        assert!(result.is_ok());

        let new_filepath = result.unwrap().expect("Expected Some(PathBuf)");
        let content = fs::read_to_string(&new_filepath).unwrap();
        let saved_logs: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Should have both entries
        assert_eq!(saved_logs.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_deduplication_with_older_existing_files() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        // Create an existing log file that is older than the new logs
        let existing_logs = json!([
            {
                "action": "Login",
                "timestamp_utc": "2025-01-24 10:00:00",
                "user": "test_user"
            }
        ]);

        let existing_filename = "audit_log_20250124_100000_UTC.json";
        let existing_filepath = temp_dir.path().join(existing_filename);
        fs::write(
            &existing_filepath,
            serde_json::to_string_pretty(&existing_logs).unwrap(),
        )
        .unwrap();

        // Create new logs that are all newer
        let new_logs = json!([
            {
                "action": "Create",
                "timestamp_utc": "2025-01-24 14:00:00",
                "user": "test_user"
            },
            {
                "action": "Update",
                "timestamp_utc": "2025-01-24 15:00:00",
                "user": "test_user"
            }
        ]);

        // Write the new logs
        let result = write_audit_log_file(output_dir, new_logs, false, None);
        assert!(result.is_ok());

        let new_filepath = result.unwrap().expect("Expected Some(PathBuf)");
        let content = fs::read_to_string(&new_filepath).unwrap();
        let saved_logs: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Should have both entries (no deduplication since existing file is older)
        assert_eq!(saved_logs.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_deduplication_can_be_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        // Create an existing log file with some entries
        let existing_logs = json!([
            {
                "action": "Login",
                "timestamp_utc": "2025-01-24 14:00:00",
                "user": "test_user"
            }
        ]);

        let existing_filename = "audit_log_20250124_143000_UTC.json";
        let existing_filepath = temp_dir.path().join(existing_filename);
        fs::write(
            &existing_filepath,
            serde_json::to_string_pretty(&existing_logs).unwrap(),
        )
        .unwrap();

        // Create new logs that include the same entry
        let new_logs = json!([
            {
                "action": "Login",
                "timestamp_utc": "2025-01-24 14:00:00",
                "user": "test_user"
            },  // Would be duplicate
            {
                "action": "Logout",
                "timestamp_utc": "2025-01-24 15:00:00",
                "user": "test_user"
            }
        ]);

        // Write the new logs with deduplication DISABLED
        let result = write_audit_log_file(output_dir, new_logs, true, None);
        assert!(result.is_ok());

        let new_filepath = result.unwrap().expect("Expected Some(PathBuf)");
        let content = fs::read_to_string(&new_filepath).unwrap();
        let saved_logs: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Should have both entries (deduplication was skipped)
        assert_eq!(saved_logs.as_array().unwrap().len(), 2);
    }
}

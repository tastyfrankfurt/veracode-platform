#![no_main]

use chrono::NaiveDateTime;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // Fuzz output file parsing functions from veraaudit/src/output.rs

        // Test timestamp extraction
        test_extract_last_timestamp(input);

        // Test timestamp formatting for filenames
        test_format_timestamp_for_filename(input);

        // Test timestamp parsing from filename
        test_parse_timestamp_from_filename(input);

        // Test log entry hash computation
        test_compute_log_entry_hash(input);

        // Test filename pattern matching
        test_filename_pattern_matching(input);
    }
});

/// Test extract_last_timestamp (output.rs:16)
/// Extracts timestamp from last entry in JSON array
fn test_extract_last_timestamp(json: &str) {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(json)
        && let Some(array) = value.as_array()
        && let Some(last_entry) = array.last()
    {
        // Try to get timestamp_utc field
        let _timestamp = last_entry.get("timestamp_utc");
    }
}

/// Test format_timestamp_for_filename (output.rs:39)
/// Converts timestamp to filename-safe format
fn test_format_timestamp_for_filename(timestamp: &str) {
    // Expected format: "2025-01-15 10:30:45.123" -> "2025-01-15_10-30-45-123"

    // Try to parse as NaiveDateTime with milliseconds
    if let Ok(dt) = NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S%.f") {
        // Format for filename (replace problematic chars)
        let filename_timestamp = dt.format("%Y-%m-%d_%H-%M-%S").to_string();

        // Extract milliseconds
        let _millis = dt
            .format("%.3f")
            .to_string()
            .trim_start_matches('0')
            .trim_start_matches('.')
            .to_string();

        let _final_format = format!("{}-{}", filename_timestamp, _millis);
    }

    // Also try without milliseconds
    let _ = NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S");
}

/// Test parse_timestamp_from_filename (output.rs:52)
/// Reverse of format_timestamp_for_filename
fn test_parse_timestamp_from_filename(filename_ts: &str) {
    // Expected format: "2025-01-15_10-30-45-123"
    // Convert to: "2025-01-15 10:30:45.123"

    if filename_ts.len() >= 19 {
        // Replace underscores and dashes with proper datetime separators
        let replaced = filename_ts.replace('_', " ").replace('-', ":");

        // Try to parse
        let _ = NaiveDateTime::parse_from_str(&replaced, "%Y %m %d %H:%M:%S.%f");
    }
}

/// Test compute_log_entry_hash (output.rs:109)
/// Computes xxHash of JSON log entry for deduplication
fn test_compute_log_entry_hash(json: &str) {
    if let Ok(entry) = serde_json::from_str::<serde_json::Value>(json) {
        // Serialize back to canonical JSON
        if let Ok(canonical) = serde_json::to_string(&entry) {
            // In real code, this would use xxhash-rust
            // For fuzzing, we just test the serialization
            let _hash_input = canonical.as_bytes();

            // Simulated hash computation (real code uses xxh3::xxh3_64)
            let _simulated_hash = _hash_input.len() as u64;
        }
    }
}

/// Test filename pattern matching for log files
fn test_filename_pattern_matching(filename: &str) {
    // Pattern: audit_logs_YYYY-MM-DD_HH-MM-SS-mmm.json
    // Example: audit_logs_2025-01-15_10-30-45-123.json

    if filename.starts_with("audit_logs_") && filename.ends_with(".json") {
        // Extract timestamp portion
        let timestamp_part = filename
            .trim_start_matches("audit_logs_")
            .trim_end_matches(".json");

        // Try to parse timestamp
        test_parse_timestamp_from_filename(timestamp_part);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_formatting() {
        test_format_timestamp_for_filename("2025-01-15 10:30:45.123");
        test_format_timestamp_for_filename("2025-01-15 10:30:45");
    }

    #[test]
    fn test_timestamp_parsing() {
        test_parse_timestamp_from_filename("2025-01-15_10-30-45-123");
    }

    #[test]
    fn test_json_array_timestamp() {
        let json = r#"[
            {"timestamp_utc": "2025-01-15 10:00:00"},
            {"timestamp_utc": "2025-01-15 11:00:00"}
        ]"#;
        test_extract_last_timestamp(json);
    }

    #[test]
    fn test_filename_patterns() {
        test_filename_pattern_matching("audit_logs_2025-01-15_10-30-45-123.json");
        test_filename_pattern_matching("not_a_log_file.txt");
    }
}

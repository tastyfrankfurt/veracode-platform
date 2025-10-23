//! Timestamped file output for audit logs
use crate::error::Result;
use chrono::Utc;
use log::{debug, info};
use std::fs;
use std::path::PathBuf;

/// Write audit log data to a timestamped file
///
/// # Arguments
///
/// * `output_dir` - Directory to write the file to
/// * `data` - JSON data to write
///
/// # Returns
///
/// The path to the created file
///
/// # Errors
///
/// Returns error if directory creation or file writing fails
pub fn write_audit_log_file(output_dir: &str, data: &serde_json::Value) -> Result<PathBuf> {
    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir)?;

    // Generate timestamped filename
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S_UTC");
    let filename = format!("audit_log_{timestamp}.json");
    let filepath = PathBuf::from(output_dir).join(&filename);

    debug!("Writing audit log to: {}", filepath.display());

    // Serialize and write the data
    let json_string = serde_json::to_string_pretty(data)?;
    fs::write(&filepath, json_string)?;

    info!("Audit log written to: {}", filepath.display());
    Ok(filepath)
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

        let result = write_audit_log_file(output_dir, &test_data);
        assert!(result.is_ok());

        let filepath = result.unwrap();
        assert!(filepath.exists());
        assert!(filepath.to_str().unwrap().contains("audit_log_"));
        assert!(filepath.to_str().unwrap().ends_with("_UTC.json"));

        // Verify content
        let content = fs::read_to_string(&filepath).unwrap();
        assert!(content.contains("AUDIT"));
    }
}

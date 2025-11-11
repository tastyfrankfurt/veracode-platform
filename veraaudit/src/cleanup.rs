//! File cleanup logic for audit logs
use crate::error::Result;
use chrono::{Duration, Utc};
use log::{debug, info, warn};
use std::fs;
use std::path::Path;

/// Clean up old audit log files by count
///
/// Keeps only the N most recent files, deleting older ones
///
/// # Arguments
///
/// * `output_dir` - Directory containing audit log files
/// * `keep_count` - Number of most recent files to keep
///
/// # Errors
///
/// Returns error if directory reading or file deletion fails
pub fn cleanup_by_count(output_dir: &str, keep_count: usize) -> Result<usize> {
    let path = Path::new(output_dir);
    if !path.exists() {
        debug!("Output directory does not exist, skipping cleanup");
        return Ok(0);
    }

    // Get all audit log files
    let mut files: Vec<_> = fs::read_dir(path)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with("audit_log_") && name.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();

    if files.len() <= keep_count {
        debug!(
            "File count ({}) is within limit ({}), no cleanup needed",
            files.len(),
            keep_count
        );
        return Ok(0);
    }

    // Sort by modification time (newest first)
    files.sort_by_key(|entry| entry.metadata().and_then(|m| m.modified()).ok());
    files.reverse(); // Newest first

    // Delete older files
    let mut deleted_count: usize = 0;
    for file in files.iter().skip(keep_count) {
        let filepath = file.path();
        match fs::remove_file(&filepath) {
            Ok(_) => {
                info!("Deleted old audit log: {}", filepath.display());
                deleted_count = deleted_count.saturating_add(1);
            }
            Err(e) => {
                warn!("Failed to delete {}: {}", filepath.display(), e);
            }
        }
    }

    info!(
        "Cleanup by count: deleted {} files, kept {}",
        deleted_count, keep_count
    );
    Ok(deleted_count)
}

/// Clean up audit log files older than specified hours
///
/// # Arguments
///
/// * `output_dir` - Directory containing audit log files
/// * `max_age_hours` - Maximum age in hours before deletion
///
/// # Errors
///
/// Returns error if directory reading or file deletion fails
pub fn cleanup_by_age(output_dir: &str, max_age_hours: u64) -> Result<usize> {
    let path = Path::new(output_dir);
    if !path.exists() {
        debug!("Output directory does not exist, skipping cleanup");
        return Ok(0);
    }

    let now = Utc::now();
    #[allow(clippy::cast_possible_wrap)] // max_age_hours is user-controlled but validated elsewhere
    let max_age = Duration::hours(max_age_hours as i64);
    #[allow(clippy::arithmetic_side_effects)] // chrono uses checked operations internally
    let cutoff_time = now - max_age;

    // Get all audit log files
    let files = fs::read_dir(path)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with("audit_log_") && name.ends_with(".json"))
                .unwrap_or(false)
        });

    let mut deleted_count: usize = 0;
    for file in files {
        let filepath = file.path();

        // Get file modification time
        if let Ok(metadata) = file.metadata()
            && let Ok(modified) = metadata.modified()
        {
            let file_time: chrono::DateTime<Utc> = modified.into();

            if file_time < cutoff_time {
                match fs::remove_file(&filepath) {
                    Ok(_) => {
                        #[allow(clippy::arithmetic_side_effects)]
                        // chrono uses checked operations internally
                        let age_hours = (now - file_time).num_hours();
                        info!(
                            "Deleted old audit log (age: {} hours): {}",
                            age_hours,
                            filepath.display()
                        );
                        deleted_count = deleted_count.saturating_add(1);
                    }
                    Err(e) => {
                        warn!("Failed to delete {}: {}", filepath.display(), e);
                    }
                }
            }
        }
    }

    info!(
        "Cleanup by age: deleted {} files older than {} hours",
        deleted_count, max_age_hours
    );
    Ok(deleted_count)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    use super::*;
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    use crate::test_utils::TempDir;
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    use std::fs::File;
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    use std::thread;
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    use std::time::Duration as StdDuration;

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))] // Skip in Miri due to filesystem isolation
    fn test_cleanup_by_count() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        // Create test files
        for i in 0..5 {
            let filename = format!("audit_log_test_{}.json", i);
            let filepath = temp_dir.path().join(filename);
            File::create(&filepath).unwrap();
            // Small delay to ensure different modification times
            thread::sleep(StdDuration::from_millis(10));
        }

        // Keep only 2 most recent files
        let result = cleanup_by_count(output_dir, 2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3); // Should delete 3 files

        // Verify only 2 files remain
        let remaining = fs::read_dir(temp_dir.path()).unwrap().count();
        assert_eq!(remaining, 2);
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))] // Skip in Miri due to filesystem isolation
    fn test_cleanup_by_count_no_files() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        let result = cleanup_by_count(output_dir, 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
}
